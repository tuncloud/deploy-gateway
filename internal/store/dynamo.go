package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awscfg "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// dynamoAPI is the slice of the SDK client the store needs. Extracted so
// Scan pagination is unit-testable without a live DynamoDB (v1.63.x of the
// SDK no longer ships generated per-operation client interfaces).
type dynamoAPI interface {
	PutItem(ctx context.Context, in *dynamodb.PutItemInput, opts ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error)
	UpdateItem(ctx context.Context, in *dynamodb.UpdateItemInput, opts ...func(*dynamodb.Options)) (*dynamodb.UpdateItemOutput, error)
	Scan(ctx context.Context, in *dynamodb.ScanInput, opts ...func(*dynamodb.Options)) (*dynamodb.ScanOutput, error)
}

type dynamoStore struct {
	table  string
	client dynamoAPI
}

// NewDynamo loads region + credentials via the default AWS env chain.
func NewDynamo(ctx context.Context, table string) (Store, error) {
	cfg, err := awscfg.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("aws config: %w", err)
	}
	return &dynamoStore{table: table, client: dynamodb.NewFromConfig(cfg)}, nil
}

func (d *dynamoStore) PutOperation(ctx context.Context, op *Operation) error {
	av, err := attributevalue.MarshalMap(op)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	_, err = d.client.PutItem(ctx, &dynamodb.PutItemInput{TableName: &d.table, Item: av})
	if err != nil {
		return fmt.Errorf("put: %w", err)
	}
	return nil
}

func (d *dynamoStore) GetOperation(ctx context.Context, id string) (*Operation, error) {
	return d.findOperation(ctx, id)
}

func (d *dynamoStore) UpdateTerminal(ctx context.Context, id string, upd TerminalUpdate) error {
	op, err := d.findOperation(ctx, id)
	if err != nil {
		return err
	}

	// events list_append: ":empty" guards items created without an events list.
	expr := "SET #st = :st, events = list_append(if_not_exists(events, :empty), :ev), " +
		"error_code = :ec, error_message = :em, completed_at = :ca"
	for _, key := range d.updateKeysFor(op) {
		_, err = d.client.UpdateItem(ctx, &dynamodb.UpdateItemInput{
			TableName:        &d.table,
			Key:              key,
			UpdateExpression: aws.String(expr),
			// Guard against racing writers (watcher vs reconciler): only the first
			// terminal write wins, later ones fail the condition.
			ConditionExpression:      aws.String("#st = :running"),
			ExpressionAttributeNames: map[string]string{"#st": "status"},
			ExpressionAttributeValues: map[string]types.AttributeValue{
				":st":      &types.AttributeValueMemberS{Value: string(upd.Status)},
				":running": &types.AttributeValueMemberS{Value: string(StatusRunning)},
				":ev": &types.AttributeValueMemberL{Value: []types.AttributeValue{
					&types.AttributeValueMemberM{Value: map[string]types.AttributeValue{
						"event": &types.AttributeValueMemberS{Value: upd.Event},
						"at":    &types.AttributeValueMemberS{Value: upd.CompletedAt.UTC().Format(time.RFC3339Nano)},
					}},
				}},
				":empty": &types.AttributeValueMemberL{Value: []types.AttributeValue{}},
				":ec":    &types.AttributeValueMemberS{Value: upd.ErrorCode},
				":em":    &types.AttributeValueMemberS{Value: upd.ErrorMessage},
				":ca":    &types.AttributeValueMemberS{Value: upd.CompletedAt.UTC().Format(time.RFC3339Nano)},
			},
		})
		if err == nil {
			return nil
		}
		if !isKeySchemaMismatch(err) {
			break
		}
	}

	var nf *types.ResourceNotFoundException
	if errors.As(err, &nf) {
		return ErrNotFound
	}
	var ccfe *types.ConditionalCheckFailedException
	if errors.As(err, &ccfe) {
		return ErrAlreadyTerminal
	}
	return fmt.Errorf("update: %w", err)
}

func (d *dynamoStore) ListRunningPastDeadline(ctx context.Context, olderThan time.Time) ([]*Operation, error) {
	// Table is tiny (a few items/day); Scan with filter is correct and cheap here.
	// Scan Limit counts items EVALUATED, not matched — terminal items (365d TTL)
	// can fill many pages before a running one appears in scan order, so we must
	// loop on LastEvaluatedKey or orphaned running ops past page one are never
	// swept (violates "no op stuck running forever").
	ops := []*Operation{}
	var start map[string]types.AttributeValue
	for {
		out, err := d.client.Scan(ctx, &dynamodb.ScanInput{
			TableName:                &d.table,
			FilterExpression:         aws.String("#st = :running AND requested_at < :t"),
			ExpressionAttributeNames: map[string]string{"#st": "status"},
			ExpressionAttributeValues: map[string]types.AttributeValue{
				":running": &types.AttributeValueMemberS{Value: string(StatusRunning)},
				":t":       &types.AttributeValueMemberS{Value: olderThan.UTC().Format(time.RFC3339Nano)},
			},
			Limit:             aws.Int32(100),
			ExclusiveStartKey: start,
		})
		if err != nil {
			return nil, fmt.Errorf("scan: %w", err)
		}
		for _, item := range out.Items {
			var op Operation
			if err := attributevalue.UnmarshalMap(item, &op); err != nil {
				return nil, fmt.Errorf("unmarshal scan item: %w", err)
			}
			ops = append(ops, &op)
		}
		if out.LastEvaluatedKey == nil {
			return ops, nil
		}
		start = out.LastEvaluatedKey
	}
}

func (d *dynamoStore) Ping(ctx context.Context) error {
	_, err := d.client.Scan(ctx, &dynamodb.ScanInput{
		TableName: &d.table,
		Limit:     aws.Int32(1),
	})
	return err
}

func (d *dynamoStore) findOperation(ctx context.Context, id string) (*Operation, error) {
	var start map[string]types.AttributeValue
	var found *Operation
	for {
		out, err := d.client.Scan(ctx, &dynamodb.ScanInput{
			TableName:        &d.table,
			FilterExpression: aws.String("#op = :op"),
			ExpressionAttributeNames: map[string]string{
				"#op": "operation_id",
			},
			ExpressionAttributeValues: map[string]types.AttributeValue{
				":op": &types.AttributeValueMemberS{Value: id},
			},
			Limit:             aws.Int32(100),
			ExclusiveStartKey: start,
		})
		if err != nil {
			return nil, fmt.Errorf("scan by operation_id: %w", err)
		}
		for _, item := range out.Items {
			var op Operation
			if err := attributevalue.UnmarshalMap(item, &op); err != nil {
				return nil, fmt.Errorf("unmarshal operation: %w", err)
			}
			if found != nil {
				return nil, fmt.Errorf("scan by operation_id: duplicate operation_id %q", id)
			}
			found = &op
		}
		if out.LastEvaluatedKey == nil {
			if found == nil {
				return nil, ErrNotFound
			}
			return found, nil
		}
		start = out.LastEvaluatedKey
	}
}

func (d *dynamoStore) updateKeysFor(op *Operation) []map[string]types.AttributeValue {
	hashOnly := map[string]types.AttributeValue{
		"operation_id": &types.AttributeValueMemberS{Value: op.OperationID},
	}
	if op.RequestedAt.IsZero() {
		return []map[string]types.AttributeValue{hashOnly}
	}
	withSort := map[string]types.AttributeValue{
		"operation_id": &types.AttributeValueMemberS{Value: op.OperationID},
		"requested_at": &types.AttributeValueMemberS{Value: op.RequestedAt.UTC().Format(time.RFC3339Nano)},
	}
	return []map[string]types.AttributeValue{withSort, hashOnly}
}

func isKeySchemaMismatch(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "ValidationException") &&
		strings.Contains(msg, "key element does not match the schema")
}
