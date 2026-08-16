package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	awscfg "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// dynamoAPI is the slice of the SDK client the store needs. Extracted so
// Scan pagination is unit-testable without a live DynamoDB (v1.63.x of the
// SDK no longer ships generated per-operation client interfaces).
type dynamoAPI interface {
	PutItem(ctx context.Context, in *dynamodb.PutItemInput, opts ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error)
	GetItem(ctx context.Context, in *dynamodb.GetItemInput, opts ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error)
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
	out, err := d.client.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: &d.table,
		Key:       map[string]types.AttributeValue{"operation_id": &types.AttributeValueMemberS{Value: id}},
	})
	if err != nil {
		return nil, fmt.Errorf("get: %w", err)
	}
	if out.Item == nil {
		return nil, ErrNotFound
	}
	var op Operation
	if err := attributevalue.UnmarshalMap(out.Item, &op); err != nil {
		return nil, fmt.Errorf("unmarshal: %w", err)
	}
	return &op, nil
}

func (d *dynamoStore) UpdateTerminal(ctx context.Context, id string, upd TerminalUpdate) error {
	// events list_append: ":empty" guards items created without an events list.
	expr := "SET #st = :st, events = list_append(if_not_exists(events, :empty), :ev), " +
		"error_code = :ec, error_message = :em, completed_at = :ca"
	_, err := d.client.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:        &d.table,
		Key:              map[string]types.AttributeValue{"operation_id": &types.AttributeValueMemberS{Value: id}},
		UpdateExpression: aws.String(expr),
		// Guard against racing writers (watcher vs reconciler): only the first
		// terminal write wins, later ones fail the condition.
		ConditionExpression:       aws.String("#st = :running"),
		ExpressionAttributeNames:  map[string]string{"#st": "status"},
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
	if err != nil {
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
	return nil
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
			TableName:                 &d.table,
			FilterExpression:          aws.String("#st = :running AND requested_at < :t"),
			ExpressionAttributeNames:  map[string]string{"#st": "status"},
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
	_, err := d.client.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: &d.table,
		Key:       map[string]types.AttributeValue{"operation_id": &types.AttributeValueMemberS{Value: "op_ping"}},
	})
	return err
}
