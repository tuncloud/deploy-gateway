package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

type fakeSchemaClient struct {
	dynamoAPI
	scanOutputs  []*dynamodb.ScanOutput
	scanInputs   []*dynamodb.ScanInput
	scanCalls    int
	updateErrs   []error
	updateInputs []*dynamodb.UpdateItemInput
	updateCalls  int
}

func (f *fakeSchemaClient) Scan(_ context.Context, in *dynamodb.ScanInput, _ ...func(*dynamodb.Options)) (*dynamodb.ScanOutput, error) {
	f.scanInputs = append(f.scanInputs, in)
	if f.scanCalls >= len(f.scanOutputs) {
		return nil, errors.New("fakeSchemaClient: no more scan outputs")
	}
	out := f.scanOutputs[f.scanCalls]
	f.scanCalls++
	return out, nil
}

func (f *fakeSchemaClient) UpdateItem(_ context.Context, in *dynamodb.UpdateItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.UpdateItemOutput, error) {
	f.updateInputs = append(f.updateInputs, in)
	if f.updateCalls >= len(f.updateErrs) {
		f.updateCalls++
		return &dynamodb.UpdateItemOutput{}, nil
	}
	err := f.updateErrs[f.updateCalls]
	f.updateCalls++
	if err != nil {
		return nil, err
	}
	return &dynamodb.UpdateItemOutput{}, nil
}

func opPage(t *testing.T, lastKey string, ops ...*Operation) *dynamodb.ScanOutput {
	t.Helper()
	items := make([]map[string]types.AttributeValue, 0, len(ops))
	for _, op := range ops {
		av, err := attributevalue.MarshalMap(op)
		if err != nil {
			t.Fatal(err)
		}
		items = append(items, av)
	}
	out := &dynamodb.ScanOutput{Items: items}
	if lastKey != "" {
		out.LastEvaluatedKey = map[string]types.AttributeValue{
			"operation_id": &types.AttributeValueMemberS{Value: lastKey},
		}
	}
	return out
}

func TestPingUsesScanLimitOne(t *testing.T) {
	fc := &fakeSchemaClient{scanOutputs: []*dynamodb.ScanOutput{{}}}
	d := &dynamoStore{table: "ops", client: fc}

	if err := d.Ping(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(fc.scanInputs) != 1 {
		t.Fatalf("want 1 Scan call, got %d", len(fc.scanInputs))
	}
	if fc.scanInputs[0].Limit == nil || *fc.scanInputs[0].Limit != 1 {
		t.Fatalf("want readiness scan limit 1, got %+v", fc.scanInputs[0].Limit)
	}
}

func TestGetOperationFindsOperationByScan(t *testing.T) {
	op := runningOp("op_123", time.Hour)
	fc := &fakeSchemaClient{scanOutputs: []*dynamodb.ScanOutput{opPage(t, "", op)}}
	d := &dynamoStore{table: "ops", client: fc}

	got, err := d.GetOperation(context.Background(), "op_123")
	if err != nil {
		t.Fatal(err)
	}
	if got.OperationID != op.OperationID {
		t.Fatalf("want %q, got %q", op.OperationID, got.OperationID)
	}
}

func TestUpdateTerminalFallsBackToHashOnlyKey(t *testing.T) {
	op := runningOp("op_123", time.Hour)
	fc := &fakeSchemaClient{
		scanOutputs: []*dynamodb.ScanOutput{opPage(t, "", op)},
		updateErrs: []error{
			errors.New("ValidationException: The provided key element does not match the schema"),
			nil,
		},
	}
	d := &dynamoStore{table: "ops", client: fc}

	err := d.UpdateTerminal(context.Background(), op.OperationID, TerminalUpdate{
		Status:      StatusSucceeded,
		Event:       "SUCCEEDED",
		CompletedAt: time.Now().UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(fc.updateInputs) != 2 {
		t.Fatalf("want 2 UpdateItem attempts, got %d", len(fc.updateInputs))
	}
	if _, ok := fc.updateInputs[0].Key["requested_at"]; !ok {
		t.Fatalf("first update should try composite key, got %+v", fc.updateInputs[0].Key)
	}
	if _, ok := fc.updateInputs[1].Key["requested_at"]; ok {
		t.Fatalf("fallback update should use hash-only key, got %+v", fc.updateInputs[1].Key)
	}
}
