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

// fakeScanner serves canned Scan pages in order and records every input.
// Embedded nil dynamoAPI satisfies the other methods; only Scan is used here.
type fakeScanner struct {
	dynamoAPI
	pages  []*dynamodb.ScanOutput
	inputs []*dynamodb.ScanInput
	calls  int
}

func (f *fakeScanner) Scan(_ context.Context, in *dynamodb.ScanInput, _ ...func(*dynamodb.Options)) (*dynamodb.ScanOutput, error) {
	f.inputs = append(f.inputs, in)
	if f.calls >= len(f.pages) {
		return nil, errors.New("fakeScanner: no more pages")
	}
	out := f.pages[f.calls]
	f.calls++
	return out, nil
}

func page(t *testing.T, lastKey string, ops ...*Operation) *dynamodb.ScanOutput {
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

func runningOp(id string, age time.Duration) *Operation {
	return &Operation{
		OperationID: id, Repository: "r", RepositoryID: "1",
		Action: "deployment.restart", Namespace: "ns", Deployment: "d",
		NsDep: "ns#d", Status: StatusRunning,
		RequestedAt: time.Now().UTC().Add(-age),
		ExpiresAt:   time.Now().Add(365 * 24 * time.Hour).Unix(),
	}
}

// Page one evaluates 100 terminal items — none pass the server-side filter,
// so Items is empty, but a LastEvaluatedKey is still returned. The matching
// running op lives on page two; the sweeper must follow the key or never see it.
// (The fake cannot emulate FilterExpression, so pages carry only items that
// would have passed it.)
func TestListRunningPastDeadlinePaginates(t *testing.T) {
	fs := &fakeScanner{pages: []*dynamodb.ScanOutput{
		page(t, "op_t100"), // terminal-only page: 0 matched items, key present
		page(t, "", runningOp("op_r1", 3*time.Hour)),
	}}
	d := &dynamoStore{table: "ops", client: fs}

	ops, err := d.ListRunningPastDeadline(context.Background(), time.Now().Add(-2*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(ops) != 1 || ops[0].OperationID != "op_r1" {
		t.Fatalf("want only op_r1 from page two, got %d ops", len(ops))
	}
	if fs.calls != 2 {
		t.Fatalf("want 2 Scan calls, got %d", fs.calls)
	}
	if fs.inputs[1].ExclusiveStartKey == nil ||
		fs.inputs[1].ExclusiveStartKey["operation_id"].(*types.AttributeValueMemberS).Value != "op_t100" {
		t.Fatalf("second Scan must resume at page-one LastEvaluatedKey, got %+v", fs.inputs[1].ExclusiveStartKey)
	}
}

// Single page, no LastEvaluatedKey → exactly one Scan, no follow-up.
func TestListRunningPastDeadlineSinglePage(t *testing.T) {
	fs := &fakeScanner{pages: []*dynamodb.ScanOutput{
		page(t, "", runningOp("op_r1", 3*time.Hour)),
	}}
	d := &dynamoStore{table: "ops", client: fs}

	ops, err := d.ListRunningPastDeadline(context.Background(), time.Now().Add(-2*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(ops) != 1 {
		t.Fatalf("want 1 op, got %+v", ops)
	}
	if fs.calls != 1 {
		t.Fatalf("want 1 Scan call, got %d", fs.calls)
	}
}
