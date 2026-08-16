package store_test

import (
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/tuncloud/deploy-gateway/internal/store"
)

func TestOperationDynamoRoundTrip(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	done := now.Add(2 * time.Minute)
	op := &store.Operation{
		OperationID: "op_01HXYZ", Repository: "tuncloud/backend", RepositoryID: "123",
		Actor: "tuando", Workflow: "deploy.yml", RunID: "1827", RunAttempt: "1",
		EventName: "push", Action: "deployment.restart",
		Namespace: "backend", Deployment: "api", NsDep: "backend#api",
		Status: store.StatusSucceeded, ErrorCode: "", ErrorMessage: "",
		RequestedAt: now, CompletedAt: &done,
		ExpiresAt: now.Add(365 * 24 * time.Hour).Unix(),
		Events:    []store.AuditEvent{{Event: "REQUESTED", At: now}, {Event: "SUCCEEDED", At: done}},
	}

	av, err := attributevalue.MarshalMap(op)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := av["ns_dep"]; !ok {
		t.Fatal("ns_dep attr missing (GSI-2 key)")
	}

	var back store.Operation
	if err := attributevalue.UnmarshalMap(av, &back); err != nil {
		t.Fatal(err)
	}
	if back.OperationID != op.OperationID || back.Status != op.Status ||
		back.NsDep != op.NsDep || back.ExpiresAt != op.ExpiresAt {
		t.Fatalf("round trip mismatch: %+v", back)
	}
	if back.CompletedAt == nil || !back.CompletedAt.Equal(*op.CompletedAt) {
		t.Fatalf("completedAt mismatch: %v", back.CompletedAt)
	}
	if len(back.Events) != 2 || back.Events[1].Event != "SUCCEEDED" {
		t.Fatalf("events mismatch: %+v", back.Events)
	}
}

// TestUpdateTerminalEventShapeUnmarshals pins the hand-built :ev AttributeValue
// from dynamoStore.UpdateTerminal against attributevalue's AuditEvent decoding.
// GetOperation UnmarshalMaps whatever UpdateItem wrote, so any divergence between
// the hand-built {"event","at"} map shape and AuditEvent's dynamodbav tags would
// make every GET on a terminal op fail.
func TestUpdateTerminalEventShapeUnmarshals(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	done := now.Add(5 * time.Minute)

	// Exact shape dynamoStore.UpdateTerminal builds for the :ev placeholder.
	handBuilt := &types.AttributeValueMemberL{Value: []types.AttributeValue{
		&types.AttributeValueMemberM{Value: map[string]types.AttributeValue{
			"event": &types.AttributeValueMemberS{Value: "TIMED_OUT"},
			"at":    &types.AttributeValueMemberS{Value: done.UTC().Format(time.RFC3339Nano)},
		}},
	}}

	// One event marshalled by attributevalue itself, as PutOperation would write.
	requested, err := attributevalue.Marshal(store.AuditEvent{Event: "REQUESTED", At: now})
	if err != nil {
		t.Fatal(err)
	}

	item := map[string]types.AttributeValue{
		"operation_id": &types.AttributeValueMemberS{Value: "op_01HXYZ"},
		"events": &types.AttributeValueMemberL{Value: append(
			[]types.AttributeValue{handBuilt.Value[0]}, requested,
		)},
	}

	var op store.Operation
	if err := attributevalue.UnmarshalMap(item, &op); err != nil {
		t.Fatal(err)
	}
	if len(op.Events) != 2 {
		t.Fatalf("want 2 events, got %d: %+v", len(op.Events), op.Events)
	}
	if op.Events[0].Event != "TIMED_OUT" || op.Events[1].Event != "REQUESTED" {
		t.Fatalf("event names mismatch: %+v", op.Events)
	}
	if !op.Events[0].At.Equal(done) || !op.Events[1].At.Equal(now) {
		t.Fatalf("timestamps mismatch: %+v", op.Events)
	}
}
