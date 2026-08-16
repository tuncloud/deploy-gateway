package store_test

import (
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
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
