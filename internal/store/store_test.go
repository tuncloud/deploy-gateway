package store_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/tuncloud/deploy-gateway/internal/store"
)

func newOp(id string, status store.OperationStatus, requested time.Time) *store.Operation {
	return &store.Operation{
		OperationID: id, Repository: "tuncloud/backend", RepositoryID: "1",
		Action: "deployment.restart", Namespace: "backend", Deployment: "api",
		NsDep: "backend#api", Status: status, RequestedAt: requested,
		ExpiresAt: requested.Add(365 * 24 * time.Hour).Unix(),
	}
}

func TestInMemoryPutGet(t *testing.T) {
	s := store.NewInMemory()
	ctx := context.Background()
	op := newOp("op_1", store.StatusRunning, time.Now())
	if err := s.PutOperation(ctx, op); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetOperation(ctx, "op_1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != store.StatusRunning || got.Repository != "tuncloud/backend" {
		t.Fatalf("round trip mismatch: %+v", got)
	}
}

func TestInMemoryPutGetRolloutFields(t *testing.T) {
	s := store.NewInMemory()
	ctx := context.Background()
	op := newOp("op_roll", store.StatusRunning, time.Now())
	op.Action = "deployment.rollout"
	op.Container = "app"
	op.Image = "ghcr.io/tuncloud/api:v2"
	if err := s.PutOperation(ctx, op); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetOperation(ctx, "op_roll")
	if err != nil {
		t.Fatal(err)
	}
	if got.Action != "deployment.rollout" || got.Container != "app" || got.Image != "ghcr.io/tuncloud/api:v2" {
		t.Fatalf("rollout fields lost: action=%s container=%s image=%s", got.Action, got.Container, got.Image)
	}

	plain := newOp("op_restart", store.StatusRunning, time.Now())
	if err := s.PutOperation(ctx, plain); err != nil {
		t.Fatal(err)
	}
	got, _ = s.GetOperation(ctx, "op_restart")
	if got.Container != "" || got.Image != "" {
		t.Fatalf("restart op must keep container/image empty: %+v", got)
	}
}

func TestInMemoryGetNotFound(t *testing.T) {
	s := store.NewInMemory()
	if _, err := s.GetOperation(context.Background(), "missing"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
}

func TestInMemoryUpdateTerminal(t *testing.T) {
	s := store.NewInMemory()
	ctx := context.Background()
	s.PutOperation(ctx, newOp("op_2", store.StatusRunning, time.Now()))

	done := time.Now().Add(time.Minute)
	err := s.UpdateTerminal(ctx, "op_2", store.TerminalUpdate{
		Status: store.StatusSucceeded, Event: "SUCCEEDED", CompletedAt: done,
	})
	if err != nil {
		t.Fatal(err)
	}
	got, _ := s.GetOperation(ctx, "op_2")
	if got.Status != store.StatusSucceeded {
		t.Fatalf("status = %s, want succeeded", got.Status)
	}
	if got.CompletedAt == nil || !got.CompletedAt.Equal(done) {
		t.Fatalf("completedAt = %v, want %v", got.CompletedAt, done)
	}
	if len(got.Events) != 1 || got.Events[0].Event != "SUCCEEDED" {
		t.Fatalf("events = %+v", got.Events)
	}
}

func TestInMemoryUpdateTerminalAlreadyTerminal(t *testing.T) {
	s := store.NewInMemory()
	ctx := context.Background()
	s.PutOperation(ctx, newOp("op_t1", store.StatusRunning, time.Now()))

	err := s.UpdateTerminal(ctx, "op_t1", store.TerminalUpdate{
		Status: store.StatusSucceeded, Event: "SUCCEEDED", CompletedAt: time.Now(),
	})
	if err != nil {
		t.Fatalf("first terminal write on running op: %v", err)
	}

	// second writer races in (watcher vs reconciler) — must be rejected,
	// not silently overwrite the first terminal outcome.
	err = s.UpdateTerminal(ctx, "op_t1", store.TerminalUpdate{
		Status: store.StatusTimeout, Event: "TIMEOUT", CompletedAt: time.Now(),
	})
	if !errors.Is(err, store.ErrAlreadyTerminal) {
		t.Fatalf("want ErrAlreadyTerminal, got %v", err)
	}
	got, _ := s.GetOperation(ctx, "op_t1")
	if got.Status != store.StatusSucceeded {
		t.Fatalf("status = %s, want original succeeded preserved", got.Status)
	}
	if n := len(got.Events); n != 1 {
		t.Fatalf("events = %d, want 1 (rejected write must not append)", n)
	}
}

func TestInMemoryListRunningPastDeadline(t *testing.T) {
	s := store.NewInMemory()
	ctx := context.Background()
	old := time.Now().Add(-3 * time.Hour)
	fresh := time.Now().Add(-time.Minute)
	s.PutOperation(ctx, newOp("op_old", store.StatusRunning, old))
	s.PutOperation(ctx, newOp("op_fresh", store.StatusRunning, fresh))
	s.PutOperation(ctx, newOp("op_done", store.StatusSucceeded, old))

	ops, err := s.ListRunningPastDeadline(ctx, time.Now().Add(-2*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(ops) != 1 || ops[0].OperationID != "op_old" {
		t.Fatalf("want [op_old], got %+v", ops)
	}
}
