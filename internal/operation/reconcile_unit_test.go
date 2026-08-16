package operation_test

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	"k8s.io/apimachinery/pkg/watch"

	"github.com/tuncloud/deploy-gateway/internal/operation"
	"github.com/tuncloud/deploy-gateway/internal/store"
)

// getErrKube fails every GetDeployment with the configured error; used to
// unit-test resolveRunning's error classification without envtest.
type getErrKube struct{ getErr error }

func (g *getErrKube) RestartDeployment(context.Context, string, string) error { return nil }
func (g *getErrKube) GetDeployment(context.Context, string, string) (*appsv1.Deployment, error) {
	return nil, g.getErr
}
func (g *getErrKube) WatchDeployment(context.Context, string, string) (watch.Interface, error) {
	return watch.NewFake(), nil
}

func staleRunningOp() *store.Operation {
	return &store.Operation{
		OperationID: "op_cancel", Repository: "r", RepositoryID: "1",
		Action: operation.ActionRestart, Namespace: "gone", Deployment: "d",
		NsDep: "gone#d", Status: store.StatusRunning,
		RequestedAt: time.Now().Add(-3 * time.Hour),
		ExpiresAt:   time.Now().Add(365 * 24 * time.Hour).Unix(),
	}
}

// A canceled context (HTTP client aborted a lazy GET, sweeper shut down on
// SIGTERM) must NOT resolve a possibly-healthy operation: the op is returned
// as-is running, no terminal write.
func TestResolveRunningCanceledContextLeavesOpRunning(t *testing.T) {
	ctx := context.Background()
	st := store.NewInMemory()
	m := operation.NewManager(&getErrKube{getErr: context.Canceled}, st, slog.Default(), time.Minute)
	st.PutOperation(ctx, staleRunningOp())

	op, err := m.Get(ctx, "op_cancel")
	if err != nil {
		t.Fatal(err)
	}
	if op.Status != store.StatusRunning {
		t.Fatalf("canceled ctx must not resolve op, got %s (code=%q)", op.Status, op.ErrorCode)
	}
}

// Sweeper path: same guard via ReconcileSweep with a canceled context.
func TestReconcileSweepCanceledContextLeavesOpRunning(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	st := store.NewInMemory()
	m := operation.NewManager(&getErrKube{getErr: context.Canceled}, st, slog.Default(), time.Minute)
	st.PutOperation(context.Background(), staleRunningOp())

	m.ReconcileSweep(ctx)

	op, _ := st.GetOperation(context.Background(), "op_cancel")
	if op.Status != store.StatusRunning {
		t.Fatalf("canceled sweep must not resolve op, got %s", op.Status)
	}
}

// Contrast: a genuine (non-cancel) read error still resolves to timeout.
func TestResolveRunningRealErrorStillTimesOut(t *testing.T) {
	ctx := context.Background()
	st := store.NewInMemory()
	m := operation.NewManager(&getErrKube{getErr: errors.New("connection refused")}, st, slog.Default(), time.Minute)
	st.PutOperation(ctx, staleRunningOp())

	m.ReconcileSweep(ctx)

	op, _ := st.GetOperation(ctx, "op_cancel")
	if op.Status != store.StatusTimeout {
		t.Fatalf("real read error should timeout op, got %s", op.Status)
	}
}
