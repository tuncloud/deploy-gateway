package operation_test

import (
	"context"
	"log/slog"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"

	"github.com/tuncloud/deploy-gateway/internal/notify"
	"github.com/tuncloud/deploy-gateway/internal/operation"
	"github.com/tuncloud/deploy-gateway/internal/store"
)

// fakeNotifier records what the manager announced. It returns a nil handle,
// which the real Message type accepts everywhere.
type fakeNotifier struct {
	mu       sync.Mutex
	started  []*store.Operation
	resolved []*store.Operation
}

func (f *fakeNotifier) Started(op *store.Operation) *notify.Message {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.started = append(f.started, op)
	return nil
}

func (f *fakeNotifier) Resolved(op *store.Operation, _ *notify.Message) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.resolved = append(f.resolved, op)
}

func (f *fakeNotifier) counts() (int, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.started), len(f.resolved)
}

func (f *fakeNotifier) lastResolved() *store.Operation {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.resolved) == 0 {
		return nil
	}
	return f.resolved[len(f.resolved)-1]
}

// alreadyTerminalStore simulates losing the terminal-write race to another
// resolver (watcher vs sweeper vs lazy GET).
type alreadyTerminalStore struct{ store.Store }

func (alreadyTerminalStore) UpdateTerminal(context.Context, string, store.TerminalUpdate) error {
	return store.ErrAlreadyTerminal
}

func TestRolloutAnnouncesStartAfterPatch(t *testing.T) {
	ctx := context.Background()
	fk := &rolloutFakeKube{containers: []corev1.Container{{Name: "app"}}}
	fn := &fakeNotifier{}
	m := operation.NewManager(fk, store.NewInMemory(), fn, slog.Default(), time.Minute)

	if _, err := m.Rollout(ctx, identity(), "ns", "api", "", "img:v2"); err != nil {
		t.Fatal(err)
	}

	started, _ := fn.counts()
	if started != 1 {
		t.Fatalf("started notifications = %d, want 1", started)
	}
	if got := fn.started[0].Image; got != "img:v2" {
		t.Fatalf("announced image = %q, want img:v2", got)
	}
}

func TestPatchFailureNotifiesTerminalOnly(t *testing.T) {
	ctx := context.Background()
	fk := &rolloutFakeKube{containers: []corev1.Container{{Name: "app"}}, failRollout: true}
	fn := &fakeNotifier{}
	m := operation.NewManager(fk, store.NewInMemory(), fn, slog.Default(), time.Minute)

	if _, err := m.Rollout(ctx, identity(), "ns", "api", "", "img:v2"); err == nil {
		t.Fatal("patch failure must surface error")
	}

	started, resolved := fn.counts()
	if started != 0 {
		t.Fatalf("started notifications = %d, want 0 (patch never landed)", started)
	}
	if resolved != 1 {
		t.Fatalf("resolved notifications = %d, want 1", resolved)
	}
	last := fn.lastResolved()
	if last.Status != store.StatusFailed || last.ErrorCode != "K8S_PATCH_FAILED" {
		t.Fatalf("notified op = %s/%s, want failed/K8S_PATCH_FAILED", last.Status, last.ErrorCode)
	}
	if last.CompletedAt == nil {
		t.Fatal("notified op must carry CompletedAt so the message can show elapsed time")
	}
}

func TestTerminalRaceLoserDoesNotNotify(t *testing.T) {
	ctx := context.Background()
	fk := &rolloutFakeKube{containers: []corev1.Container{{Name: "app"}}, failRollout: true}
	fn := &fakeNotifier{}
	m := operation.NewManager(fk, alreadyTerminalStore{store.NewInMemory()}, fn, slog.Default(), time.Minute)

	if _, err := m.Rollout(ctx, identity(), "ns", "api", "", "img:v2"); err == nil {
		t.Fatal("patch failure must surface error")
	}

	if _, resolved := fn.counts(); resolved != 0 {
		t.Fatalf("resolved notifications = %d, want 0 (another writer already notified)", resolved)
	}
}

func TestSweepResolutionNotifiesOnce(t *testing.T) {
	ctx := context.Background()
	fn := &fakeNotifier{}
	st := store.NewInMemory()
	m := operation.NewManager(&getErrKube{getErr: context.DeadlineExceeded}, st, fn, slog.Default(), time.Minute)

	st.PutOperation(ctx, staleRunningOp())
	m.ReconcileSweep(ctx)

	started, resolved := fn.counts()
	if started != 0 {
		t.Fatalf("started notifications = %d, want 0 (sweeper announces nothing)", started)
	}
	if resolved != 1 {
		t.Fatalf("resolved notifications = %d, want 1", resolved)
	}
	if got := fn.lastResolved().Status; got != store.StatusTimeout {
		t.Fatalf("notified status = %s, want timeout", got)
	}
}

// A real notifier whose every call fails must leave the operation record
// untouched: delivery is best-effort, the audit table is the source of truth.
func TestUndeliverableNotificationsDoNotAffectTheOperation(t *testing.T) {
	ctx := context.Background()
	fk := &rolloutFakeKube{containers: []corev1.Container{{Name: "app"}}, failRollout: true}
	st := store.NewInMemory()
	// nothing is listening on port 1, so every send fails after its retries
	dead := notify.New(notify.Config{
		BotToken: "t", ChatID: "-1", APIBase: "http://127.0.0.1:1",
	}, slog.Default())
	m := operation.NewManager(fk, st, dead, slog.Default(), time.Minute)

	opID, err := m.Rollout(ctx, identity(), "ns", "api", "", "img:v2")
	if err == nil {
		t.Fatal("patch failure must surface error")
	}

	op, err := st.GetOperation(ctx, opID)
	if err != nil {
		t.Fatal(err)
	}
	if op.Status != store.StatusFailed || op.ErrorCode != "K8S_PATCH_FAILED" {
		t.Fatalf("op = %s/%s, want failed/K8S_PATCH_FAILED", op.Status, op.ErrorCode)
	}
}
