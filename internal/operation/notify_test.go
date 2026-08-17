package operation_test

import (
	"context"
	"log/slog"
	"sync"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/watch"

	"github.com/tuncloud/deploy-gateway/internal/notify"
	"github.com/tuncloud/deploy-gateway/internal/operation"
	"github.com/tuncloud/deploy-gateway/internal/store"
)

// fakeNotifier records what the manager announced, and the *notify.Message
// handles it hands out and receives back, so tests can assert the manager
// threads the same handle from Started through to Resolved rather than
// discarding it (which would silently double the messages per deploy).
type fakeNotifier struct {
	mu              sync.Mutex
	started         []*store.Operation
	resolved        []*store.Operation
	startedHandles  []*notify.Message
	resolvedHandles []*notify.Message
}

func (f *fakeNotifier) Started(op *store.Operation) *notify.Message {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.started = append(f.started, op)
	// A sentinel handle, not nil: this is legal because we never call wait()
	// on it, so a zero-value (nil) ready channel is harmless.
	msg := &notify.Message{}
	f.startedHandles = append(f.startedHandles, msg)
	return msg
}

func (f *fakeNotifier) Resolved(op *store.Operation, msg *notify.Message) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.resolved = append(f.resolved, op)
	f.resolvedHandles = append(f.resolvedHandles, msg)
}

// handles returns the most recently handed-out Started handle and the most
// recently received Resolved handle.
func (f *fakeNotifier) handles() (started, resolved *notify.Message) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.startedHandles) > 0 {
		started = f.startedHandles[len(f.startedHandles)-1]
	}
	if len(f.resolvedHandles) > 0 {
		resolved = f.resolvedHandles[len(f.resolvedHandles)-1]
	}
	return started, resolved
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

// completingKube reports the rollout as already complete on the very first
// GetDeployment call, so watchRollout resolves the operation in evalOnce
// without ever needing to start a watch.
type completingKube struct {
	containers []corev1.Container
}

func (f *completingKube) RestartDeployment(context.Context, string, string) error { return nil }
func (f *completingKube) RolloutDeployment(context.Context, string, string, string, string) error {
	return nil
}
func (f *completingKube) GetDeployment(context.Context, string, string) (*appsv1.Deployment, error) {
	return &appsv1.Deployment{
		Spec: appsv1.DeploymentSpec{Template: corev1.PodTemplateSpec{
			Spec: corev1.PodSpec{Containers: f.containers},
		}},
		Status: appsv1.DeploymentStatus{
			UpdatedReplicas:   1,
			ReadyReplicas:     1,
			AvailableReplicas: 1,
		},
	}, nil
}
func (f *completingKube) WatchDeployment(context.Context, string, string) (watch.Interface, error) {
	return watch.NewFake(), nil
}

// TestResolvedReceivesTheHandleStartedReturned is the regression test for the
// manager silently degrading "one message, edited in place" into "two
// messages per deploy": it is the pointer identity of the *notify.Message
// handle — not just the notification counts — that proves watchRollout
// threaded the handle Started returned through to Resolved instead of
// dropping it (e.g. by passing nil).
func TestResolvedReceivesTheHandleStartedReturned(t *testing.T) {
	ctx := context.Background()
	fk := &completingKube{containers: []corev1.Container{{Name: "app"}}}
	fn := &fakeNotifier{}
	m := operation.NewManager(fk, store.NewInMemory(), fn, slog.Default(), time.Minute)

	if _, err := m.Rollout(ctx, identity(), "ns", "api", "", "img:v2"); err != nil {
		t.Fatal(err)
	}

	waitFor(t, 2*time.Second, func() bool {
		_, resolved := fn.counts()
		return resolved == 1
	})

	started, resolved := fn.handles()
	if started == nil {
		t.Fatal("Started must hand out a non-nil handle")
	}
	if started != resolved {
		t.Fatalf("Resolved handle = %p, want the identical handle Started returned (%p)", resolved, started)
	}
}
