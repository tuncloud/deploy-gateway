package operation_test

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"

	"github.com/tuncloud/deploy-gateway/internal/authn"
	"github.com/tuncloud/deploy-gateway/internal/kube"
	"github.com/tuncloud/deploy-gateway/internal/kubetest"
	"github.com/tuncloud/deploy-gateway/internal/operation"
	"github.com/tuncloud/deploy-gateway/internal/store"
)

func identity() *authn.GitHubIdentity {
	return &authn.GitHubIdentity{
		Subject:      "repo:tuncloud/backend:ref:refs/heads/main",
		Repository:   "tuncloud/backend", RepositoryID: "123",
		Actor: "tuando", Workflow: "deploy.yml", RunID: "1827", RunAttempt: "1", EventName: "push",
	}
}

func setup(t *testing.T) (*operation.Manager, store.Store, kubernetes.Interface) {
	cfg, cs := kubetest.Start(t)
	k, err := kube.NewFromConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	st := store.NewInMemory()
	m := operation.NewManager(k, st, slog.Default(), 30*time.Second)
	return m, st, cs
}

func TestRestartHappyPathSucceeds(t *testing.T) {
	ctx := context.Background()
	m, st, cs := setup(t)
	ns := "app"
	cs.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}}, metav1.CreateOptions{})
	dep := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: ns, Generation: 1},
		Spec: appsv1.DeploymentSpec{
			Replicas: ptr32(1),
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "api"}},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "api"}},
				Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "c", Image: "busybox"}}},
			},
		},
	}
	cs.AppsV1().Deployments(ns).Create(ctx, dep, metav1.CreateOptions{})

	opID, err := m.Restart(ctx, identity(), ns, "api")
	if err != nil {
		t.Fatalf("restart: %v", err)
	}
	if opID == "" {
		t.Fatal("operation id empty")
	}

	// simulate rollout completing (no kubelet in envtest): patch bumped generation,
	// we update status to the completed shape.
	got, _ := cs.AppsV1().Deployments(ns).Get(ctx, "api", metav1.GetOptions{})
	got.Status.Replicas = 1
	got.Status.ObservedGeneration = got.Generation
	got.Status.UpdatedReplicas = 1
	got.Status.ReadyReplicas = 1
	got.Status.AvailableReplicas = 1
	if _, err := cs.AppsV1().Deployments(ns).UpdateStatus(ctx, got, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}

	waitFor(t, 10*time.Second, func() bool {
		op, err := st.GetOperation(ctx, opID)
		return err == nil && op.Status == store.StatusSucceeded
	})
}

func TestRestartPatchFailureMarksFailed(t *testing.T) {
	ctx := context.Background()
	m, st, _ := setup(t)

	opID, err := m.Restart(ctx, identity(), "missing-ns", "ghost")
	if err == nil {
		t.Fatal("patch against missing deployment must error")
	}
	if opID == "" {
		t.Fatal("operation must exist even when patch fails")
	}
	op, err := st.GetOperation(ctx, opID)
	if err != nil {
		t.Fatal(err)
	}
	if op.Status != store.StatusFailed || op.ErrorCode != "K8S_PATCH_FAILED" {
		t.Fatalf("op = %s/%s, want failed/K8S_PATCH_FAILED", op.Status, op.ErrorCode)
	}
}

func TestRestartRolloutFailed(t *testing.T) {
	ctx := context.Background()
	m, st, cs := setup(t)
	ns := "fail-ns"
	cs.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}}, metav1.CreateOptions{})
	dep := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: ns, Generation: 1},
		Spec: appsv1.DeploymentSpec{
			Replicas: ptr32(1),
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "api"}},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "api"}},
				Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "c", Image: "busybox"}}},
			},
		},
	}
	cs.AppsV1().Deployments(ns).Create(ctx, dep, metav1.CreateOptions{})

	opID, _ := m.Restart(ctx, identity(), ns, "api")

	got, _ := cs.AppsV1().Deployments(ns).Get(ctx, "api", metav1.GetOptions{})
	got.Status.ObservedGeneration = got.Generation
	got.Status.Conditions = []appsv1.DeploymentCondition{{
		Type: appsv1.DeploymentProgressing, Status: corev1.ConditionFalse,
		Reason: "ProgressDeadlineExceeded", LastUpdateTime: metav1.Now(),
	}}
	cs.AppsV1().Deployments(ns).UpdateStatus(ctx, got, metav1.UpdateOptions{})

	waitFor(t, 10*time.Second, func() bool {
		op, err := st.GetOperation(ctx, opID)
		return err == nil && op.Status == store.StatusFailed && op.ErrorCode == "ROLLOUT_FAILED"
	})
}

func TestReconcileSweepResolvesStaleRunning(t *testing.T) {
	ctx := context.Background()
	m, st, _ := setup(t)

	// stale running op whose deployment is actually complete
	stale := &store.Operation{
		OperationID: "op_stale", Repository: "tuncloud/backend", RepositoryID: "1",
		Action: operation.ActionRestart, Namespace: "gone-ns", Deployment: "api",
		NsDep: "gone-ns#api", Status: store.StatusRunning,
		RequestedAt: time.Now().Add(-3 * time.Hour),
		ExpiresAt:   time.Now().Add(365 * 24 * time.Hour).Unix(),
	}
	st.PutOperation(ctx, stale)

	m.ReconcileSweep(ctx)

	op, err := st.GetOperation(ctx, "op_stale")
	if err != nil {
		t.Fatal(err)
	}
	if op.Status != store.StatusTimeout {
		t.Fatalf("deployment gone + stale → want timeout, got %s", op.Status)
	}
}

func TestReconcileSweepResolvesCompleted(t *testing.T) {
	ctx := context.Background()
	m, st, cs := setup(t)
	ns := "recon-ns"
	cs.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}}, metav1.CreateOptions{})
	dep := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: ns},
		Spec: appsv1.DeploymentSpec{
			Replicas: ptr32(1),
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "api"}},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "api"}},
				Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "c", Image: "busybox"}}},
			},
		},
	}
	if _, err := cs.AppsV1().Deployments(ns).Create(ctx, dep, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	// apiserver strips status on Create; set the completed shape via UpdateStatus.
	got, _ := cs.AppsV1().Deployments(ns).Get(ctx, "api", metav1.GetOptions{})
	got.Status.Replicas = 1
	got.Status.ObservedGeneration = got.Generation
	got.Status.UpdatedReplicas = 1
	got.Status.ReadyReplicas = 1
	got.Status.AvailableReplicas = 1
	if _, err := cs.AppsV1().Deployments(ns).UpdateStatus(ctx, got, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}

	stale := &store.Operation{
		OperationID: "op_recon", Repository: "tuncloud/backend", RepositoryID: "1",
		Action: operation.ActionRestart, Namespace: ns, Deployment: "api",
		NsDep: ns + "#api", Status: store.StatusRunning,
		RequestedAt: time.Now().Add(-3 * time.Hour),
		ExpiresAt:   time.Now().Add(365 * 24 * time.Hour).Unix(),
	}
	st.PutOperation(ctx, stale)

	m.ReconcileSweep(ctx)

	op, _ := st.GetOperation(ctx, "op_recon")
	if op.Status != store.StatusSucceeded {
		t.Fatalf("deployment complete + stale → want succeeded, got %s", op.Status)
	}
}

func TestGetLazyReconcilesStale(t *testing.T) {
	ctx := context.Background()
	m, st, _ := setup(t)
	st.PutOperation(ctx, &store.Operation{
		OperationID: "op_lazy", Repository: "r", RepositoryID: "1",
		Action: operation.ActionRestart, Namespace: "gone", Deployment: "d",
		NsDep: "gone#d", Status: store.StatusRunning,
		RequestedAt: time.Now().Add(-2 * time.Hour),
		ExpiresAt:   time.Now().Add(365 * 24 * time.Hour).Unix(),
	})

	op, err := m.Get(ctx, "op_lazy")
	if err != nil {
		t.Fatal(err)
	}
	if op.Status != store.StatusTimeout {
		t.Fatalf("lazy reconcile: want timeout, got %s", op.Status)
	}
}

// rolloutFakeKube captures rollout calls and controls Get responses for
// container resolution tests (no envtest needed).
type rolloutFakeKube struct {
	containers    []corev1.Container
	getErr        error
	gotContainer  string
	gotImage      string
	failRollout   bool
	rolloutCalled bool
}

func (f *rolloutFakeKube) RestartDeployment(context.Context, string, string) error { return nil }
func (f *rolloutFakeKube) RolloutDeployment(_ context.Context, _, _, container, image string) error {
	f.rolloutCalled, f.gotContainer, f.gotImage = true, container, image
	if f.failRollout {
		return errFakeRollout
	}
	return nil
}
func (f *rolloutFakeKube) GetDeployment(context.Context, string, string) (*appsv1.Deployment, error) {
	if f.getErr != nil {
		return nil, f.getErr
	}
	return &appsv1.Deployment{
		Spec: appsv1.DeploymentSpec{Template: corev1.PodTemplateSpec{
			Spec: corev1.PodSpec{Containers: f.containers},
		}},
	}, nil
}
func (f *rolloutFakeKube) WatchDeployment(context.Context, string, string) (watch.Interface, error) {
	return watch.NewFake(), nil
}

var errFakeRollout = errors.New("fake rollout failure")

func newRolloutManager(k kube.Kube) (*operation.Manager, store.Store) {
	st := store.NewInMemory()
	return operation.NewManager(k, st, slog.Default(), time.Minute), st
}

func TestRolloutHappyPathRecordsImageAndContainer(t *testing.T) {
	ctx := context.Background()
	fk := &rolloutFakeKube{containers: []corev1.Container{{Name: "app", Image: "img:v1"}}}
	m, st := newRolloutManager(fk)

	opID, err := m.Rollout(ctx, identity(), "ns", "api", "", "img:v2")
	if err != nil || opID == "" {
		t.Fatalf("rollout: %v (opID=%q)", err, opID)
	}
	if !fk.rolloutCalled || fk.gotContainer != "app" || fk.gotImage != "img:v2" {
		t.Fatalf("kube call = container:%q image:%q called:%v", fk.gotContainer, fk.gotImage, fk.rolloutCalled)
	}
	op, _ := st.GetOperation(ctx, opID)
	if op.Action != operation.ActionRollout || op.Image != "img:v2" || op.Container != "app" {
		t.Fatalf("audit fields = action:%s image:%s container:%s", op.Action, op.Image, op.Container)
	}
}

func TestRolloutExplicitContainerPassedThrough(t *testing.T) {
	ctx := context.Background()
	fk := &rolloutFakeKube{containers: []corev1.Container{{Name: "a"}, {Name: "b"}}}
	m, _ := newRolloutManager(fk)

	if _, err := m.Rollout(ctx, identity(), "ns", "api", "b", "img:v9"); err != nil {
		t.Fatal(err)
	}
	if fk.gotContainer != "b" {
		t.Fatalf("explicit container ignored: %q", fk.gotContainer)
	}
}

func TestRolloutAmbiguousContainerRejectsBeforePersist(t *testing.T) {
	ctx := context.Background()
	fk := &rolloutFakeKube{containers: []corev1.Container{{Name: "a"}, {Name: "b"}}}
	m, st := newRolloutManager(fk)

	opID, err := m.Rollout(ctx, identity(), "ns", "api", "", "img:v2")
	if !errors.Is(err, operation.ErrAmbiguousContainer) {
		t.Fatalf("want ErrAmbiguousContainer, got %v", err)
	}
	if opID != "" {
		t.Fatalf("no operation must be persisted, got %q", opID)
	}
	if _, err := st.GetOperation(ctx, opID); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("store must be untouched")
	}
	if fk.rolloutCalled {
		t.Fatal("kube must not be called")
	}
}

func TestRolloutResolutionGetFailureRecordsFailedOp(t *testing.T) {
	ctx := context.Background()
	fk := &rolloutFakeKube{getErr: errors.New("apiserver down")}
	m, st := newRolloutManager(fk)

	opID, err := m.Rollout(ctx, identity(), "ns", "ghost", "", "img:v2")
	if err == nil {
		t.Fatal("resolution Get failure must surface error")
	}
	if opID == "" {
		t.Fatal("failed resolution must still record operation")
	}
	op, _ := st.GetOperation(ctx, opID)
	if op.Status != store.StatusFailed || op.ErrorCode != "K8S_PATCH_FAILED" {
		t.Fatalf("op = %s/%s, want failed/K8S_PATCH_FAILED", op.Status, op.ErrorCode)
	}
	if op.Action != operation.ActionRollout || op.Image != "img:v2" {
		t.Fatalf("audit fields = action:%s image:%s", op.Action, op.Image)
	}
}

func TestRolloutPatchFailureMarksFailed(t *testing.T) {
	ctx := context.Background()
	fk := &rolloutFakeKube{containers: []corev1.Container{{Name: "app"}}, failRollout: true}
	m, st := newRolloutManager(fk)

	opID, err := m.Rollout(ctx, identity(), "ns", "api", "", "img:v2")
	if err == nil {
		t.Fatal("patch failure must surface error")
	}
	op, _ := st.GetOperation(ctx, opID)
	if op.Status != store.StatusFailed || op.ErrorCode != "K8S_PATCH_FAILED" {
		t.Fatalf("op = %s/%s, want failed/K8S_PATCH_FAILED", op.Status, op.ErrorCode)
	}
}

func waitFor(t *testing.T, d time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("condition not met before deadline")
}

func ptr32(v int32) *int32 { return &v }
