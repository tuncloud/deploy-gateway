package operation_test

import (
	"context"
	"log/slog"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
