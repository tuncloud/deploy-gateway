package kube_test

import (
	"context"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/tuncloud/deploy-gateway/internal/kube"
	"github.com/tuncloud/deploy-gateway/internal/kubetest"
)

func makeDeployment(name, ns string) *appsv1.Deployment {
	one := int32(1)
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec: appsv1.DeploymentSpec{
			Replicas: &one,
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": name}},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": name}},
				Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "c", Image: "busybox"}}},
			},
		},
	}
}

func TestRestartDeploymentSetsAnnotation(t *testing.T) {
	cfg, cs := kubetest.Start(t)
	ctx := context.Background()
	ns := "test-ns"
	if _, err := cs.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}}, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := cs.AppsV1().Deployments(ns).Create(ctx, makeDeployment("api", ns), metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}

	k, err := kube.NewFromConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}

	before, _ := cs.AppsV1().Deployments(ns).Get(ctx, "api", metav1.GetOptions{})
	if before.Spec.Template.Annotations != nil {
		t.Fatal("precondition: no restartedAt annotation expected")
	}

	if err := k.RestartDeployment(ctx, ns, "api"); err != nil {
		t.Fatal(err)
	}

	after, err := cs.AppsV1().Deployments(ns).Get(ctx, "api", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	ts, ok := after.Spec.Template.Annotations["kubectl.kubernetes.io/restartedAt"]
	if !ok {
		t.Fatal("restartedAt annotation not set")
	}
	if _, err := time.Parse(time.RFC3339, ts); err != nil {
		t.Fatalf("restartedAt not RFC3339: %q", ts)
	}
}

func TestRolloutUpdatesImageSingleContainer(t *testing.T) {
	cfg, cs := kubetest.Start(t)
	ctx := context.Background()
	ns := "rollout-ns"
	if _, err := cs.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}}, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := cs.AppsV1().Deployments(ns).Create(ctx, makeDeployment("api", ns), metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}

	k, err := kube.NewFromConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := k.RolloutDeployment(ctx, ns, "api", "c", "busybox:2"); err != nil {
		t.Fatal(err)
	}

	after, err := cs.AppsV1().Deployments(ns).Get(ctx, "api", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if got := after.Spec.Template.Spec.Containers[0].Image; got != "busybox:2" {
		t.Fatalf("image = %q, want busybox:2", got)
	}
	if _, ok := after.Spec.Template.Annotations["kubectl.kubernetes.io/restartedAt"]; !ok {
		t.Fatal("rollout must set restartedAt so the pod template always changes")
	}
}

func TestRolloutMergesByNameLeavesOtherContainers(t *testing.T) {
	cfg, cs := kubetest.Start(t)
	ctx := context.Background()
	ns := "rollout-multi-ns"
	if _, err := cs.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}}, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	dep := makeDeployment("api", ns)
	dep.Spec.Template.Spec.Containers = append(
		dep.Spec.Template.Spec.Containers,
		corev1.Container{Name: "sidecar", Image: "proxy:1"},
	)
	if _, err := cs.AppsV1().Deployments(ns).Create(ctx, dep, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}

	k, err := kube.NewFromConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := k.RolloutDeployment(ctx, ns, "api", "sidecar", "proxy:2"); err != nil {
		t.Fatal(err)
	}

	after, err := cs.AppsV1().Deployments(ns).Get(ctx, "api", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]string{}
	for _, c := range after.Spec.Template.Spec.Containers {
		byName[c.Name] = c.Image
	}
	if byName["sidecar"] != "proxy:2" {
		t.Fatalf("sidecar image = %q, want proxy:2", byName["sidecar"])
	}
	if byName["c"] != "busybox" {
		t.Fatalf("main container image = %q, want untouched busybox", byName["c"])
	}
}

func TestRolloutRequiresContainerAndImage(t *testing.T) {
	cfg, _ := kubetest.Start(t)
	k, err := kube.NewFromConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := k.RolloutDeployment(context.Background(), "ns", "dep", "", "img"); err == nil {
		t.Fatal("empty container must error")
	}
	if err := k.RolloutDeployment(context.Background(), "ns", "dep", "c", ""); err == nil {
		t.Fatal("empty image must error")
	}
}

func TestRestartMissingDeploymentFails(t *testing.T) {
	cfg, _ := kubetest.Start(t)
	k, _ := kube.NewFromConfig(cfg)
	if err := k.RestartDeployment(context.Background(), "nope", "ghost"); err == nil {
		t.Fatal("missing deployment must return error")
	}
}

func TestWatchDeploymentReceivesEvents(t *testing.T) {
	cfg, cs := kubetest.Start(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ns := "watch-ns"
	cs.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}}, metav1.CreateOptions{})
	cs.AppsV1().Deployments(ns).Create(ctx, makeDeployment("api", ns), metav1.CreateOptions{})

	k, _ := kube.NewFromConfig(cfg)
	w, err := k.WatchDeployment(ctx, ns, "api")
	if err != nil {
		t.Fatal(err)
	}
	defer w.Stop()

	// modify status subresource → should produce a MODIFIED event
	dep, _ := cs.AppsV1().Deployments(ns).Get(ctx, "api", metav1.GetOptions{})
	dep.Status.ObservedGeneration = dep.Generation
	dep.Status.Replicas = 1
	dep.Status.UpdatedReplicas = 1
	dep.Status.ReadyReplicas = 1
	dep.Status.AvailableReplicas = 1
	if _, err := cs.AppsV1().Deployments(ns).UpdateStatus(ctx, dep, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}

	for event := range w.ResultChan() {
		d, ok := event.Object.(*appsv1.Deployment)
		if !ok {
			continue
		}
		if d.Status.ReadyReplicas == 1 {
			return // got expected event
		}
	}
	t.Fatal("no expected watch event before channel close/timeout")
}

func TestRolloutSameImageStillRollsDeployment(t *testing.T) {
	cfg, cs := kubetest.Start(t)
	ctx := context.Background()
	ns := "same-tag-ns"
	if _, err := cs.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}}, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := cs.AppsV1().Deployments(ns).Create(ctx, makeDeployment("api", ns), metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	k, err := kube.NewFromConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}

	if err := k.RolloutDeployment(ctx, ns, "api", "c", "busybox:7"); err != nil {
		t.Fatal(err)
	}
	first, err := cs.AppsV1().Deployments(ns).Get(ctx, "api", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}

	// Same image again: the tag did not move, but the deployment must still roll.
	if err := k.RolloutDeployment(ctx, ns, "api", "c", "busybox:7"); err != nil {
		t.Fatal(err)
	}
	second, err := cs.AppsV1().Deployments(ns).Get(ctx, "api", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}

	if second.Generation <= first.Generation {
		t.Fatalf("generation = %d, want > %d (same-tag rollout must still roll)",
			second.Generation, first.Generation)
	}
	const key = "kubectl.kubernetes.io/restartedAt"
	if first.Spec.Template.Annotations[key] == second.Spec.Template.Annotations[key] {
		t.Fatalf("restartedAt unchanged (%q): pod template hash would be identical",
			second.Spec.Template.Annotations[key])
	}
}
