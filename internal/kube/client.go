package kube

import (
	"context"
	"fmt"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/typed/apps/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/util/retry"
)

// Kube is the subset of the Kubernetes API the gateway needs.
type Kube interface {
	RestartDeployment(ctx context.Context, namespace, name string) error
	RolloutDeployment(ctx context.Context, namespace, name, container, image string) error
	GetDeployment(ctx context.Context, namespace, name string) (*appsv1.Deployment, error)
	WatchDeployment(ctx context.Context, namespace, name string) (watch.Interface, error)
}

type client struct {
	deployments func(namespace string) v1.DeploymentInterface
}

// NewFromConfig builds a Kube client from an existing REST config.
func NewFromConfig(cfg *rest.Config) (Kube, error) {
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, err
	}
	return &client{deployments: cs.AppsV1().Deployments}, nil
}

// NewInCluster builds a Kube client from the in-cluster service account config.
func NewInCluster() (Kube, error) {
	cfg, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("in-cluster config: %w", err)
	}
	return NewFromConfig(cfg)
}

// restartStamp is the annotation value that forces a pod-template change.
// Nanosecond precision matters: at second resolution two operations inside the
// same second produce an identical template, no new generation, and a rollout
// that silently does nothing.
func restartStamp() string {
	return time.Now().UTC().Format(time.RFC3339Nano)
}

// RestartDeployment performs a kubectl-rollout-restart equivalent patch on the
// deployment's pod template. The timestamp is server-visible and only serves to
// change the template hash; RetryOnConflict guards against resourceVersion
// races with concurrent controllers.
func (c *client) RestartDeployment(ctx context.Context, namespace, name string) error {
	return retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		patch := fmt.Sprintf(
			`{"spec":{"template":{"metadata":{"annotations":{"kubectl.kubernetes.io/restartedAt":%q}}}}}`,
			restartStamp(),
		)
		_, err := c.deployments(namespace).Patch(
			ctx, name, types.StrategicMergePatchType, []byte(patch), metav1.PatchOptions{})
		return err
	})
}

// RolloutDeployment sets a container's image via strategic merge patch
// (containers merge by name, so other containers and fields are untouched) and
// stamps the same restartedAt annotation restart uses. The annotation is what
// makes a rollout to an unchanged tag still roll: without it the pod template
// is identical, no generation is created, and the operation would resolve as
// succeeded against pre-patch state without replacing a pod.
func (c *client) RolloutDeployment(ctx context.Context, namespace, name, container, image string) error {
	if container == "" || image == "" {
		return fmt.Errorf("rollout requires container and image")
	}
	return retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		patch := fmt.Sprintf(
			`{"spec":{"template":{"metadata":{"annotations":{"kubectl.kubernetes.io/restartedAt":%q}},`+
				`"spec":{"containers":[{"name":%q,"image":%q}]}}}}`,
			restartStamp(), container, image,
		)
		_, err := c.deployments(namespace).Patch(
			ctx, name, types.StrategicMergePatchType, []byte(patch), metav1.PatchOptions{})
		return err
	})
}

// GetDeployment fetches a single deployment.
func (c *client) GetDeployment(ctx context.Context, namespace, name string) (*appsv1.Deployment, error) {
	return c.deployments(namespace).Get(ctx, name, metav1.GetOptions{})
}

// WatchDeployment streams events for a single deployment, selected by
// metadata.name on the server side.
func (c *client) WatchDeployment(ctx context.Context, namespace, name string) (watch.Interface, error) {
	return c.deployments(namespace).Watch(ctx, metav1.ListOptions{
		FieldSelector: "metadata.name=" + name,
	})
}
