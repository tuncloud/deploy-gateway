package kube_test

import (
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/tuncloud/deploy-gateway/internal/kube"
)

func deployment(gen int64, updated, ready, available, desired int32, progressingStatus, progressingReason string, progressingObservedGen int64) *appsv1.Deployment {
	cond := appsv1.DeploymentCondition{
		Type:           appsv1.DeploymentProgressing,
		Status:         corev1.ConditionStatus(progressingStatus),
		Reason:         progressingReason,
		LastUpdateTime: metav1.Now(),
	}
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Generation: gen, UID: types.UID("u")},
		Spec:       appsv1.DeploymentSpec{Replicas: &desired, ProgressDeadlineSeconds: ptrInt32(600)},
		Status: appsv1.DeploymentStatus{
			ObservedGeneration: progressingObservedGen,
			UpdatedReplicas:    updated,
			ReadyReplicas:      ready,
			AvailableReplicas:  available,
			Conditions:         []appsv1.DeploymentCondition{cond},
		},
	}
}

func ptrInt32(v int32) *int32 { return &v }

func TestEvaluateRollout(t *testing.T) {
	cases := []struct {
		name string
		dep  *appsv1.Deployment
		want kube.RolloutState
	}{
		{
			name: "complete",
			dep:  deployment(2, 3, 3, 3, 3, "True", "NewReplicaSetAvailable", 2),
			want: kube.RolloutComplete,
		},
		{
			name: "stale status generation",
			dep:  deployment(2, 3, 3, 3, 3, "True", "NewReplicaSetAvailable", 1),
			want: kube.RolloutProgressing,
		},
		{
			name: "replicas not ready",
			dep:  deployment(2, 3, 1, 1, 3, "True", "ReplicaSetUpdated", 2),
			want: kube.RolloutProgressing,
		},
		{
			name: "progress deadline exceeded",
			dep:  deployment(2, 1, 0, 0, 3, "False", "ProgressDeadlineExceeded", 2),
			want: kube.RolloutFailed,
		},
		{
			name: "still rolling",
			dep:  deployment(2, 1, 1, 1, 3, "True", "ReplicaSetUpdated", 2),
			want: kube.RolloutProgressing,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := kube.EvaluateRollout(tc.dep)
			if got.State != tc.want {
				t.Fatalf("state = %v, want %v (reason=%q)", got.State, tc.want, got.Reason)
			}
		})
	}
}
