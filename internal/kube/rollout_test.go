package kube_test

import (
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/tuncloud/deploy-gateway/internal/kube"
)

// depState is the deployment shape EvaluateRollout reads. The fields are named
// rather than positional because the interesting cases differ in only one or
// two of them, and which one is the whole point of the case.
//
// replicas counts every non-terminated pod matching the selector, old
// ReplicaSets included — it is what distinguishes "the new pods are ready"
// from "some pods are ready".
type depState struct {
	generation         int64
	observedGeneration int64
	desired            int32
	replicas           int32
	updated            int32
	ready              int32
	available          int32
	progressingStatus  string
	progressingReason  string
}

func deployment(s depState) *appsv1.Deployment {
	desired := s.desired
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Generation: s.generation, UID: types.UID("u")},
		Spec:       appsv1.DeploymentSpec{Replicas: &desired, ProgressDeadlineSeconds: ptrInt32(600)},
		Status: appsv1.DeploymentStatus{
			ObservedGeneration: s.observedGeneration,
			Replicas:           s.replicas,
			UpdatedReplicas:    s.updated,
			ReadyReplicas:      s.ready,
			AvailableReplicas:  s.available,
			Conditions: []appsv1.DeploymentCondition{{
				Type:           appsv1.DeploymentProgressing,
				Status:         corev1.ConditionStatus(s.progressingStatus),
				Reason:         s.progressingReason,
				LastUpdateTime: metav1.Now(),
			}},
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
			dep: deployment(depState{
				generation: 2, observedGeneration: 2,
				desired: 3, replicas: 3, updated: 3, ready: 3, available: 3,
				progressingStatus: "True", progressingReason: "NewReplicaSetAvailable",
			}),
			want: kube.RolloutComplete,
		},
		{
			name: "stale status generation",
			dep: deployment(depState{
				generation: 2, observedGeneration: 1,
				desired: 3, replicas: 3, updated: 3, ready: 3, available: 3,
				progressingStatus: "True", progressingReason: "NewReplicaSetAvailable",
			}),
			want: kube.RolloutProgressing,
		},
		{
			name: "replicas not ready",
			dep: deployment(depState{
				generation: 2, observedGeneration: 2,
				desired: 3, replicas: 3, updated: 3, ready: 1, available: 1,
				progressingStatus: "True", progressingReason: "ReplicaSetUpdated",
			}),
			want: kube.RolloutProgressing,
		},
		{
			name: "progress deadline exceeded",
			dep: deployment(depState{
				generation: 2, observedGeneration: 2,
				desired: 3, replicas: 3, updated: 1, ready: 0, available: 0,
				progressingStatus: "False", progressingReason: "ProgressDeadlineExceeded",
			}),
			want: kube.RolloutFailed,
		},
		{
			name: "stale deadline condition from previous rollout",
			dep: deployment(depState{
				generation: 2, observedGeneration: 1,
				desired: 3, replicas: 3, updated: 1, ready: 1, available: 1,
				progressingStatus: "False", progressingReason: "ProgressDeadlineExceeded",
			}),
			want: kube.RolloutProgressing,
		},
		{
			name: "still rolling",
			dep: deployment(depState{
				generation: 2, observedGeneration: 2,
				desired: 3, replicas: 3, updated: 1, ready: 1, available: 1,
				progressingStatus: "True", progressingReason: "ReplicaSetUpdated",
			}),
			want: kube.RolloutProgressing,
		},
		{
			// The single-replica surge: maxUnavailable rounds to 0 and maxSurge to
			// 1, so the new pod is created while the old one still serves. updated,
			// ready and available all equal desired, but the ready pod is the OLD
			// one and the new image has not served a request yet. Only the extra
			// pod in replicas reveals it.
			name: "new pod created while old pod still ready",
			dep: deployment(depState{
				generation: 2, observedGeneration: 2,
				desired: 1, replicas: 2, updated: 1, ready: 1, available: 1,
				progressingStatus: "True", progressingReason: "ReplicaSetUpdated",
			}),
			want: kube.RolloutProgressing,
		},
		{
			// All new pods are ready, but an old pod is still terminating: its
			// grace period has not elapsed, so it is not yet gone.
			name: "old pod still terminating",
			dep: deployment(depState{
				generation: 2, observedGeneration: 2,
				desired: 3, replicas: 4, updated: 3, ready: 3, available: 3,
				progressingStatus: "True", progressingReason: "ReplicaSetUpdated",
			}),
			want: kube.RolloutProgressing,
		},
		{
			// A deployment scaled to zero has nothing to roll: every counter is
			// zero and that is the finished state, not a stalled one.
			name: "scaled to zero",
			dep: deployment(depState{
				generation: 2, observedGeneration: 2,
				desired: 0, replicas: 0, updated: 0, ready: 0, available: 0,
				progressingStatus: "True", progressingReason: "NewReplicaSetAvailable",
			}),
			want: kube.RolloutComplete,
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
