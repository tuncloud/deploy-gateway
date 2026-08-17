package kube

import (
	"fmt"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
)

type RolloutState int

const (
	RolloutProgressing RolloutState = iota
	RolloutComplete
	RolloutFailed
)

func (s RolloutState) String() string {
	switch s {
	case RolloutComplete:
		return "complete"
	case RolloutFailed:
		return "failed"
	default:
		return "progressing"
	}
}

type RolloutEvaluation struct {
	State  RolloutState
	Reason string
}

func getCondition(dep *appsv1.Deployment, t appsv1.DeploymentConditionType) *appsv1.DeploymentCondition {
	for i := range dep.Status.Conditions {
		if dep.Status.Conditions[i].Type == t {
			return &dep.Status.Conditions[i]
		}
	}
	return nil
}

func EvaluateRollout(dep *appsv1.Deployment) RolloutEvaluation {
	// Only trust the ProgressDeadlineExceeded condition when the controller has
	// observed the current generation — otherwise the condition is a leftover
	// from a previous rollout (e.g. right after a spec patch bumps Generation)
	// and must not fail a fresh rollout.
	if c := getCondition(dep, appsv1.DeploymentProgressing); c != nil &&
		c.Status == corev1.ConditionFalse && c.Reason == "ProgressDeadlineExceeded" &&
		dep.Status.ObservedGeneration >= dep.Generation {
		return RolloutEvaluation{State: RolloutFailed, Reason: "progress deadline exceeded"}
	}

	if dep.Status.ObservedGeneration >= dep.Generation {
		desired := int32(1)
		if dep.Spec.Replicas != nil {
			desired = *dep.Spec.Replicas
		}
		if dep.Status.UpdatedReplicas == desired &&
			// No pods from an older ReplicaSet remain. Status.Replicas counts every
			// non-terminated pod matching the selector, so without this check an
			// old ready pod can satisfy ReadyReplicas while the new pod is still
			// starting — reporting success for an image that never served a
			// request. A single-replica deployment hits exactly that state on every
			// rollout, because maxUnavailable rounds to 0 and maxSurge to 1.
			dep.Status.Replicas == desired &&
			dep.Status.ReadyReplicas == desired &&
			dep.Status.AvailableReplicas == desired {
			return RolloutEvaluation{State: RolloutComplete, Reason: "all replicas are new, ready and available"}
		}
	}

	return RolloutEvaluation{State: RolloutProgressing, Reason: fmt.Sprintf("observedGeneration=%d generation=%d replicas=%d updated=%d ready=%d available=%d",
		dep.Status.ObservedGeneration, dep.Generation, dep.Status.Replicas,
		dep.Status.UpdatedReplicas, dep.Status.ReadyReplicas, dep.Status.AvailableReplicas)}
}
