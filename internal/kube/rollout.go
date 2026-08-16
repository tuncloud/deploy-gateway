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
	if c := getCondition(dep, appsv1.DeploymentProgressing); c != nil &&
		c.Status == corev1.ConditionFalse && c.Reason == "ProgressDeadlineExceeded" {
		return RolloutEvaluation{State: RolloutFailed, Reason: "progress deadline exceeded"}
	}

	if dep.Status.ObservedGeneration >= dep.Generation {
		desired := int32(1)
		if dep.Spec.Replicas != nil {
			desired = *dep.Spec.Replicas
		}
		if dep.Status.UpdatedReplicas == desired &&
			dep.Status.ReadyReplicas == desired &&
			dep.Status.AvailableReplicas == desired {
			return RolloutEvaluation{State: RolloutComplete, Reason: "all replicas updated, ready and available"}
		}
	}

	return RolloutEvaluation{State: RolloutProgressing, Reason: fmt.Sprintf("observedGeneration=%d generation=%d updated=%d ready=%d available=%d",
		dep.Status.ObservedGeneration, dep.Generation,
		dep.Status.UpdatedReplicas, dep.Status.ReadyReplicas, dep.Status.AvailableReplicas)}
}
