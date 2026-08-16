package operation

import (
	"context"
	"time"

	"github.com/tuncloud/deploy-gateway/internal/kube"
	"github.com/tuncloud/deploy-gateway/internal/store"
)

// staleAfter: any op still running longer than this is resolved by the
// reconciler. Generous margin over progressDeadlineSeconds (600s default).
const staleAfter = 2 * time.Hour

const sweepInterval = 60 * time.Second

func (m *Manager) StartSweeper(ctx context.Context) {
	ticker := time.NewTicker(sweepInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.ReconcileSweep(ctx)
		}
	}
}

func (m *Manager) ReconcileSweep(ctx context.Context) {
	ops, err := m.store.ListRunningPastDeadline(ctx, time.Now().Add(-staleAfter))
	if err != nil {
		m.log.Error("sweeper list", "err", err)
		return
	}
	for _, op := range ops {
		m.resolveRunning(ctx, op)
	}
}

// resolveRunning reads the deployment (source of truth) and resolves the
// operation: complete → succeeded, failed → failed, gone-or-progressing-past-
// every-deadline → timeout.
func (m *Manager) resolveRunning(ctx context.Context, op *store.Operation) {
	dep, err := m.kube.GetDeployment(ctx, op.Namespace, op.Deployment)
	if err != nil {
		m.timeoutOperation(op.OperationID, "deployment no longer readable while operation running: "+err.Error())
		return
	}
	ev := kube.EvaluateRollout(dep)
	switch ev.State {
	case kube.RolloutComplete:
		m.completeOperation(op.OperationID, ev.Reason)
	case kube.RolloutFailed:
		m.failOperation(op.OperationID, "ROLLOUT_FAILED", ev.Reason)
	default:
		m.timeoutOperation(op.OperationID, "operation stale and rollout still not terminal: "+ev.Reason)
	}
}
