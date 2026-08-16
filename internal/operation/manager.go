package operation

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	appsv1 "k8s.io/api/apps/v1"

	"github.com/oklog/ulid/v2"

	"github.com/tuncloud/deploy-gateway/internal/authn"
	"github.com/tuncloud/deploy-gateway/internal/kube"
	"github.com/tuncloud/deploy-gateway/internal/store"
)

const ActionRestart = "deployment.restart"

type Manager struct {
	kube            kube.Kube
	store           store.Store
	log             *slog.Logger
	defaultDeadline time.Duration
}

func NewManager(k kube.Kube, st store.Store, log *slog.Logger, defaultDeadline time.Duration) *Manager {
	if defaultDeadline <= 0 {
		defaultDeadline = 10 * time.Minute
	}
	return &Manager{kube: k, store: st, log: log, defaultDeadline: defaultDeadline}
}

func NewOperationID() string {
	return "op_" + strings.ToLower(ulid.Make().String())
}

func (m *Manager) Restart(ctx context.Context, id *authn.GitHubIdentity, namespace, deployment string) (string, error) {
	now := time.Now().UTC()
	op := &store.Operation{
		OperationID:     NewOperationID(),
		Repository:      id.Repository,
		RepositoryID:    id.RepositoryID,
		RepositoryOwner: id.RepositoryOwner,
		Actor:           id.Actor,
		Workflow:        id.Workflow,
		WorkflowRef:     id.WorkflowRef,
		RunID:           id.RunID,
		RunAttempt:      id.RunAttempt,
		EventName:       id.EventName,
		Action:          ActionRestart,
		Namespace:       namespace,
		Deployment:      deployment,
		NsDep:           namespace + "#" + deployment,
		Status:          store.StatusRunning,
		RequestedAt:     now,
		ExpiresAt:       now.Add(365 * 24 * time.Hour).Unix(),
		Events:          []store.AuditEvent{{Event: "REQUESTED", At: now}, {Event: "STARTED", At: now}},
	}
	if err := m.store.PutOperation(ctx, op); err != nil {
		return "", fmt.Errorf("persist operation: %w", err)
	}

	if err := m.kube.RestartDeployment(ctx, namespace, deployment); err != nil {
		m.failOperation(op.OperationID, "K8S_PATCH_FAILED", err.Error())
		return op.OperationID, fmt.Errorf("patch deployment: %w", err)
	}

	m.log.Info("restart started",
		"operation_id", op.OperationID, "repository", id.Repository,
		"namespace", namespace, "deployment", deployment, "run_id", id.RunID)

	go m.watchRollout(op)
	return op.OperationID, nil
}

func (m *Manager) failOperation(opID, code, msg string) {
	if err := m.store.UpdateTerminal(context.Background(), opID, store.TerminalUpdate{
		Status: store.StatusFailed, Event: "FAILED",
		ErrorCode: code, ErrorMessage: msg, CompletedAt: time.Now().UTC(),
	}); err != nil {
		m.logTerminalWriteErr("mark operation failed", opID, err)
	}
}

// logTerminalWriteErr: ErrAlreadyTerminal means another writer (watcher vs
// reconciler vs sweep) resolved the op first — benign, not an error.
func (m *Manager) logTerminalWriteErr(what, opID string, err error) {
	if errors.Is(err, store.ErrAlreadyTerminal) {
		m.log.Info(what+" skipped: already terminal", "operation_id", opID)
		return
	}
	m.log.Error(what, "operation_id", opID, "err", err)
}

func (m *Manager) progressDeadline(dep *appsv1.Deployment) time.Duration {
	if dep.Spec.ProgressDeadlineSeconds != nil && *dep.Spec.ProgressDeadlineSeconds > 0 {
		return time.Duration(*dep.Spec.ProgressDeadlineSeconds) * time.Second
	}
	return m.defaultDeadline
}

// watchRollout follows the deployment until terminal state. Watch channel close,
// 410 Gone, or transport errors are NOT failures: re-get, evaluate, re-watch.
func (m *Manager) watchRollout(op *store.Operation) {
	ctx := context.Background()

	var deadline time.Duration
	if dep, err := m.kube.GetDeployment(ctx, op.Namespace, op.Deployment); err == nil {
		deadline = m.progressDeadline(dep)
	} else {
		deadline = m.defaultDeadline
	}
	ctx, cancel := context.WithTimeout(ctx, deadline+2*time.Minute)
	defer cancel()

	backoff := time.Second
	const maxBackoff = 15 * time.Second
	for {
		if ctx.Err() != nil {
			m.timeoutOperation(op.OperationID, "watch deadline exceeded before rollout resolved")
			return
		}

		if m.evalOnce(ctx, op) {
			return
		}

		w, err := m.kube.WatchDeployment(ctx, op.Namespace, op.Deployment)
		if err != nil {
			m.log.Warn("watch start failed", "operation_id", op.OperationID, "err", err)
			if !sleepCtx(ctx, backoff) {
				m.timeoutOperation(op.OperationID, "watch deadline exceeded")
				return
			}
			backoff = min(2*backoff, maxBackoff)
			continue
		}

		for event := range w.ResultChan() {
			dep, ok := event.Object.(*appsv1.Deployment)
			if !ok {
				continue
			}
			ev := kube.EvaluateRollout(dep)
			if ev.State == kube.RolloutComplete {
				m.completeOperation(op.OperationID, ev.Reason)
				w.Stop()
				return
			}
			if ev.State == kube.RolloutFailed {
				m.failOperation(op.OperationID, "ROLLOUT_FAILED", ev.Reason)
				w.Stop()
				return
			}
		}
		// channel closed — re-list, re-evaluate, restart watch
		if !sleepCtx(ctx, backoff) {
			m.timeoutOperation(op.OperationID, "watch deadline exceeded after reconnect")
			return
		}
		backoff = min(2*backoff, maxBackoff)
	}
}

// evalOnce re-reads the deployment and resolves the operation if already
// terminal. Returns true when the operation was resolved.
func (m *Manager) evalOnce(ctx context.Context, op *store.Operation) bool {
	dep, err := m.kube.GetDeployment(ctx, op.Namespace, op.Deployment)
	if err != nil {
		m.log.Warn("re-get deployment", "operation_id", op.OperationID, "err", err)
		return false
	}
	ev := kube.EvaluateRollout(dep)
	switch ev.State {
	case kube.RolloutComplete:
		m.completeOperation(op.OperationID, ev.Reason)
		return true
	case kube.RolloutFailed:
		m.failOperation(op.OperationID, "ROLLOUT_FAILED", ev.Reason)
		return true
	}
	return false
}

func (m *Manager) completeOperation(opID, reason string) {
	if err := m.store.UpdateTerminal(context.Background(), opID, store.TerminalUpdate{
		Status: store.StatusSucceeded, Event: "SUCCEEDED", CompletedAt: time.Now().UTC(),
	}); err != nil {
		m.logTerminalWriteErr("mark operation succeeded", opID, err)
	}
	m.log.Info("rollout succeeded", "operation_id", opID, "reason", reason)
}

func (m *Manager) timeoutOperation(opID, msg string) {
	if err := m.store.UpdateTerminal(context.Background(), opID, store.TerminalUpdate{
		Status: store.StatusTimeout, Event: "TIMEOUT",
		ErrorCode: "TIMEOUT", ErrorMessage: msg, CompletedAt: time.Now().UTC(),
	}); err != nil {
		m.logTerminalWriteErr("mark operation timeout", opID, err)
	}
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	select {
	case <-ctx.Done():
		return false
	case <-time.After(d):
		return true
	}
}

func (m *Manager) Get(ctx context.Context, opID string) (*store.Operation, error) {
	op, err := m.store.GetOperation(ctx, opID)
	if err != nil {
		return nil, err
	}
	if op.Status == store.StatusRunning && time.Since(op.RequestedAt) > staleAfter {
		m.resolveRunning(ctx, op)
		if refreshed, err := m.store.GetOperation(ctx, opID); err == nil {
			return refreshed, nil
		}
	}
	return op, nil
}
