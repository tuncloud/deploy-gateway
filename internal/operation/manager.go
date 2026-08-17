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
	"github.com/tuncloud/deploy-gateway/internal/notify"
	"github.com/tuncloud/deploy-gateway/internal/store"
)

const ActionRestart = "deployment.restart"
const ActionRollout = "deployment.rollout"

// ErrAmbiguousContainer is returned when no container was specified and the
// deployment has more than one, so the caller must pick explicitly.
var ErrAmbiguousContainer = errors.New("deployment has multiple containers; container must be specified")

type Manager struct {
	kube            kube.Kube
	store           store.Store
	notify          notify.Notifier
	log             *slog.Logger
	defaultDeadline time.Duration
}

func NewManager(k kube.Kube, st store.Store, n notify.Notifier, log *slog.Logger, defaultDeadline time.Duration) *Manager {
	if defaultDeadline <= 0 {
		defaultDeadline = 10 * time.Minute
	}
	if n == nil {
		n = notify.Disabled()
	}
	return &Manager{kube: k, store: st, notify: n, log: log, defaultDeadline: defaultDeadline}
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
		m.failOperation(op, nil, "K8S_PATCH_FAILED", err.Error())
		return op.OperationID, fmt.Errorf("patch deployment: %w", err)
	}

	m.log.Info("restart started",
		"operation_id", op.OperationID, "repository", id.Repository,
		"namespace", namespace, "deployment", deployment, "run_id", id.RunID)

	msg := m.notify.Started(op)
	go m.watchRollout(op, msg)
	return op.OperationID, nil
}

func (m *Manager) Rollout(ctx context.Context, id *authn.GitHubIdentity, namespace, deployment, container, image string) (string, error) {
	if container == "" {
		resolved, resolveErr := m.resolveContainer(ctx, namespace, deployment)
		if errors.Is(resolveErr, ErrAmbiguousContainer) {
			return "", ErrAmbiguousContainer
		}
		if resolveErr != nil || resolved == "" {
			opID := m.recordFailedRollout(ctx, id, namespace, deployment, "", image,
				"K8S_PATCH_FAILED", "resolve container: "+resolveErr.Error())
			return opID, resolveErr
		}
		container = resolved
	}

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
		Action:          ActionRollout,
		Namespace:       namespace,
		Deployment:      deployment,
		Container:       container,
		Image:           image,
		NsDep:           namespace + "#" + deployment,
		Status:          store.StatusRunning,
		RequestedAt:     now,
		ExpiresAt:       now.Add(365 * 24 * time.Hour).Unix(),
		Events:          []store.AuditEvent{{Event: "REQUESTED", At: now}, {Event: "STARTED", At: now}},
	}
	if err := m.store.PutOperation(ctx, op); err != nil {
		return "", fmt.Errorf("persist operation: %w", err)
	}

	if err := m.kube.RolloutDeployment(ctx, namespace, deployment, container, image); err != nil {
		m.failOperation(op, nil, "K8S_PATCH_FAILED", err.Error())
		return op.OperationID, fmt.Errorf("patch deployment: %w", err)
	}

	m.log.Info("rollout started",
		"operation_id", op.OperationID, "repository", id.Repository,
		"namespace", namespace, "deployment", deployment,
		"container", container, "image", image, "run_id", id.RunID)

	msg := m.notify.Started(op)
	go m.watchRollout(op, msg)
	return op.OperationID, nil
}

// resolveContainer returns the only container name when the deployment has
// exactly one, the Get error if the deployment can't be fetched, or
// ErrAmbiguousContainer when the caller must choose.
func (m *Manager) resolveContainer(ctx context.Context, namespace, deployment string) (string, error) {
	dep, err := m.kube.GetDeployment(ctx, namespace, deployment)
	if err != nil {
		return "", fmt.Errorf("get deployment: %w", err)
	}
	containers := dep.Spec.Template.Spec.Containers
	switch len(containers) {
	case 1:
		return containers[0].Name, nil
	case 0:
		return "", fmt.Errorf("deployment %s/%s has no containers", namespace, deployment)
	default:
		return "", ErrAmbiguousContainer
	}
}

// recordFailedRollout persists a rollout operation straight to failed, for
// resolution errors that only surface before the patch runs.
func (m *Manager) recordFailedRollout(ctx context.Context, id *authn.GitHubIdentity, namespace, deployment, container, image, code, msg string) string {
	now := time.Now().UTC()
	op := &store.Operation{
		OperationID:  NewOperationID(),
		Repository:   id.Repository,
		RepositoryID: id.RepositoryID,
		Actor:        id.Actor,
		Workflow:     id.Workflow,
		WorkflowRef:  id.WorkflowRef,
		RunID:        id.RunID,
		RunAttempt:   id.RunAttempt,
		EventName:    id.EventName,
		Action:       ActionRollout,
		Namespace:    namespace,
		Deployment:   deployment,
		Container:    container,
		Image:        image,
		NsDep:        namespace + "#" + deployment,
		Status:       store.StatusRunning,
		RequestedAt:  now,
		ExpiresAt:    now.Add(365 * 24 * time.Hour).Unix(),
		Events:       []store.AuditEvent{{Event: "REQUESTED", At: now}},
	}
	if err := m.store.PutOperation(ctx, op); err != nil {
		m.log.Error("persist failed rollout operation", "err", err)
		return ""
	}
	m.failOperation(op, nil, code, msg)
	return op.OperationID
}

// applyTerminal returns a copy of op with the terminal update applied, so a
// notification renders final status, error and elapsed time without re-reading
// the store.
func applyTerminal(op *store.Operation, upd store.TerminalUpdate) *store.Operation {
	cp := *op
	cp.Status = upd.Status
	cp.ErrorCode = upd.ErrorCode
	cp.ErrorMessage = upd.ErrorMessage
	completed := upd.CompletedAt
	cp.CompletedAt = &completed
	return &cp
}

// resolve performs the single terminal write and notifies only when this
// writer won: UpdateTerminal returns ErrAlreadyTerminal to everyone else, so
// exactly one of watcher, sweeper or lazy GET sends the message.
func (m *Manager) resolve(op *store.Operation, msg *notify.Message, what string, upd store.TerminalUpdate) {
	if err := m.store.UpdateTerminal(context.Background(), op.OperationID, upd); err != nil {
		m.logTerminalWriteErr(what, op.OperationID, err)
		return
	}
	m.notify.Resolved(applyTerminal(op, upd), msg)
}

func (m *Manager) failOperation(op *store.Operation, msg *notify.Message, code, errMsg string) {
	m.resolve(op, msg, "mark operation failed", store.TerminalUpdate{
		Status: store.StatusFailed, Event: "FAILED",
		ErrorCode: code, ErrorMessage: errMsg, CompletedAt: time.Now().UTC(),
	})
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
func (m *Manager) watchRollout(op *store.Operation, msg *notify.Message) {
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
			m.timeoutOperation(op, msg, "watch deadline exceeded before rollout resolved")
			return
		}

		if m.evalOnce(ctx, op, msg) {
			return
		}

		w, err := m.kube.WatchDeployment(ctx, op.Namespace, op.Deployment)
		if err != nil {
			m.log.Warn("watch start failed", "operation_id", op.OperationID, "err", err)
			if !sleepCtx(ctx, backoff) {
				m.timeoutOperation(op, msg, "watch deadline exceeded")
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
				m.completeOperation(op, msg, ev.Reason)
				w.Stop()
				return
			}
			if ev.State == kube.RolloutFailed {
				m.failOperation(op, msg, "ROLLOUT_FAILED", ev.Reason)
				w.Stop()
				return
			}
		}
		// channel closed — re-list, re-evaluate, restart watch
		if !sleepCtx(ctx, backoff) {
			m.timeoutOperation(op, msg, "watch deadline exceeded after reconnect")
			return
		}
		backoff = min(2*backoff, maxBackoff)
	}
}

// evalOnce re-reads the deployment and resolves the operation if already
// terminal. Returns true when the operation was resolved.
func (m *Manager) evalOnce(ctx context.Context, op *store.Operation, msg *notify.Message) bool {
	dep, err := m.kube.GetDeployment(ctx, op.Namespace, op.Deployment)
	if err != nil {
		m.log.Warn("re-get deployment", "operation_id", op.OperationID, "err", err)
		return false
	}
	ev := kube.EvaluateRollout(dep)
	switch ev.State {
	case kube.RolloutComplete:
		m.completeOperation(op, msg, ev.Reason)
		return true
	case kube.RolloutFailed:
		m.failOperation(op, msg, "ROLLOUT_FAILED", ev.Reason)
		return true
	}
	return false
}

func (m *Manager) completeOperation(op *store.Operation, msg *notify.Message, reason string) {
	m.resolve(op, msg, "mark operation succeeded", store.TerminalUpdate{
		Status: store.StatusSucceeded, Event: "SUCCEEDED", CompletedAt: time.Now().UTC(),
	})
	m.log.Info("rollout succeeded", "operation_id", op.OperationID, "reason", reason)
}

func (m *Manager) timeoutOperation(op *store.Operation, msg *notify.Message, errMsg string) {
	m.resolve(op, msg, "mark operation timeout", store.TerminalUpdate{
		Status: store.StatusTimeout, Event: "TIMEOUT",
		ErrorCode: "TIMEOUT", ErrorMessage: errMsg, CompletedAt: time.Now().UTC(),
	})
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
