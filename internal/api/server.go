package api

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/tuncloud/deploy-gateway/internal/authn"
	"github.com/tuncloud/deploy-gateway/internal/authz"
	"github.com/tuncloud/deploy-gateway/internal/operation"
	"github.com/tuncloud/deploy-gateway/internal/store"
)

type TokenVerifier interface {
	Verify(ctx context.Context, rawToken string) (*authn.GitHubIdentity, error)
}

type Deps struct {
	Verifier TokenVerifier
	Policy   *authz.Policy
	Ops      *operation.Manager
	Store    store.Store
	Log      *slog.Logger
}

type ctxKeyIdentity struct{}

func writeError(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]string{"code": code, "message": msg},
	})
}

func (d *Deps) authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authzHeader := r.Header.Get("Authorization")
		const prefix = "Bearer "
		if !strings.HasPrefix(authzHeader, prefix) {
			writeError(w, http.StatusUnauthorized, "UNAUTHENTICATED", "missing bearer token")
			return
		}
		id, err := d.Verifier.Verify(r.Context(), strings.TrimPrefix(authzHeader, prefix))
		if err != nil {
			// never include token or verification detail (may echo JWT internals)
			d.Log.Warn("token rejected")
			writeError(w, http.StatusUnauthorized, "UNAUTHENTICATED", "invalid token")
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKeyIdentity{}, id)))
	})
}

func identityFrom(r *http.Request) *authn.GitHubIdentity {
	id, _ := r.Context().Value(ctxKeyIdentity{}).(*authn.GitHubIdentity)
	return id
}

func (d *Deps) handleRestart(w http.ResponseWriter, r *http.Request) {
	id := identityFrom(r)

	var body struct {
		Namespace  string `json:"namespace"`
		Deployment string `json:"deployment"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil ||
		body.Namespace == "" || body.Deployment == "" {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "namespace and deployment are required")
		return
	}

	if !d.Policy.Authorize(id.Repository, operation.ActionRestart, body.Namespace, body.Deployment) {
		now := time.Now().UTC()
		if err := d.Store.PutOperation(r.Context(), &store.Operation{
			OperationID: operation.NewOperationID(),
			Repository:  id.Repository, RepositoryID: id.RepositoryID,
			RepositoryOwner: id.RepositoryOwner, Actor: id.Actor,
			Workflow: id.Workflow, WorkflowRef: id.WorkflowRef,
			RunID: id.RunID, RunAttempt: id.RunAttempt, EventName: id.EventName,
			Action:    operation.ActionRestart,
			Namespace: body.Namespace, Deployment: body.Deployment,
			NsDep:     body.Namespace + "#" + body.Deployment,
			Status:    store.StatusDenied,
			ErrorCode: "DENIED",
			ErrorMessage: "policy does not allow " + operation.ActionRestart +
				" on " + body.Namespace + "/" + body.Deployment,
			RequestedAt: now,
			ExpiresAt:   now.Add(365 * 24 * time.Hour).Unix(),
			Events:      []store.AuditEvent{{Event: "DENIED", At: now}},
		}); err != nil {
			// err is a store-side error (no token/claims content) — surface it so
			// a denied request never silently vanishes from the audit trail.
			d.Log.Error("denied audit write failed",
				"repository", id.Repository,
				"namespace", body.Namespace, "deployment", body.Deployment, "err", err)
		}
		d.Log.Warn("denied", "repository", id.Repository,
			"namespace", body.Namespace, "deployment", body.Deployment)
		writeError(w, http.StatusForbidden, "FORBIDDEN", "not allowed")
		return
	}

	opID, err := d.Ops.Restart(r.Context(), id, body.Namespace, body.Deployment)
	if err != nil {
		if opID == "" {
			writeError(w, http.StatusServiceUnavailable, "STORE_UNAVAILABLE", "operation could not be recorded")
			return
		}
		// operation exists; patch failed — surface 502 with op id for follow-up
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadGateway)
		json.NewEncoder(w).Encode(map[string]any{
			"error":        map[string]string{"code": "K8S_UNAVAILABLE", "message": "kubernetes api call failed"},
			"operation_id": opID,
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]string{"operation_id": opID, "status": "running"})
}

func (d *Deps) handleRollout(w http.ResponseWriter, r *http.Request) {
	id := identityFrom(r)

	var body struct {
		Namespace  string `json:"namespace"`
		Deployment string `json:"deployment"`
		Container  string `json:"container"`
		Image      string `json:"image"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil ||
		body.Namespace == "" || body.Deployment == "" || body.Image == "" {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "namespace, deployment and image are required")
		return
	}

	if !d.Policy.Authorize(id.Repository, operation.ActionRollout, body.Namespace, body.Deployment) {
		now := time.Now().UTC()
		if err := d.Store.PutOperation(r.Context(), &store.Operation{
			OperationID: operation.NewOperationID(),
			Repository:  id.Repository, RepositoryID: id.RepositoryID,
			RepositoryOwner: id.RepositoryOwner, Actor: id.Actor,
			Workflow: id.Workflow, WorkflowRef: id.WorkflowRef,
			RunID: id.RunID, RunAttempt: id.RunAttempt, EventName: id.EventName,
			Action:    operation.ActionRollout,
			Namespace: body.Namespace, Deployment: body.Deployment,
			Container: body.Container, Image: body.Image,
			NsDep:     body.Namespace + "#" + body.Deployment,
			Status:    store.StatusDenied,
			ErrorCode: "DENIED",
			ErrorMessage: "policy does not allow " + operation.ActionRollout +
				" on " + body.Namespace + "/" + body.Deployment,
			RequestedAt: now,
			ExpiresAt:   now.Add(365 * 24 * time.Hour).Unix(),
			Events:      []store.AuditEvent{{Event: "DENIED", At: now}},
		}); err != nil {
			// err is a store-side error (no token/claims content) — surface it so
			// a denied request never silently vanishes from the audit trail.
			d.Log.Error("denied audit write failed",
				"repository", id.Repository,
				"namespace", body.Namespace, "deployment", body.Deployment, "err", err)
		}
		d.Log.Warn("denied", "repository", id.Repository,
			"namespace", body.Namespace, "deployment", body.Deployment)
		writeError(w, http.StatusForbidden, "FORBIDDEN", "not allowed")
		return
	}

	opID, err := d.Ops.Rollout(r.Context(), id, body.Namespace, body.Deployment, body.Container, body.Image)
	if err != nil {
		if errors.Is(err, operation.ErrAmbiguousContainer) {
			writeError(w, http.StatusBadRequest, "AMBIGUOUS_CONTAINER", operation.ErrAmbiguousContainer.Error())
			return
		}
		if opID == "" {
			writeError(w, http.StatusServiceUnavailable, "STORE_UNAVAILABLE", "operation could not be recorded")
			return
		}
		// operation exists; patch failed — surface 502 with op id for follow-up
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadGateway)
		json.NewEncoder(w).Encode(map[string]any{
			"error":        map[string]string{"code": "K8S_UNAVAILABLE", "message": "kubernetes api call failed"},
			"operation_id": opID,
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]string{"operation_id": opID, "status": "running"})
}

func (d *Deps) handleGetOperation(w http.ResponseWriter, r *http.Request) {
	opID := chi.URLParam(r, "operation_id")
	op, err := d.Ops.Get(r.Context(), opID)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "operation not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "STORE_UNAVAILABLE", "operation store unavailable")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"operation_id": op.OperationID,
		"status":       op.Status,
		"action":       op.Action,
		"namespace":    op.Namespace,
		"deployment":   op.Deployment,
		"error":        errBody(op),
	})
}

func errBody(op *store.Operation) map[string]string {
	if op.ErrorCode == "" {
		return nil
	}
	return map[string]string{"code": op.ErrorCode, "message": op.ErrorMessage}
}

func (d *Deps) handleReadyz(w http.ResponseWriter, r *http.Request) {
	if err := d.Store.Ping(r.Context()); err != nil {
		d.Log.Error("readiness check failed", "err", err)
		writeError(w, http.StatusServiceUnavailable, "STORE_UNAVAILABLE", "store not reachable")
		return
	}
	w.Write([]byte("ok"))
}

func NewRouter(d Deps) http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(30 * time.Second))

	r.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok")) })
	r.Get("/readyz", d.handleReadyz)

	r.Group(func(r chi.Router) {
		r.Use(d.authenticate)
		r.Post("/v1/deployments/restart", d.handleRestart)
		r.Post("/v1/deployments/rollout", d.handleRollout)
		r.Get("/v1/operations/{operation_id}", d.handleGetOperation)
	})
	return r
}
