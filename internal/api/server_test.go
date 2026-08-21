package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/watch"

	"github.com/tuncloud/deploy-gateway/internal/api"
	"github.com/tuncloud/deploy-gateway/internal/authn"
	"github.com/tuncloud/deploy-gateway/internal/authz"
	"github.com/tuncloud/deploy-gateway/internal/kube"
	"github.com/tuncloud/deploy-gateway/internal/notify"
	"github.com/tuncloud/deploy-gateway/internal/operation"
	"github.com/tuncloud/deploy-gateway/internal/store"
)

// fakeKube implements kube.Kube for api-level tests without envtest.
type fakeKube struct {
	failPatch  bool
	containers []corev1.Container
}

func (f *fakeKube) RestartDeployment(context.Context, string, string) error {
	if f.failPatch {
		return errPatch
	}
	return nil
}
func (f *fakeKube) RolloutDeployment(context.Context, string, string, string, string) error {
	if f.failPatch {
		return errPatch
	}
	return nil
}
func (f *fakeKube) GetDeployment(context.Context, string, string) (*appsv1.Deployment, error) {
	return &appsv1.Deployment{Spec: appsv1.DeploymentSpec{Template: corev1.PodTemplateSpec{
		Spec: corev1.PodSpec{Containers: f.containers},
	}}}, nil
}
func (f *fakeKube) WatchDeployment(context.Context, string, string) (watch.Interface, error) {
	return watch.NewFake(), nil
}

var errPatch = errors.New("patch failed")

// fakeAuthz implements authz.Authorizer. err simulates unavailability;
// allowed/reason simulate a reached decision.
type fakeAuthz struct {
	allowed bool
	reason  string
	err     error
	seen    []authz.Request
}

func (f *fakeAuthz) Authorize(_ context.Context, req authz.Request) (authz.Decision, error) {
	f.seen = append(f.seen, req)
	if f.err != nil {
		return authz.Decision{}, f.err
	}
	return authz.Decision{Allowed: f.allowed, Reason: f.reason}, nil
}

func newDeps(t *testing.T, policyYAML string, failPatch bool) (http.Handler, func() []*store.Operation) {
	t.Helper()
	return newDepsK(t, policyYAML, &fakeKube{failPatch: failPatch})
}

func newDepsK(t *testing.T, policyYAML string, k kube.Kube) (http.Handler, func() []*store.Operation) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "p.yaml")
	os.WriteFile(path, []byte(policyYAML), 0o644)
	a, err := authz.NewFileAuthorizer(path)
	if err != nil {
		t.Fatal(err)
	}
	st := store.NewRecording() // wraps NewInMemory, records PutOperation calls
	m := operation.NewManager(k, st, notify.Disabled(), slog.Default(), time.Minute)
	// Static verifier accepts any token; real signature checks are covered by
	// the authn tests (Task 3).
	v := authn.NewStaticVerifier(&authn.GitHubIdentity{
		Repository: "tuncloud/backend", RepositoryID: "123", Actor: "tuando",
		RunID: "1", RunAttempt: "1", EventName: "push", Workflow: "deploy.yml",
	})
	return api.NewRouter(api.Deps{Verifier: v, Authz: a, Ops: m, Store: st, Log: slog.Default()}), st.Recorder()
}

func newDepsAuthz(t *testing.T, a authz.Authorizer) (http.Handler, func() []*store.Operation) {
	t.Helper()
	st := store.NewRecording()
	m := operation.NewManager(&fakeKube{}, st, notify.Disabled(), slog.Default(), time.Minute)
	v := authn.NewStaticVerifier(&authn.GitHubIdentity{
		Repository: "tuncloud/backend", RepositoryID: "123", Actor: "tuando",
		RunID: "1", RunAttempt: "1", EventName: "push", Workflow: "deploy.yml",
		Ref: "refs/heads/main",
	})
	return api.NewRouter(api.Deps{
		Verifier: v, Authz: a, Ops: m, Store: st, Log: slog.Default(),
	}), st.Recorder()
}

const testPolicy = `version: 1
repositories:
  - repository: tuncloud/backend
    permissions:
      - action: deployment.restart
        namespaces: [backend]
        deployments: [backend-api]
`

const rolloutPolicy = `version: 1
repositories:
  - repository: tuncloud/backend
    permissions:
      - action: deployment.rollout
        namespaces: [backend]
        deployments: [backend-api]
`

func doReq(h http.Handler, method, path, body, token string) *httptest.ResponseRecorder {
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, path, nil)
	} else {
		r = httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestRestartMissingToken401(t *testing.T) {
	h, _ := newDeps(t, testPolicy, false)
	w := doReq(h, http.MethodPost, "/v1/deployments/restart", `{"namespace":"backend","deployment":"backend-api"}`, "")
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("code = %d, want 401", w.Code)
	}
	if !strings.Contains(w.Body.String(), "UNAUTHENTICATED") {
		t.Fatalf("body = %s", w.Body.String())
	}
}

func TestRestartDenied403WritesAuditItem(t *testing.T) {
	h, rec := newDeps(t, testPolicy, false)
	w := doReq(h, http.MethodPost, "/v1/deployments/restart", `{"namespace":"kube-system","deployment":"coredns"}`, "tok")
	if w.Code != http.StatusForbidden {
		t.Fatalf("code = %d, want 403", w.Code)
	}
	ops := rec()
	if len(ops) != 1 || ops[0].Status != store.StatusDenied || ops[0].ErrorCode != "DENIED" {
		t.Fatalf("denied audit item not written: %+v", ops)
	}
}

func TestRestartHappyPath202(t *testing.T) {
	h, _ := newDeps(t, testPolicy, false)
	w := doReq(h, http.MethodPost, "/v1/deployments/restart", `{"namespace":"backend","deployment":"backend-api"}`, "tok")
	if w.Code != http.StatusAccepted {
		t.Fatalf("code = %d, want 202: %s", w.Code, w.Body.String())
	}
	var resp struct {
		OperationID string `json:"operation_id"`
		Status      string
	}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if !strings.HasPrefix(resp.OperationID, "op_") || resp.Status != "running" {
		t.Fatalf("resp = %+v", resp)
	}
}

func TestRestartPatchFailure502(t *testing.T) {
	h, _ := newDeps(t, testPolicy, true)
	w := doReq(h, http.MethodPost, "/v1/deployments/restart", `{"namespace":"backend","deployment":"backend-api"}`, "tok")
	if w.Code != http.StatusBadGateway {
		t.Fatalf("code = %d, want 502", w.Code)
	}
}

func TestRestartBadBody400(t *testing.T) {
	h, _ := newDeps(t, testPolicy, false)
	w := doReq(h, http.MethodPost, "/v1/deployments/restart", `{"namespace":""}`, "tok")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("code = %d, want 400", w.Code)
	}
}

func TestRolloutMissingImage400(t *testing.T) {
	h, _ := newDeps(t, rolloutPolicy, false)
	w := doReq(h, http.MethodPost, "/v1/deployments/rollout",
		`{"namespace":"backend","deployment":"backend-api"}`, "tok")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("code = %d, want 400", w.Code)
	}
	if !strings.Contains(w.Body.String(), "INVALID_REQUEST") {
		t.Fatalf("body = %s", w.Body.String())
	}
}

// testPolicy grants only deployment.restart — it must not grant rollout.
func TestRolloutDenied403AuditHasActionRollout(t *testing.T) {
	h, rec := newDeps(t, testPolicy, false)
	w := doReq(h, http.MethodPost, "/v1/deployments/rollout",
		`{"namespace":"backend","deployment":"backend-api","image":"img:v2"}`, "tok")
	if w.Code != http.StatusForbidden {
		t.Fatalf("code = %d, want 403", w.Code)
	}
	ops := rec()
	if len(ops) != 1 || ops[0].Status != store.StatusDenied {
		t.Fatalf("denied audit item not written: %+v", ops)
	}
	if ops[0].Action != operation.ActionRollout || ops[0].Image != "img:v2" {
		t.Fatalf("audit fields = action:%s image:%s", ops[0].Action, ops[0].Image)
	}
}

func TestRolloutHappyPath202(t *testing.T) {
	h, rec := newDepsK(t, rolloutPolicy, &fakeKube{
		containers: []corev1.Container{{Name: "app", Image: "img:v1"}},
	})
	w := doReq(h, http.MethodPost, "/v1/deployments/rollout",
		`{"namespace":"backend","deployment":"backend-api","image":"img:v2"}`, "tok")
	if w.Code != http.StatusAccepted {
		t.Fatalf("code = %d, want 202: %s", w.Code, w.Body.String())
	}
	var resp struct {
		OperationID string `json:"operation_id"`
		Status      string
	}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if !strings.HasPrefix(resp.OperationID, "op_") || resp.Status != "running" {
		t.Fatalf("resp = %+v", resp)
	}
	ops := rec()
	if len(ops) != 1 {
		t.Fatalf("want 1 recorded op, got %d", len(ops))
	}
	if ops[0].Image != "img:v2" || ops[0].Container != "app" {
		t.Fatalf("audit fields = image:%s container:%s", ops[0].Image, ops[0].Container)
	}
}

func TestRolloutAmbiguousContainer400(t *testing.T) {
	h, rec := newDepsK(t, rolloutPolicy, &fakeKube{
		containers: []corev1.Container{{Name: "a"}, {Name: "b"}},
	})
	w := doReq(h, http.MethodPost, "/v1/deployments/rollout",
		`{"namespace":"backend","deployment":"backend-api","image":"img:v2"}`, "tok")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("code = %d, want 400: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "AMBIGUOUS_CONTAINER") {
		t.Fatalf("body = %s", w.Body.String())
	}
	if ops := rec(); len(ops) != 0 {
		t.Fatalf("ambiguous request must persist nothing, got %+v", ops)
	}
}

func TestRolloutPatchFail502WithOpID(t *testing.T) {
	h, _ := newDeps(t, rolloutPolicy, true)
	w := doReq(h, http.MethodPost, "/v1/deployments/rollout",
		`{"namespace":"backend","deployment":"backend-api","container":"app","image":"img:v2"}`, "tok")
	if w.Code != http.StatusBadGateway {
		t.Fatalf("code = %d, want 502", w.Code)
	}
	var resp struct {
		Error       map[string]string `json:"error"`
		OperationID string            `json:"operation_id"`
	}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Error["code"] != "K8S_UNAVAILABLE" || !strings.HasPrefix(resp.OperationID, "op_") {
		t.Fatalf("resp = %+v", resp)
	}
}

func TestRestartAllowedReturns202(t *testing.T) {
	h, _ := newDepsAuthz(t, &fakeAuthz{allowed: true})
	w := doReq(h, http.MethodPost, "/v1/deployments/restart",
		`{"namespace":"backend","deployment":"backend-api"}`, "t")
	if w.Code != http.StatusAccepted {
		t.Fatalf("code = %d, want 202", w.Code)
	}
}

func TestRestartDeniedReturns403AndWritesAuditRow(t *testing.T) {
	h, rec := newDepsAuthz(t, &fakeAuthz{allowed: false, reason: "no grant"})
	w := doReq(h, http.MethodPost, "/v1/deployments/restart",
		`{"namespace":"backend","deployment":"backend-api"}`, "t")
	if w.Code != http.StatusForbidden {
		t.Fatalf("code = %d, want 403", w.Code)
	}
	ops := rec()
	if len(ops) != 1 {
		t.Fatalf("recorded %d operations, want 1 denial row", len(ops))
	}
	if ops[0].Status != store.StatusDenied {
		t.Fatalf("status = %q, want denied", ops[0].Status)
	}
	if ops[0].ErrorMessage != "no grant" {
		t.Fatalf("ErrorMessage = %q, want the authorizer's reason", ops[0].ErrorMessage)
	}
}

// The central invariant: an unreachable authorizer is 503, not 403, and must
// not write a denial row that would misattribute an outage to a policy decision.
func TestRestartAuthzUnavailableReturns503AndWritesNoAuditRow(t *testing.T) {
	h, rec := newDepsAuthz(t, &fakeAuthz{err: errors.New("keycloak down")})
	w := doReq(h, http.MethodPost, "/v1/deployments/restart",
		`{"namespace":"backend","deployment":"backend-api"}`, "t")
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("code = %d, want 503", w.Code)
	}
	if !strings.Contains(w.Body.String(), "AUTHZ_UNAVAILABLE") {
		t.Fatalf("body = %s, want AUTHZ_UNAVAILABLE", w.Body.String())
	}
	if ops := rec(); len(ops) != 0 {
		t.Fatalf("recorded %d operations, want 0 on unavailability", len(ops))
	}
}

func TestRolloutAuthzUnavailableReturns503(t *testing.T) {
	h, rec := newDepsAuthz(t, &fakeAuthz{err: errors.New("keycloak down")})
	w := doReq(h, http.MethodPost, "/v1/deployments/rollout",
		`{"namespace":"backend","deployment":"backend-api","image":"ghcr.io/o/a:v1"}`, "t")
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("code = %d, want 503", w.Code)
	}
	if ops := rec(); len(ops) != 0 {
		t.Fatalf("recorded %d operations, want 0", len(ops))
	}
}

func TestRolloutDeniedAuditRowKeepsImageAndContainer(t *testing.T) {
	h, rec := newDepsAuthz(t, &fakeAuthz{allowed: false, reason: "no grant"})
	doReq(h, http.MethodPost, "/v1/deployments/rollout",
		`{"namespace":"backend","deployment":"backend-api","container":"api","image":"ghcr.io/o/a:v1"}`, "t")
	ops := rec()
	if len(ops) != 1 {
		t.Fatalf("recorded %d operations, want 1", len(ops))
	}
	if ops[0].Image != "ghcr.io/o/a:v1" || ops[0].Container != "api" {
		t.Fatalf("denial row lost rollout detail: %+v", ops[0])
	}
}

// The ref claim must reach the authorizer, or ref constraints can never apply.
func TestHandlersPassRefToAuthorizer(t *testing.T) {
	fa := &fakeAuthz{allowed: true}
	h, _ := newDepsAuthz(t, fa)
	doReq(h, http.MethodPost, "/v1/deployments/restart",
		`{"namespace":"backend","deployment":"backend-api"}`, "t")
	if len(fa.seen) != 1 {
		t.Fatalf("authorizer saw %d requests, want 1", len(fa.seen))
	}
	if fa.seen[0].Ref != "refs/heads/main" {
		t.Fatalf("Ref = %q, want refs/heads/main", fa.seen[0].Ref)
	}
	if fa.seen[0].Action != operation.ActionRestart {
		t.Fatalf("Action = %q, want %q", fa.seen[0].Action, operation.ActionRestart)
	}
}

func TestGetOperation(t *testing.T) {
	h, _ := newDeps(t, testPolicy, false)
	w := doReq(h, http.MethodPost, "/v1/deployments/restart", `{"namespace":"backend","deployment":"backend-api"}`, "tok")
	var resp struct {
		OperationID string `json:"operation_id"`
	}
	json.Unmarshal(w.Body.Bytes(), &resp)

	g := doReq(h, http.MethodGet, "/v1/operations/"+resp.OperationID, "", "tok")
	if g.Code != http.StatusOK {
		t.Fatalf("get code = %d", g.Code)
	}
	var op struct {
		OperationID string `json:"operation_id"`
		Action      string `json:"action"`
	}
	json.Unmarshal(g.Body.Bytes(), &op)
	if op.OperationID != resp.OperationID || op.Action != operation.ActionRestart {
		t.Fatalf("op = %+v", op)
	}
}

func TestGetOperationNotFound404(t *testing.T) {
	h, _ := newDeps(t, testPolicy, false)
	w := doReq(h, http.MethodGet, "/v1/operations/op_missing", "", "tok")
	if w.Code != http.StatusNotFound {
		t.Fatalf("code = %d, want 404", w.Code)
	}
}

func TestReadyzStoreFailure503LogsCause(t *testing.T) {
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, nil))
	h := newDepsCustom(t, authn.NewStaticVerifier(&authn.GitHubIdentity{}),
		pingFailStore{store.NewInMemory()}, logger)

	w := doReq(h, http.MethodGet, "/readyz", "", "")
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("code = %d, want 503", w.Code)
	}
	if strings.Contains(w.Body.String(), "AccessDeniedException") {
		t.Fatalf("store error leaked into response: %s", w.Body.String())
	}
	if !strings.Contains(logBuf.String(), "readiness check failed") ||
		!strings.Contains(logBuf.String(), "AccessDeniedException") {
		t.Fatalf("expected readiness failure log, got: %s", logBuf.String())
	}
}
func TestHealthzStillWorks(t *testing.T) {
	h, _ := newDeps(t, testPolicy, false)
	w := doReq(h, http.MethodGet, "/healthz", "", "")
	if w.Code != 200 {
		t.Fatalf("code = %d", w.Code)
	}
}

// failingVerifier rejects every token with an error carrying sentinel detail
// (claims internals) that must never reach the response body or logs.
type failingVerifier struct{ err error }

func (f failingVerifier) Verify(_ context.Context, _ string) (*authn.GitHubIdentity, error) {
	return nil, f.err
}

// putFailStore fails every PutOperation; used to prove a broken audit store
// still yields 403 and logs the write failure.
type putFailStore struct{ store.Store }

func (putFailStore) PutOperation(context.Context, *store.Operation) error {
	return errors.New("dynamo backpressure")
}

type pingFailStore struct{ store.Store }

func (pingFailStore) Ping(context.Context) error {
	return errors.New("dynamodb: AccessDeniedException")
}

func newDepsCustom(t *testing.T, v api.TokenVerifier, st store.Store, log *slog.Logger) http.Handler {
	t.Helper()
	path := filepath.Join(t.TempDir(), "p.yaml")
	os.WriteFile(path, []byte(testPolicy), 0o644)
	a, err := authz.NewFileAuthorizer(path)
	if err != nil {
		t.Fatal(err)
	}
	m := operation.NewManager(&fakeKube{}, st, notify.Disabled(), log, time.Minute)
	return api.NewRouter(api.Deps{Verifier: v, Authz: a, Ops: m, Store: st, Log: log})
}

func TestRestartRejectedToken401GenericBodyNoEcho(t *testing.T) {
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, nil))
	verr := errors.New("AUDIENCE bob evil-token-claims")
	h := newDepsCustom(t, failingVerifier{err: verr}, store.NewRecording(), logger)

	w := doReq(h, http.MethodPost, "/v1/deployments/restart",
		`{"namespace":"backend","deployment":"backend-api"}`, "forged.jwt.value")

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("code = %d, want 401", w.Code)
	}
	want := "{\"error\":{\"code\":\"UNAUTHENTICATED\",\"message\":\"invalid token\"}}\n"
	if w.Body.String() != want {
		t.Fatalf("body = %q, want exact generic 401 body %q", w.Body.String(), want)
	}
	for _, leak := range []string{"AUDIENCE", "evil-token-claims", "forged.jwt.value", verr.Error()} {
		if strings.Contains(w.Body.String(), leak) {
			t.Fatalf("sensitive detail %q leaked into response body", leak)
		}
		if strings.Contains(logBuf.String(), leak) {
			t.Fatalf("sensitive detail %q leaked into logs: %s", leak, logBuf.String())
		}
	}
	if !strings.Contains(logBuf.String(), "token rejected") {
		t.Fatalf("expected rejection log entry, got: %s", logBuf.String())
	}
}

func TestRestartDeniedAuditWriteFailureStill403(t *testing.T) {
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, nil))
	h := newDepsCustom(t, authn.NewStaticVerifier(&authn.GitHubIdentity{
		Repository: "tuncloud/backend", RepositoryID: "123", Actor: "tuando",
		RunID: "1", RunAttempt: "1", EventName: "push", Workflow: "deploy.yml",
	}), putFailStore{store.NewRecording()}, logger)

	w := doReq(h, http.MethodPost, "/v1/deployments/restart",
		`{"namespace":"kube-system","deployment":"coredns"}`, "tok")

	if w.Code != http.StatusForbidden {
		t.Fatalf("code = %d, want 403 even when audit write fails", w.Code)
	}
	if !strings.Contains(w.Body.String(), "FORBIDDEN") {
		t.Fatalf("body = %s", w.Body.String())
	}
	if !strings.Contains(logBuf.String(), "denied audit write failed") {
		t.Fatalf("expected audit-write failure log, got: %s", logBuf.String())
	}
}
