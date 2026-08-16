package api_test

import (
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
	"k8s.io/apimachinery/pkg/watch"

	"github.com/tuncloud/deploy-gateway/internal/api"
	"github.com/tuncloud/deploy-gateway/internal/authn"
	"github.com/tuncloud/deploy-gateway/internal/authz"
	"github.com/tuncloud/deploy-gateway/internal/operation"
	"github.com/tuncloud/deploy-gateway/internal/store"
)

// fakeKube implements kube.Kube for api-level tests without envtest.
type fakeKube struct{ failPatch bool }

func (f *fakeKube) RestartDeployment(context.Context, string, string) error {
	if f.failPatch {
		return errPatch
	}
	return nil
}
func (f *fakeKube) GetDeployment(context.Context, string, string) (*appsv1.Deployment, error) {
	return &appsv1.Deployment{}, nil
}
func (f *fakeKube) WatchDeployment(context.Context, string, string) (watch.Interface, error) {
	return watch.NewFake(), nil
}

var errPatch = errors.New("patch failed")

func newDeps(t *testing.T, policyYAML string, failPatch bool) (http.Handler, func() []*store.Operation) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "p.yaml")
	os.WriteFile(path, []byte(policyYAML), 0o644)
	pol, err := authz.LoadPolicy(path)
	if err != nil {
		t.Fatal(err)
	}
	st := store.NewRecording() // wraps NewInMemory, records PutOperation calls
	m := operation.NewManager(&fakeKube{failPatch: failPatch}, st, slog.Default(), time.Minute)
	// Static verifier accepts any token; real signature checks are covered by
	// the authn tests (Task 3).
	v := authn.NewStaticVerifier(&authn.GitHubIdentity{
		Repository: "tuncloud/backend", RepositoryID: "123", Actor: "tuando",
		RunID: "1", RunAttempt: "1", EventName: "push", Workflow: "deploy.yml",
	})
	return api.NewRouter(api.Deps{Verifier: v, Policy: pol, Ops: m, Store: st, Log: slog.Default()}), st.Recorder()
}

const testPolicy = `version: 1
repositories:
  - repository: tuncloud/backend
    repository_id: "123"
    permissions:
      - action: deployment.restart
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

func TestHealthzStillWorks(t *testing.T) {
	h, _ := newDeps(t, testPolicy, false)
	w := doReq(h, http.MethodGet, "/healthz", "", "")
	if w.Code != 200 {
		t.Fatalf("code = %d", w.Code)
	}
}
