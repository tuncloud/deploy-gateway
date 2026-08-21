package keycloak

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tuncloud/deploy-gateway/internal/authz"
)

// authzStub is a full fake Keycloak for authorizer-level tests. down makes
// every admin call fail, simulating an outage.
type authzStub struct {
	status        string
	refs          string // JSON array body for the resource endpoint
	down          atomic.Bool
	evaluateCalls int32
}

func (s *authzStub) server(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()

	mux.HandleFunc("/realms/master/protocol/openid-connect/token",
		func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"access_token":"tok","expires_in":300}`))
		})
	mux.HandleFunc("/admin/realms/master/clients",
		func(w http.ResponseWriter, r *http.Request) {
			if s.down.Load() {
				http.Error(w, "down", http.StatusServiceUnavailable)
				return
			}
			w.Write([]byte(`[{"id":"cu1"}]`))
		})
	mux.HandleFunc("/admin/realms/master/users",
		func(w http.ResponseWriter, r *http.Request) {
			if s.down.Load() {
				http.Error(w, "down", http.StatusServiceUnavailable)
				return
			}
			w.Write([]byte(`[{"id":"uu1"}]`))
		})
	mux.HandleFunc("/admin/realms/master/clients/cu1/authz/resource-server/resource",
		func(w http.ResponseWriter, r *http.Request) {
			if s.down.Load() {
				http.Error(w, "down", http.StatusServiceUnavailable)
				return
			}
			body := s.refs
			if body == "" {
				body = `[{"_id":"r1","attributes":{}}]`
			}
			w.Write([]byte(body))
		})
	mux.HandleFunc("/admin/realms/master/clients/cu1/authz/resource-server/policy/evaluate",
		func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt32(&s.evaluateCalls, 1)
			if s.down.Load() {
				http.Error(w, "down", http.StatusServiceUnavailable)
				return
			}
			w.Write([]byte(`{"status":"` + s.status + `"}`))
		})

	return httptest.NewServer(mux)
}

func newTestAuthorizer(t *testing.T, s *authzStub, clk Clock) (*Authorizer, *httptest.Server) {
	t.Helper()
	srv := s.server(t)
	a := NewAuthorizer(testConfig(srv.URL), slog.Default(), clk)
	a.client.hc = srv.Client()
	return a, srv
}

func rolloutReq() authz.Request {
	return authz.Request{
		Repository: "tuncloud/backend",
		Action:     "deployment.rollout",
		Namespace:  "backend",
		Deployment: "backend-api",
		Ref:        "refs/heads/main",
	}
}

func TestAuthorizerPermit(t *testing.T) {
	s := &authzStub{status: "PERMIT"}
	a, srv := newTestAuthorizer(t, s, newTestClock())
	defer srv.Close()

	dec, err := a.Authorize(context.Background(), rolloutReq())
	if err != nil {
		t.Fatal(err)
	}
	if !dec.Allowed {
		t.Fatal("expected allowed")
	}
}

func TestAuthorizerDenyCarriesReason(t *testing.T) {
	s := &authzStub{status: "DENY"}
	a, srv := newTestAuthorizer(t, s, newTestClock())
	defer srv.Close()

	dec, err := a.Authorize(context.Background(), rolloutReq())
	if err != nil {
		t.Fatalf("DENY must not be an error: %v", err)
	}
	if dec.Allowed || dec.Reason == "" {
		t.Fatalf("expected denial with reason, got %+v", dec)
	}
}

// A ref that fails the constraint denies even though the grant permits.
func TestAuthorizerRefMismatchDenies(t *testing.T) {
	s := &authzStub{
		status: "PERMIT",
		refs:   `[{"_id":"r1","attributes":{"allowed_refs.deployment.rollout":["refs/heads/main"]}}]`,
	}
	a, srv := newTestAuthorizer(t, s, newTestClock())
	defer srv.Close()

	req := rolloutReq()
	req.Ref = "refs/heads/feature"
	dec, err := a.Authorize(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if dec.Allowed {
		t.Fatal("ref mismatch must deny")
	}
	if dec.Reason == "" {
		t.Fatal("ref denial needs a distinguishable reason")
	}
}

// Ref denials must be distinguishable from grant denials in the audit trail.
func TestAuthorizerRefDenialReasonDiffersFromGrantDenial(t *testing.T) {
	refStub := &authzStub{
		status: "PERMIT",
		refs:   `[{"_id":"r1","attributes":{"allowed_refs.deployment.rollout":["refs/heads/main"]}}]`,
	}
	a1, s1 := newTestAuthorizer(t, refStub, newTestClock())
	defer s1.Close()
	req := rolloutReq()
	req.Ref = "refs/heads/feature"
	refDec, _ := a1.Authorize(context.Background(), req)

	grantStub := &authzStub{status: "DENY"}
	a2, s2 := newTestAuthorizer(t, grantStub, newTestClock())
	defer s2.Close()
	grantDec, _ := a2.Authorize(context.Background(), rolloutReq())

	if refDec.Reason == grantDec.Reason {
		t.Fatalf("ref and grant denials share reason %q", refDec.Reason)
	}
}

func TestAuthorizerMalformedRefConstraintDenies(t *testing.T) {
	s := &authzStub{
		status: "PERMIT",
		refs:   `[{"_id":"r1","attributes":{"allowed_refs.deployment.rollout":["refs/*/main"]}}]`,
	}
	a, srv := newTestAuthorizer(t, s, newTestClock())
	defer srv.Close()

	dec, err := a.Authorize(context.Background(), rolloutReq())
	if err != nil {
		t.Fatalf("a malformed constraint is a denial, not unavailability: %v", err)
	}
	if dec.Allowed {
		t.Fatal("malformed constraint must deny")
	}
}

// An unknown repository has no Keycloak subject: a clean deny, not an outage.
func TestAuthorizerNoSubjectDenies(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/realms/master/protocol/openid-connect/token":
			w.Write([]byte(`{"access_token":"tok","expires_in":300}`))
		case "/admin/realms/master/clients":
			w.Write([]byte(`[{"id":"cu1"}]`))
		case "/admin/realms/master/users":
			w.Write([]byte(`[]`))
		default:
			t.Errorf("unexpected path %q", r.URL.Path)
		}
	}))
	defer srv.Close()

	a := NewAuthorizer(testConfig(srv.URL), slog.Default(), newTestClock())
	a.client.hc = srv.Client()

	dec, err := a.Authorize(context.Background(), rolloutReq())
	if err != nil {
		t.Fatalf("ErrNoSubject must be a denial, not an error: %v", err)
	}
	if dec.Allowed {
		t.Fatal("expected denial")
	}
}

func TestAuthorizerCachesPermit(t *testing.T) {
	s := &authzStub{status: "PERMIT"}
	clk := newTestClock()
	a, srv := newTestAuthorizer(t, s, clk)
	defer srv.Close()

	for i := 0; i < 3; i++ {
		if _, err := a.Authorize(context.Background(), rolloutReq()); err != nil {
			t.Fatal(err)
		}
	}
	if n := atomic.LoadInt32(&s.evaluateCalls); n != 1 {
		t.Fatalf("evaluate called %d times, want 1 (PERMIT must cache)", n)
	}
}

// DENY is never cached, so granting access takes effect immediately.
func TestAuthorizerNeverCachesDeny(t *testing.T) {
	s := &authzStub{status: "DENY"}
	a, srv := newTestAuthorizer(t, s, newTestClock())
	defer srv.Close()

	for i := 0; i < 3; i++ {
		a.Authorize(context.Background(), rolloutReq())
	}
	if n := atomic.LoadInt32(&s.evaluateCalls); n != 3 {
		t.Fatalf("evaluate called %d times, want 3 (DENY must not cache)", n)
	}
}

func TestAuthorizerServesStalePermitWhileDown(t *testing.T) {
	s := &authzStub{status: "PERMIT"}
	clk := newTestClock()
	a, srv := newTestAuthorizer(t, s, clk)
	defer srv.Close()

	if _, err := a.Authorize(context.Background(), rolloutReq()); err != nil {
		t.Fatal(err)
	}

	s.down.Store(true)
	clk.advance(2 * time.Minute) // past the 30s TTL, inside the 5m stale window

	dec, err := a.Authorize(context.Background(), rolloutReq())
	if err != nil {
		t.Fatalf("must serve stale permit during an outage: %v", err)
	}
	if !dec.Allowed {
		t.Fatal("stale permit must still allow")
	}
}

func TestAuthorizerFailsClosedBeyondStaleWindow(t *testing.T) {
	s := &authzStub{status: "PERMIT"}
	clk := newTestClock()
	a, srv := newTestAuthorizer(t, s, clk)
	defer srv.Close()

	a.Authorize(context.Background(), rolloutReq())

	s.down.Store(true)
	clk.advance(6 * time.Minute) // beyond TTL + 5m stale window

	_, err := a.Authorize(context.Background(), rolloutReq())
	if err == nil {
		t.Fatal("beyond the stale window the authorizer must fail closed with an error")
	}
}

func TestAuthorizerUnavailableIsErrorNotDenial(t *testing.T) {
	s := &authzStub{status: "PERMIT"}
	s.down.Store(true)
	a, srv := newTestAuthorizer(t, s, newTestClock())
	defer srv.Close()

	_, err := a.Authorize(context.Background(), rolloutReq())
	if err == nil {
		t.Fatal("an outage with no cached permit must return an error, never a denial")
	}
}
