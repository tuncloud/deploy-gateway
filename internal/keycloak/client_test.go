package keycloak

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// kcStub is a minimal fake Keycloak admin API. Each field lets one test
// override one behaviour.
type kcStub struct {
	evaluateStatus  string // "PERMIT" or "DENY"
	evaluateHTTP    int    // non-zero overrides the evaluate response code
	userFound       bool
	evaluateCalls   int32
	tokenCalls      int32
	lastEvaluateReq map[string]any
}

func (s *kcStub) server(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()

	mux.HandleFunc("/realms/master/protocol/openid-connect/token",
		func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt32(&s.tokenCalls, 1)
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"access_token":"tok","expires_in":300}`))
		})

	mux.HandleFunc("/admin/realms/master/clients",
		func(w http.ResponseWriter, r *http.Request) {
			if got := r.URL.Query().Get("clientId"); got != "deploy-gateway" {
				t.Errorf("clientId query = %q", got)
			}
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`[{"id":"client-uuid-1","clientId":"deploy-gateway"}]`))
		})

	mux.HandleFunc("/admin/realms/master/users",
		func(w http.ResponseWriter, r *http.Request) {
			if got := r.URL.Query().Get("exact"); got != "true" {
				t.Errorf("exact query = %q, want true", got)
			}
			w.Header().Set("Content-Type", "application/json")
			if !s.userFound {
				w.Write([]byte(`[]`))
				return
			}
			w.Write([]byte(`[{"id":"user-uuid-1","username":"tuncloud/backend"}]`))
		})

	mux.HandleFunc("/admin/realms/master/clients/client-uuid-1/authz/resource-server/policy/evaluate",
		func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt32(&s.evaluateCalls, 1)
			if s.evaluateHTTP != 0 {
				http.Error(w, "boom", s.evaluateHTTP)
				return
			}
			var body map[string]any
			json.NewDecoder(r.Body).Decode(&body)
			s.lastEvaluateReq = body
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"status":"` + s.evaluateStatus +
				`","results":[{"status":"` + s.evaluateStatus + `"}]}`))
		})

	return httptest.NewServer(mux)
}

func newTestClient(t *testing.T, s *kcStub) (*Client, *httptest.Server) {
	t.Helper()
	srv := s.server(t)
	c := NewClient(testConfig(srv.URL), slog.Default(), newTestClock())
	c.hc = srv.Client()
	return c, srv
}

func TestClientEvaluatePermit(t *testing.T) {
	s := &kcStub{evaluateStatus: "PERMIT", userFound: true}
	c, srv := newTestClient(t, s)
	defer srv.Close()

	allowed, err := c.Evaluate(context.Background(), "user-uuid-1",
		"backend/backend-api", "deployment.rollout")
	if err != nil {
		t.Fatal(err)
	}
	if !allowed {
		t.Fatal("PERMIT must map to allowed")
	}
}

func TestClientEvaluateDeny(t *testing.T) {
	s := &kcStub{evaluateStatus: "DENY", userFound: true}
	c, srv := newTestClient(t, s)
	defer srv.Close()

	allowed, err := c.Evaluate(context.Background(), "user-uuid-1",
		"backend/backend-api", "deployment.rollout")
	if err != nil {
		t.Fatalf("DENY is a decision, not an error: %v", err)
	}
	if allowed {
		t.Fatal("DENY must map to not allowed")
	}
}

func TestClientEvaluateSendsResourceAndScope(t *testing.T) {
	s := &kcStub{evaluateStatus: "PERMIT", userFound: true}
	c, srv := newTestClient(t, s)
	defer srv.Close()

	c.Evaluate(context.Background(), "user-uuid-1", "backend/backend-api", "deployment.rollout")

	raw, _ := json.Marshal(s.lastEvaluateReq)
	for _, want := range []string{"backend/backend-api", "deployment.rollout", "user-uuid-1"} {
		if !strings.Contains(string(raw), want) {
			t.Fatalf("evaluate request %s missing %q", raw, want)
		}
	}
}

func TestClientEvaluateServerErrorIsAnError(t *testing.T) {
	s := &kcStub{evaluateStatus: "PERMIT", userFound: true, evaluateHTTP: 500}
	c, srv := newTestClient(t, s)
	defer srv.Close()

	_, err := c.Evaluate(context.Background(), "user-uuid-1",
		"backend/backend-api", "deployment.rollout")
	if err == nil {
		t.Fatal("a 500 must be an error, never a silent deny")
	}
}

func TestClientEvaluateRetriesOnce(t *testing.T) {
	s := &kcStub{evaluateStatus: "PERMIT", userFound: true, evaluateHTTP: 503}
	c, srv := newTestClient(t, s)
	defer srv.Close()

	c.Evaluate(context.Background(), "user-uuid-1", "backend/backend-api", "deployment.rollout")
	if n := atomic.LoadInt32(&s.evaluateCalls); n != 2 {
		t.Fatalf("evaluate called %d times, want 2 (one retry on 5xx)", n)
	}
}

func TestClientUserIDFound(t *testing.T) {
	s := &kcStub{evaluateStatus: "PERMIT", userFound: true}
	c, srv := newTestClient(t, s)
	defer srv.Close()

	id, err := c.UserID(context.Background(), "tuncloud/backend")
	if err != nil {
		t.Fatal(err)
	}
	if id != "user-uuid-1" {
		t.Fatalf("UserID = %q, want user-uuid-1", id)
	}
}

// A repository with no Keycloak user is a clean denial, not an outage.
func TestClientUserIDAbsentIsErrNoSubject(t *testing.T) {
	s := &kcStub{evaluateStatus: "PERMIT", userFound: false}
	c, srv := newTestClient(t, s)
	defer srv.Close()

	_, err := c.UserID(context.Background(), "tuncloud/unknown")
	if !errors.Is(err, ErrNoSubject) {
		t.Fatalf("err = %v, want ErrNoSubject", err)
	}
}

func TestClientResourceServerUUIDCached(t *testing.T) {
	s := &kcStub{evaluateStatus: "PERMIT", userFound: true}
	c, srv := newTestClient(t, s)
	defer srv.Close()

	for i := 0; i < 3; i++ {
		got, err := c.ResourceServerUUID(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if got != "client-uuid-1" {
			t.Fatalf("ResourceServerUUID = %q", got)
		}
	}
}
