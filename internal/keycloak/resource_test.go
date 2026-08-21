package keycloak

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func resourceServer(t *testing.T, resourceJSON string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/realms/master/protocol/openid-connect/token",
		func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"access_token":"tok","expires_in":300}`))
		})
	mux.HandleFunc("/admin/realms/master/clients",
		func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`[{"id":"client-uuid-1"}]`))
		})
	mux.HandleFunc("/admin/realms/master/clients/client-uuid-1/authz/resource-server/resource",
		func(w http.ResponseWriter, r *http.Request) {
			if got := r.URL.Query().Get("exactName"); got != "true" {
				t.Errorf("exactName = %q, want true", got)
			}
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(resourceJSON))
		})
	return httptest.NewServer(mux)
}

func clientFor(t *testing.T, srv *httptest.Server) *Client {
	t.Helper()
	c := NewClient(testConfig(srv.URL), slog.Default(), newTestClock())
	c.hc = srv.Client()
	return c
}

func TestAllowedRefsActionSpecificWins(t *testing.T) {
	srv := resourceServer(t, `[{"_id":"r1","name":"backend/backend-api","attributes":{
		"allowed_refs":["*"],
		"allowed_refs.deployment.rollout":["refs/heads/main"]
	}}]`)
	defer srv.Close()

	got, err := clientFor(t, srv).AllowedRefs(context.Background(),
		"backend/backend-api", "deployment.rollout")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != "refs/heads/main" {
		t.Fatalf("AllowedRefs = %v, want [refs/heads/main]", got)
	}
}

func TestAllowedRefsFallsBackToBareKey(t *testing.T) {
	srv := resourceServer(t, `[{"_id":"r1","name":"backend/backend-api","attributes":{
		"allowed_refs":["refs/heads/main","refs/tags/v*"]
	}}]`)
	defer srv.Close()

	got, err := clientFor(t, srv).AllowedRefs(context.Background(),
		"backend/backend-api", "deployment.rollout")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("AllowedRefs = %v, want 2 entries", got)
	}
}

// No attribute at all means unrestricted — the migration-safe default.
func TestAllowedRefsAbsentIsNil(t *testing.T) {
	srv := resourceServer(t, `[{"_id":"r1","name":"backend/backend-api","attributes":{}}]`)
	defer srv.Close()

	got, err := clientFor(t, srv).AllowedRefs(context.Background(),
		"backend/backend-api", "deployment.rollout")
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Fatalf("AllowedRefs = %v, want nil", got)
	}
}

func TestAllowedRefsUnknownResourceIsNil(t *testing.T) {
	srv := resourceServer(t, `[]`)
	defer srv.Close()

	got, err := clientFor(t, srv).AllowedRefs(context.Background(),
		"backend/absent", "deployment.rollout")
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Fatalf("AllowedRefs = %v, want nil", got)
	}
}

func TestAllowedRefsCachesPerResourceAndAction(t *testing.T) {
	var resourceCalls int32
	mux := http.NewServeMux()
	mux.HandleFunc("/realms/master/protocol/openid-connect/token",
		func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"access_token":"tok","expires_in":300}`))
		})
	mux.HandleFunc("/admin/realms/master/clients",
		func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`[{"id":"client-uuid-1"}]`))
		})
	mux.HandleFunc("/admin/realms/master/clients/client-uuid-1/authz/resource-server/resource",
		func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt32(&resourceCalls, 1)
			w.Write([]byte(`[{"_id":"r1","attributes":{
				"allowed_refs.deployment.rollout":["refs/heads/main"],
				"allowed_refs.deployment.restart":["*"]
			}}]`))
		})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := clientFor(t, srv)
	for i := 0; i < 3; i++ {
		got, err := c.AllowedRefs(context.Background(),
			"backend/backend-api", "deployment.rollout")
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 || got[0] != "refs/heads/main" {
			t.Fatalf("AllowedRefs = %v, want [refs/heads/main]", got)
		}
	}
	if n := atomic.LoadInt32(&resourceCalls); n != 1 {
		t.Fatalf("resource endpoint called %d times, want 1 (must cache)", n)
	}

	// A different action is a different cache key, so it fetches again and
	// must return that action's own constraint.
	got, err := c.AllowedRefs(context.Background(),
		"backend/backend-api", "deployment.restart")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != "*" {
		t.Fatalf("AllowedRefs(restart) = %v, want [*]", got)
	}
	if n := atomic.LoadInt32(&resourceCalls); n != 2 {
		t.Fatalf("resource endpoint called %d times, want 2 (per-action key)", n)
	}
}

// A zero-resource lookup must still return (nil, nil) — unchanged semantics,
// since AllowedRefs is only reached after Evaluate already permitted this
// same resource name, so finding none here is a wiring/name-format bug that
// this fail-open path can only surface via a log line, never an error.
func TestAllowedRefsUnknownResourceLogsWarning(t *testing.T) {
	srv := resourceServer(t, `[]`)
	defer srv.Close()

	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, nil))
	c := NewClient(testConfig(srv.URL), logger, newTestClock())
	c.hc = srv.Client()

	got, err := c.AllowedRefs(context.Background(), "backend/absent", "deployment.rollout")
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Fatalf("AllowedRefs = %v, want nil", got)
	}
	logged := logBuf.String()
	if !strings.Contains(logged, "resource not found") {
		t.Fatalf("expected a resource-not-found warning, got: %s", logged)
	}
	if !strings.Contains(logged, "backend/absent") || !strings.Contains(logged, "deployment.rollout") {
		t.Fatalf("expected warning to name the resource and action, got: %s", logged)
	}
}
