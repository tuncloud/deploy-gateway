package keycloak

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func testConfig(baseURL string) Config {
	return Config{
		BaseURL:      baseURL,
		Realm:        "master",
		ClientID:     "deploy-gateway",
		ClientSecret: "s3cr3t",
		Timeout:      3 * time.Second,
	}
}

func TestTokenSourceFetchesAndCaches(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		if r.URL.Path != "/realms/master/protocol/openid-connect/token" {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		if got := r.Form.Get("grant_type"); got != "client_credentials" {
			t.Errorf("grant_type = %q", got)
		}
		if got := r.Form.Get("client_secret"); got != "s3cr3t" {
			t.Errorf("client_secret = %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"access_token":"tok-1","expires_in":300}`))
	}))
	defer srv.Close()

	clk := newTestClock()
	ts := newTokenSource(testConfig(srv.URL), srv.Client(), clk)

	for i := 0; i < 3; i++ {
		got, err := ts.Token(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if got != "tok-1" {
			t.Fatalf("Token() = %q, want tok-1", got)
		}
	}
	if n := atomic.LoadInt32(&calls); n != 1 {
		t.Fatalf("token endpoint called %d times, want 1 (must cache)", n)
	}
}

func TestTokenSourceRefreshesBeforeExpiry(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&calls, 1)
		w.Header().Set("Content-Type", "application/json")
		if n == 1 {
			w.Write([]byte(`{"access_token":"tok-1","expires_in":300}`))
			return
		}
		w.Write([]byte(`{"access_token":"tok-2","expires_in":300}`))
	}))
	defer srv.Close()

	clk := newTestClock()
	ts := newTokenSource(testConfig(srv.URL), srv.Client(), clk)
	if _, err := ts.Token(context.Background()); err != nil {
		t.Fatal(err)
	}

	// 300s lifetime minus the 30s safety skew => refresh at 270s.
	clk.advance(271 * time.Second)
	got, err := ts.Token(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got != "tok-2" {
		t.Fatalf("Token() = %q, want tok-2 after expiry", got)
	}
}

func TestTokenSourceInvalidateForcesRefetch(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&calls, 1)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"access_token":"tok-` + string(rune('0'+n)) + `","expires_in":300}`))
	}))
	defer srv.Close()

	ts := newTokenSource(testConfig(srv.URL), srv.Client(), newTestClock())
	first, _ := ts.Token(context.Background())
	ts.Invalidate()
	second, _ := ts.Token(context.Background())
	if first == second {
		t.Fatal("Invalidate must force a new token")
	}
}

// The client secret sits in the request path; it must never reach an error
// string, matching the Telegram bot token discipline.
func TestTokenSourceErrorNeverLeaksSecret(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unauthorized_client", http.StatusUnauthorized)
	}))
	defer srv.Close()

	ts := newTokenSource(testConfig(srv.URL), srv.Client(), newTestClock())
	_, err := ts.Token(context.Background())
	if err == nil {
		t.Fatal("expected an error on 401")
	}
	if strings.Contains(err.Error(), "s3cr3t") {
		t.Fatalf("error leaked the client secret: %v", err)
	}
}
