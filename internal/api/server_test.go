package api_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/tuncloud/deploy-gateway/internal/api"
)

func TestHealthz(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	w := httptest.NewRecorder()

	api.NewRouter().ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("healthz status = %d, want 200", w.Code)
	}
	if body := w.Body.String(); body != "ok" {
		t.Fatalf("healthz body = %q, want ok", body)
	}
}
