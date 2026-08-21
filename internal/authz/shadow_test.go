package authz_test

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/tuncloud/deploy-gateway/internal/authz"
)

type stubAuthorizer struct {
	dec   authz.Decision
	err   error
	calls int
}

func (s *stubAuthorizer) Authorize(context.Context, authz.Request) (authz.Decision, error) {
	s.calls++
	return s.dec, s.err
}

func TestShadowReturnsPrimaryDecision(t *testing.T) {
	primary := &stubAuthorizer{dec: authz.Decision{Allowed: true}}
	shadow := &stubAuthorizer{dec: authz.Decision{Allowed: false, Reason: "no"}}
	s := authz.NewShadow(primary, shadow, slog.Default())

	dec, err := s.Authorize(context.Background(), authz.Request{})
	if err != nil {
		t.Fatal(err)
	}
	if !dec.Allowed {
		t.Fatal("primary decides; shadow must not change the answer")
	}
}

func TestShadowCallsShadow(t *testing.T) {
	primary := &stubAuthorizer{dec: authz.Decision{Allowed: true}}
	shadow := &stubAuthorizer{dec: authz.Decision{Allowed: true}}
	s := authz.NewShadow(primary, shadow, slog.Default())

	s.Authorize(context.Background(), authz.Request{})
	if shadow.calls != 1 {
		t.Fatalf("shadow called %d times, want 1", shadow.calls)
	}
}

// A shadow error must never affect the response — that is the whole point of
// running in shadow mode.
func TestShadowErrorIsNonFatal(t *testing.T) {
	primary := &stubAuthorizer{dec: authz.Decision{Allowed: true}}
	shadow := &stubAuthorizer{err: errors.New("keycloak down")}
	s := authz.NewShadow(primary, shadow, slog.Default())

	dec, err := s.Authorize(context.Background(), authz.Request{})
	if err != nil {
		t.Fatalf("shadow error must be discarded, got %v", err)
	}
	if !dec.Allowed {
		t.Fatal("shadow error must not change the decision")
	}
}

func TestShadowPrimaryErrorPropagates(t *testing.T) {
	primary := &stubAuthorizer{err: errors.New("file broken")}
	shadow := &stubAuthorizer{dec: authz.Decision{Allowed: true}}
	s := authz.NewShadow(primary, shadow, slog.Default())

	if _, err := s.Authorize(context.Background(), authz.Request{}); err == nil {
		t.Fatal("a primary error must propagate")
	}
}

func TestShadowPrimaryDenialStillReturnsDenial(t *testing.T) {
	primary := &stubAuthorizer{dec: authz.Decision{Allowed: false, Reason: "no grant"}}
	shadow := &stubAuthorizer{dec: authz.Decision{Allowed: true}}
	s := authz.NewShadow(primary, shadow, slog.Default())

	dec, _ := s.Authorize(context.Background(), authz.Request{})
	if dec.Allowed {
		t.Fatal("shadow agreeing to allow must not override a primary denial")
	}
	if dec.Reason != "no grant" {
		t.Fatalf("Reason = %q, want the primary's reason", dec.Reason)
	}
}
