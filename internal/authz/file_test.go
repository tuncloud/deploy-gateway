package authz_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/tuncloud/deploy-gateway/internal/authz"
)

func newFileAuthorizer(t *testing.T) *authz.FileAuthorizer {
	t.Helper()
	path := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(path, []byte(testPolicy), 0o644); err != nil {
		t.Fatal(err)
	}
	a, err := authz.NewFileAuthorizer(path)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestFileAuthorizerAllows(t *testing.T) {
	a := newFileAuthorizer(t)
	dec, err := a.Authorize(context.Background(), authz.Request{
		Repository: "tuncloud/backend", Action: "deployment.restart",
		Namespace: "backend", Deployment: "backend-api",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !dec.Allowed {
		t.Fatal("expected allowed")
	}
}

func TestFileAuthorizerDeniesWithReason(t *testing.T) {
	a := newFileAuthorizer(t)
	dec, err := a.Authorize(context.Background(), authz.Request{
		Repository: "tuncloud/backend", Action: "deployment.restart",
		Namespace: "backend", Deployment: "coredns",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dec.Allowed {
		t.Fatal("expected denied")
	}
	if dec.Reason == "" {
		t.Fatal("denial must carry a reason for the audit row")
	}
}

// The file authorizer ignores Ref: ref constraints live in Keycloak only.
func TestFileAuthorizerIgnoresRef(t *testing.T) {
	a := newFileAuthorizer(t)
	dec, _ := a.Authorize(context.Background(), authz.Request{
		Repository: "tuncloud/backend", Action: "deployment.restart",
		Namespace: "backend", Deployment: "backend-api",
		Ref: "refs/heads/anything",
	})
	if !dec.Allowed {
		t.Fatal("file authorizer must not apply ref constraints")
	}
}
