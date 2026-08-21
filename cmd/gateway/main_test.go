package main

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/tuncloud/deploy-gateway/internal/authz"
)

const testPolicy = `version: 1
repositories:
  - repository: tuncloud/example-app
    permissions:
      - action: deployment.restart
        namespaces: [example]
        deployments: [example-web]
`

func writePolicy(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(path, []byte(testPolicy), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestBuildAuthorizerUnknownBackend(t *testing.T) {
	if _, err := buildAuthorizer("keyclock", writePolicy(t), discardLogger()); err == nil {
		t.Fatal("unknown AUTHZ_BACKEND must return an error, not fall through to a default")
	}
}

func TestBuildAuthorizerUnsetSelectsFile(t *testing.T) {
	authorizer, err := buildAuthorizer("", writePolicy(t), discardLogger())
	if err != nil {
		t.Fatalf("unset AUTHZ_BACKEND must select the file backend: %v", err)
	}
	if _, ok := authorizer.(*authz.FileAuthorizer); !ok {
		t.Fatalf("unset AUTHZ_BACKEND selected %T, want the file backend", authorizer)
	}
}

func TestBuildAuthorizerFile(t *testing.T) {
	authorizer, err := buildAuthorizer("file", writePolicy(t), discardLogger())
	if err != nil {
		t.Fatalf("AUTHZ_BACKEND=file with a valid policy must succeed: %v", err)
	}
	if authorizer == nil {
		t.Fatal("expected a non-nil authorizer")
	}
}

func TestBuildAuthorizerKeycloakMissingConfig(t *testing.T) {
	t.Setenv("KEYCLOAK_BASE_URL", "")
	t.Setenv("KEYCLOAK_REALM", "")
	t.Setenv("KEYCLOAK_CLIENT_ID", "")
	t.Setenv("KEYCLOAK_CLIENT_SECRET", "")

	if _, err := buildAuthorizer("keycloak", writePolicy(t), discardLogger()); err == nil {
		t.Fatal("AUTHZ_BACKEND=keycloak without KEYCLOAK_* variables must return an error")
	}
}

func TestBuildAuthorizerShadowMissingConfig(t *testing.T) {
	t.Setenv("KEYCLOAK_BASE_URL", "")
	t.Setenv("KEYCLOAK_REALM", "")
	t.Setenv("KEYCLOAK_CLIENT_ID", "")
	t.Setenv("KEYCLOAK_CLIENT_SECRET", "")

	if _, err := buildAuthorizer("shadow", writePolicy(t), discardLogger()); err == nil {
		t.Fatal("AUTHZ_BACKEND=shadow without KEYCLOAK_* variables must return an error")
	}
}
