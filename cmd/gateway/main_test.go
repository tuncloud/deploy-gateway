package main

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tuncloud/deploy-gateway/internal/authz"
	"github.com/tuncloud/deploy-gateway/internal/keycloak"
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

func setKeycloakEnv(t *testing.T, baseURL, realm, clientID, secret string) {
	t.Helper()
	t.Setenv("KEYCLOAK_BASE_URL", baseURL)
	t.Setenv("KEYCLOAK_REALM", realm)
	t.Setenv("KEYCLOAK_CLIENT_ID", clientID)
	t.Setenv("KEYCLOAK_CLIENT_SECRET", secret)
}

// The secret was read but never validated, so a misspelled Secret key started
// cleanly and only surfaced later as a 401 from the token endpoint — which
// reads as a service-account roles problem, not a missing value. A
// configuration error must exit at boot.
func TestBuildAuthorizerKeycloakMissingSecret(t *testing.T) {
	setKeycloakEnv(t, "https://sso.example.com", "platform", "deploy-gateway", "")

	_, err := buildAuthorizer("keycloak", writePolicy(t), discardLogger())
	if err == nil {
		t.Fatal("AUTHZ_BACKEND=keycloak without KEYCLOAK_CLIENT_SECRET must return an error")
	}
	if !strings.Contains(err.Error(), "KEYCLOAK_CLIENT_SECRET") {
		t.Fatalf("err = %v, want it to name the missing variable", err)
	}
}

func TestBuildAuthorizerShadowMissingSecret(t *testing.T) {
	setKeycloakEnv(t, "https://sso.example.com", "platform", "deploy-gateway", "")

	_, err := buildAuthorizer("shadow", writePolicy(t), discardLogger())
	if err == nil {
		t.Fatal("AUTHZ_BACKEND=shadow without KEYCLOAK_CLIENT_SECRET must return an error")
	}
	if !strings.Contains(err.Error(), "KEYCLOAK_CLIENT_SECRET") {
		t.Fatalf("err = %v, want it to name the missing variable", err)
	}
}

// Complete configuration must build, for both Keycloak-backed backends — so
// the completeness check cannot drift into rejecting a valid setup.
func TestBuildAuthorizerCompleteKeycloakConfigSucceeds(t *testing.T) {
	setKeycloakEnv(t, "https://sso.example.com", "platform", "deploy-gateway", "s3cr3t")

	for _, backend := range []string{"keycloak", "shadow"} {
		a, err := buildAuthorizer(backend, writePolicy(t), discardLogger())
		if err != nil {
			t.Fatalf("AUTHZ_BACKEND=%s with complete config: %v", backend, err)
		}
		if a == nil {
			t.Fatalf("AUTHZ_BACKEND=%s returned a nil authorizer", backend)
		}
	}
}

// The error must name the variables and never their values: the client secret
// must not reach a log line or an error string.
func TestRequireKeycloakConfigNeverEchoesTheSecret(t *testing.T) {
	err := requireKeycloakConfig("keycloak", keycloak.Config{ClientSecret: "s3cr3t"})
	if err == nil {
		t.Fatal("incomplete config must be an error")
	}
	if strings.Contains(err.Error(), "s3cr3t") {
		t.Fatalf("error text leaked the client secret: %v", err)
	}
}
