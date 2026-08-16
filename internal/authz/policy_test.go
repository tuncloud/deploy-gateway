package authz_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/tuncloud/deploy-gateway/internal/authz"
)

const testPolicy = `version: 1
repositories:
  - repository: tuncloud/backend
    permissions:
      - action: deployment.restart
        namespaces: [backend]
        deployments: [backend-api, backend-worker]
  - repository: tuncloud/infra
    permissions:
      - action: deployment.restart
        namespaces: ["*"]
        deployments: ["*"]
`

func load(t *testing.T) *authz.Policy {
	t.Helper()
	path := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(path, []byte(testPolicy), 0o644); err != nil {
		t.Fatal(err)
	}
	p, err := authz.LoadPolicy(path)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestAuthorizeExactMatch(t *testing.T) {
	p := load(t)
	if !p.Authorize("tuncloud/backend", "deployment.restart", "backend", "backend-api") {
		t.Fatal("exact match should be allowed")
	}
}

func TestAuthorizeDenyWrongDeployment(t *testing.T) {
	p := load(t)
	if p.Authorize("tuncloud/backend", "deployment.restart", "backend", "coredns") {
		t.Fatal("unknown deployment must be denied")
	}
}

func TestAuthorizeDenyWrongNamespace(t *testing.T) {
	p := load(t)
	if p.Authorize("tuncloud/backend", "deployment.restart", "kube-system", "backend-api") {
		t.Fatal("wrong namespace must be denied")
	}
}

func TestAuthorizeDenyUnknownRepo(t *testing.T) {
	p := load(t)
	if p.Authorize("evil/repo", "deployment.restart", "backend", "backend-api") {
		t.Fatal("unknown repository must be denied")
	}
}

func TestAuthorizeDenyUnknownAction(t *testing.T) {
	p := load(t)
	if p.Authorize("tuncloud/backend", "deployment.delete", "backend", "backend-api") {
		t.Fatal("unknown action must be denied")
	}
}

func TestAuthorizeWildcard(t *testing.T) {
	p := load(t)
	if !p.Authorize("tuncloud/infra", "deployment.restart", "anything", "whatever") {
		t.Fatal("wildcard entry should allow any ns/dep")
	}
}

func TestLoadPolicyRejectsUnknownVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.yaml")
	os.WriteFile(path, []byte("version: 2\nrepositories: []\n"), 0o644)
	if _, err := authz.LoadPolicy(path); err == nil {
		t.Fatal("version != 1 must be rejected")
	}
}
