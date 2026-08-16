package authn_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/tuncloud/deploy-gateway/internal/authn"
)

const audience = "https://gateway.tuando.app"

type fakeIDP struct {
	srv *httptest.Server
	key *rsa.PrivateKey
	kid string
}

func newFakeIDP(t *testing.T) *fakeIDP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeIDP{key: key, kid: "test-key-1"}

	// Handler reads f.srv.URL lazily (inside the handler), so the issuer is
	// correct even though the server URL only exists after ListenAndServe.
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			json.NewEncoder(w).Encode(map[string]string{
				"issuer":   f.srv.URL,
				"jwks_uri": f.srv.URL + "/keys",
			})
		case "/keys":
			jwks := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
				{Key: f.key.Public(), KeyID: f.kid, Algorithm: "RS256", Use: "sig"},
			}}
			json.NewEncoder(w).Encode(jwks)
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeIDP) signToken(t *testing.T, claims map[string]any) string {
	t.Helper()
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: f.key},
		(&jose.SignerOptions{}).WithHeader("kid", f.kid),
	)
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(claims)
	obj, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	s, err := obj.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func githubClaims(t *testing.T, f *fakeIDP, mut func(map[string]any)) map[string]any {
	t.Helper()
	now := time.Now()
	claims := map[string]any{
		"iss": f.srv.URL,
		"aud": audience,
		"sub": "repo:tuncloud/backend:ref:refs/heads/main",
		"exp": now.Add(5 * time.Minute).Unix(),
		"iat": now.Unix(),
		"repository":       "tuncloud/backend",
		"repository_id":    "123456789",
		"repository_owner": "tuncloud",
		"ref":              "refs/heads/main",
		"workflow":         "deploy.yml",
		"workflow_ref":     "tuncloud/backend/.github/workflows/deploy.yml@refs/heads/main",
		"job_workflow_ref": "tuncloud/deploy-gateway/.github/workflows/restart-deployment.yml@refs/heads/v1",
		"actor":            "tuando",
		"event_name":       "push",
		"run_id":           "1827",
		"run_attempt":      "1",
		"environment":      "production",
	}
	mut(claims)
	return claims
}

func TestVerifyValidToken(t *testing.T) {
	f := newFakeIDP(t)
	v, err := authn.NewVerifier(context.Background(), f.srv.URL, audience)
	if err != nil {
		t.Fatal(err)
	}
	token := f.signToken(t, githubClaims(t, f, func(map[string]any) {}))

	id, err := v.Verify(context.Background(), token)
	if err != nil {
		t.Fatalf("valid token rejected: %v", err)
	}
	if id.Repository != "tuncloud/backend" || id.RepositoryID != "123456789" {
		t.Fatalf("claims not extracted: %+v", id)
	}
	if id.Actor != "tuando" || id.RunID != "1827" || id.EventName != "push" {
		t.Fatalf("claims not extracted: %+v", id)
	}
}

func TestVerifyExpiredToken(t *testing.T) {
	f := newFakeIDP(t)
	v, _ := authn.NewVerifier(context.Background(), f.srv.URL, audience)
	token := f.signToken(t, githubClaims(t, f, func(c map[string]any) {
		c["exp"] = time.Now().Add(-time.Minute).Unix()
	}))
	if _, err := v.Verify(context.Background(), token); err == nil {
		t.Fatal("expired token must be rejected")
	}
}

func TestVerifyWrongAudience(t *testing.T) {
	f := newFakeIDP(t)
	v, _ := authn.NewVerifier(context.Background(), f.srv.URL, audience)
	token := f.signToken(t, githubClaims(t, f, func(c map[string]any) {
		c["aud"] = "sts.amazonaws.com"
	}))
	if _, err := v.Verify(context.Background(), token); err == nil {
		t.Fatal("wrong audience must be rejected")
	}
}

func TestVerifyGarbageToken(t *testing.T) {
	f := newFakeIDP(t)
	v, _ := authn.NewVerifier(context.Background(), f.srv.URL, audience)
	if _, err := v.Verify(context.Background(), "not-a-jwt"); err == nil {
		t.Fatal("garbage token must be rejected")
	}
}
