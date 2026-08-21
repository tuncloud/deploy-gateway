package keycloak

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// refreshSkew renews the token this long before it actually expires, so an
// in-flight request never carries a token that expires mid-call.
const refreshSkew = 30 * time.Second

type Config struct {
	BaseURL      string
	Realm        string
	ClientID     string
	ClientSecret string
	Timeout      time.Duration
}

func (c Config) tokenURL() string {
	return strings.TrimSuffix(c.BaseURL, "/") +
		"/realms/" + url.PathEscape(c.Realm) + "/protocol/openid-connect/token"
}

func (c Config) adminURL(path string) string {
	return strings.TrimSuffix(c.BaseURL, "/") +
		"/admin/realms/" + url.PathEscape(c.Realm) + path
}

type tokenSource struct {
	cfg   Config
	hc    *http.Client
	clock Clock

	mu        sync.Mutex
	token     string
	expiresAt time.Time
}

func newTokenSource(cfg Config, hc *http.Client, clock Clock) *tokenSource {
	return &tokenSource{cfg: cfg, hc: hc, clock: clock}
}

func (t *tokenSource) Token(ctx context.Context) (string, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.token != "" && t.clock.Now().Before(t.expiresAt) {
		return t.token, nil
	}

	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {t.cfg.ClientID},
		"client_secret": {t.cfg.ClientSecret},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		t.cfg.tokenURL(), strings.NewReader(form.Encode()))
	if err != nil {
		// Never wrap err here with the URL-encoded form: it holds the secret.
		return "", fmt.Errorf("keycloak: build token request")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := t.hc.Do(req)
	if err != nil {
		// url.Error carries the request URL but not the body, so the secret is
		// not exposed; still, report only the operation.
		return "", fmt.Errorf("keycloak: token request failed")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("keycloak: token endpoint returned %d", resp.StatusCode)
	}

	var body struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return "", fmt.Errorf("keycloak: decode token response: %w", err)
	}
	if body.AccessToken == "" {
		return "", fmt.Errorf("keycloak: token response had no access_token")
	}

	lifetime := time.Duration(body.ExpiresIn) * time.Second
	if lifetime > refreshSkew {
		lifetime -= refreshSkew
	}
	t.token = body.AccessToken
	t.expiresAt = t.clock.Now().Add(lifetime)
	return t.token, nil
}

// Invalidate drops the cached token so the next Token call refetches. Called
// when Keycloak rejects a token with 401 mid-lifetime.
func (t *tokenSource) Invalidate() {
	t.mu.Lock()
	t.token = ""
	t.mu.Unlock()
}
