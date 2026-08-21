package keycloak

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"sync"
	"time"
)

// ErrNoSubject: the repository has no corresponding Keycloak user. This is a
// clean denial, not an outage — the caller must not treat it as unavailability.
var ErrNoSubject = errors.New("keycloak: repository has no subject")

// Client talks to the Keycloak Admin API: resolving the resource server's
// UUID, resolving a repository name to a Keycloak user UUID, and asking
// policy/evaluate for a decision. It is safe for concurrent use.
type Client struct {
	cfg   Config
	hc    *http.Client
	ts    *tokenSource
	log   *slog.Logger
	clock Clock

	uuidMu sync.Mutex
	uuid   string

	userIDs *cache[string]
}

// NewClient builds a Client. cfg.Timeout defaults to 3s if unset.
func NewClient(cfg Config, log *slog.Logger, clock Clock) *Client {
	if cfg.Timeout == 0 {
		cfg.Timeout = 3 * time.Second
	}
	hc := &http.Client{Timeout: cfg.Timeout}
	return &Client{
		cfg:     cfg,
		hc:      hc,
		ts:      newTokenSource(cfg, hc, clock),
		log:     log,
		clock:   clock,
		userIDs: newCache[string](10*time.Minute, 0, clock),
	}
}

// do issues an authenticated request with one retry on connection error, 5xx,
// or 401 (so at most two attempts). A 401 additionally invalidates the cached
// token before its retry. A 4xx other than 401 is not transient and is
// returned immediately without a retry.
func (c *Client) do(ctx context.Context, method, url string, body []byte) ([]byte, error) {
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		tok, err := c.ts.Token(ctx)
		if err != nil {
			lastErr = err
			continue
		}

		var rdr *bytes.Reader
		if body != nil {
			rdr = bytes.NewReader(body)
		} else {
			rdr = bytes.NewReader(nil)
		}
		req, err := http.NewRequestWithContext(ctx, method, url, rdr)
		if err != nil {
			return nil, fmt.Errorf("keycloak: build request: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+tok)
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}

		resp, err := c.hc.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("keycloak: %s request failed", method)
			continue
		}
		out, readErr := readAllClose(resp)
		switch {
		case resp.StatusCode == http.StatusUnauthorized:
			c.ts.Invalidate()
			lastErr = fmt.Errorf("keycloak: unauthorized")
			continue
		case resp.StatusCode >= 500:
			lastErr = fmt.Errorf("keycloak: returned %d", resp.StatusCode)
			continue
		case resp.StatusCode >= 400:
			// 4xx other than 401 is not transient — do not retry.
			return nil, fmt.Errorf("keycloak: returned %d", resp.StatusCode)
		}
		if readErr != nil {
			return nil, fmt.Errorf("keycloak: read response: %w", readErr)
		}
		return out, nil
	}
	return nil, lastErr
}

func readAllClose(resp *http.Response) ([]byte, error) {
	defer resp.Body.Close()
	var buf bytes.Buffer
	_, err := buf.ReadFrom(resp.Body)
	return buf.Bytes(), err
}

// ResourceServerUUID resolves the deploy-gateway client's internal UUID, which
// the evaluate endpoint needs in its path. Resolved once per process and
// cached for the Client's lifetime.
func (c *Client) ResourceServerUUID(ctx context.Context) (string, error) {
	c.uuidMu.Lock()
	defer c.uuidMu.Unlock()
	if c.uuid != "" {
		return c.uuid, nil
	}

	u := c.cfg.adminURL("/clients?clientId=" + url.QueryEscape(c.cfg.ClientID))
	raw, err := c.do(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", err
	}
	var clients []struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(raw, &clients); err != nil {
		return "", fmt.Errorf("keycloak: decode clients: %w", err)
	}
	if len(clients) == 0 || clients[0].ID == "" {
		return "", fmt.Errorf("keycloak: client %q not found", c.cfg.ClientID)
	}
	c.uuid = clients[0].ID
	return c.uuid, nil
}

// UserID resolves a repository name to its Keycloak user UUID. Returns
// ErrNoSubject when no such user exists — a clean denial, not an outage.
func (c *Client) UserID(ctx context.Context, username string) (string, error) {
	if id, ok := c.userIDs.Get(username); ok {
		return id, nil
	}

	u := c.cfg.adminURL("/users?exact=true&username=" + url.QueryEscape(username))
	raw, err := c.do(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", err
	}
	var users []struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(raw, &users); err != nil {
		return "", fmt.Errorf("keycloak: decode users: %w", err)
	}
	if len(users) == 0 || users[0].ID == "" {
		return "", fmt.Errorf("%w: %s", ErrNoSubject, username)
	}
	c.userIDs.Put(username, users[0].ID)
	return users[0].ID, nil
}

// UNVERIFIED against a live Keycloak: this request/response shape is assumed
// from the Admin API's documented behaviour, not confirmed by a spike. If
// Keycloak returns a different shape, Evaluate's status switch falls through
// to its error branch, so the gateway fails closed (503) rather than
// mis-authorizing. Correcting this is a single localized edit to these types
// and the switch below.
type evalScope struct {
	Name string `json:"name"`
}

// UNVERIFIED against a live Keycloak: this request/response shape is assumed
// from the Admin API's documented behaviour, not confirmed by a spike. If
// Keycloak returns a different shape, Evaluate's status switch falls through
// to its error branch, so the gateway fails closed (503) rather than
// mis-authorizing. Correcting this is a single localized edit to these types
// and the switch below.
type evalResource struct {
	Name   string      `json:"name"`
	Scopes []evalScope `json:"scopes"`
}

// UNVERIFIED against a live Keycloak: this request/response shape is assumed
// from the Admin API's documented behaviour, not confirmed by a spike. If
// Keycloak returns a different shape, Evaluate's status switch falls through
// to its error branch, so the gateway fails closed (503) rather than
// mis-authorizing. Correcting this is a single localized edit to these types
// and the switch below.
type evalRequest struct {
	Resources    []evalResource `json:"resources"`
	UserID       string         `json:"userId"`
	Entitlements bool           `json:"entitlements"`
	Context      struct {
		Attributes map[string]string `json:"attributes"`
	} `json:"context"`
}

// UNVERIFIED against a live Keycloak: this request/response shape is assumed
// from the Admin API's documented behaviour, not confirmed by a spike. If
// Keycloak returns a different shape, Evaluate's status switch falls through
// to its error branch, so the gateway fails closed (503) rather than
// mis-authorizing. Correcting this is a single localized edit to these types
// and the switch below.
type evalResponse struct {
	Status string `json:"status"`
}

// Evaluate asks Keycloak whether userID holds scope on resource. A returned
// error means the decision could not be reached — it is never a denial. Only
// an explicit "PERMIT" or "DENY" status becomes a (bool, nil) result; any
// other status is treated as an error so an unrecognised response fails
// closed instead of being silently interpreted as a decision.
func (c *Client) Evaluate(ctx context.Context, userID, resource, scope string) (bool, error) {
	uuid, err := c.ResourceServerUUID(ctx)
	if err != nil {
		return false, err
	}

	body := evalRequest{
		Resources: []evalResource{{
			Name:   resource,
			Scopes: []evalScope{{Name: scope}},
		}},
		UserID: userID,
	}
	body.Context.Attributes = map[string]string{}

	payload, err := json.Marshal(body)
	if err != nil {
		return false, fmt.Errorf("keycloak: encode evaluate request: %w", err)
	}

	u := c.cfg.adminURL("/clients/" + url.PathEscape(uuid) +
		"/authz/resource-server/policy/evaluate")
	raw, err := c.do(ctx, http.MethodPost, u, payload)
	if err != nil {
		return false, err
	}

	var out evalResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return false, fmt.Errorf("keycloak: decode evaluate response: %w", err)
	}
	switch out.Status {
	case "PERMIT":
		return true, nil
	case "DENY":
		return false, nil
	default:
		return false, fmt.Errorf("keycloak: unexpected evaluate status %q", out.Status)
	}
}
