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
	"strings"
	"sync"
	"time"
)

// ErrNoSubject: the repository has no corresponding Keycloak user. This is a
// clean denial, not an outage — the caller must not treat it as unavailability.
var ErrNoSubject = errors.New("keycloak: repository has no subject")

const (
	// userIDTTL caches the repository → user UUID lookup. This is an identity
	// mapping, not a policy decision: a repository's UUID does not change when
	// its grants do, so revoking a grant is not delayed by this cache. The one
	// case it does delay is deleting the user outright, which is why the README
	// tells operators to revoke by removing the grant instead.
	userIDTTL = 10 * time.Minute

	// refsTTL caches a resource's allowed_refs attributes. It is deliberately
	// pinned to decisionTTL: a ref constraint is a policy control just like a
	// grant, so tightening one must propagate on the same schedule as
	// tightening the other. Anything longer would mean the documented
	// revocation window silently does not apply to ref narrowing.
	refsTTL = decisionTTL
)

// Client talks to the Keycloak Admin API: resolving the resource server's
// UUID, resolving a repository name to a Keycloak user UUID, and asking
// policy/evaluate for a decision. It is safe for concurrent use.
type Client struct {
	cfg Config
	hc  *http.Client
	ts  *tokenSource
	log *slog.Logger

	uuidMu sync.Mutex
	uuid   string

	userIDs *cache[string]
	refs    *cache[[]string]
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
		userIDs: newCache[string](userIDTTL, 0, clock),
		refs:    newCache[[]string](refsTTL, 0, clock),
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
			// Unlike the token request, an admin call's error is safe to wrap:
			// the client secret only ever rides in the token endpoint's POST
			// body, never in an admin URL or header value that url.Error would
			// echo. Discarding the cause here would strip the detail from
			// exactly the outage being triaged.
			lastErr = fmt.Errorf("keycloak: %s request failed: %w", method, err)
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
		ID       string `json:"id"`
		ClientID string `json:"clientId"`
	}
	if err := json.Unmarshal(raw, &clients); err != nil {
		return "", fmt.Errorf("keycloak: decode clients: %w", err)
	}
	// Scan for the clientId that was actually asked for rather than trusting
	// element zero: ?clientId= is documented as an exact filter, but that has
	// not been verified against a live server, and a Keycloak that treats it
	// as a substring search would hand back a neighbouring client whose UUID
	// then becomes the resource server for every evaluate call.
	for _, cl := range clients {
		if cl.ClientID == c.cfg.ClientID && cl.ID != "" {
			c.uuid = cl.ID
			return c.uuid, nil
		}
	}
	return "", fmt.Errorf("keycloak: client %q not found in %d results",
		c.cfg.ClientID, len(clients))
}

// UserID resolves a repository name to its Keycloak user UUID. Returns
// ErrNoSubject when no returned user actually carries that username — a clean
// denial, not an outage. A near-miss (a user whose name merely contains the
// one requested) is a not-found, never a substitute subject.
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
		ID       string `json:"id"`
		Username string `json:"username"`
	}
	if err := json.Unmarshal(raw, &users); err != nil {
		return "", fmt.Errorf("keycloak: decode users: %w", err)
	}
	// Verify the username before trusting the UUID. ?exact=true is meant to
	// make this redundant, but it is unverified against a live server: a
	// Keycloak that infix-matches would answer a lookup for "tuncloud/backend"
	// with ["tuncloud/backend-api", "tuncloud/backend"], and indexing [0]
	// would evaluate this deploy against another repository's grants — then
	// cache that identity swap. Scanning rather than indexing also tolerates a
	// correct-but-unordered response.
	//
	// EqualFold, not ==: Keycloak normalises usernames to lower case, so a
	// repository slug carrying capitals ("tuncloud/Backend") is stored folded
	// and a case-sensitive compare would deny a correctly onboarded repo. Case
	// folding still rejects every near-miss this check exists to catch.
	for _, u := range users {
		if u.ID != "" && strings.EqualFold(u.Username, username) {
			c.userIDs.Put(username, u.ID)
			return u.ID, nil
		}
	}
	return "", fmt.Errorf("%w: %s", ErrNoSubject, username)
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

// UNVERIFIED against a live Keycloak: this response shape — a JSON array of
// resources each carrying a "name" and an "attributes" map of string to
// string-slice — is assumed from the Admin API's documented behaviour, not
// confirmed by a spike. A mismatch yields no attributes, which reads as
// "unrestricted"; see the note on AllowedRefs. Name is decoded so the
// element's identity can be checked rather than assumed.
type resourceRepresentation struct {
	Name       string              `json:"name"`
	Attributes map[string][]string `json:"attributes"`
}

// AllowedRefs returns the ref constraints for a resource and action, most
// specific first: "allowed_refs.<action>" wins over the bare "allowed_refs".
// Only a returned resource whose name equals the one asked for is read; any
// other result is treated as not-found and logged.
// A nil result means unrestricted, and that is the deliberate, migration-safe
// default: there was no ref check at all before Keycloak, so treating an
// absent attribute as a denial would break every repository at cutover.
//
// This is the asymmetric case in this package: where Evaluate fails closed
// on an unrecognised response shape (an error, never a silent decision), a
// mismatch here has nowhere to signal through — it just decodes to no
// attributes, which this method cannot distinguish from a resource that
// genuinely has no ref constraint. So an unverified wrong guess about the
// wire shape fails OPEN with respect to ref enforcement: refs would stop
// being restricted, silently, with no error to surface it. That risk is why
// the shape assumption is called out on resourceRepresentation above.
func (c *Client) AllowedRefs(ctx context.Context, resource, action string) ([]string, error) {
	key := resource + "\x00" + action
	if v, ok := c.refs.Get(key); ok {
		return v, nil
	}

	uuid, err := c.ResourceServerUUID(ctx)
	if err != nil {
		return nil, err
	}

	u := c.cfg.adminURL("/clients/" + url.PathEscape(uuid) +
		"/authz/resource-server/resource?exactName=true&name=" + url.QueryEscape(resource))
	raw, err := c.do(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}

	var resources []resourceRepresentation
	if err := json.Unmarshal(raw, &resources); err != nil {
		return nil, fmt.Errorf("keycloak: decode resources: %w", err)
	}

	// Match on name rather than indexing [0]. ?exactName=true is unverified
	// against a live server, and this is the worse of the two list endpoints
	// to get wrong: a Keycloak that infix-matches would return a neighbouring
	// resource, len(resources) > 0 would hold, the fail-open warning below
	// would never fire, and this deploy target would silently inherit some
	// other target's ref constraints — or none at all. Treating a name
	// mismatch as not-found routes it into that warning instead, so the
	// failure is greppable rather than invisible.
	var match *resourceRepresentation
	for i := range resources {
		if resources[i].Name == resource {
			match = &resources[i]
			break
		}
	}

	var out []string
	if match != nil {
		attrs := match.Attributes
		if v, ok := attrs["allowed_refs."+action]; ok {
			out = v
		} else if v, ok := attrs["allowed_refs"]; ok {
			out = v
		}
	} else {
		// AllowedRefs is only reached after Evaluate already returned PERMIT
		// for this same resource name, so finding no resource with that name
		// here means the name this call asked about disagrees with the name
		// Keycloak just matched a permission against — a wiring or
		// name-format bug, or a list endpoint that did not filter exactly.
		// This is the one path in the package that fails open, so this log
		// line is the only observability that failure mode gets; the
		// found-but-unconstrained case below stays silent on purpose.
		c.log.Warn("keycloak resource not found; ref constraints cannot be applied",
			"resource", resource, "action", action)
	}
	c.refs.Put(key, out)
	return out, nil
}
