# Keycloak-Backed Authorization Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the static YAML authorization policy with Keycloak as the per-request policy decision point, with git-ref restrictions evaluated in the gateway against constraints stored in Keycloak.

**Architecture:** An `authz.Authorizer` interface abstracts the decision. Three implementations sit behind it: the existing file policy (adapted), a Keycloak authorizer that calls the Admin `policy/evaluate` endpoint, and a shadow authorizer that runs one authoritatively while logging the other's disagreements. All Keycloak HTTP wire shapes are confined to `internal/keycloak`; ref matching is pure logic in `internal/authz`.

**Tech Stack:** Go 1.26.5, `net/http` (no new HTTP client dependency), `httptest.Server` for all Keycloak tests, `chi` router, existing `slog` logging.

**Spec:** `docs/superpowers/specs/2026-08-21-keycloak-authorization-design.md`

## Global Constraints

- Module path is `github.com/tuncloud/deploy-gateway`. Go 1.26.5.
- Scope strings MUST equal the existing Go constants verbatim: `operation.ActionRestart` = `"deployment.restart"`, `operation.ActionRollout` = `"deployment.rollout"`. No mapping table.
- **Three outcomes, never two.** PERMIT → proceed; DENY → `403 FORBIDDEN` + audit row; UNAVAILABLE → `503 AUTHZ_UNAVAILABLE`, no audit row. Collapsing UNAVAILABLE into DENY is the specific bug this design exists to prevent.
- Decision cache: PERMIT cached **30s**; served up to **5 minutes** past TTL only while Keycloak is unreachable. `DENY` is **never** cached.
- Per-call Keycloak timeout **3s**, **one** retry on connection error or 5xx. Worst-case authz budget ~7s.
- Ref constraint **absent** → unrestricted. **Present but malformed** → deny.
- `KEYCLOAK_CLIENT_SECRET` is never logged and never included in an error string, matching the existing Telegram bot token discipline.
- Never fail fast at boot on Keycloak. Resolve lazily; gate `/readyz` instead.
- Out of scope for this plan: deleting the file backend, `policy.example.yaml`, or the ConfigMap. That is a separate follow-up change.
- Every task ends green: `go test ./...` passes before the commit.

---

### Task 1: Spike — resolve the four open Keycloak questions

**This task writes no production code and gates every Keycloak task that follows.** The spec records four unresolved questions. If question 2 resolves badly — if `policy/evaluate` requires `manage-authorization` — the gateway would hold a token able to rewrite the realm's authz config, which is a materially different security story and grounds to stop and revisit the rejected JWT-bearer approach with the user.

**Files:**
- Create: `docs/superpowers/spikes/2026-08-21-keycloak-evaluate-findings.md`

**Interfaces:**
- Consumes: nothing.
- Produces: confirmed JSON request/response shapes for Tasks 5–7, and a go/no-go decision.

- [ ] **Step 1: Stand up a scratch Keycloak 26.x**

```bash
podman run -d --name kc-spike -p 8088:8080 \
  -e KC_BOOTSTRAP_ADMIN_USERNAME=admin \
  -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin \
  quay.io/keycloak/keycloak:26.4 start-dev
```

Wait for readiness: `curl -sf http://localhost:8088/realms/master` returns JSON.

- [ ] **Step 2: Build the minimal object graph by hand in the UI**

At `http://localhost:8088`, in realm `master` (a scratch realm is fine — this is throwaway):

1. Create client `deploy-gateway`: Client authentication **ON**, Authorization **ON**, Service accounts roles **ON**.
2. In its **Authorization** tab → Scopes: create `deployment.restart` and `deployment.rollout`.
3. Authorization → Resources: create `backend/backend-api`, type `urn:deploy-gateway:deployment`, both scopes attached, and add attribute key `allowed_refs.deployment.rollout` value `refs/heads/main`.
4. Users: create user `tuncloud/backend`, no credentials.
5. Authorization → Policies: create a **User** policy named `repo-tuncloud-backend` selecting that user.
6. Authorization → Permissions: create a **scope-based** permission named `backend-api-rollout` over resource `backend/backend-api`, scope `deployment.rollout`, policy `repo-tuncloud-backend`.

- [ ] **Step 3: Get a service-account token and record the exact shape**

```bash
SECRET=<from client Credentials tab>
TOKEN=$(curl -s -X POST \
  http://localhost:8088/realms/master/protocol/openid-connect/token \
  -d grant_type=client_credentials \
  -d client_id=deploy-gateway \
  -d client_secret="$SECRET" | jq -r .access_token)
echo "${TOKEN:0:20}..."
```

- [ ] **Step 4: Answer question 1 — does a credential-less user work as an evaluation subject?**

```bash
CUUID=$(curl -s -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8088/admin/realms/master/clients?clientId=deploy-gateway" | jq -r '.[0].id')
UUID=$(curl -s -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8088/admin/realms/master/users?username=tuncloud%2Fbackend&exact=true" | jq -r '.[0].id')

curl -s -X POST -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  "http://localhost:8088/admin/realms/master/clients/$CUUID/authz/resource-server/policy/evaluate" \
  -d "{\"resources\":[{\"name\":\"backend/backend-api\",\"scopes\":[{\"name\":\"deployment.rollout\"}]}],\"userId\":\"$UUID\",\"entitlements\":false,\"context\":{\"attributes\":{}}}" | jq '{status, results: [.results[] | {status}]}'
```

Record: the exact top-level field the decision lives in, and whether `PERMIT` comes back. Then re-run with scope `deployment.restart` (no permission exists for it) and confirm `DENY`.

- [ ] **Step 5: Answer question 2 — the minimum service-account role set**

In the `deploy-gateway` client → Service accounts roles, start from **zero** assigned roles and re-run Step 4's evaluate call. It should fail. Then assign, one at a time, re-testing after each: `realm-management` → `view-clients`, then `view-users`, then `view-authorization`. Record the smallest set that makes both the user lookup and the evaluate call succeed.

**Decision gate:** if `manage-authorization` turns out to be required, **stop and report to the user before continuing** — write it in the findings file as a blocking finding. Do not proceed to Task 5.

- [ ] **Step 6: Answer question 3 — do resource attributes come back with the evaluation?**

Inspect the full evaluate response for the resource representation and whether `attributes` is populated:

```bash
curl -s -X POST -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  "http://localhost:8088/admin/realms/master/clients/$CUUID/authz/resource-server/policy/evaluate" \
  -d "{\"resources\":[{\"name\":\"backend/backend-api\",\"scopes\":[{\"name\":\"deployment.rollout\"}]}],\"userId\":\"$UUID\",\"entitlements\":false,\"context\":{\"attributes\":{}}}" \
  | jq '.results[0].resource'
```

Then confirm the separate resource read works and carries attributes:

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8088/admin/realms/master/clients/$CUUID/authz/resource-server/resource?name=backend%2Fbackend-api&exactName=true" \
  | jq '.[0] | {name, attributes}'
```

If attributes arrive with the evaluate response, note it — Task 7 can then be simplified to skip a call. If not, Task 7 stands as written.

- [ ] **Step 7: Answer question 4 — is a client subject viable instead of a per-repo user?**

Create a second client `repo-test` (no service account, no authz), add a **Client** policy for it, attach that policy to the permission, and re-run the evaluate call substituting `"clientId":"<repo-test uuid>"` for `"userId"`. Record whether it evaluates.

- [ ] **Step 8: Write the findings file**

Create `docs/superpowers/spikes/2026-08-21-keycloak-evaluate-findings.md` with one section per question, each containing: the question, the exact curl used, the verbatim response excerpt, and the conclusion. End with a **Go / No-go** line and a **Shapes confirmed for implementation** section giving the final request and response JSON that Tasks 5–7 must encode.

- [ ] **Step 9: Tear down and commit**

```bash
podman rm -f kc-spike
git add docs/superpowers/spikes/2026-08-21-keycloak-evaluate-findings.md
git commit -m "docs: keycloak policy-evaluate spike findings"
```

---

### Task 2: The `Authorizer` interface and file adapter

**Files:**
- Create: `internal/authz/authz.go`
- Create: `internal/authz/file.go`
- Test: `internal/authz/file_test.go`

**Interfaces:**
- Consumes: existing `authz.LoadPolicy(path string) (*Policy, error)` and `(*Policy).Authorize(repo, action, namespace, deployment string) bool` from `internal/authz/policy.go` — both left untouched so `policy_test.go` stays green.
- Produces:
  - `authz.Request{Repository, Action, Namespace, Deployment, Ref string}`
  - `authz.Decision{Allowed bool; Reason string}`
  - `authz.Authorizer` interface with `Authorize(ctx context.Context, req Request) (Decision, error)`
  - `authz.NewFileAuthorizer(path string) (*FileAuthorizer, error)`

- [ ] **Step 1: Write the failing test**

Create `internal/authz/file_test.go`:

```go
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
```

`testPolicy` already exists in `internal/authz/policy_test.go` in the same `authz_test` package — reuse it, do not redeclare it.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/authz/ -run TestFileAuthorizer -v`
Expected: FAIL — `undefined: authz.FileAuthorizer`, `undefined: authz.NewFileAuthorizer`, `undefined: authz.Request`.

- [ ] **Step 3: Write the interface**

Create `internal/authz/authz.go`:

```go
package authz

import "context"

// Request is one authorization question: may this repository perform this
// action on this deployment, from this git ref?
type Request struct {
	Repository string
	Action     string
	Namespace  string
	Deployment string
	Ref        string
}

// Decision is the answer. Reason is carried into the audit row on denial and
// distinguishes a missing grant from a rejected ref.
type Decision struct {
	Allowed bool
	Reason  string
}

// Authorizer answers Requests. An error means the decision could not be
// reached — it is NOT a denial, and callers must surface it as unavailability
// rather than as forbidden.
type Authorizer interface {
	Authorize(ctx context.Context, req Request) (Decision, error)
}
```

- [ ] **Step 4: Write the file adapter**

Create `internal/authz/file.go`:

```go
package authz

import "context"

// FileAuthorizer adapts the static YAML policy to the Authorizer interface.
// It never returns an error: the policy is in memory, so a decision is always
// reachable. Ref constraints are not supported by the file backend.
type FileAuthorizer struct{ policy *Policy }

func NewFileAuthorizer(path string) (*FileAuthorizer, error) {
	p, err := LoadPolicy(path)
	if err != nil {
		return nil, err
	}
	return &FileAuthorizer{policy: p}, nil
}

func (f *FileAuthorizer) Authorize(_ context.Context, req Request) (Decision, error) {
	if f.policy.Authorize(req.Repository, req.Action, req.Namespace, req.Deployment) {
		return Decision{Allowed: true}, nil
	}
	return Decision{
		Reason: "policy does not allow " + req.Action + " on " +
			req.Namespace + "/" + req.Deployment,
	}, nil
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./internal/authz/ -v`
Expected: PASS — the new `TestFileAuthorizer*` tests plus all pre-existing `TestAuthorize*` tests.

- [ ] **Step 6: Commit**

```bash
git add internal/authz/authz.go internal/authz/file.go internal/authz/file_test.go
git commit -m "authz: Authorizer interface with file-backed adapter"
```

---

### Task 3: Ref matching

**Files:**
- Create: `internal/authz/ref.go`
- Test: `internal/authz/ref_test.go`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `authz.MatchRef(allowed []string, ref string) (bool, error)`
  - `authz.ErrMalformedRefConstraint` — sentinel error

- [ ] **Step 1: Write the failing test**

Create `internal/authz/ref_test.go`:

```go
package authz_test

import (
	"errors"
	"testing"

	"github.com/tuncloud/deploy-gateway/internal/authz"
)

func TestMatchRef(t *testing.T) {
	tests := []struct {
		name    string
		allowed []string
		ref     string
		want    bool
	}{
		{"nil allowed is unrestricted", nil, "refs/heads/anything", true},
		{"empty allowed is unrestricted", []string{}, "refs/heads/anything", true},
		{"exact match", []string{"refs/heads/main"}, "refs/heads/main", true},
		{"exact mismatch", []string{"refs/heads/main"}, "refs/heads/dev", false},
		{"star matches anything", []string{"*"}, "refs/heads/dev", true},
		{"prefix glob matches", []string{"refs/heads/release/*"}, "refs/heads/release/1.2", true},
		{"prefix glob rejects sibling", []string{"refs/heads/release/*"}, "refs/heads/main", false},
		{"prefix glob matches tags", []string{"refs/tags/v*"}, "refs/tags/v2.1.0", true},
		{"any of several", []string{"refs/heads/main", "refs/tags/v*"}, "refs/tags/v1", true},
		{"none of several", []string{"refs/heads/main", "refs/tags/v*"}, "refs/heads/dev", false},
		{"empty ref with constraints denies", []string{"refs/heads/main"}, "", false},
		{"glob does not match its own prefix without separator", []string{"refs/heads/release/*"}, "refs/heads/release", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := authz.MatchRef(tt.allowed, tt.ref)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("MatchRef(%q, %q) = %v, want %v", tt.allowed, tt.ref, got, tt.want)
			}
		})
	}
}

func TestMatchRefMalformedDenies(t *testing.T) {
	malformed := [][]string{
		{""},                        // empty pattern
		{"refs/*/main"},             // star not at the end
		{"refs/heads/**"},           // double star
		{"refs/heads/main", "a*b"},  // one bad pattern poisons the set
	}
	for _, allowed := range malformed {
		got, err := authz.MatchRef(allowed, "refs/heads/main")
		if !errors.Is(err, authz.ErrMalformedRefConstraint) {
			t.Fatalf("MatchRef(%q) error = %v, want ErrMalformedRefConstraint", allowed, err)
		}
		if got {
			t.Fatalf("MatchRef(%q) = true, malformed constraints must deny", allowed)
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/authz/ -run TestMatchRef -v`
Expected: FAIL — `undefined: authz.MatchRef`.

- [ ] **Step 3: Write the implementation**

Create `internal/authz/ref.go`:

```go
package authz

import (
	"errors"
	"strings"
)

// ErrMalformedRefConstraint: a constraint was present but unparseable. A typo
// in a ref constraint fails closed rather than silently permitting everything.
var ErrMalformedRefConstraint = errors.New("malformed ref constraint")

// MatchRef reports whether ref satisfies any of the allowed patterns.
//
// An empty allowed list is unrestricted — this is the migration-safe default,
// since there was no ref check at all before Keycloak.
//
// Patterns are deliberately dumb, with no regex:
//   - "*"                    matches any ref
//   - "refs/heads/main"      exact match
//   - "refs/heads/release/*" prefix match on everything before the trailing *
//
// A "*" anywhere but the final character, or an empty pattern, is malformed
// and denies.
func MatchRef(allowed []string, ref string) (bool, error) {
	if len(allowed) == 0 {
		return true, nil
	}
	// Validate every pattern before matching any, so a malformed entry cannot
	// be masked by an earlier successful match.
	for _, p := range allowed {
		if p == "*" {
			continue
		}
		if p == "" {
			return false, ErrMalformedRefConstraint
		}
		if i := strings.IndexByte(p, '*'); i >= 0 && i != len(p)-1 {
			return false, ErrMalformedRefConstraint
		}
	}
	if ref == "" {
		return false, nil
	}
	for _, p := range allowed {
		if p == "*" {
			return true, nil
		}
		if strings.HasSuffix(p, "*") {
			if strings.HasPrefix(ref, strings.TrimSuffix(p, "*")) {
				return true, nil
			}
			continue
		}
		if p == ref {
			return true, nil
		}
	}
	return false, nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/authz/ -v`
Expected: PASS, all subtests including `TestMatchRefMalformedDenies`.

- [ ] **Step 5: Commit**

```bash
git add internal/authz/ref.go internal/authz/ref_test.go
git commit -m "authz: ref matching with exact, star and prefix-glob patterns"
```

---

### Task 4: Clock seam and TTL cache with stale-while-unavailable

**Files:**
- Create: `internal/keycloak/clock.go`
- Create: `internal/keycloak/cache.go`
- Test: `internal/keycloak/cache_test.go`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `keycloak.Clock` interface with `Now() time.Time`
  - `keycloak.RealClock` (exported so `main.go` can pass it)
  - unexported generic `cache[V any]`, `newCache[V any](ttl, staleFor time.Duration, clock Clock) *cache[V]`
  - methods `Get(key string) (V, bool)`, `GetStale(key string) (V, bool)`, `Put(key string, v V)`

- [ ] **Step 1: Write the failing test**

Create `internal/keycloak/cache_test.go`:

```go
package keycloak

import (
	"sync"
	"testing"
	"time"
)

// testClock is a manually advanced Clock. TTL behaviour must be testable
// without time.Sleep, which would make the suite slow and flaky.
type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func newTestClock() *testClock {
	return &testClock{now: time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)}
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *testClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func TestCacheGetWithinTTL(t *testing.T) {
	clk := newTestClock()
	c := newCache[bool](30*time.Second, 5*time.Minute, clk)
	c.Put("k", true)

	clk.advance(29 * time.Second)
	if v, ok := c.Get("k"); !ok || !v {
		t.Fatal("entry must be fresh at 29s")
	}
}

func TestCacheGetExpiredAfterTTL(t *testing.T) {
	clk := newTestClock()
	c := newCache[bool](30*time.Second, 5*time.Minute, clk)
	c.Put("k", true)

	clk.advance(31 * time.Second)
	if _, ok := c.Get("k"); ok {
		t.Fatal("entry must be stale at 31s")
	}
}

// GetStale is what the authorizer falls back to when Keycloak is unreachable.
func TestCacheGetStaleWithinStaleWindow(t *testing.T) {
	clk := newTestClock()
	c := newCache[bool](30*time.Second, 5*time.Minute, clk)
	c.Put("k", true)

	clk.advance(4 * time.Minute)
	if _, ok := c.Get("k"); ok {
		t.Fatal("Get must not serve a stale entry")
	}
	if v, ok := c.GetStale("k"); !ok || !v {
		t.Fatal("GetStale must serve within the stale window")
	}
}

func TestCacheGetStaleBeyondStaleWindow(t *testing.T) {
	clk := newTestClock()
	c := newCache[bool](30*time.Second, 5*time.Minute, clk)
	c.Put("k", true)

	// TTL 30s + stale 5m = 5m30s of total usable life.
	clk.advance(5*time.Minute + 31*time.Second)
	if _, ok := c.GetStale("k"); ok {
		t.Fatal("GetStale must refuse beyond ttl+staleFor")
	}
}

func TestCacheMissingKey(t *testing.T) {
	c := newCache[bool](30*time.Second, 5*time.Minute, newTestClock())
	if _, ok := c.Get("absent"); ok {
		t.Fatal("Get on absent key must miss")
	}
	if _, ok := c.GetStale("absent"); ok {
		t.Fatal("GetStale on absent key must miss")
	}
}

func TestCachePutOverwritesAndRefreshes(t *testing.T) {
	clk := newTestClock()
	c := newCache[string](30*time.Second, 5*time.Minute, clk)
	c.Put("k", "first")

	clk.advance(20 * time.Second)
	c.Put("k", "second")

	clk.advance(20 * time.Second) // 40s since first Put, 20s since second
	v, ok := c.Get("k")
	if !ok {
		t.Fatal("re-Put must reset the TTL")
	}
	if v != "second" {
		t.Fatalf("Get = %q, want %q", v, "second")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/keycloak/ -v`
Expected: FAIL — no such package / `undefined: newCache`.

- [ ] **Step 3: Write the clock**

Create `internal/keycloak/clock.go`:

```go
package keycloak

import "time"

// Clock exists so cache TTL and the stale-while-unavailable window are
// testable without sleeping. Scoped to this package only — this is not a
// codebase-wide time abstraction.
type Clock interface {
	Now() time.Time
}

type RealClock struct{}

func (RealClock) Now() time.Time { return time.Now() }
```

- [ ] **Step 4: Write the cache**

Create `internal/keycloak/cache.go`:

```go
package keycloak

import (
	"sync"
	"time"
)

type entry[V any] struct {
	value    V
	storedAt time.Time
}

// cache is a TTL cache with a bounded grace period. Get serves only fresh
// entries; GetStale additionally serves entries within staleFor past their
// TTL, and is used exclusively when Keycloak is unreachable.
type cache[V any] struct {
	mu       sync.RWMutex
	entries  map[string]entry[V]
	ttl      time.Duration
	staleFor time.Duration
	clock    Clock
}

func newCache[V any](ttl, staleFor time.Duration, clock Clock) *cache[V] {
	return &cache[V]{
		entries:  make(map[string]entry[V]),
		ttl:      ttl,
		staleFor: staleFor,
		clock:    clock,
	}
}

func (c *cache[V]) get(key string, maxAge time.Duration) (V, bool) {
	c.mu.RLock()
	e, ok := c.entries[key]
	c.mu.RUnlock()
	var zero V
	if !ok {
		return zero, false
	}
	if c.clock.Now().Sub(e.storedAt) > maxAge {
		return zero, false
	}
	return e.value, true
}

func (c *cache[V]) Get(key string) (V, bool) {
	return c.get(key, c.ttl)
}

func (c *cache[V]) GetStale(key string) (V, bool) {
	return c.get(key, c.ttl+c.staleFor)
}

func (c *cache[V]) Put(key string, v V) {
	c.mu.Lock()
	c.entries[key] = entry[V]{value: v, storedAt: c.clock.Now()}
	c.mu.Unlock()
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./internal/keycloak/ -v`
Expected: PASS, all six cache tests.

- [ ] **Step 6: Commit**

```bash
git add internal/keycloak/clock.go internal/keycloak/cache.go internal/keycloak/cache_test.go
git commit -m "keycloak: injectable clock and TTL cache with bounded stale window"
```

---

### Task 5: Service-account token source

**Files:**
- Create: `internal/keycloak/token.go`
- Test: `internal/keycloak/token_test.go`

**Interfaces:**
- Consumes: `Clock` from Task 4.
- Produces:
  - `keycloak.Config{BaseURL, Realm, ClientID, ClientSecret string; Timeout time.Duration}`
  - unexported `tokenSource` with `newTokenSource(cfg Config, hc *http.Client, clock Clock) *tokenSource`
  - `(*tokenSource).Token(ctx context.Context) (string, error)`
  - `(*tokenSource).Invalidate()`

**Before starting:** re-read the "Shapes confirmed for implementation" section of `docs/superpowers/spikes/2026-08-21-keycloak-evaluate-findings.md`. If the spike recorded a different token response shape than assumed here, follow the spike.

- [ ] **Step 1: Write the failing test**

Create `internal/keycloak/token_test.go`:

```go
package keycloak

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func testConfig(baseURL string) Config {
	return Config{
		BaseURL:      baseURL,
		Realm:        "master",
		ClientID:     "deploy-gateway",
		ClientSecret: "s3cr3t",
		Timeout:      3 * time.Second,
	}
}

func TestTokenSourceFetchesAndCaches(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		if r.URL.Path != "/realms/master/protocol/openid-connect/token" {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		if got := r.Form.Get("grant_type"); got != "client_credentials" {
			t.Errorf("grant_type = %q", got)
		}
		if got := r.Form.Get("client_secret"); got != "s3cr3t" {
			t.Errorf("client_secret = %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"access_token":"tok-1","expires_in":300}`))
	}))
	defer srv.Close()

	clk := newTestClock()
	ts := newTokenSource(testConfig(srv.URL), srv.Client(), clk)

	for i := 0; i < 3; i++ {
		got, err := ts.Token(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if got != "tok-1" {
			t.Fatalf("Token() = %q, want tok-1", got)
		}
	}
	if n := atomic.LoadInt32(&calls); n != 1 {
		t.Fatalf("token endpoint called %d times, want 1 (must cache)", n)
	}
}

func TestTokenSourceRefreshesBeforeExpiry(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&calls, 1)
		w.Header().Set("Content-Type", "application/json")
		if n == 1 {
			w.Write([]byte(`{"access_token":"tok-1","expires_in":300}`))
			return
		}
		w.Write([]byte(`{"access_token":"tok-2","expires_in":300}`))
	}))
	defer srv.Close()

	clk := newTestClock()
	ts := newTokenSource(testConfig(srv.URL), srv.Client(), clk)
	if _, err := ts.Token(context.Background()); err != nil {
		t.Fatal(err)
	}

	// 300s lifetime minus the 30s safety skew => refresh at 270s.
	clk.advance(271 * time.Second)
	got, err := ts.Token(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got != "tok-2" {
		t.Fatalf("Token() = %q, want tok-2 after expiry", got)
	}
}

func TestTokenSourceInvalidateForcesRefetch(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&calls, 1)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"access_token":"tok-` + string(rune('0'+n)) + `","expires_in":300}`))
	}))
	defer srv.Close()

	ts := newTokenSource(testConfig(srv.URL), srv.Client(), newTestClock())
	first, _ := ts.Token(context.Background())
	ts.Invalidate()
	second, _ := ts.Token(context.Background())
	if first == second {
		t.Fatal("Invalidate must force a new token")
	}
}

// The client secret sits in the request path; it must never reach an error
// string, matching the Telegram bot token discipline.
func TestTokenSourceErrorNeverLeaksSecret(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unauthorized_client", http.StatusUnauthorized)
	}))
	defer srv.Close()

	ts := newTokenSource(testConfig(srv.URL), srv.Client(), newTestClock())
	_, err := ts.Token(context.Background())
	if err == nil {
		t.Fatal("expected an error on 401")
	}
	if strings.Contains(err.Error(), "s3cr3t") {
		t.Fatalf("error leaked the client secret: %v", err)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/keycloak/ -run TestTokenSource -v`
Expected: FAIL — `undefined: newTokenSource`, `undefined: Config`.

- [ ] **Step 3: Write the implementation**

Create `internal/keycloak/token.go`:

```go
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/keycloak/ -v`
Expected: PASS, all token and cache tests.

- [ ] **Step 5: Commit**

```bash
git add internal/keycloak/token.go internal/keycloak/token_test.go
git commit -m "keycloak: service-account token source with skewed refresh"
```

---

### Task 6: Admin client — lookups and policy evaluation

**Files:**
- Create: `internal/keycloak/client.go`
- Test: `internal/keycloak/client_test.go`

**Interfaces:**
- Consumes: `Config`, `tokenSource`, `Clock` from Tasks 4–5.
- Produces:
  - `keycloak.Client` with `keycloak.NewClient(cfg Config, log *slog.Logger, clock Clock) *Client`
  - `(*Client).ResourceServerUUID(ctx context.Context) (string, error)`
  - `(*Client).UserID(ctx context.Context, username string) (string, error)`
  - `(*Client).Evaluate(ctx context.Context, userID, resource, scope string) (bool, error)`
  - `keycloak.ErrNoSubject` — sentinel meaning the repository has no Keycloak user, which is a clean DENY rather than an outage

**Before starting:** the request and response JSON below must match the "Shapes confirmed for implementation" section of the Task 1 findings file. If the spike recorded different field names or a different location for the decision, follow the spike and adjust both the test and the implementation.

- [ ] **Step 1: Write the failing test**

Create `internal/keycloak/client_test.go`:

```go
package keycloak

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// kcStub is a minimal fake Keycloak admin API. Each field lets one test
// override one behaviour.
type kcStub struct {
	evaluateStatus  string // "PERMIT" or "DENY"
	evaluateHTTP    int    // non-zero overrides the evaluate response code
	userFound       bool
	evaluateCalls   int32
	tokenCalls      int32
	lastEvaluateReq map[string]any
}

func (s *kcStub) server(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()

	mux.HandleFunc("/realms/master/protocol/openid-connect/token",
		func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt32(&s.tokenCalls, 1)
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"access_token":"tok","expires_in":300}`))
		})

	mux.HandleFunc("/admin/realms/master/clients",
		func(w http.ResponseWriter, r *http.Request) {
			if got := r.URL.Query().Get("clientId"); got != "deploy-gateway" {
				t.Errorf("clientId query = %q", got)
			}
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`[{"id":"client-uuid-1","clientId":"deploy-gateway"}]`))
		})

	mux.HandleFunc("/admin/realms/master/users",
		func(w http.ResponseWriter, r *http.Request) {
			if got := r.URL.Query().Get("exact"); got != "true" {
				t.Errorf("exact query = %q, want true", got)
			}
			w.Header().Set("Content-Type", "application/json")
			if !s.userFound {
				w.Write([]byte(`[]`))
				return
			}
			w.Write([]byte(`[{"id":"user-uuid-1","username":"tuncloud/backend"}]`))
		})

	mux.HandleFunc("/admin/realms/master/clients/client-uuid-1/authz/resource-server/policy/evaluate",
		func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt32(&s.evaluateCalls, 1)
			if s.evaluateHTTP != 0 {
				http.Error(w, "boom", s.evaluateHTTP)
				return
			}
			var body map[string]any
			json.NewDecoder(r.Body).Decode(&body)
			s.lastEvaluateReq = body
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"status":"` + s.evaluateStatus +
				`","results":[{"status":"` + s.evaluateStatus + `"}]}`))
		})

	return httptest.NewServer(mux)
}

func newTestClient(t *testing.T, s *kcStub) (*Client, *httptest.Server) {
	t.Helper()
	srv := s.server(t)
	c := NewClient(testConfig(srv.URL), slog.Default(), newTestClock())
	c.hc = srv.Client()
	return c, srv
}

func TestClientEvaluatePermit(t *testing.T) {
	s := &kcStub{evaluateStatus: "PERMIT", userFound: true}
	c, srv := newTestClient(t, s)
	defer srv.Close()

	allowed, err := c.Evaluate(context.Background(), "user-uuid-1",
		"backend/backend-api", "deployment.rollout")
	if err != nil {
		t.Fatal(err)
	}
	if !allowed {
		t.Fatal("PERMIT must map to allowed")
	}
}

func TestClientEvaluateDeny(t *testing.T) {
	s := &kcStub{evaluateStatus: "DENY", userFound: true}
	c, srv := newTestClient(t, s)
	defer srv.Close()

	allowed, err := c.Evaluate(context.Background(), "user-uuid-1",
		"backend/backend-api", "deployment.rollout")
	if err != nil {
		t.Fatalf("DENY is a decision, not an error: %v", err)
	}
	if allowed {
		t.Fatal("DENY must map to not allowed")
	}
}

func TestClientEvaluateSendsResourceAndScope(t *testing.T) {
	s := &kcStub{evaluateStatus: "PERMIT", userFound: true}
	c, srv := newTestClient(t, s)
	defer srv.Close()

	c.Evaluate(context.Background(), "user-uuid-1", "backend/backend-api", "deployment.rollout")

	raw, _ := json.Marshal(s.lastEvaluateReq)
	for _, want := range []string{"backend/backend-api", "deployment.rollout", "user-uuid-1"} {
		if !strings.Contains(string(raw), want) {
			t.Fatalf("evaluate request %s missing %q", raw, want)
		}
	}
}

func TestClientEvaluateServerErrorIsAnError(t *testing.T) {
	s := &kcStub{evaluateStatus: "PERMIT", userFound: true, evaluateHTTP: 500}
	c, srv := newTestClient(t, s)
	defer srv.Close()

	_, err := c.Evaluate(context.Background(), "user-uuid-1",
		"backend/backend-api", "deployment.rollout")
	if err == nil {
		t.Fatal("a 500 must be an error, never a silent deny")
	}
}

func TestClientEvaluateRetriesOnce(t *testing.T) {
	s := &kcStub{evaluateStatus: "PERMIT", userFound: true, evaluateHTTP: 503}
	c, srv := newTestClient(t, s)
	defer srv.Close()

	c.Evaluate(context.Background(), "user-uuid-1", "backend/backend-api", "deployment.rollout")
	if n := atomic.LoadInt32(&s.evaluateCalls); n != 2 {
		t.Fatalf("evaluate called %d times, want 2 (one retry on 5xx)", n)
	}
}

func TestClientUserIDFound(t *testing.T) {
	s := &kcStub{evaluateStatus: "PERMIT", userFound: true}
	c, srv := newTestClient(t, s)
	defer srv.Close()

	id, err := c.UserID(context.Background(), "tuncloud/backend")
	if err != nil {
		t.Fatal(err)
	}
	if id != "user-uuid-1" {
		t.Fatalf("UserID = %q, want user-uuid-1", id)
	}
}

// A repository with no Keycloak user is a clean denial, not an outage.
func TestClientUserIDAbsentIsErrNoSubject(t *testing.T) {
	s := &kcStub{evaluateStatus: "PERMIT", userFound: false}
	c, srv := newTestClient(t, s)
	defer srv.Close()

	_, err := c.UserID(context.Background(), "tuncloud/unknown")
	if !errors.Is(err, ErrNoSubject) {
		t.Fatalf("err = %v, want ErrNoSubject", err)
	}
}

func TestClientResourceServerUUIDCached(t *testing.T) {
	s := &kcStub{evaluateStatus: "PERMIT", userFound: true}
	c, srv := newTestClient(t, s)
	defer srv.Close()

	for i := 0; i < 3; i++ {
		got, err := c.ResourceServerUUID(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if got != "client-uuid-1" {
			t.Fatalf("ResourceServerUUID = %q", got)
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/keycloak/ -run TestClient -v`
Expected: FAIL — `undefined: NewClient`, `undefined: ErrNoSubject`.

- [ ] **Step 3: Write the implementation**

Create `internal/keycloak/client.go`:

```go
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

type Client struct {
	cfg   Config
	hc    *http.Client
	ts    *tokenSource
	log   *slog.Logger
	clock Clock

	uuidMu   sync.Mutex
	uuid     string
	userIDs  *cache[string]
}

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
// or 401. A 401 additionally invalidates the cached token before retrying.
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
// the evaluate endpoint needs in its path. Resolved once per process.
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
	var clients []struct{ ID string `json:"id"` }
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
// ErrNoSubject when no such user exists.
func (c *Client) UserID(ctx context.Context, username string) (string, error) {
	if id, ok := c.userIDs.Get(username); ok {
		return id, nil
	}

	u := c.cfg.adminURL("/users?exact=true&username=" + url.QueryEscape(username))
	raw, err := c.do(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", err
	}
	var users []struct{ ID string `json:"id"` }
	if err := json.Unmarshal(raw, &users); err != nil {
		return "", fmt.Errorf("keycloak: decode users: %w", err)
	}
	if len(users) == 0 || users[0].ID == "" {
		return "", fmt.Errorf("%w: %s", ErrNoSubject, username)
	}
	c.userIDs.Put(username, users[0].ID)
	return users[0].ID, nil
}

type evalScope struct {
	Name string `json:"name"`
}

type evalResource struct {
	Name   string      `json:"name"`
	Scopes []evalScope `json:"scopes"`
}

type evalRequest struct {
	Resources    []evalResource `json:"resources"`
	UserID       string         `json:"userId"`
	Entitlements bool           `json:"entitlements"`
	Context      struct {
		Attributes map[string]string `json:"attributes"`
	} `json:"context"`
}

type evalResponse struct {
	Status string `json:"status"`
}

// Evaluate asks Keycloak whether userID holds scope on resource. A returned
// error means the decision could not be reached; it is never a denial.
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/keycloak/ -v`
Expected: PASS, all client, token and cache tests.

- [ ] **Step 5: Commit**

```bash
git add internal/keycloak/client.go internal/keycloak/client_test.go
git commit -m "keycloak: admin client for lookups and policy evaluation"
```

---

### Task 7: Reading `allowed_refs` resource attributes

**Files:**
- Modify: `internal/keycloak/client.go` (add one method plus its types)
- Test: `internal/keycloak/resource_test.go`

**Interfaces:**
- Consumes: `(*Client).do`, `(*Client).ResourceServerUUID` from Task 6.
- Produces: `(*Client).AllowedRefs(ctx context.Context, resource, action string) ([]string, error)`

**If the Task 1 spike found that resource attributes come back on the evaluate response**, skip the extra HTTP call: read them from the evaluate response in Task 6's `Evaluate` and have `AllowedRefs` become a pure accessor. The tests below still apply to the resulting behaviour.

Attribute key precedence: `allowed_refs.<action>` wins; bare `allowed_refs` is the fallback; neither present means unrestricted (nil).

- [ ] **Step 1: Write the failing test**

Create `internal/keycloak/resource_test.go`:

```go
package keycloak

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func resourceServer(t *testing.T, resourceJSON string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/realms/master/protocol/openid-connect/token",
		func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"access_token":"tok","expires_in":300}`))
		})
	mux.HandleFunc("/admin/realms/master/clients",
		func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`[{"id":"client-uuid-1"}]`))
		})
	mux.HandleFunc("/admin/realms/master/clients/client-uuid-1/authz/resource-server/resource",
		func(w http.ResponseWriter, r *http.Request) {
			if got := r.URL.Query().Get("exactName"); got != "true" {
				t.Errorf("exactName = %q, want true", got)
			}
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(resourceJSON))
		})
	return httptest.NewServer(mux)
}

func clientFor(t *testing.T, srv *httptest.Server) *Client {
	t.Helper()
	c := NewClient(testConfig(srv.URL), slog.Default(), newTestClock())
	c.hc = srv.Client()
	return c
}

func TestAllowedRefsActionSpecificWins(t *testing.T) {
	srv := resourceServer(t, `[{"_id":"r1","name":"backend/backend-api","attributes":{
		"allowed_refs":["*"],
		"allowed_refs.deployment.rollout":["refs/heads/main"]
	}}]`)
	defer srv.Close()

	got, err := clientFor(t, srv).AllowedRefs(context.Background(),
		"backend/backend-api", "deployment.rollout")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != "refs/heads/main" {
		t.Fatalf("AllowedRefs = %v, want [refs/heads/main]", got)
	}
}

func TestAllowedRefsFallsBackToBareKey(t *testing.T) {
	srv := resourceServer(t, `[{"_id":"r1","name":"backend/backend-api","attributes":{
		"allowed_refs":["refs/heads/main","refs/tags/v*"]
	}}]`)
	defer srv.Close()

	got, err := clientFor(t, srv).AllowedRefs(context.Background(),
		"backend/backend-api", "deployment.rollout")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("AllowedRefs = %v, want 2 entries", got)
	}
}

// No attribute at all means unrestricted — the migration-safe default.
func TestAllowedRefsAbsentIsNil(t *testing.T) {
	srv := resourceServer(t, `[{"_id":"r1","name":"backend/backend-api","attributes":{}}]`)
	defer srv.Close()

	got, err := clientFor(t, srv).AllowedRefs(context.Background(),
		"backend/backend-api", "deployment.rollout")
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Fatalf("AllowedRefs = %v, want nil", got)
	}
}

func TestAllowedRefsUnknownResourceIsNil(t *testing.T) {
	srv := resourceServer(t, `[]`)
	defer srv.Close()

	got, err := clientFor(t, srv).AllowedRefs(context.Background(),
		"backend/absent", "deployment.rollout")
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Fatalf("AllowedRefs = %v, want nil", got)
	}
}

func TestAllowedRefsCachesPerResourceAndAction(t *testing.T) {
	var resourceCalls int32
	mux := http.NewServeMux()
	mux.HandleFunc("/realms/master/protocol/openid-connect/token",
		func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"access_token":"tok","expires_in":300}`))
		})
	mux.HandleFunc("/admin/realms/master/clients",
		func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`[{"id":"client-uuid-1"}]`))
		})
	mux.HandleFunc("/admin/realms/master/clients/client-uuid-1/authz/resource-server/resource",
		func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt32(&resourceCalls, 1)
			w.Write([]byte(`[{"_id":"r1","attributes":{
				"allowed_refs.deployment.rollout":["refs/heads/main"],
				"allowed_refs.deployment.restart":["*"]
			}}]`))
		})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := clientFor(t, srv)
	for i := 0; i < 3; i++ {
		got, err := c.AllowedRefs(context.Background(),
			"backend/backend-api", "deployment.rollout")
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 || got[0] != "refs/heads/main" {
			t.Fatalf("AllowedRefs = %v, want [refs/heads/main]", got)
		}
	}
	if n := atomic.LoadInt32(&resourceCalls); n != 1 {
		t.Fatalf("resource endpoint called %d times, want 1 (must cache)", n)
	}

	// A different action is a different cache key, so it fetches again and
	// must return that action's own constraint.
	got, err := c.AllowedRefs(context.Background(),
		"backend/backend-api", "deployment.restart")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != "*" {
		t.Fatalf("AllowedRefs(restart) = %v, want [*]", got)
	}
	if n := atomic.LoadInt32(&resourceCalls); n != 2 {
		t.Fatalf("resource endpoint called %d times, want 2 (per-action key)", n)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/keycloak/ -run TestAllowedRefs -v`
Expected: FAIL — `c.AllowedRefs undefined`.

- [ ] **Step 3: Add the refs cache to the Client**

In `internal/keycloak/client.go`, add a field to the `Client` struct and initialise it in `NewClient`:

```go
// in struct Client, alongside userIDs:
	refs *cache[[]string]
```

```go
// in NewClient's returned &Client{...}, alongside userIDs:
		refs:    newCache[[]string](10*time.Minute, 0, clock),
```

- [ ] **Step 4: Write the implementation**

Append to `internal/keycloak/client.go`:

```go
// AllowedRefs returns the ref constraints for a resource and action, most
// specific first: "allowed_refs.<action>" wins over the bare "allowed_refs".
// A nil result means unrestricted, which is the migration-safe default: there
// was no ref check before Keycloak, so an absent attribute must not deny.
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

	var resources []struct {
		Attributes map[string][]string `json:"attributes"`
	}
	if err := json.Unmarshal(raw, &resources); err != nil {
		return nil, fmt.Errorf("keycloak: decode resources: %w", err)
	}

	var out []string
	if len(resources) > 0 {
		attrs := resources[0].Attributes
		if v, ok := attrs["allowed_refs."+action]; ok {
			out = v
		} else if v, ok := attrs["allowed_refs"]; ok {
			out = v
		}
	}
	c.refs.Put(key, out)
	return out, nil
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./internal/keycloak/ -v`
Expected: PASS, all tests in the package.

- [ ] **Step 6: Commit**

```bash
git add internal/keycloak/client.go internal/keycloak/resource_test.go
git commit -m "keycloak: read allowed_refs resource attributes with action precedence"
```

---

### Task 8: The Keycloak authorizer

**Files:**
- Create: `internal/keycloak/authorizer.go`
- Test: `internal/keycloak/authorizer_test.go`

**Interfaces:**
- Consumes: `Client`, `cache`, `Clock`, `ErrNoSubject`; `authz.Request`, `authz.Decision`, `authz.MatchRef`, `authz.ErrMalformedRefConstraint`.
- Produces:
  - `keycloak.NewAuthorizer(cfg Config, log *slog.Logger, clock Clock) *Authorizer`
  - `(*Authorizer).Authorize(ctx context.Context, req authz.Request) (authz.Decision, error)` — satisfies `authz.Authorizer`
  - `(*Authorizer).Ready(ctx context.Context) error` — for the `/readyz` gate in Task 11

- [ ] **Step 1: Write the failing test**

Create `internal/keycloak/authorizer_test.go`:

```go
package keycloak

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tuncloud/deploy-gateway/internal/authz"
)

// authzStub is a full fake Keycloak for authorizer-level tests. down makes
// every admin call fail, simulating an outage.
type authzStub struct {
	status        string
	refs          string // JSON array body for the resource endpoint
	down          atomic.Bool
	evaluateCalls int32
}

func (s *authzStub) server(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()

	mux.HandleFunc("/realms/master/protocol/openid-connect/token",
		func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"access_token":"tok","expires_in":300}`))
		})
	mux.HandleFunc("/admin/realms/master/clients",
		func(w http.ResponseWriter, r *http.Request) {
			if s.down.Load() {
				http.Error(w, "down", http.StatusServiceUnavailable)
				return
			}
			w.Write([]byte(`[{"id":"cu1"}]`))
		})
	mux.HandleFunc("/admin/realms/master/users",
		func(w http.ResponseWriter, r *http.Request) {
			if s.down.Load() {
				http.Error(w, "down", http.StatusServiceUnavailable)
				return
			}
			w.Write([]byte(`[{"id":"uu1"}]`))
		})
	mux.HandleFunc("/admin/realms/master/clients/cu1/authz/resource-server/resource",
		func(w http.ResponseWriter, r *http.Request) {
			if s.down.Load() {
				http.Error(w, "down", http.StatusServiceUnavailable)
				return
			}
			body := s.refs
			if body == "" {
				body = `[{"_id":"r1","attributes":{}}]`
			}
			w.Write([]byte(body))
		})
	mux.HandleFunc("/admin/realms/master/clients/cu1/authz/resource-server/policy/evaluate",
		func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt32(&s.evaluateCalls, 1)
			if s.down.Load() {
				http.Error(w, "down", http.StatusServiceUnavailable)
				return
			}
			w.Write([]byte(`{"status":"` + s.status + `"}`))
		})

	return httptest.NewServer(mux)
}

func newTestAuthorizer(t *testing.T, s *authzStub, clk Clock) (*Authorizer, *httptest.Server) {
	t.Helper()
	srv := s.server(t)
	a := NewAuthorizer(testConfig(srv.URL), slog.Default(), clk)
	a.client.hc = srv.Client()
	return a, srv
}

func rolloutReq() authz.Request {
	return authz.Request{
		Repository: "tuncloud/backend",
		Action:     "deployment.rollout",
		Namespace:  "backend",
		Deployment: "backend-api",
		Ref:        "refs/heads/main",
	}
}

func TestAuthorizerPermit(t *testing.T) {
	s := &authzStub{status: "PERMIT"}
	a, srv := newTestAuthorizer(t, s, newTestClock())
	defer srv.Close()

	dec, err := a.Authorize(context.Background(), rolloutReq())
	if err != nil {
		t.Fatal(err)
	}
	if !dec.Allowed {
		t.Fatal("expected allowed")
	}
}

func TestAuthorizerDenyCarriesReason(t *testing.T) {
	s := &authzStub{status: "DENY"}
	a, srv := newTestAuthorizer(t, s, newTestClock())
	defer srv.Close()

	dec, err := a.Authorize(context.Background(), rolloutReq())
	if err != nil {
		t.Fatalf("DENY must not be an error: %v", err)
	}
	if dec.Allowed || dec.Reason == "" {
		t.Fatalf("expected denial with reason, got %+v", dec)
	}
}

// A ref that fails the constraint denies even though the grant permits.
func TestAuthorizerRefMismatchDenies(t *testing.T) {
	s := &authzStub{
		status: "PERMIT",
		refs:   `[{"_id":"r1","attributes":{"allowed_refs.deployment.rollout":["refs/heads/main"]}}]`,
	}
	a, srv := newTestAuthorizer(t, s, newTestClock())
	defer srv.Close()

	req := rolloutReq()
	req.Ref = "refs/heads/feature"
	dec, err := a.Authorize(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if dec.Allowed {
		t.Fatal("ref mismatch must deny")
	}
	if dec.Reason == "" {
		t.Fatal("ref denial needs a distinguishable reason")
	}
}

// Ref denials must be distinguishable from grant denials in the audit trail.
func TestAuthorizerRefDenialReasonDiffersFromGrantDenial(t *testing.T) {
	refStub := &authzStub{
		status: "PERMIT",
		refs:   `[{"_id":"r1","attributes":{"allowed_refs.deployment.rollout":["refs/heads/main"]}}]`,
	}
	a1, s1 := newTestAuthorizer(t, refStub, newTestClock())
	defer s1.Close()
	req := rolloutReq()
	req.Ref = "refs/heads/feature"
	refDec, _ := a1.Authorize(context.Background(), req)

	grantStub := &authzStub{status: "DENY"}
	a2, s2 := newTestAuthorizer(t, grantStub, newTestClock())
	defer s2.Close()
	grantDec, _ := a2.Authorize(context.Background(), rolloutReq())

	if refDec.Reason == grantDec.Reason {
		t.Fatalf("ref and grant denials share reason %q", refDec.Reason)
	}
}

func TestAuthorizerMalformedRefConstraintDenies(t *testing.T) {
	s := &authzStub{
		status: "PERMIT",
		refs:   `[{"_id":"r1","attributes":{"allowed_refs.deployment.rollout":["refs/*/main"]}}]`,
	}
	a, srv := newTestAuthorizer(t, s, newTestClock())
	defer srv.Close()

	dec, err := a.Authorize(context.Background(), rolloutReq())
	if err != nil {
		t.Fatalf("a malformed constraint is a denial, not unavailability: %v", err)
	}
	if dec.Allowed {
		t.Fatal("malformed constraint must deny")
	}
}

// An unknown repository has no Keycloak subject: a clean deny, not an outage.
func TestAuthorizerNoSubjectDenies(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/realms/master/protocol/openid-connect/token":
			w.Write([]byte(`{"access_token":"tok","expires_in":300}`))
		case "/admin/realms/master/clients":
			w.Write([]byte(`[{"id":"cu1"}]`))
		case "/admin/realms/master/users":
			w.Write([]byte(`[]`))
		default:
			t.Errorf("unexpected path %q", r.URL.Path)
		}
	}))
	defer srv.Close()

	a := NewAuthorizer(testConfig(srv.URL), slog.Default(), newTestClock())
	a.client.hc = srv.Client()

	dec, err := a.Authorize(context.Background(), rolloutReq())
	if err != nil {
		t.Fatalf("ErrNoSubject must be a denial, not an error: %v", err)
	}
	if dec.Allowed {
		t.Fatal("expected denial")
	}
}

func TestAuthorizerCachesPermit(t *testing.T) {
	s := &authzStub{status: "PERMIT"}
	clk := newTestClock()
	a, srv := newTestAuthorizer(t, s, clk)
	defer srv.Close()

	for i := 0; i < 3; i++ {
		if _, err := a.Authorize(context.Background(), rolloutReq()); err != nil {
			t.Fatal(err)
		}
	}
	if n := atomic.LoadInt32(&s.evaluateCalls); n != 1 {
		t.Fatalf("evaluate called %d times, want 1 (PERMIT must cache)", n)
	}
}

// DENY is never cached, so granting access takes effect immediately.
func TestAuthorizerNeverCachesDeny(t *testing.T) {
	s := &authzStub{status: "DENY"}
	a, srv := newTestAuthorizer(t, s, newTestClock())
	defer srv.Close()

	for i := 0; i < 3; i++ {
		a.Authorize(context.Background(), rolloutReq())
	}
	if n := atomic.LoadInt32(&s.evaluateCalls); n != 3 {
		t.Fatalf("evaluate called %d times, want 3 (DENY must not cache)", n)
	}
}

func TestAuthorizerServesStalePermitWhileDown(t *testing.T) {
	s := &authzStub{status: "PERMIT"}
	clk := newTestClock()
	a, srv := newTestAuthorizer(t, s, clk)
	defer srv.Close()

	if _, err := a.Authorize(context.Background(), rolloutReq()); err != nil {
		t.Fatal(err)
	}

	s.down.Store(true)
	clk.advance(2 * time.Minute) // past the 30s TTL, inside the 5m stale window

	dec, err := a.Authorize(context.Background(), rolloutReq())
	if err != nil {
		t.Fatalf("must serve stale permit during an outage: %v", err)
	}
	if !dec.Allowed {
		t.Fatal("stale permit must still allow")
	}
}

func TestAuthorizerFailsClosedBeyondStaleWindow(t *testing.T) {
	s := &authzStub{status: "PERMIT"}
	clk := newTestClock()
	a, srv := newTestAuthorizer(t, s, clk)
	defer srv.Close()

	a.Authorize(context.Background(), rolloutReq())

	s.down.Store(true)
	clk.advance(6 * time.Minute) // beyond TTL + 5m stale window

	_, err := a.Authorize(context.Background(), rolloutReq())
	if err == nil {
		t.Fatal("beyond the stale window the authorizer must fail closed with an error")
	}
}

func TestAuthorizerUnavailableIsErrorNotDenial(t *testing.T) {
	s := &authzStub{status: "PERMIT"}
	s.down.Store(true)
	a, srv := newTestAuthorizer(t, s, newTestClock())
	defer srv.Close()

	_, err := a.Authorize(context.Background(), rolloutReq())
	if err == nil {
		t.Fatal("an outage with no cached permit must return an error, never a denial")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/keycloak/ -run TestAuthorizer -v`
Expected: FAIL — `undefined: NewAuthorizer`.

- [ ] **Step 3: Write the implementation**

Create `internal/keycloak/authorizer.go`:

```go
package keycloak

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/tuncloud/deploy-gateway/internal/authz"
)

const (
	// decisionTTL is how long a PERMIT is reused normally.
	decisionTTL = 30 * time.Second
	// decisionStaleFor is the extra grace period during which a PERMIT is
	// reused only because Keycloak is unreachable.
	decisionStaleFor = 5 * time.Minute
)

// Authorizer answers authorization questions from Keycloak. Keycloak owns the
// grant; this type owns the request-scoped ref check, because Keycloak's
// built-in policy types cannot evaluate a pushed claim.
type Authorizer struct {
	client    *Client
	decisions *cache[bool]
	log       *slog.Logger
}

func NewAuthorizer(cfg Config, log *slog.Logger, clock Clock) *Authorizer {
	return &Authorizer{
		client:    NewClient(cfg, log, clock),
		decisions: newCache[bool](decisionTTL, decisionStaleFor, clock),
		log:       log,
	}
}

func decisionKey(req authz.Request) string {
	return req.Repository + "\x00" + req.Action + "\x00" +
		req.Namespace + "\x00" + req.Deployment + "\x00" + req.Ref
}

func resourceName(req authz.Request) string {
	return req.Namespace + "/" + req.Deployment
}

func grantDenied(req authz.Request) authz.Decision {
	return authz.Decision{Reason: "keycloak does not grant " + req.Action +
		" on " + resourceName(req)}
}

func refDenied(req authz.Request) authz.Decision {
	return authz.Decision{Reason: "ref " + req.Ref + " is not permitted to " +
		req.Action + " on " + resourceName(req)}
}

// Authorize returns a Decision, or an error meaning the decision could not be
// reached. An error is never a denial: callers must surface it as
// unavailability. Denials are never cached, so granting access is immediate.
func (a *Authorizer) Authorize(ctx context.Context, req authz.Request) (authz.Decision, error) {
	key := decisionKey(req)
	if allowed, ok := a.decisions.Get(key); ok && allowed {
		return authz.Decision{Allowed: true}, nil
	}

	decision, err := a.evaluate(ctx, req)
	if err != nil {
		// Keycloak is unreachable. Ride out a blip on a stale permit, but only
		// within the bounded window; past that, fail closed.
		if allowed, ok := a.decisions.GetStale(key); ok && allowed {
			a.log.Warn("serving stale authorization decision",
				"repository", req.Repository, "action", req.Action,
				"namespace", req.Namespace, "deployment", req.Deployment)
			return authz.Decision{Allowed: true}, nil
		}
		return authz.Decision{}, err
	}

	if decision.Allowed {
		a.decisions.Put(key, true)
	}
	return decision, nil
}

func (a *Authorizer) evaluate(ctx context.Context, req authz.Request) (authz.Decision, error) {
	userID, err := a.client.UserID(ctx, req.Repository)
	if err != nil {
		if errors.Is(err, ErrNoSubject) {
			// No Keycloak subject for this repository: a clean denial.
			return grantDenied(req), nil
		}
		return authz.Decision{}, err
	}

	granted, err := a.client.Evaluate(ctx, userID, resourceName(req), req.Action)
	if err != nil {
		return authz.Decision{}, err
	}
	if !granted {
		return grantDenied(req), nil
	}

	allowedRefs, err := a.client.AllowedRefs(ctx, resourceName(req), req.Action)
	if err != nil {
		return authz.Decision{}, err
	}
	ok, err := authz.MatchRef(allowedRefs, req.Ref)
	if err != nil {
		// A malformed constraint fails closed: a denial, not unavailability.
		a.log.Warn("malformed ref constraint, denying",
			"namespace", req.Namespace, "deployment", req.Deployment,
			"action", req.Action, "err", err)
		return refDenied(req), nil
	}
	if !ok {
		return refDenied(req), nil
	}
	return authz.Decision{Allowed: true}, nil
}

// Ready reports whether Keycloak is reachable and the resource server client
// resolves. Used to gate /readyz rather than to fail the process at boot.
func (a *Authorizer) Ready(ctx context.Context) error {
	_, err := a.client.ResourceServerUUID(ctx)
	return err
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/keycloak/ -v`
Expected: PASS, all tests in the package.

- [ ] **Step 5: Commit**

```bash
git add internal/keycloak/authorizer.go internal/keycloak/authorizer_test.go
git commit -m "keycloak: authorizer with permit cache and bounded stale serving"
```

---

### Task 9: Three-outcome handler contract and denial-block extraction

**Files:**
- Modify: `internal/api/server.go` — `Deps` struct, `handleRestart`, `handleRollout`, `handleReadyz`
- Modify: `internal/api/server_test.go` — replace the YAML-file setup with a fake authorizer
- Test: `internal/api/server_test.go`

**Interfaces:**
- Consumes: `authz.Authorizer`, `authz.Request`, `authz.Decision`.
- Produces:
  - `api.Deps.Authz authz.Authorizer` replacing `api.Deps.Policy *authz.Policy`
  - `api.ReadinessChecker` interface with `Ready(ctx context.Context) error`
  - unexported `(*Deps).recordDenied(ctx context.Context, id *authn.GitHubIdentity, action, namespace, deployment, container, image, reason string)`

- [ ] **Step 1: Write the failing test**

In `internal/api/server_test.go`, add the fake authorizer and new tests. Add near `fakeKube`:

```go
// fakeAuthz implements authz.Authorizer. err simulates unavailability;
// allowed/reason simulate a reached decision.
type fakeAuthz struct {
	allowed bool
	reason  string
	err     error
	seen    []authz.Request
}

func (f *fakeAuthz) Authorize(_ context.Context, req authz.Request) (authz.Decision, error) {
	f.seen = append(f.seen, req)
	if f.err != nil {
		return authz.Decision{}, f.err
	}
	return authz.Decision{Allowed: f.allowed, Reason: f.reason}, nil
}
```

Add a new constructor alongside the existing ones:

```go
func newDepsAuthz(t *testing.T, a authz.Authorizer) (http.Handler, func() []*store.Operation) {
	t.Helper()
	st := store.NewRecording()
	m := operation.NewManager(&fakeKube{}, st, notify.Disabled(), slog.Default(), time.Minute)
	v := authn.NewStaticVerifier(&authn.GitHubIdentity{
		Repository: "tuncloud/backend", RepositoryID: "123", Actor: "tuando",
		RunID: "1", RunAttempt: "1", EventName: "push", Workflow: "deploy.yml",
		Ref: "refs/heads/main",
	})
	return api.NewRouter(api.Deps{
		Verifier: v, Authz: a, Ops: m, Store: st, Log: slog.Default(),
	}), st.Recorder()
}
```

Add the tests:

```go
func TestRestartAllowedReturns202(t *testing.T) {
	h, _ := newDepsAuthz(t, &fakeAuthz{allowed: true})
	w := doReq(h, http.MethodPost, "/v1/deployments/restart",
		`{"namespace":"backend","deployment":"backend-api"}`, "t")
	if w.Code != http.StatusAccepted {
		t.Fatalf("code = %d, want 202", w.Code)
	}
}

func TestRestartDeniedReturns403AndWritesAuditRow(t *testing.T) {
	h, rec := newDepsAuthz(t, &fakeAuthz{allowed: false, reason: "no grant"})
	w := doReq(h, http.MethodPost, "/v1/deployments/restart",
		`{"namespace":"backend","deployment":"backend-api"}`, "t")
	if w.Code != http.StatusForbidden {
		t.Fatalf("code = %d, want 403", w.Code)
	}
	ops := rec()
	if len(ops) != 1 {
		t.Fatalf("recorded %d operations, want 1 denial row", len(ops))
	}
	if ops[0].Status != store.StatusDenied {
		t.Fatalf("status = %q, want denied", ops[0].Status)
	}
	if ops[0].ErrorMessage != "no grant" {
		t.Fatalf("ErrorMessage = %q, want the authorizer's reason", ops[0].ErrorMessage)
	}
}

// The central invariant: an unreachable authorizer is 503, not 403, and must
// not write a denial row that would misattribute an outage to a policy decision.
func TestRestartAuthzUnavailableReturns503AndWritesNoAuditRow(t *testing.T) {
	h, rec := newDepsAuthz(t, &fakeAuthz{err: errors.New("keycloak down")})
	w := doReq(h, http.MethodPost, "/v1/deployments/restart",
		`{"namespace":"backend","deployment":"backend-api"}`, "t")
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("code = %d, want 503", w.Code)
	}
	if !strings.Contains(w.Body.String(), "AUTHZ_UNAVAILABLE") {
		t.Fatalf("body = %s, want AUTHZ_UNAVAILABLE", w.Body.String())
	}
	if ops := rec(); len(ops) != 0 {
		t.Fatalf("recorded %d operations, want 0 on unavailability", len(ops))
	}
}

func TestRolloutAuthzUnavailableReturns503(t *testing.T) {
	h, rec := newDepsAuthz(t, &fakeAuthz{err: errors.New("keycloak down")})
	w := doReq(h, http.MethodPost, "/v1/deployments/rollout",
		`{"namespace":"backend","deployment":"backend-api","image":"ghcr.io/o/a:v1"}`, "t")
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("code = %d, want 503", w.Code)
	}
	if ops := rec(); len(ops) != 0 {
		t.Fatalf("recorded %d operations, want 0", len(ops))
	}
}

func TestRolloutDeniedAuditRowKeepsImageAndContainer(t *testing.T) {
	h, rec := newDepsAuthz(t, &fakeAuthz{allowed: false, reason: "no grant"})
	doReq(h, http.MethodPost, "/v1/deployments/rollout",
		`{"namespace":"backend","deployment":"backend-api","container":"api","image":"ghcr.io/o/a:v1"}`, "t")
	ops := rec()
	if len(ops) != 1 {
		t.Fatalf("recorded %d operations, want 1", len(ops))
	}
	if ops[0].Image != "ghcr.io/o/a:v1" || ops[0].Container != "api" {
		t.Fatalf("denial row lost rollout detail: %+v", ops[0])
	}
}

// The ref claim must reach the authorizer, or ref constraints can never apply.
func TestHandlersPassRefToAuthorizer(t *testing.T) {
	fa := &fakeAuthz{allowed: true}
	h, _ := newDepsAuthz(t, fa)
	doReq(h, http.MethodPost, "/v1/deployments/restart",
		`{"namespace":"backend","deployment":"backend-api"}`, "t")
	if len(fa.seen) != 1 {
		t.Fatalf("authorizer saw %d requests, want 1", len(fa.seen))
	}
	if fa.seen[0].Ref != "refs/heads/main" {
		t.Fatalf("Ref = %q, want refs/heads/main", fa.seen[0].Ref)
	}
	if fa.seen[0].Action != operation.ActionRestart {
		t.Fatalf("Action = %q, want %q", fa.seen[0].Action, operation.ActionRestart)
	}
}
```

Then update the two existing helpers to build a `FileAuthorizer` instead of a `*Policy`, so the pre-existing tests keep passing:

```go
func newDepsK(t *testing.T, policyYAML string, k kube.Kube) (http.Handler, func() []*store.Operation) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "p.yaml")
	os.WriteFile(path, []byte(policyYAML), 0o644)
	a, err := authz.NewFileAuthorizer(path)
	if err != nil {
		t.Fatal(err)
	}
	st := store.NewRecording()
	m := operation.NewManager(k, st, notify.Disabled(), slog.Default(), time.Minute)
	v := authn.NewStaticVerifier(&authn.GitHubIdentity{
		Repository: "tuncloud/backend", RepositoryID: "123", Actor: "tuando",
		RunID: "1", RunAttempt: "1", EventName: "push", Workflow: "deploy.yml",
	})
	return api.NewRouter(api.Deps{Verifier: v, Authz: a, Ops: m, Store: st, Log: slog.Default()}), st.Recorder()
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/api/ -v`
Expected: FAIL — `unknown field Authz in struct literal of type api.Deps`.

- [ ] **Step 3: Swap the Deps field and add the denial helper**

In `internal/api/server.go`, change the `Deps` struct field:

```go
type Deps struct {
	Verifier TokenVerifier
	Authz    authz.Authorizer
	Ops      *operation.Manager
	Store    store.Store
	Log      *slog.Logger
}

// ReadinessChecker is implemented by authorizers that depend on a remote
// service. Checked by /readyz; authorizers without a remote dependency simply
// do not implement it.
type ReadinessChecker interface {
	Ready(ctx context.Context) error
}
```

Add the extracted helper (replacing the two duplicated blocks at the old `server.go:81-107` and `server.go:148-175`):

```go
// recordDenied writes the audit row for a rejected request. Both handlers
// share it: a denial row must look the same whichever action was refused.
func (d *Deps) recordDenied(ctx context.Context, id *authn.GitHubIdentity,
	action, namespace, deployment, container, image, reason string) {

	now := time.Now().UTC()
	if err := d.Store.PutOperation(ctx, &store.Operation{
		OperationID: operation.NewOperationID(),
		Repository:  id.Repository, RepositoryID: id.RepositoryID,
		RepositoryOwner: id.RepositoryOwner, Actor: id.Actor,
		Workflow: id.Workflow, WorkflowRef: id.WorkflowRef,
		RunID: id.RunID, RunAttempt: id.RunAttempt, EventName: id.EventName,
		Action:    action,
		Namespace: namespace, Deployment: deployment,
		Container: container, Image: image,
		NsDep:        namespace + "#" + deployment,
		Status:       store.StatusDenied,
		ErrorCode:    "DENIED",
		ErrorMessage: reason,
		RequestedAt:  now,
		ExpiresAt:    now.Add(365 * 24 * time.Hour).Unix(),
		Events:       []store.AuditEvent{{Event: "DENIED", At: now}},
	}); err != nil {
		// err is a store-side error (no token/claims content) — surface it so
		// a denied request never silently vanishes from the audit trail.
		d.Log.Error("denied audit write failed",
			"repository", id.Repository,
			"namespace", namespace, "deployment", deployment, "err", err)
	}
	d.Log.Warn("denied", "repository", id.Repository,
		"namespace", namespace, "deployment", deployment, "reason", reason)
}

// authorize resolves the three-outcome contract. It returns false when the
// response has already been written, so the handler must simply return.
func (d *Deps) authorize(w http.ResponseWriter, r *http.Request,
	id *authn.GitHubIdentity, action, namespace, deployment, container, image string) bool {

	dec, err := d.Authz.Authorize(r.Context(), authz.Request{
		Repository: id.Repository, Action: action,
		Namespace: namespace, Deployment: deployment, Ref: id.Ref,
	})
	if err != nil {
		// The decision could not be reached. This is NOT a denial: reporting it
		// as 403 would tell the caller their permissions are wrong when they
		// are not, and would poison the audit table with a false denial.
		d.Log.Error("authorization unavailable",
			"repository", id.Repository, "action", action,
			"namespace", namespace, "deployment", deployment, "err", err)
		writeError(w, http.StatusServiceUnavailable, "AUTHZ_UNAVAILABLE",
			"authorization service unavailable")
		return false
	}
	if !dec.Allowed {
		d.recordDenied(r.Context(), id, action, namespace, deployment,
			container, image, dec.Reason)
		writeError(w, http.StatusForbidden, "FORBIDDEN", "not allowed")
		return false
	}
	return true
}
```

- [ ] **Step 4: Rewrite the two authorization checks**

In `handleRestart`, replace the entire `if !d.Policy.Authorize(...) { ... }` block with:

```go
	if !d.authorize(w, r, id, operation.ActionRestart,
		body.Namespace, body.Deployment, "", "") {
		return
	}
```

In `handleRollout`, replace the entire `if !d.Policy.Authorize(...) { ... }` block with:

```go
	if !d.authorize(w, r, id, operation.ActionRollout,
		body.Namespace, body.Deployment, body.Container, body.Image) {
		return
	}
```

- [ ] **Step 5: Gate readiness on the authorizer**

Replace `handleReadyz` in `internal/api/server.go`:

```go
func (d *Deps) handleReadyz(w http.ResponseWriter, r *http.Request) {
	if err := d.Store.Ping(r.Context()); err != nil {
		d.Log.Error("readiness check failed", "err", err)
		writeError(w, http.StatusServiceUnavailable, "STORE_UNAVAILABLE", "store not reachable")
		return
	}
	// Authorizers with a remote dependency gate readiness too, so Kubernetes
	// withholds traffic from a gateway that cannot authorize — rather than the
	// process failing fast at boot and crashlooping.
	if rc, ok := d.Authz.(ReadinessChecker); ok {
		if err := rc.Ready(r.Context()); err != nil {
			d.Log.Error("readiness check failed", "err", err)
			writeError(w, http.StatusServiceUnavailable, "AUTHZ_UNAVAILABLE",
				"authorization service not reachable")
			return
		}
	}
	w.Write([]byte("ok"))
}
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `go test ./internal/api/ -v`
Expected: PASS — the new tests plus every pre-existing handler test.

Then run the whole suite: `go test ./...`
Expected: PASS. `cmd/gateway` will still fail to build until Task 11; if `go build ./...` errors on `main.go` referencing `Policy:`, that is expected and fixed in Task 11.

- [ ] **Step 7: Commit**

```bash
git add internal/api/server.go internal/api/server_test.go
git commit -m "api: three-outcome authorization with 503 on unavailability"
```

---

### Task 10: Shadow authorizer

**Files:**
- Create: `internal/authz/shadow.go`
- Test: `internal/authz/shadow_test.go`

**Interfaces:**
- Consumes: `authz.Authorizer`, `authz.Request`, `authz.Decision`.
- Produces: `authz.NewShadow(primary, shadow Authorizer, log *slog.Logger) *Shadow`, implementing `Authorizer`.

- [ ] **Step 1: Write the failing test**

Create `internal/authz/shadow_test.go`:

```go
package authz_test

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/tuncloud/deploy-gateway/internal/authz"
)

type stubAuthorizer struct {
	dec    authz.Decision
	err    error
	calls  int
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/authz/ -run TestShadow -v`
Expected: FAIL — `undefined: authz.NewShadow`.

- [ ] **Step 3: Write the implementation**

Create `internal/authz/shadow.go`:

```go
package authz

import (
	"context"
	"log/slog"
	"time"
)

// shadowTimeout bounds the shadow call so validation can never stall a real
// deploy. It is independent of the primary's own budget.
const shadowTimeout = 3 * time.Second

// Shadow runs two authorizers: primary decides, shadow is observed. The
// shadow's decision, denial, error, and timeout are all logged and discarded —
// they can never change a response or an audit row. This is how the Keycloak
// object model gets validated against real traffic before the cutover.
type Shadow struct {
	primary Authorizer
	shadow  Authorizer
	log     *slog.Logger
}

func NewShadow(primary, shadow Authorizer, log *slog.Logger) *Shadow {
	return &Shadow{primary: primary, shadow: shadow, log: log}
}

func (s *Shadow) Authorize(ctx context.Context, req Request) (Decision, error) {
	dec, err := s.primary.Authorize(ctx, req)

	shadowCtx, cancel := context.WithTimeout(ctx, shadowTimeout)
	defer cancel()
	shadowDec, shadowErr := s.shadow.Authorize(shadowCtx, req)

	switch {
	case shadowErr != nil:
		s.log.Warn("shadow authorizer unavailable",
			"repository", req.Repository, "action", req.Action,
			"namespace", req.Namespace, "deployment", req.Deployment,
			"err", shadowErr)
	case err != nil:
		// Primary failed, so there is nothing to compare against.
		s.log.Warn("primary authorizer unavailable, shadow not compared",
			"repository", req.Repository, "action", req.Action)
	case shadowDec.Allowed != dec.Allowed:
		s.log.Warn("shadow authorizer disagrees",
			"repository", req.Repository, "action", req.Action,
			"namespace", req.Namespace, "deployment", req.Deployment,
			"ref", req.Ref,
			"primary_allowed", dec.Allowed, "shadow_allowed", shadowDec.Allowed,
			"shadow_reason", shadowDec.Reason)
	default:
		s.log.Info("shadow authorizer agrees",
			"repository", req.Repository, "action", req.Action,
			"namespace", req.Namespace, "deployment", req.Deployment,
			"allowed", dec.Allowed)
	}

	return dec, err
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/authz/ -v`
Expected: PASS, all shadow, ref, file and policy tests.

- [ ] **Step 5: Commit**

```bash
git add internal/authz/shadow.go internal/authz/shadow_test.go
git commit -m "authz: shadow authorizer for pre-cutover validation"
```

---

### Task 11: Wire up `main.go`

**Files:**
- Modify: `cmd/gateway/main.go`

**Interfaces:**
- Consumes: `authz.NewFileAuthorizer`, `authz.NewShadow`, `keycloak.NewAuthorizer`, `keycloak.Config`, `keycloak.RealClock`, `api.Deps.Authz`.
- Produces: nothing consumed by later tasks.

- [ ] **Step 1: Add the backend selector**

In `cmd/gateway/main.go`, add the import for `internal/keycloak` and replace the policy-loading block (currently `policy, err := authz.LoadPolicy(policyPath)` through its `os.Exit(1)`) with a call to a new helper, then pass `Authz: authorizer` to `api.Deps` instead of `Policy: policy`.

```go
// buildAuthorizer selects the authorization backend. Keycloak is resolved
// lazily and never fails the process at boot: a Keycloak hiccup during a
// gateway rollout must not produce a crashlooping gateway at the exact moment
// deploys are needed. /readyz gates traffic instead.
func buildAuthorizer(backend, policyPath string, logger *slog.Logger) (authz.Authorizer, error) {
	kcConfig := func() keycloak.Config {
		return keycloak.Config{
			BaseURL:      os.Getenv("KEYCLOAK_BASE_URL"),
			Realm:        os.Getenv("KEYCLOAK_REALM"),
			ClientID:     os.Getenv("KEYCLOAK_CLIENT_ID"),
			ClientSecret: os.Getenv("KEYCLOAK_CLIENT_SECRET"),
		}
	}

	switch backend {
	case "keycloak":
		cfg := kcConfig()
		if cfg.BaseURL == "" || cfg.Realm == "" || cfg.ClientID == "" {
			return nil, fmt.Errorf("AUTHZ_BACKEND=keycloak requires KEYCLOAK_BASE_URL, KEYCLOAK_REALM and KEYCLOAK_CLIENT_ID")
		}
		logger.Info("authorization backend", "backend", "keycloak",
			"realm", cfg.Realm, "client_id", cfg.ClientID)
		return keycloak.NewAuthorizer(cfg, logger, keycloak.RealClock{}), nil

	case "shadow":
		file, err := authz.NewFileAuthorizer(policyPath)
		if err != nil {
			return nil, err
		}
		cfg := kcConfig()
		if cfg.BaseURL == "" || cfg.Realm == "" || cfg.ClientID == "" {
			return nil, fmt.Errorf("AUTHZ_BACKEND=shadow requires KEYCLOAK_BASE_URL, KEYCLOAK_REALM and KEYCLOAK_CLIENT_ID")
		}
		logger.Info("authorization backend", "backend", "shadow",
			"authoritative", "file", "shadowed", "keycloak")
		return authz.NewShadow(file,
			keycloak.NewAuthorizer(cfg, logger, keycloak.RealClock{}), logger), nil

	case "file", "":
		logger.Info("authorization backend", "backend", "file", "path", policyPath)
		return authz.NewFileAuthorizer(policyPath)

	default:
		return nil, fmt.Errorf("unknown AUTHZ_BACKEND %q (want file, keycloak or shadow)", backend)
	}
}
```

- [ ] **Step 2: Call it from main**

Replace the old policy block in `main()`:

```go
	authorizer, err := buildAuthorizer(os.Getenv("AUTHZ_BACKEND"), policyPath, logger)
	if err != nil {
		logger.Error("authorization backend", "err", err)
		os.Exit(1)
	}
```

and change the router construction:

```go
		Handler: api.NewRouter(api.Deps{
			Verifier: verifier, Authz: authorizer, Ops: ops, Store: st, Log: logger,
		}),
```

Add `"fmt"` and `"github.com/tuncloud/deploy-gateway/internal/keycloak"` to the imports.

Note: the `os.Exit(1)` here is on **configuration** errors only — a bad `AUTHZ_BACKEND` value, or a missing required variable. It never fires because Keycloak is unreachable, which is the distinction the spec requires.

- [ ] **Step 3: Verify the whole thing builds and passes**

Run: `go build ./... && go vet ./... && go test ./...`
Expected: all succeed, with no remaining references to `api.Deps.Policy`.

- [ ] **Step 4: Confirm no reference to the old field survives**

Run: `grep -rn "Deps.Policy\|Policy:" --include="*.go" .`
Expected: no output.

- [ ] **Step 5: Commit**

```bash
git add cmd/gateway/main.go
git commit -m "gateway: select authorization backend via AUTHZ_BACKEND"
```

---

### Task 12: Documentation

**Files:**
- Modify: `README.md`

**Interfaces:**
- Consumes: the configuration surface from Task 11 and the failure posture from Task 8.
- Produces: nothing consumed by later tasks.

- [ ] **Step 1: Replace the ConfigMap onboarding paragraph**

In `README.md`, find the paragraph under "Usage from a repository" beginning *"The repository must be listed in the gateway policy ConfigMap"* and replace it with:

```markdown
The repository must be granted permission in Keycloak. To onboard a repository:

1. Create a Keycloak user whose username is the repository slug exactly
   (`tuncloud/backend`). It needs no credentials and never logs in — it exists
   only as a subject to evaluate.
2. In the `deploy-gateway` client's Authorization tab, create a **User** policy
   selecting that user.
3. Create the resource for the target if it does not exist: name it
   `<namespace>/<deployment>` (e.g. `backend/backend-api`), type
   `urn:deploy-gateway:deployment`, with the scopes it should offer.
4. Add the repository's user policy to the **scope-based permission** for that
   resource and action.

Changes take effect without redeploying the gateway. Granting access is
immediate; revoking it takes effect within 30 seconds.
```

- [ ] **Step 2: Add the authorization configuration section**

Add a new `## Authorization` section after the `## API` section:

```markdown
## Authorization

Authorization decisions come from Keycloak, evaluated per request. The gateway
authenticates the caller's GitHub OIDC token itself, then asks Keycloak whether
that repository may perform the requested action on the requested deployment.

| Variable | Purpose |
|---|---|
| `AUTHZ_BACKEND` | `file` (default), `keycloak`, or `shadow` |
| `KEYCLOAK_BASE_URL` | e.g. `https://sso.example.com` |
| `KEYCLOAK_REALM` | realm holding the `deploy-gateway` client |
| `KEYCLOAK_CLIENT_ID` | the resource-server client, `deploy-gateway` |
| `KEYCLOAK_CLIENT_SECRET` | service-account secret, from a Secret |

`shadow` keeps the file policy authoritative while also calling Keycloak and
logging disagreements — run it before cutting over. Grep for
`shadow authorizer disagrees`; a clean log means the Keycloak object model
matches the file it is replacing.

### Object model

| Concept | Keycloak object |
|---|---|
| a repository | a credential-less user, username = repository slug |
| an action | a scope: `deployment.restart`, `deployment.rollout` |
| a deploy target | a resource named `<namespace>/<deployment>` |
| a grant | a scope-based permission listing repository user policies |

There are no wildcards. Every namespace/deployment a repository may touch is a
real resource, so breadth is always visible in the Keycloak UI.

### Ref restrictions

Set a resource attribute to restrict which git refs may deploy it:

| Attribute | Effect |
|---|---|
| `allowed_refs.deployment.rollout` | refs allowed to roll out this resource |
| `allowed_refs.deployment.restart` | refs allowed to restart this resource |
| `allowed_refs` | fallback when no action-specific key is set |

Values are matched as: `refs/heads/main` exactly, `*` for any ref, or a
trailing glob such as `refs/heads/release/*` or `refs/tags/v*`. An absent
attribute means unrestricted. A malformed value denies.

This is how you grant `deployment.rollout` more narrowly than
`deployment.restart` — a restart can't change code, a rollout can, so a restart
may be allowed from any branch while a rollout requires `main`.

### Required service-account roles

The `deploy-gateway` client's service account needs the minimum realm-management
roles recorded in
`docs/superpowers/spikes/2026-08-21-keycloak-evaluate-findings.md`.

### When Keycloak is unavailable

The gateway fails **closed** and returns `503 AUTHZ_UNAVAILABLE` — never `403`,
so an outage is never reported to a caller as a permissions problem and never
written to the audit table as a denial.

| Event | Effect |
|---|---|
| brief Keycloak blip | invisible; cached permits are served |
| sustained outage | deploys fail closed within 5 minutes |
| granting access | immediate |
| revoking access | within 30s; up to 5 min during an outage |

`PERMIT` decisions are cached 30s and served up to 5 minutes past that only
while Keycloak is unreachable. `DENY` is never cached. `/readyz` reports
not-ready until Keycloak has been reached once, so Kubernetes withholds traffic
rather than the gateway crashlooping.

Log lines worth grepping: `authorization unavailable`,
`serving stale authorization decision`, `malformed ref constraint, denying`,
`shadow authorizer disagrees`.

### Upgrading Keycloak

The gateway calls the Admin `policy/evaluate` endpoint, which is not a
stability-promised API. **After any Keycloak major or minor upgrade, manually
re-verify the contract** using the curl commands in
`docs/superpowers/spikes/2026-08-21-keycloak-evaluate-findings.md`. There is no
automated integration test that will catch a shape change.
```

- [ ] **Step 3: Update the Security section**

In `README.md`'s `## Security` section, replace the bullet reading
`` - `deployment.rollout` controls which images run — grant it more narrowly than `deployment.restart` (a restart can't change code, a rollout can). ``
with:

```markdown
- `deployment.rollout` controls which images run — grant it more narrowly than
  `deployment.restart` (a restart can't change code, a rollout can). Use
  `allowed_refs.deployment.rollout` to require a trusted branch for rollouts.
- The Keycloak client secret is never logged: it sits in the API request path,
  so request URLs and transport errors are never surfaced.
- An unreachable Keycloak fails closed (`503`), bounded by a 5-minute
  stale-permit window. It is never reported as `403`.
```

- [ ] **Step 4: Verify the docs match reality**

Run: `grep -n "AUTHZ_BACKEND\|allowed_refs\|AUTHZ_UNAVAILABLE" README.md`
Expected: matches in the new sections.

Run: `go test ./...`
Expected: PASS (no code changed, but confirm the tree is green before committing).

- [ ] **Step 5: Commit**

```bash
git add README.md
git commit -m "docs: Keycloak authorization configuration, object model and failure posture"
```

---

## Post-plan: manual cutover steps (not code)

These are operational, performed by a human after Task 12 ships:

1. Build the Keycloak object graph in the real realm by hand, per the README's onboarding steps — one user, user policy, resource, and scope-based permission per existing entry in `policy.example.yaml`. Existing `*` wildcard entries must be resolved into explicit resources by a human decision.
2. Deploy with `AUTHZ_BACKEND=shadow`. Watch for `shadow authorizer disagrees` until the log is clean across real deploy traffic.
3. Flip to `AUTHZ_BACKEND=keycloak`. Rollback is reverting that one variable and restarting the pod.
4. **Follow-up change, not in this plan:** delete the file backend (`internal/authz/policy.go`, `internal/authz/file.go`, `internal/authz/shadow.go`), `policy.example.yaml`, and the `deploy-gateway-policy` ConfigMap. Note this removes the escape hatch, leaving the stale-permit window as the only resilience — which is why it comes last.
