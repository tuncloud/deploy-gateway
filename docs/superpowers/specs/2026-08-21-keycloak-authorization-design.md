# Keycloak-backed authorization

Date: 2026-08-21
Status: approved, not yet implemented

## Problem

Authorization lives in a static YAML file (`internal/authz/policy.go`), loaded once
at startup from a ConfigMap-mounted path. Four things are wrong with it:

- **Changes need a redeploy.** Editing the `deploy-gateway-policy` ConfigMap does
  nothing until `kubectl -n platform-system rollout restart deploy/deploy-gateway`.
- **No self-service.** Granting a repo permission to deploy requires cluster access
  and comfort editing YAML, so it can only be done by cluster admins.
- **A second source of truth.** The organisation already runs Keycloak as its
  identity and access authority; this file is a parallel, unaudited policy store.
- **Too coarse.** The model is `repository × action × namespace × deployment` with
  `*` wildcards. It cannot express which git refs may deploy where.

## Goals

- Policy is authored in Keycloak and takes effect without redeploying the gateway.
- Onboarding a repository is a UI operation, not a cluster operation.
- Keycloak is the single source of truth for who may deploy what.
- Grants can be restricted by git ref.
- A Keycloak problem degrades deploys in a bounded, understood way.

## Non-goals

- GitHub environment gating, group-based grants, and time-window/change-freeze
  policies. All three were considered and explicitly declined; only ref
  restrictions are in scope.
- Replacing authentication. GitHub OIDC token verification (`internal/authn`)
  is unchanged. Keycloak decides *authorization only*.
- Wildcard grants. See "Explicit enumeration" below.

## Decision

Keycloak is the policy decision point, consulted **per request**. The gateway
authenticates the caller's GitHub OIDC token locally as it does today, then asks
Keycloak whether that repository may perform the requested action on the requested
deployment.

The gateway reaches Keycloak's decision through the **Admin policy-evaluation
endpoint**, authenticating as a single service account:

```
POST /admin/realms/{realm}/clients/{client-uuid}/authz/resource-server/policy/evaluate
```

Each repository is a credential-less Keycloak **user** that exists only as a
subject to evaluate; it never logs in and holds no credentials.

### Why this and not the alternatives

**Rejected: JWT Authorization Grant + `uma-ticket`.** The canonical UMA flow —
exchange the GitHub JWT via `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer`,
then evaluate with `grant_type=urn:ietf:params:oauth:grant-type:uma-ticket` and
`response_mode=decision` — uses supported public token endpoints and would be the
textbook answer. It was rejected because the external `sub` must be *pre-linked* to
a Keycloak user through federated identity, and GitHub Actions' default `sub` is
`repo:owner/name:ref:refs/heads/main` — it varies per branch. Making the link stable
requires pinning each repository's subject claim through GitHub's customization API.
Onboarding a repo would become: create user → link federated identity → customize
the GitHub subject claim → attach permission. That directly defeats the
self-service goal, for two round trips instead of one.

**Rejected: custom policy provider JAR.** Deploying a Java policy provider into
Keycloak would let the entire rule, ref condition included, live in Keycloak with a
single decision call. It was rejected because it means maintaining Java code against
Keycloak's internal SPI, rebuilding the Keycloak image, re-verifying on every
Keycloak upgrade, and losing the ability to test the ref decision from Go — a
permanent tax for one condition.

**Rejected: gateway syncs policy from Keycloak and decides locally.** Keycloak as
authoring UI with the gateway polling and caching the mapping would make deploys
immune to Keycloak outages, but policy edits would only take effect after a sync
interval. Immediate effect was the priority.

**Accepted cost of the chosen path.** `policy/evaluate` is an admin API built for
the Admin Console's Evaluate tab. It requires broader privileges than a public token
endpoint and carries less of a contract-stability promise. This is mitigated by
quarantining it in one package with one seam, and by pinning its wire shape in tests.

### Constraint that shaped the design

Keycloak's built-in policy engine cannot cleanly evaluate a request-scoped value
like a git ref:

- Script/JS policies were removed in Keycloak 18. Custom logic now requires
  deploying a Java provider as a JAR.
- The built-in Regex policy reads claims from the identity's attributes and does not
  reliably see claims pushed via `claim_token` on an authorization request.
- `policy/evaluate` carries a `context.attributes` field, but no built-in policy
  type reads it.

Therefore the work splits: **Keycloak owns the grant** (which repository may perform
which action on which deployment), and **the gateway owns the request-scoped ref
check**, against a constraint that is *stored in Keycloak* and editable in its UI.
This keeps Keycloak as the source of truth without pretending its policy engine does
something it does not.

## Keycloak object model

One client, `deploy-gateway`, with Authorization Services enabled. It is the
resource server holding everything below.

**Scopes** are the two actions, named to match the Go constants exactly so that
`operation.ActionRestart` *is* the scope string:

- `deployment.restart`
- `deployment.rollout`

No mapping table, nothing to drift.

**Resources** are deploy targets, one per `<namespace>/<deployment>`, e.g.
`backend/backend-api`, of type `urn:deploy-gateway:deployment`. Ref constraints ride
as resource attributes (below).

**Repository principals** are one credential-less Keycloak user per repository, with
username set to the `repository` claim verbatim (`tuncloud/backend`).

A user rather than a client was chosen deliberately: the user subject is what the
Admin Console's Evaluate tab drives, and is therefore the safer bet against an API
whose contract we are already treating carefully. If the spike shows a client
subject works, switching is a one-line change.

**Grants** are wired as one **User policy** per repository (created once, reusable)
plus one **scope-based permission** per `(resource, scope)` pair listing which
repository policies are permitted. Granting an existing deployment to a new
repository is then: open that permission, add the repository's policy.

### Explicit enumeration, no wildcards

Today's YAML supports `*` for namespaces and deployments — `policy_test.go` has
`tuncloud/infra` with `namespaces: ["*"], deployments: ["*"]`. Keycloak resources do
not glob on name, only on URI, and no catch-all resource will be introduced.

Every namespace/deployment a repository may touch is a real resource in Keycloak.
The cost is more objects to create; the benefit is that breadth is always visible in
the UI and there is no mechanism by which a grant can silently cover the cluster.

**Migration consequence:** existing `*` entries cannot be translated mechanically. A
human must decide what each such repository actually needs.

## Gateway architecture

### The contract gains a third outcome

Today `Authorize` returns a bare `bool`, and both handlers treat `false` as DENIED
(`server.go:80`, `server.go:147`). Once the decision crosses a network there are
three outcomes, and collapsing them is a real bug: a Keycloak outage would be
written to the audit table as a policy denial and returned as `403 FORBIDDEN`,
sending someone to debug a permission they already have.

```go
// internal/authz
type Request struct {
    Repository, Action, Namespace, Deployment, Ref string
}

type Decision struct {
    Allowed bool
    Reason  string // carried into the audit row on denial
}

type Authorizer interface {
    Authorize(ctx context.Context, req Request) (Decision, error)
}
```

`api.Deps.Policy *authz.Policy` becomes `api.Deps.Authz authz.Authorizer`.

### Package layout

- `internal/authz` — the `Authorizer` interface, `Request`, `Decision`, and the ref
  matching function. No Keycloak wire types.
- `internal/keycloak` — the HTTP client: service-account token acquisition and
  refresh, the `policy/evaluate` call, resource-attribute reads, and the caches.
  The Keycloak authorizer lives here and implements `authz.Authorizer`.

Keycloak's wire shapes stay out of `authz`, so the admin-API surface is confined to
one package with one seam to test against a stub server.

**How a ref constraint reaches the matcher.** `internal/keycloak` owns fetching:
it calls `policy/evaluate` for the grant, reads the resource's `allowed_refs`
attributes, and then calls the exported ref-matching function in `internal/authz`
with those constraint strings and the request's `Ref`. Matching logic therefore has
no Keycloak dependency and is unit-testable on its own; fetching has no matching
logic. A grant that evaluates to `PERMIT` but fails the ref match is a DENY with a
ref-specific `Reason`.

### Lookups and caching

`policy/evaluate` needs the resource server's internal client UUID and the subject's
user UUID — not the username. So:

| Lookup | When | Cached |
|---|---|---|
| `clientId` → client UUID | first use | for process lifetime |
| `repository` → user UUID | per new repository | TTL; "no such user" is a clean DENY |
| decision | per request | 30s, PERMIT only (see below) |
| resource `allowed_refs` | per new resource | TTL, independent of decision cache |

Warm path is **one** HTTP call per deploy.

## Ref restrictions

The `ref` claim is already available as `authn.GitHubIdentity.Ref` and is currently
unused. No changes to `internal/authn`.

### Where the constraint lives

As resource attributes on the Keycloak resource, keyed per action:

- `allowed_refs.deployment.rollout`
- `allowed_refs.deployment.restart`
- `allowed_refs` — fallback when no action-specific key is set

The per-action split exists because the README already draws this distinction:
*"grant `deployment.rollout` more narrowly than `deployment.restart` (a restart
can't change code, a rollout can)"*. This lets `backend/backend-api` accept a
restart from any branch while admitting a rollout only from `main`.

Attributes sit on the **resource** rather than on the permission because resource
representations are reliably readable through the admin resource endpoint, whereas
it is not confirmed that scope-based-permission attributes are returned by the
evaluate response. The ref rule will not be built on an unverified field of an API
already being treated with care.

### Matching rules

Deliberately dumb — no regex, no policy language:

| Pattern | Matches |
|---|---|
| `refs/heads/main` | that ref exactly |
| `*` | any ref |
| `refs/heads/release/*` | any ref with that prefix |

Trailing globs cover tags for free (`refs/tags/v*`); prefix matching does not care
that it is a tag.

### Defaults

- **Attribute absent → unrestricted.** This is the only safe migration default:
  there is no ref check today, so treating a missing attribute as "deny" would break
  every repository at cutover.
- **Attribute present but malformed → deny.** A typo in a constraint fails closed.

### Audit distinguishability

A ref rejection writes a different `Reason` than a missing grant, so the operations
table distinguishes "you need a permission" from "you pushed from the wrong branch".

## Failure posture

Keycloak is now in the deploy hot path. This section decides whether that is a net
win or a new outage source.

**Fail closed.** An unreachable Keycloak means the caller's permission cannot be
proven, and this service patches production workloads. The response is
`503 AUTHZ_UNAVAILABLE`, deliberately *not* `403 FORBIDDEN`.

**Bounded stale-while-unavailable.** Pure fail-closed would mean a 20-second
Keycloak restart fails every in-flight deploy. Therefore:

- `PERMIT` decisions are cached for **30s**, keyed by
  `(repository, action, namespace, deployment, ref)`.
- While Keycloak is unreachable, cached permits keep being served for up to
  **5 minutes** past their TTL.
- `DENY` is **never** cached.

Consequences, stated plainly:

| Event | Effect |
|---|---|
| Brief Keycloak blip | invisible to callers |
| Sustained Keycloak outage | deploys fail closed within 5 minutes |
| Granting access | takes effect immediately |
| Revoking access | takes effect within 30s; up to 5 min during an outage |

The accepted exposure is one additional deploy from a repository that was trusted 30
seconds earlier.

**Timeouts.** The router's existing `middleware.Timeout(30 * time.Second)` is far
too loose to be the only bound. Keycloak calls get a 3s per-call timeout and one
retry on connection error or 5xx, so the worst-case authz budget is ~7s and a slow
Keycloak degrades to `503` rather than hanging the caller's workflow.

**No fail-fast at boot.** `LoadPolicy` failing calls `os.Exit(1)`
(`main.go:42-45`), which is right for a local file and wrong for a network
dependency — it would turn a Keycloak hiccup during a gateway rollout into a
crashlooping gateway, at the worst possible moment. Instead: resolve Keycloak
configuration lazily, log a warning, and extend `/readyz` (which today pings only
the store, `server.go:233`) to report not-ready until first successful Keycloak
contact. Kubernetes then withholds traffic without killing the pod.

**Outage events go to logs and metrics, not the audit table.** A denial is a durable
security decision about a caller and belongs in DynamoDB. An outage is a gateway
health event, and writing audit rows for every failed request during an incident
would add DynamoDB write load exactly when things are already bad.

## Refactor folded in

`handleRestart` and `handleRollout` each contain a ~30-line, near-identical block
building a `store.Operation` for the denial audit row (`server.go:81-107` and
`server.go:148-175`). Adding a third outcome to both copies would make the
duplication worse. It is extracted to a single helper as part of this work — code
already being edited, not a side quest.

## Configuration

| Variable | Purpose |
|---|---|
| `AUTHZ_BACKEND` | `file`, `keycloak`, or `shadow`; selects the implementation |
| `KEYCLOAK_BASE_URL` | Keycloak base URL |
| `KEYCLOAK_REALM` | realm name |
| `KEYCLOAK_CLIENT_ID` | the `deploy-gateway` resource-server client |
| `KEYCLOAK_CLIENT_SECRET` | service-account secret, from a Secret |

`KEYCLOAK_CLIENT_SECRET` gets the same discipline the README already establishes for
the Telegram bot token: never logged, never surfaced in transport errors, because it
sits in the request path.

**Service-account privileges** must be documented to a minimum set. The evaluate
call and resource reads need realm-management roles in the `view-clients` /
`view-authorization` family. Whether read-only roles suffice or
`manage-authorization` is required is an open question (below) — "the gateway holds
a token that can rewrite your realm's authz config" is a materially different
security story and must be known before committing.

## Migration

Sequenced deliberately; the file backend is removed only after Keycloak has proven
itself.

1. **Build.** Introduce the `Authorizer` interface; rename today's `authz.Policy` to
   `authz.FileAuthorizer` implementing it (mostly a rename — it already works and is
   already tested). Add `internal/keycloak` and the Keycloak authorizer.
2. **Populate Keycloak by hand.** Create the scopes, resources, per-repo users, user
   policies, and scope-based permissions through the Keycloak UI. No converter tool:
   the object count is small enough that clicking through once is faster than
   writing and testing a converter, and it forces a deliberate look at every
   existing grant — which the dropped wildcards require anyway.
3. **Shadow mode** (`AUTHZ_BACKEND=shadow`). The **file** authorizer's decision is
   the one returned to the caller and the one written to the audit table. Keycloak is
   called in addition, purely to log agreement or disagreement. A Keycloak DENY, a
   Keycloak error, and a Keycloak timeout are **all** non-fatal in this mode: they
   are logged and discarded, and can never change a response or an audit row. Run
   against real deploy traffic until the disagreement log is clean. This is the
   de-risking step — it surfaces a wrong object model during a validation window
   rather than during a production hotfix.
4. **Flip** `AUTHZ_BACKEND=keycloak`. Rollback is an env var and a pod restart, not
   a code revert and a release.
5. **Remove the file backend** — `internal/authz/policy.go`'s file loading,
   `policy.example.yaml`, the `deploy-gateway-policy` ConfigMap, and shadow mode.

### Accepted consequence of step 5

Deleting the file backend removes the escape hatch, so the bounded
stale-while-unavailable window becomes the *only* resilience against a Keycloak
problem. This is accepted knowingly, which is why step 5 is a separate, later change
rather than part of the cutover commit.

### Documentation

- The README's *"must be listed in the gateway policy ConfigMap
  (`deploy-gateway-policy`, namespace `platform-system`); after editing it, run
  `kubectl -n platform-system rollout restart deploy/deploy-gateway`"* paragraph is
  the thing this project exists to delete. It is replaced by the Keycloak onboarding
  flow.
- The Security section's note about granting `deployment.rollout` narrowly now has a
  concrete mechanism to point at: `allowed_refs.deployment.rollout`.
- New: Keycloak configuration, required service-account roles, the failure posture
  and its timing table, and the manual re-verification step below.

## Testing

**Unit, no Keycloak.** Ref matching (exact, `*`, trailing glob, malformed-denies,
absent-allows) is pure logic and gets table-driven tests. The three-outcome contract
is likewise pure.

**Wire contract, stubbed.** `internal/keycloak` is tested against an
`httptest.Server` returning canned responses: `PERMIT`, `DENY`, 500, timeout, and a
401-then-successful-refresh proving token renewal. This pins the admin API's shape
in code.

**Cache behaviour needs an injectable clock.** TTL expiry and the 5-minute stale
window cannot be tested with `time.Sleep` without a slow, flaky suite. The codebase
calls `time.Now()` directly (`server.go:81`, `server.go:148`), so a minimal clock
seam is introduced **scoped to the authz cache only** — not a codebase-wide
refactor.

**Handler tests get simpler.** `server_test.go:59-80` currently writes a YAML policy
to a temp dir and passes `Policy: pol`; with the interface it injects a fake
authorizer instead, covering:

- PERMIT → `202`
- DENY → `403` plus an audit row
- UNAVAILABLE → `503` and **no** audit row

That last assertion protects the central failure-posture decision from silent
regression.

**No automated integration test against a real Keycloak.** The real contract is
verified by hand during the spike and the shadow-mode window; stubs cover it
thereafter.

### Accepted consequence

Nothing automatically catches a contract change on Keycloak upgrade. Mitigation:
the stub tests document the expected request and response shapes precisely, and the
README gains an explicit step requiring manual re-verification of the
`policy/evaluate` contract as part of any Keycloak major/minor upgrade.

## Open questions for the spike

To be answered against the real Keycloak 26.x before implementation is committed:

1. Does `policy/evaluate` accept the subject shape we plan to send, and does a
   credential-less user work as an evaluation subject?
2. What is the **minimum** set of service-account realm-management roles that makes
   the evaluate call and resource-attribute reads succeed? Specifically: do
   read-only roles suffice, or is `manage-authorization` required?
3. What exactly does the evaluate response return — confirm `PERMIT`/`DENY` at the
   level we intend to read, and confirm whether resource attributes come back with
   it (which would remove the separate attribute read).
4. Is a client subject viable as an alternative to a per-repo user? If so it removes
   per-repo user objects.

## Risks

| Risk | Mitigation |
|---|---|
| Admin API contract changes on upgrade | quarantined in `internal/keycloak`; stub tests pin the shape; manual re-verification step in the README upgrade docs |
| Keycloak becomes a deploy-blocking dependency | fail closed with bounded stale-while-unavailable; tight timeouts; `/readyz` gating |
| Broad service-account privileges | spike question 2 pins the minimum role set before commit |
| Revoked access remains usable briefly | bounded to 30s normally, 5 min during an outage; `DENY` never cached |
| Enumerating resources is tedious | accepted in exchange for grants always being visible; revisit only if it proves painful |
| No escape hatch after step 5 | step 5 is deliberately sequenced after shadow-mode validation and a successful cutover |
