# deploy-gateway

Restarts Kubernetes Deployments on behalf of GitHub Actions via GitHub OIDC.
No kubeconfig, k8s tokens, or SSH keys in GitHub Secrets.

## API

| Method | Path | Auth | Result |
|---|---|---|---|
| POST | /v1/deployments/restart | GitHub OIDC JWT | `202 {operation_id, status:"running"}` |
| POST | /v1/deployments/rollout | GitHub OIDC JWT | `202 {operation_id, status:"running"}` |
| GET | /v1/operations/{id} | GitHub OIDC JWT | operation status |

Issuer `https://token.actions.githubusercontent.com`, audience
`https://gateway.tuando.app`.

### `POST /v1/deployments/rollout`

```json
{"namespace": "backend", "deployment": "backend-api", "image": "ghcr.io/org/api:v2.1.0"}
```

- `image` (required): new container image. Patches the deployment and watches
  the rollout — same operation tracking as restart.
- `container` (optional): target container name. Omitted, the gateway uses the
  pod's only container; if the pod spec has more than one, the request fails
  `400 AMBIGUOUS_CONTAINER` and `container` must be set explicitly.
- Rolling the same image again still rolls: the patch also stamps
  `kubectl.kubernetes.io/restartedAt`, so the pod template always changes and
  pods are always replaced — required for mutable tags (`:latest`, `:staging`).
- An operation reports `succeeded` only once every running pod is a new pod that
  is ready and available, and no pod from the previous ReplicaSet is left —
  the same bar as `kubectl rollout status`. Old pods finishing their termination
  grace period therefore keep the operation `running` for a few more seconds.
- A same-tag rollout now consumes the caller's workflow timeout budget:
  workflows that previously got an instant green check from re-pushing a
  mutable tag will now wait for a real rollout, so `timeout-seconds` in the
  reusable workflow (default 600, matching the gateway's own 10-minute
  deadline) may need raising.

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

An unset `AUTHZ_BACKEND` is not an error: `""` and `"file"` both select the
file backend — the same behavior as before Keycloak existed. That is a
deliberate backward-compatible default during migration, but it cuts the other
way once you're cut over: dropping the variable from the deployment manifest
silently reverts authorization to the static YAML policy, with no error
anywhere. A typo'd value (e.g. `Keycloack`) does fail loudly — the process
refuses to start. Once cut over, pin `AUTHZ_BACKEND=keycloak` explicitly in
the manifest rather than relying on its being set.

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

**Absence-means-unrestricted is a considered trade-off, not an oversight**:
there was no ref check at all before Keycloak, so treating an absent attribute
as a denial would break every repository at cutover. But it has a sharp edge
the rest of this system doesn't share. Everywhere else, an unexpected Keycloak
response fails *closed* — the gateway returns `503` rather than guess (see
below). Ref constraints are the one exception: if the resource-attributes
response doesn't decode the way the gateway expects, or a resource name
doesn't match, it decodes to zero attributes — indistinguishable from a
resource that's genuinely unrestricted. Ref constraints would then silently
stop being enforced, with no error anywhere. The one signal is a log line,
`keycloak resource not found; ref constraints cannot be applied` — worth
alerting on.

### Required service-account roles

The minimum realm-management roles the `deploy-gateway` client's service
account needs have **not been determined** — this has not been verified
against a live Keycloak. As a starting point, the roles believed necessary sit
in the `view-clients` / `view-users` / `view-authorization` family; treat that
as unverified.

To find the true minimum: start the service account with zero assigned roles,
add one role at a time, and re-test after each addition — both the
`policy/evaluate` call and the user lookup (`GET .../users?username=...`,
below) must succeed. Stop as soon as both do.

This matters beyond tidiness: if it turns out `manage-authorization` is
required rather than the `view-*` equivalents, the gateway would hold a token
that can rewrite the realm's authorization config — resources, policies,
permissions — not just read it. That's a materially different security
posture, worth knowing deliberately rather than discovering after
over-granting "to make it work."

### Verifying the Keycloak contract

**No Keycloak wire shape used by this gateway has been verified against a
live server.** The request and response shapes in `internal/keycloak/client.go`
(the `policy/evaluate` body and its `status` field, and the resource-attributes
response) are readings of the Admin REST API's documented behaviour, not
confirmed empirically — see the `UNVERIFIED` comments in that file. For
`policy/evaluate`, an unrecognised response falls through to an error, so the
gateway returns `503 AUTHZ_UNAVAILABLE` and fails closed rather than
mis-authorizing. The resource-attributes lookup does **not** fail closed — see
Ref restrictions above.

Confirm the contract yourself before cutover, and again after any Keycloak
major or minor upgrade: `policy/evaluate` is not a stability-promised API, and
there is no automated integration test that will catch a shape change.

1. Get a service-account token:

   ```bash
   TOKEN=$(curl -s -X POST \
     "$KEYCLOAK_BASE_URL/realms/$KEYCLOAK_REALM/protocol/openid-connect/token" \
     -d grant_type=client_credentials \
     -d client_id="$KEYCLOAK_CLIENT_ID" \
     -d client_secret="$KEYCLOAK_CLIENT_SECRET" \
   | jq -r .access_token)
   echo "${TOKEN:0:12}..."   # confirm it's non-empty without printing the whole token
   ```

2. Resolve the resource-server client's UUID (its internal `id`, not its
   `clientId`):

   ```bash
   CLIENT_UUID=$(curl -s -H "Authorization: Bearer $TOKEN" \
     "$KEYCLOAK_BASE_URL/admin/realms/$KEYCLOAK_REALM/clients?clientId=deploy-gateway" \
   | jq -r '.[0].id')
   echo "$CLIENT_UUID"
   ```

3. Resolve a repository's user UUID. The repository slug contains a `/` and
   must be URL-encoded as `%2F`:

   ```bash
   USER_UUID=$(curl -s -H "Authorization: Bearer $TOKEN" \
     "$KEYCLOAK_BASE_URL/admin/realms/$KEYCLOAK_REALM/users?username=tuncloud%2Fbackend&exact=true" \
   | jq -r '.[0].id')
   echo "$USER_UUID"
   ```

4. Evaluate a decision:

   ```bash
   curl -s -X POST \
     -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
     "$KEYCLOAK_BASE_URL/admin/realms/$KEYCLOAK_REALM/clients/$CLIENT_UUID/authz/resource-server/policy/evaluate" \
     -d '{
       "resources": [{"name": "backend/backend-api", "scopes": [{"name": "deployment.restart"}]}],
       "userId": "'"$USER_UUID"'",
       "entitlements": false,
       "context": {"attributes": {}}
     }' \
   | jq -r .status
   ```

   Confirm the response has a top-level `status` field and that it reads
   `PERMIT` for a grant that should be allowed, `DENY` for one that shouldn't.

5. Read a resource's attributes (the ref-restriction contract):

   ```bash
   curl -s -H "Authorization: Bearer $TOKEN" \
     "$KEYCLOAK_BASE_URL/admin/realms/$KEYCLOAK_REALM/clients/$CLIENT_UUID/authz/resource-server/resource?name=backend%2Fbackend-api&exactName=true" \
   | jq .
   ```

   Confirm the response is a JSON array whose first element has an
   `attributes` object mapping each attribute name to an array of strings —
   that's the shape ref-restriction lookups expect.

If any of these differs from what's described here, update the corresponding
types in `internal/keycloak/client.go` before relying on the affected path.

### When Keycloak is unavailable

The gateway fails **closed** and returns `503 AUTHZ_UNAVAILABLE` — never `403`,
so an outage is never reported to a caller as a permissions problem and never
written to the audit table as a denial.

| Event | Effect |
|---|---|
| brief Keycloak blip | invisible; cached permits are served |
| sustained outage | deploys fail closed within 5m30s of the last successful permit |
| granting access | immediate |
| revoking access | within 30s; up to 5m30s during an outage |

`PERMIT` decisions are cached 30s and served up to 5 minutes past that only
while Keycloak is unreachable. `DENY` is never cached. `/readyz` reports
not-ready until Keycloak has been reached once, so Kubernetes withholds traffic
rather than the gateway crashlooping.

Log lines worth grepping: `authorization unavailable`,
`serving stale authorization decision`, `malformed ref constraint, denying`,
`keycloak resource not found; ref constraints cannot be applied`,
`shadow authorizer disagrees`.

## Usage from a repository

```yaml
jobs:
  restart:
    uses: tuncloud/deploy-gateway/.github/workflows/restart-deployment.yml@v1
    permissions:
      id-token: write
      contents: read
    with:
      namespace: backend
      deployment: backend-api

  rollout:
    uses: tuncloud/deploy-gateway/.github/workflows/rollout-deployment.yml@v1
    permissions:
      id-token: write
      contents: read
    with:
      namespace: backend
      deployment: backend-api
      image: ghcr.io/tuncloud/backend-api:${{ github.sha }}
```

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

## Notifications

Set both variables to post a Telegram message per deploy. Unset, notifications
are disabled and the gateway logs `telegram notifications disabled` at startup.

| Variable | Purpose |
|---|---|
| `TELEGRAM_BOT_TOKEN` | bot token, from a Secret |
| `TELEGRAM_CHAT_ID` | destination chat (e.g. `-1001234567890`) |
| `TELEGRAM_API_BASE` | override the API host; defaults to `https://api.telegram.org` |

```bash
kubectl -n platform-system create secret generic deploy-gateway-telegram \
  --from-literal=bot-token='123456:ABC-DEF...'
```

```yaml
env:
  - name: TELEGRAM_BOT_TOKEN
    valueFrom:
      secretKeyRef:
        name: deploy-gateway-telegram
        key: bot-token
  - name: TELEGRAM_CHAT_ID
    value: "-1001234567890"
```

One message is posted when a deploy starts and edited in place when it
resolves:

```
🟡 rollout · backend/backend-api      →   ✅ rollout · backend/backend-api
ghcr.io/org/api:v2.1.0                    ghcr.io/org/api:v2.1.0
@octocat · run #4711                      @octocat · run #4711
                                          42s · op_01hxyzabc
```

Delivery is best-effort: sends are attempted up to three times total (two
retries) on rate limits and 5xx, and a notification that never lands is logged
and dropped. It never changes an operation's status or an API response — the
audit table remains the source of truth. Delivery itself is at-most-once: the
terminal write is what suppresses duplicate notifications (only the writer
that wins the terminal update sends), so if that store write succeeds but its
response is lost, the audit row is correct and the message is simply never
sent. Operations resolved by the reconciler or after a gateway restart post a
fresh terminal message instead of editing. Policy denials are not notified.

If messages aren't showing up in the chat:

- The bot must already be a member of the target chat. A wrong
  `TELEGRAM_CHAT_ID` yields a `400 chat not found`, which is deliberately not
  retried and only logged at warn level.
- Grep the gateway logs for: `telegram notifications disabled`,
  `telegram notifications enabled`, `telegram start notification failed`,
  `telegram terminal notification failed`, `telegram terminal edit failed`.

## Development

```
go test ./...                        # unit only
KUBEBUILDER_ASSETS=$(setup-envtest use 1.30.x -p path) go test ./...
podman build -t deploy-gateway:dev .
```

## Security

- JWTs are never logged, stored, or echoed.
- Audit records in DynamoDB table `deploy-gateway-operations` (TTL 365d).
- Kubernetes RBAC: get/list/watch/patch on deployments only.
- `deployment.rollout` controls which images run — grant it more narrowly than
  `deployment.restart` (a restart can't change code, a rollout can). Use
  `allowed_refs.deployment.rollout` to require a trusted branch for rollouts.
- The Keycloak client secret is never logged: it sits in the API request path,
  so request URLs and transport errors are never surfaced.
- An unreachable Keycloak fails closed (`503`), bounded by a 5m30s
  stale-permit window (30s cache TTL plus a 5-minute stale grace period).
  It is never reported as `403`.
- The Telegram bot token is never logged: it sits in the API request path, so
  request URLs and transport errors are never surfaced.
