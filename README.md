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
- A same-tag rollout now consumes the caller's workflow timeout budget:
  workflows that previously got an instant green check from re-pushing a
  mutable tag will now wait for a real rollout, so `timeout-seconds` in the
  reusable workflow (default 600, matching the gateway's own 10-minute
  deadline) may need raising.

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

The repository must be listed in the gateway policy ConfigMap
(`deploy-gateway-policy`, namespace `platform-system`); after editing it, run
`kubectl -n platform-system rollout restart deploy/deploy-gateway`.

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
  `deployment.restart` (a restart can't change code, a rollout can).
- The Telegram bot token is never logged: it sits in the API request path, so
  request URLs and transport errors are never surfaced.
