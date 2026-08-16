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
- Rolling the same image again is a no-op rollout: the patch doesn't change the
  pod template, no new generation is created, and the operation resolves as
  succeeded against the current generation.

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
