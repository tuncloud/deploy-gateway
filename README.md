# deploy-gateway

Restarts Kubernetes Deployments on behalf of GitHub Actions via GitHub OIDC.
No kubeconfig, k8s tokens, or SSH keys in GitHub Secrets.

## API

| Method | Path | Auth | Result |
|---|---|---|---|
| POST | /v1/deployments/restart | GitHub OIDC JWT | `202 {operation_id, status:"running"}` |
| GET | /v1/operations/{id} | GitHub OIDC JWT | operation status |

Issuer `https://token.actions.githubusercontent.com`, audience
`https://gateway.tuando.app`.

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
