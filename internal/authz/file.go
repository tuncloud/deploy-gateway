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
