package authn

import (
	"context"
	"fmt"

	"github.com/coreos/go-oidc/v3/oidc"
)

type GitHubIdentity struct {
	Subject         string `json:"sub"`
	Repository      string `json:"repository"`
	RepositoryID    string `json:"repository_id"`
	RepositoryOwner string `json:"repository_owner"`
	Ref             string `json:"ref"`
	Workflow        string `json:"workflow"`
	WorkflowRef     string `json:"workflow_ref"`
	Environment     string `json:"environment"`
	Actor           string `json:"actor"`
	EventName       string `json:"event_name"`
	RunID           string `json:"run_id"`
	RunAttempt      string `json:"run_attempt"`
}

type Verifier struct {
	provider *oidc.Provider
	verifier *oidc.IDTokenVerifier
}

func NewVerifier(ctx context.Context, issuer, audience string) (*Verifier, error) {
	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, fmt.Errorf("oidc discovery: %w", err)
	}
	return &Verifier{
		provider: provider,
		verifier: provider.Verifier(&oidc.Config{ClientID: audience}),
	}, nil
}

func (v *Verifier) Verify(ctx context.Context, rawToken string) (*GitHubIdentity, error) {
	idToken, err := v.verifier.Verify(ctx, rawToken)
	if err != nil {
		return nil, fmt.Errorf("verify token: %w", err)
	}
	id := &GitHubIdentity{}
	if err := idToken.Claims(id); err != nil {
		return nil, fmt.Errorf("extract claims: %w", err)
	}
	if id.Repository == "" {
		return nil, fmt.Errorf("missing repository claim")
	}
	return id, nil
}
