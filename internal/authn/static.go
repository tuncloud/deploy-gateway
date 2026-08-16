package authn

import "context"

type staticVerifier struct{ identity *GitHubIdentity }

func NewStaticVerifier(id *GitHubIdentity) *staticVerifier { return &staticVerifier{identity: id} }

func (s *staticVerifier) Verify(_ context.Context, _ string) (*GitHubIdentity, error) {
	return s.identity, nil
}
