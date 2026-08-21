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
