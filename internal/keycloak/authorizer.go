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
