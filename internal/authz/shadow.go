package authz

import (
	"context"
	"log/slog"
	"time"
)

// shadowTimeout bounds the shadow call so validation can never stall a real
// deploy. It is independent of the primary's own budget.
const shadowTimeout = 3 * time.Second

// Shadow runs two authorizers: primary decides, shadow is observed. The
// shadow's decision, denial, error, and timeout are all logged and discarded —
// they can never change a response or an audit row. This is how the Keycloak
// object model gets validated against real traffic before the cutover.
type Shadow struct {
	primary Authorizer
	shadow  Authorizer
	log     *slog.Logger
}

func NewShadow(primary, shadow Authorizer, log *slog.Logger) *Shadow {
	return &Shadow{primary: primary, shadow: shadow, log: log}
}

func (s *Shadow) Authorize(ctx context.Context, req Request) (Decision, error) {
	dec, err := s.primary.Authorize(ctx, req)

	shadowCtx, cancel := context.WithTimeout(ctx, shadowTimeout)
	defer cancel()
	shadowDec, shadowErr := s.shadow.Authorize(shadowCtx, req)

	switch {
	case shadowErr != nil:
		s.log.Warn("shadow authorizer unavailable",
			"repository", req.Repository, "action", req.Action,
			"namespace", req.Namespace, "deployment", req.Deployment,
			"err", shadowErr)
	case err != nil:
		// Primary failed, so there is nothing to compare against.
		s.log.Warn("primary authorizer unavailable, shadow not compared",
			"repository", req.Repository, "action", req.Action)
	case shadowDec.Allowed != dec.Allowed:
		s.log.Warn("shadow authorizer disagrees",
			"repository", req.Repository, "action", req.Action,
			"namespace", req.Namespace, "deployment", req.Deployment,
			"ref", req.Ref,
			"primary_allowed", dec.Allowed, "shadow_allowed", shadowDec.Allowed,
			"shadow_reason", shadowDec.Reason)
	default:
		s.log.Info("shadow authorizer agrees",
			"repository", req.Repository, "action", req.Action,
			"namespace", req.Namespace, "deployment", req.Deployment,
			"allowed", dec.Allowed)
	}

	return dec, err
}
