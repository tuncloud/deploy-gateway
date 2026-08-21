package keycloak

import "time"

// Clock exists so cache TTL and the stale-while-unavailable window are
// testable without sleeping. Scoped to this package only — this is not a
// codebase-wide time abstraction.
type Clock interface {
	Now() time.Time
}

type RealClock struct{}

func (RealClock) Now() time.Time { return time.Now() }
