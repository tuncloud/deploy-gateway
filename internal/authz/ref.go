package authz

import (
	"errors"
	"strings"
)

// ErrMalformedRefConstraint: a constraint was present but unparseable. A typo
// in a ref constraint fails closed rather than silently permitting everything.
var ErrMalformedRefConstraint = errors.New("malformed ref constraint")

// MatchRef reports whether ref satisfies any of the allowed patterns.
//
// An empty allowed list is unrestricted — this is the migration-safe default,
// since there was no ref check at all before Keycloak.
//
// Patterns are deliberately dumb, with no regex:
//   - "*"                    matches any ref
//   - "refs/heads/main"      exact match
//   - "refs/heads/release/*" prefix match on everything before the trailing *
//
// A "*" anywhere but the final character, or an empty pattern, is malformed
// and denies.
func MatchRef(allowed []string, ref string) (bool, error) {
	if len(allowed) == 0 {
		return true, nil
	}
	// Validate every pattern before matching any, so a malformed entry cannot
	// be masked by an earlier successful match.
	for _, p := range allowed {
		if p == "*" {
			continue
		}
		if p == "" {
			return false, ErrMalformedRefConstraint
		}
		if i := strings.IndexByte(p, '*'); i >= 0 && i != len(p)-1 {
			return false, ErrMalformedRefConstraint
		}
	}
	if ref == "" {
		return false, nil
	}
	for _, p := range allowed {
		if p == "*" {
			return true, nil
		}
		if strings.HasSuffix(p, "*") {
			if strings.HasPrefix(ref, strings.TrimSuffix(p, "*")) {
				return true, nil
			}
			continue
		}
		if p == ref {
			return true, nil
		}
	}
	return false, nil
}
