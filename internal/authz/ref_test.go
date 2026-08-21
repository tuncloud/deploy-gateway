package authz_test

import (
	"errors"
	"testing"

	"github.com/tuncloud/deploy-gateway/internal/authz"
)

func TestMatchRef(t *testing.T) {
	tests := []struct {
		name    string
		allowed []string
		ref     string
		want    bool
	}{
		{"nil allowed is unrestricted", nil, "refs/heads/anything", true},
		{"empty allowed is unrestricted", []string{}, "refs/heads/anything", true},
		{"exact match", []string{"refs/heads/main"}, "refs/heads/main", true},
		{"exact mismatch", []string{"refs/heads/main"}, "refs/heads/dev", false},
		{"star matches anything", []string{"*"}, "refs/heads/dev", true},
		{"prefix glob matches", []string{"refs/heads/release/*"}, "refs/heads/release/1.2", true},
		{"prefix glob rejects sibling", []string{"refs/heads/release/*"}, "refs/heads/main", false},
		{"prefix glob matches tags", []string{"refs/tags/v*"}, "refs/tags/v2.1.0", true},
		{"any of several", []string{"refs/heads/main", "refs/tags/v*"}, "refs/tags/v1", true},
		{"none of several", []string{"refs/heads/main", "refs/tags/v*"}, "refs/heads/dev", false},
		{"empty ref with constraints denies", []string{"refs/heads/main"}, "", false},
		{"glob does not match its own prefix without separator", []string{"refs/heads/release/*"}, "refs/heads/release", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := authz.MatchRef(tt.allowed, tt.ref)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("MatchRef(%q, %q) = %v, want %v", tt.allowed, tt.ref, got, tt.want)
			}
		})
	}
}

func TestMatchRefMalformedDenies(t *testing.T) {
	malformed := [][]string{
		{""},                        // empty pattern
		{"refs/*/main"},             // star not at the end
		{"refs/heads/**"},           // double star
		{"refs/heads/main", "a*b"},  // one bad pattern poisons the set
	}
	for _, allowed := range malformed {
		got, err := authz.MatchRef(allowed, "refs/heads/main")
		if !errors.Is(err, authz.ErrMalformedRefConstraint) {
			t.Fatalf("MatchRef(%q) error = %v, want ErrMalformedRefConstraint", allowed, err)
		}
		if got {
			t.Fatalf("MatchRef(%q) = true, malformed constraints must deny", allowed)
		}
	}
}
