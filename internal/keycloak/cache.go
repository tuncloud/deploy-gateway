package keycloak

import (
	"sync"
	"time"
)

type entry[V any] struct {
	value    V
	storedAt time.Time
}

// cache is a TTL cache with a bounded grace period. Get serves only fresh
// entries; GetStale additionally serves entries within staleFor past their
// TTL, and is used exclusively when Keycloak is unreachable.
type cache[V any] struct {
	mu       sync.RWMutex
	entries  map[string]entry[V]
	ttl      time.Duration
	staleFor time.Duration
	clock    Clock
}

func newCache[V any](ttl, staleFor time.Duration, clock Clock) *cache[V] {
	return &cache[V]{
		entries:  make(map[string]entry[V]),
		ttl:      ttl,
		staleFor: staleFor,
		clock:    clock,
	}
}

func (c *cache[V]) get(key string, maxAge time.Duration) (V, bool) {
	c.mu.RLock()
	e, ok := c.entries[key]
	c.mu.RUnlock()
	var zero V
	if !ok {
		return zero, false
	}
	if c.clock.Now().Sub(e.storedAt) > maxAge {
		return zero, false
	}
	return e.value, true
}

func (c *cache[V]) Get(key string) (V, bool) {
	return c.get(key, c.ttl)
}

func (c *cache[V]) GetStale(key string) (V, bool) {
	return c.get(key, c.ttl+c.staleFor)
}

func (c *cache[V]) Put(key string, v V) {
	c.mu.Lock()
	c.entries[key] = entry[V]{value: v, storedAt: c.clock.Now()}
	c.mu.Unlock()
}
