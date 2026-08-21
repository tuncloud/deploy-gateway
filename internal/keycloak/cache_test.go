package keycloak

import (
	"sync"
	"testing"
	"time"
)

// testClock is a manually advanced Clock. TTL behaviour must be testable
// without time.Sleep, which would make the suite slow and flaky.
type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func newTestClock() *testClock {
	return &testClock{now: time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)}
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *testClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func TestCacheGetWithinTTL(t *testing.T) {
	clk := newTestClock()
	c := newCache[bool](30*time.Second, 5*time.Minute, clk)
	c.Put("k", true)

	clk.advance(29 * time.Second)
	if v, ok := c.Get("k"); !ok || !v {
		t.Fatal("entry must be fresh at 29s")
	}
}

func TestCacheGetExpiredAfterTTL(t *testing.T) {
	clk := newTestClock()
	c := newCache[bool](30*time.Second, 5*time.Minute, clk)
	c.Put("k", true)

	clk.advance(31 * time.Second)
	if _, ok := c.Get("k"); ok {
		t.Fatal("entry must be stale at 31s")
	}
}

// GetStale is what the authorizer falls back to when Keycloak is unreachable.
func TestCacheGetStaleWithinStaleWindow(t *testing.T) {
	clk := newTestClock()
	c := newCache[bool](30*time.Second, 5*time.Minute, clk)
	c.Put("k", true)

	clk.advance(4 * time.Minute)
	if _, ok := c.Get("k"); ok {
		t.Fatal("Get must not serve a stale entry")
	}
	if v, ok := c.GetStale("k"); !ok || !v {
		t.Fatal("GetStale must serve within the stale window")
	}
}

func TestCacheGetStaleBeyondStaleWindow(t *testing.T) {
	clk := newTestClock()
	c := newCache[bool](30*time.Second, 5*time.Minute, clk)
	c.Put("k", true)

	// TTL 30s + stale 5m = 5m30s of total usable life.
	clk.advance(5*time.Minute + 31*time.Second)
	if _, ok := c.GetStale("k"); ok {
		t.Fatal("GetStale must refuse beyond ttl+staleFor")
	}
}

func TestCacheMissingKey(t *testing.T) {
	c := newCache[bool](30*time.Second, 5*time.Minute, newTestClock())
	if _, ok := c.Get("absent"); ok {
		t.Fatal("Get on absent key must miss")
	}
	if _, ok := c.GetStale("absent"); ok {
		t.Fatal("GetStale on absent key must miss")
	}
}

func TestCachePutOverwritesAndRefreshes(t *testing.T) {
	clk := newTestClock()
	c := newCache[string](30*time.Second, 5*time.Minute, clk)
	c.Put("k", "first")

	clk.advance(20 * time.Second)
	c.Put("k", "second")

	clk.advance(20 * time.Second) // 40s since first Put, 20s since second
	v, ok := c.Get("k")
	if !ok {
		t.Fatal("re-Put must reset the TTL")
	}
	if v != "second" {
		t.Fatalf("Get = %q, want %q", v, "second")
	}
}
