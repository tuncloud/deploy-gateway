package notify

import (
	"log/slog"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/tuncloud/deploy-gateway/internal/store"
)

// waitFor polls until cond holds or the deadline passes. Sends are
// asynchronous by design, so assertions poll rather than sleep.
func waitFor(t *testing.T, d time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition not met before deadline")
}

func testNotifier(t *testing.T, base string) *telegram {
	t.Helper()
	tp := testTransport(t, base)
	return &telegram{tp: tp, chatID: "-100777", log: slog.Default()}
}

func TestStartedThenResolvedEditsTheSameMessage(t *testing.T) {
	base, requests := fakeTelegram(t, func(w http.ResponseWriter, _ recorded) {
		w.Write([]byte(`{"ok":true,"result":{"message_id":900}}`))
	})
	n := testNotifier(t, base)
	op := runningRollout()

	msg := n.Started(op)
	waitFor(t, 2*time.Second, func() bool { return len(requests()) == 1 })

	n.Resolved(terminal(op, store.StatusSucceeded, 42*time.Second), msg)
	waitFor(t, 2*time.Second, func() bool { return len(requests()) == 2 })

	reqs := requests()
	if reqs[0].method != "sendMessage" {
		t.Fatalf("first call = %s, want sendMessage", reqs[0].method)
	}
	if reqs[1].method != "editMessageText" {
		t.Fatalf("second call = %s, want editMessageText", reqs[1].method)
	}
	if got, _ := reqs[1].body["message_id"].(float64); int64(got) != 900 {
		t.Fatalf("edited message_id = %v, want 900", reqs[1].body["message_id"])
	}
}

// TestResolvedOrdersAfterASlowStartSend is the regression test for handleWait
// exceeding callTimeout: Resolved is called immediately after Started, well
// before the delayed sendMessage could possibly have returned, so Resolved
// must still be waiting on the handle rather than giving up and posting a
// fresh terminal message ahead of it. The assertion is the *order* requests
// arrive at the fake server (recorded on arrival, not on handler completion)
// and the message_id the edit carries — not a wall-clock race.
func TestResolvedOrdersAfterASlowStartSend(t *testing.T) {
	base, requests := fakeTelegram(t, func(w http.ResponseWriter, r recorded) {
		if r.method == "sendMessage" {
			time.Sleep(300 * time.Millisecond)
		}
		w.Write([]byte(`{"ok":true,"result":{"message_id":950}}`))
	})
	n := testNotifier(t, base)
	op := runningRollout()

	msg := n.Started(op)
	n.Resolved(terminal(op, store.StatusSucceeded, 42*time.Second), msg)

	waitFor(t, 2*time.Second, func() bool { return len(requests()) == 2 })
	// give any spurious extra call a moment to arrive before asserting the
	// count is exactly two.
	time.Sleep(200 * time.Millisecond)

	reqs := requests()
	if len(reqs) != 2 {
		t.Fatalf("requests = %d, want exactly 2", len(reqs))
	}
	if reqs[0].method != "sendMessage" {
		t.Fatalf("first call = %s, want sendMessage", reqs[0].method)
	}
	if reqs[1].method != "editMessageText" {
		t.Fatalf("second call = %s, want editMessageText — a fresh sendMessage here means Resolved gave up waiting for the slow start send", reqs[1].method)
	}
	if got, _ := reqs[1].body["message_id"].(float64); int64(got) != 950 {
		t.Fatalf("edited message_id = %v, want 950 (the id the delayed sendMessage returned)", reqs[1].body["message_id"])
	}
}

func TestResolvedWithoutHandlePostsFreshMessage(t *testing.T) {
	base, requests := fakeTelegram(t, func(w http.ResponseWriter, _ recorded) {
		w.Write([]byte(`{"ok":true,"result":{"message_id":901}}`))
	})
	n := testNotifier(t, base)

	// nil handle: the sweeper, a lazy GET, or a restarted gateway resolving an
	// operation this process never announced
	n.Resolved(terminal(runningRollout(), store.StatusTimeout, time.Hour), nil)

	waitFor(t, 2*time.Second, func() bool { return len(requests()) == 1 })
	if got := requests()[0].method; got != "sendMessage" {
		t.Fatalf("method = %s, want sendMessage", got)
	}
}

func TestResolvedAfterFailedSendPostsFreshMessage(t *testing.T) {
	var mu sync.Mutex
	first := true
	base, requests := fakeTelegram(t, func(w http.ResponseWriter, _ recorded) {
		mu.Lock()
		wasFirst := first
		first = false
		mu.Unlock()
		if wasFirst {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"ok":false,"description":"chat not found"}`))
			return
		}
		w.Write([]byte(`{"ok":true,"result":{"message_id":902}}`))
	})
	n := testNotifier(t, base)
	op := runningRollout()

	msg := n.Started(op)
	waitFor(t, 2*time.Second, func() bool { return len(requests()) == 1 })

	n.Resolved(terminal(op, store.StatusSucceeded, time.Second), msg)
	waitFor(t, 2*time.Second, func() bool { return len(requests()) == 2 })

	if got := requests()[1].method; got != "sendMessage" {
		t.Fatalf("method = %s, want sendMessage (no id to edit)", got)
	}
}

// TestResolvedGivesUpAndPostsFreshMessage shortens handleWait for this test
// only, and points at a server whose first sendMessage never answers within
// that window. Resolved must give up waiting on the handle and post a fresh
// message instead of hanging or editing a message that never got an id.
func TestResolvedGivesUpAndPostsFreshMessage(t *testing.T) {
	saved := handleWait
	handleWait = 50 * time.Millisecond
	t.Cleanup(func() { handleWait = saved })

	var mu sync.Mutex
	sendCalls := 0
	base, requests := fakeTelegram(t, func(w http.ResponseWriter, r recorded) {
		if r.method == "sendMessage" {
			mu.Lock()
			sendCalls++
			isFirstSend := sendCalls == 1
			mu.Unlock()
			if isFirstSend {
				// Slower than the shortened handleWait, so Resolved must give
				// up waiting for this send's id before this even responds.
				time.Sleep(300 * time.Millisecond)
			}
		}
		w.Write([]byte(`{"ok":true,"result":{"message_id":961}}`))
	})
	n := testNotifier(t, base)
	op := runningRollout()

	msg := n.Started(op)
	n.Resolved(terminal(op, store.StatusSucceeded, time.Second), msg)

	waitFor(t, 2*time.Second, func() bool { return len(requests()) == 2 })

	if got := requests()[1].method; got != "sendMessage" {
		t.Fatalf("method = %s, want sendMessage (Resolved must give up waiting and post a fresh message)", got)
	}
}

func TestStartedDoesNotBlockTheCaller(t *testing.T) {
	base, requests := fakeTelegram(t, func(w http.ResponseWriter, _ recorded) {
		time.Sleep(300 * time.Millisecond)
		w.Write([]byte(`{"ok":true,"result":{"message_id":903}}`))
	})
	n := testNotifier(t, base)

	start := time.Now()
	n.Started(runningRollout())
	if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
		t.Fatalf("Started blocked for %v; sends must be asynchronous", elapsed)
	}

	// Drain the in-flight send before the fake server is torn down (via
	// t.Cleanup), so the background goroutine settles inside this test's
	// window instead of racing the next test's fake server shutdown.
	waitFor(t, 2*time.Second, func() bool { return len(requests()) == 1 })
}

func TestDisabledPerformsNoRequests(t *testing.T) {
	base, requests := fakeTelegram(t, func(w http.ResponseWriter, _ recorded) {
		w.Write([]byte(`{"ok":true,"result":{"message_id":904}}`))
	})
	_ = base

	n := Disabled()
	msg := n.Started(runningRollout())
	n.Resolved(terminal(runningRollout(), store.StatusSucceeded, time.Second), msg)

	time.Sleep(100 * time.Millisecond)
	if got := len(requests()); got != 0 {
		t.Fatalf("requests = %d, want 0", got)
	}
	if msg != nil {
		t.Fatal("disabled notifier must return a nil handle")
	}
}

func TestNewWithoutCredentialsIsDisabled(t *testing.T) {
	if _, ok := New(Config{ChatID: "-100777"}, slog.Default()).(disabled); !ok {
		t.Fatal("missing bot token must yield the disabled notifier")
	}
	if _, ok := New(Config{BotToken: "t"}, slog.Default()).(disabled); !ok {
		t.Fatal("missing chat id must yield the disabled notifier")
	}
	if _, ok := New(Config{BotToken: "t", ChatID: "-1"}, slog.Default()).(*telegram); !ok {
		t.Fatal("complete config must yield the telegram notifier")
	}
}

// New must own the api.telegram.org default: callers (main.go included)
// should be able to leave APIBase empty and still get a working notifier.
func TestNewDefaultsAPIBaseToTelegramDotOrg(t *testing.T) {
	n, ok := New(Config{BotToken: "t", ChatID: "-1"}, slog.Default()).(*telegram)
	if !ok {
		t.Fatal("complete config must yield the telegram notifier")
	}
	if got := n.tp.baseURL; got != "https://api.telegram.org" {
		t.Fatalf("baseURL = %q, want https://api.telegram.org", got)
	}
}
