package notify

import (
	"log/slog"
	"net/http"
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
	var first = true
	base, requests := fakeTelegram(t, func(w http.ResponseWriter, _ recorded) {
		if first {
			first = false
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

func TestStartedDoesNotBlockTheCaller(t *testing.T) {
	base, _ := fakeTelegram(t, func(w http.ResponseWriter, _ recorded) {
		time.Sleep(300 * time.Millisecond)
		w.Write([]byte(`{"ok":true,"result":{"message_id":903}}`))
	})
	n := testNotifier(t, base)

	start := time.Now()
	n.Started(runningRollout())
	if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
		t.Fatalf("Started blocked for %v; sends must be asynchronous", elapsed)
	}
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
