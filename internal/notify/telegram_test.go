package notify

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

type recorded struct {
	method string
	body   map[string]any
}

// fakeTelegram serves the Bot API surface the transport uses and records every
// request. handler decides the response for each call.
func fakeTelegram(t *testing.T, handler func(w http.ResponseWriter, r recorded)) (string, func() []recorded) {
	t.Helper()
	var mu sync.Mutex
	var got []recorded
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		parts := strings.Split(r.URL.Path, "/")
		rec := recorded{method: parts[len(parts)-1], body: body}
		mu.Lock()
		got = append(got, rec)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		handler(w, rec)
	}))
	t.Cleanup(srv.Close)
	return srv.URL, func() []recorded {
		mu.Lock()
		defer mu.Unlock()
		return append([]recorded{}, got...)
	}
}

func testTransport(t *testing.T, base string) *transport {
	t.Helper()
	tp := newTransport(base, "secret-token", slog.Default())
	tp.retryBase = 10 * time.Millisecond
	return tp
}

func TestSendReturnsMessageID(t *testing.T) {
	base, requests := fakeTelegram(t, func(w http.ResponseWriter, _ recorded) {
		w.Write([]byte(`{"ok":true,"result":{"message_id":4242}}`))
	})
	tp := testTransport(t, base)

	id, err := tp.send(context.Background(), "-100777", "hello")
	if err != nil {
		t.Fatal(err)
	}
	if id != 4242 {
		t.Fatalf("message id = %d, want 4242", id)
	}
	reqs := requests()
	if len(reqs) != 1 || reqs[0].method != "sendMessage" {
		t.Fatalf("requests = %+v, want one sendMessage", reqs)
	}
	if reqs[0].body["chat_id"] != "-100777" || reqs[0].body["text"] != "hello" ||
		reqs[0].body["parse_mode"] != "HTML" {
		t.Fatalf("payload = %+v", reqs[0].body)
	}
}

func TestEditPostsMessageID(t *testing.T) {
	base, requests := fakeTelegram(t, func(w http.ResponseWriter, _ recorded) {
		w.Write([]byte(`{"ok":true,"result":{"message_id":4242}}`))
	})
	tp := testTransport(t, base)

	if err := tp.edit(context.Background(), "-100777", 4242, "done"); err != nil {
		t.Fatal(err)
	}
	reqs := requests()
	if len(reqs) != 1 || reqs[0].method != "editMessageText" {
		t.Fatalf("requests = %+v, want one editMessageText", reqs)
	}
	if got, ok := reqs[0].body["message_id"].(float64); !ok || int64(got) != 4242 {
		t.Fatalf("message_id = %v", reqs[0].body["message_id"])
	}
}

func TestRetriesOn429HonoringRetryAfter(t *testing.T) {
	var calls int
	var mu sync.Mutex
	base, requests := fakeTelegram(t, func(w http.ResponseWriter, _ recorded) {
		mu.Lock()
		calls++
		first := calls == 1
		mu.Unlock()
		if first {
			w.WriteHeader(http.StatusTooManyRequests)
			w.Write([]byte(`{"ok":false,"description":"Too Many Requests","parameters":{"retry_after":1}}`))
			return
		}
		w.Write([]byte(`{"ok":true,"result":{"message_id":7}}`))
	})
	tp := testTransport(t, base)

	start := time.Now()
	id, err := tp.send(context.Background(), "-100777", "hello")
	elapsed := time.Since(start)

	if err != nil {
		t.Fatal(err)
	}
	if id != 7 {
		t.Fatalf("message id = %d, want 7", id)
	}
	if len(requests()) != 2 {
		t.Fatalf("requests = %d, want 2", len(requests()))
	}
	// retry_after:1 must override the 10ms test backoff
	if elapsed < time.Second {
		t.Fatalf("elapsed = %v, want >= 1s (retry_after ignored)", elapsed)
	}
}

func TestGivesUpAfterMaxAttempts(t *testing.T) {
	base, requests := fakeTelegram(t, func(w http.ResponseWriter, _ recorded) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"ok":false,"description":"boom"}`))
	})
	tp := testTransport(t, base)

	if _, err := tp.send(context.Background(), "-100777", "hello"); err == nil {
		t.Fatal("persistent 5xx must return an error")
	}
	if got := len(requests()); got != maxAttempts {
		t.Fatalf("attempts = %d, want %d", got, maxAttempts)
	}
}

func TestDoesNotRetryClientError(t *testing.T) {
	base, requests := fakeTelegram(t, func(w http.ResponseWriter, _ recorded) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"ok":false,"description":"chat not found"}`))
	})
	tp := testTransport(t, base)

	err := tp.edit(context.Background(), "-100777", 1, "text")
	if err == nil {
		t.Fatal("400 must return an error")
	}
	if got := len(requests()); got != 1 {
		t.Fatalf("attempts = %d, want 1 (400 is not retryable)", got)
	}
}

func TestErrorsNeverLeakTheToken(t *testing.T) {
	// nothing listening: http.Client.Do returns a *url.Error carrying the full
	// URL, token included. The transport must not surface it.
	tp := testTransport(t, "http://127.0.0.1:1")
	_, err := tp.send(context.Background(), "-100777", "hello")
	if err == nil {
		t.Fatal("unreachable server must error")
	}
	if strings.Contains(err.Error(), "secret-token") {
		t.Fatalf("error leaks the bot token: %v", err)
	}
}
