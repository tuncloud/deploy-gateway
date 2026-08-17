# Same-Tag Rollouts and Telegram Notifications Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make every rollout actually roll pods even when the image tag is unchanged, and post one Telegram message per deploy that is edited in place when the operation resolves.

**Architecture:** The rollout patch gains the same `kubectl.kubernetes.io/restartedAt` annotation restart already uses, so the pod template always changes and the existing generation-based evaluation reports *progressing* instead of instantly succeeding. A new `internal/notify` package renders operations into Telegram messages behind a best-effort, non-blocking `Notifier` interface; `operation.Manager` calls `Started` after a successful patch and `Resolved` from its three terminal helpers, gated on `store.UpdateTerminal` succeeding so exactly one writer notifies.

**Tech Stack:** Go 1.26.5, standard library only for the notifier (`net/http`, `encoding/json`, `log/slog`), client-go + envtest for Kubernetes tests, `httptest` for the fake Telegram API.

**Spec:** `docs/superpowers/specs/2026-08-17-rollout-same-tag-telegram-notifications-design.md`

## Global Constraints

- Go 1.26.5. **No new module dependencies** — the notifier is stdlib only.
- **Never log the bot token, a Telegram URL, or anything derived from them.** The token sits in the request path, so `*url.Error` values from `http.Client.Do` (which embed the full URL) must never be wrapped or logged. Same rule the codebase applies to JWTs.
- **No DynamoDB schema changes, no `store.Store` interface changes, no `policy.yaml` changes.**
- Notification failures must never change an operation's status, the HTTP response, or returned errors.
- Tests use external `_test` packages (`package operation_test`) as the codebase does, **except** `internal/notify` tests, which need access to unexported types and use `package notify`.
- Kubernetes tests require envtest: `KUBEBUILDER_ASSETS=$(setup-envtest use 1.30.x -p path) go test ./...`
- Emoji status markers: 🟡 running, ✅ succeeded, ❌ failed, ⏱ timeout.

---

### Task 1: Same-tag rollout forces a pod-template change

**Files:**
- Modify: `internal/kube/client.go:48-80` (both patch builders)
- Test: `internal/kube/client_test.go:69-98` (invert an existing assertion), plus a new test

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces: no signature changes. `RolloutDeployment(ctx, namespace, name, container, image string) error` keeps its shape; only the patch body changes.

- [ ] **Step 1: Invert the existing assertion that forbids the annotation**

In `internal/kube/client_test.go`, inside `TestRolloutUpdatesImageSingleContainer`, replace this block:

```go
	if _, ok := after.Spec.Template.Annotations["kubectl.kubernetes.io/restartedAt"]; ok {
		t.Fatal("rollout must not set restartedAt")
	}
```

with:

```go
	if _, ok := after.Spec.Template.Annotations["kubectl.kubernetes.io/restartedAt"]; !ok {
		t.Fatal("rollout must set restartedAt so the pod template always changes")
	}
```

- [ ] **Step 2: Add the same-image regression test**

Append to `internal/kube/client_test.go`:

```go
func TestRolloutSameImageStillRollsDeployment(t *testing.T) {
	cfg, cs := kubetest.Start(t)
	ctx := context.Background()
	ns := "same-tag-ns"
	if _, err := cs.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}}, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := cs.AppsV1().Deployments(ns).Create(ctx, makeDeployment("api", ns), metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	k, err := kube.NewFromConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}

	if err := k.RolloutDeployment(ctx, ns, "api", "c", "busybox:7"); err != nil {
		t.Fatal(err)
	}
	first, err := cs.AppsV1().Deployments(ns).Get(ctx, "api", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}

	// Same image again: the tag did not move, but the deployment must still roll.
	if err := k.RolloutDeployment(ctx, ns, "api", "c", "busybox:7"); err != nil {
		t.Fatal(err)
	}
	second, err := cs.AppsV1().Deployments(ns).Get(ctx, "api", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}

	if second.Generation <= first.Generation {
		t.Fatalf("generation = %d, want > %d (same-tag rollout must still roll)",
			second.Generation, first.Generation)
	}
	const key = "kubectl.kubernetes.io/restartedAt"
	if first.Spec.Template.Annotations[key] == second.Spec.Template.Annotations[key] {
		t.Fatalf("restartedAt unchanged (%q): pod template hash would be identical",
			second.Spec.Template.Annotations[key])
	}
}
```

The two calls land inside the same wall-clock second — that is deliberate. It is exactly what forces nanosecond precision in Step 4.

- [ ] **Step 3: Run the tests to verify they fail**

Run: `KUBEBUILDER_ASSETS=$(setup-envtest use 1.30.x -p path) go test ./internal/kube/ -run 'TestRollout' -v`

Expected: FAIL — `TestRolloutUpdatesImageSingleContainer` reports "rollout must set restartedAt", and `TestRolloutSameImageStillRollsDeployment` reports a generation that did not advance.

- [ ] **Step 4: Implement the shared stamp and the combined patch**

In `internal/kube/client.go`, add the helper and rewrite both patch builders:

```go
// restartStamp is the annotation value that forces a pod-template change.
// Nanosecond precision matters: at second resolution two operations inside the
// same second produce an identical template, no new generation, and a rollout
// that silently does nothing.
func restartStamp() string {
	return time.Now().UTC().Format(time.RFC3339Nano)
}

// RestartDeployment performs a kubectl-rollout-restart equivalent patch on the
// deployment's pod template. The timestamp is server-visible and only serves to
// change the template hash; RetryOnConflict guards against resourceVersion
// races with concurrent controllers.
func (c *client) RestartDeployment(ctx context.Context, namespace, name string) error {
	return retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		patch := fmt.Sprintf(
			`{"spec":{"template":{"metadata":{"annotations":{"kubectl.kubernetes.io/restartedAt":%q}}}}}`,
			restartStamp(),
		)
		_, err := c.deployments(namespace).Patch(
			ctx, name, types.StrategicMergePatchType, []byte(patch), metav1.PatchOptions{})
		return err
	})
}

// RolloutDeployment sets a container's image via strategic merge patch
// (containers merge by name, so other containers and fields are untouched) and
// stamps the same restartedAt annotation restart uses. The annotation is what
// makes a rollout to an unchanged tag still roll: without it the pod template
// is identical, no generation is created, and the operation would resolve as
// succeeded against pre-patch state without replacing a pod.
func (c *client) RolloutDeployment(ctx context.Context, namespace, name, container, image string) error {
	if container == "" || image == "" {
		return fmt.Errorf("rollout requires container and image")
	}
	return retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		patch := fmt.Sprintf(
			`{"spec":{"template":{"metadata":{"annotations":{"kubectl.kubernetes.io/restartedAt":%q}},`+
				`"spec":{"containers":[{"name":%q,"image":%q}]}}}}`,
			restartStamp(), container, image,
		)
		_, err := c.deployments(namespace).Patch(
			ctx, name, types.StrategicMergePatchType, []byte(patch), metav1.PatchOptions{})
		return err
	})
}
```

- [ ] **Step 5: Run the kube tests to verify they pass**

Run: `KUBEBUILDER_ASSETS=$(setup-envtest use 1.30.x -p path) go test ./internal/kube/ -v`

Expected: PASS, including `TestRestartDeploymentSetsAnnotation` — Go's `time.Parse(time.RFC3339, ...)` accepts fractional seconds, so the existing RFC3339 assertion still holds for an RFC3339Nano value.

- [ ] **Step 6: Run the full suite**

Run: `KUBEBUILDER_ASSETS=$(setup-envtest use 1.30.x -p path) go test ./...`

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add internal/kube/client.go internal/kube/client_test.go
git commit -m "kube: stamp restartedAt on rollout so same-tag rollouts still roll"
```

---

### Task 2: Telegram transport with retry

**Files:**
- Create: `internal/notify/telegram.go`
- Test: `internal/notify/telegram_test.go`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces, for Tasks 3 and 4 (all unexported, same package):
  - `newTransport(baseURL, token string, log *slog.Logger) *transport`
  - `(*transport).send(ctx context.Context, chatID, text string) (int64, error)` — returns the new `message_id`
  - `(*transport).edit(ctx context.Context, chatID string, messageID int64, text string) error`
  - `(*transport).retryBase time.Duration` — backoff unit, 1s by default, lowered by tests
  - `sleepCtx(ctx context.Context, d time.Duration) bool`
  - constants `sendTimeout`, `callTimeout`, `maxAttempts`

- [ ] **Step 1: Write the failing tests**

Create `internal/notify/telegram_test.go`:

```go
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
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/notify/ -v`

Expected: FAIL — the package does not exist yet (`no Go files in .../internal/notify`).

- [ ] **Step 3: Implement the transport**

Create `internal/notify/telegram.go`:

```go
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

const (
	// sendTimeout bounds a single HTTP attempt.
	sendTimeout = 5 * time.Second
	// callTimeout bounds a full call including retries and backoff.
	callTimeout = 30 * time.Second
	maxAttempts = 3
)

// transport talks to the Telegram Bot API. The bot token is part of the
// request path, so nothing here ever logs or wraps a URL.
type transport struct {
	client    *http.Client
	baseURL   string
	token     string
	retryBase time.Duration
	log       *slog.Logger
}

func newTransport(baseURL, token string, log *slog.Logger) *transport {
	return &transport{
		client:    &http.Client{Timeout: sendTimeout},
		baseURL:   strings.TrimSuffix(baseURL, "/"),
		token:     token,
		retryBase: time.Second,
		log:       log,
	}
}

// apiResponse is the envelope every Bot API method returns.
type apiResponse struct {
	OK     bool `json:"ok"`
	Result struct {
		MessageID int64 `json:"message_id"`
	} `json:"result"`
	Description string `json:"description"`
	Parameters  struct {
		RetryAfter int `json:"retry_after"`
	} `json:"parameters"`
}

// send posts a new message and returns its telegram message_id.
func (t *transport) send(ctx context.Context, chatID, text string) (int64, error) {
	resp, err := t.call(ctx, "sendMessage", map[string]any{
		"chat_id":                  chatID,
		"text":                     text,
		"parse_mode":               "HTML",
		"disable_web_page_preview": true,
	})
	if err != nil {
		return 0, err
	}
	return resp.Result.MessageID, nil
}

// edit replaces the text of a message already in the chat.
func (t *transport) edit(ctx context.Context, chatID string, messageID int64, text string) error {
	_, err := t.call(ctx, "editMessageText", map[string]any{
		"chat_id":                  chatID,
		"message_id":               messageID,
		"text":                     text,
		"parse_mode":               "HTML",
		"disable_web_page_preview": true,
	})
	return err
}

// call posts to a Bot API method, retrying on 429, 5xx and transport errors.
// Telegram rate-limits group chats at roughly 20 messages per minute, so
// retry_after is honored rather than approximated.
func (t *transport) call(ctx context.Context, method string, payload map[string]any) (*apiResponse, error) {
	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		resp, status, err := t.once(ctx, method, payload)
		if err == nil && status == http.StatusOK && resp.OK {
			return resp, nil
		}
		if err != nil {
			lastErr = err
		} else {
			lastErr = fmt.Errorf("telegram %s: status %d: %s", method, status, resp.Description)
		}

		retryable := err != nil || status == http.StatusTooManyRequests || status >= 500
		if !retryable || attempt == maxAttempts {
			return nil, lastErr
		}

		delay := time.Duration(attempt) * t.retryBase
		if resp != nil && resp.Parameters.RetryAfter > 0 {
			delay = time.Duration(resp.Parameters.RetryAfter) * time.Second
		}
		if !sleepCtx(ctx, delay) {
			return nil, lastErr
		}
	}
	return nil, lastErr
}

// once performs a single attempt. It returns the decoded envelope, the HTTP
// status (0 when no response arrived), and an error.
func (t *transport) once(ctx context.Context, method string, payload map[string]any) (*apiResponse, int, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, 0, fmt.Errorf("telegram %s: marshal payload: %w", method, err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		t.baseURL+"/bot"+t.token+"/"+method, bytes.NewReader(body))
	if err != nil {
		// the error would echo the URL, which carries the token
		return nil, 0, fmt.Errorf("telegram %s: build request", method)
	}
	req.Header.Set("Content-Type", "application/json")

	httpResp, err := t.client.Do(req)
	if err != nil {
		// *url.Error embeds the request URL (token included) — never wrap it
		return nil, 0, fmt.Errorf("telegram %s: request failed", method)
	}
	defer httpResp.Body.Close()

	var out apiResponse
	if err := json.NewDecoder(httpResp.Body).Decode(&out); err != nil {
		return nil, httpResp.StatusCode, fmt.Errorf("telegram %s: decode response: %w", method, err)
	}
	return &out, httpResp.StatusCode, nil
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	select {
	case <-ctx.Done():
		return false
	case <-time.After(d):
		return true
	}
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/notify/ -v`

Expected: PASS (six tests).

- [ ] **Step 5: Vet and commit**

```bash
go vet ./internal/notify/
git add internal/notify/telegram.go internal/notify/telegram_test.go
git commit -m "notify: telegram transport with retry and token-safe errors"
```

---

### Task 3: Message rendering

**Files:**
- Create: `internal/notify/format.go`
- Test: `internal/notify/format_test.go`

**Interfaces:**
- Consumes: nothing from Task 2 (pure functions in the same package).
- Produces, for Task 4: `render(op *store.Operation) string` — the complete HTML message body for an operation in any status.

- [ ] **Step 1: Write the failing tests**

Create `internal/notify/format_test.go`:

```go
package notify

import (
	"strings"
	"testing"
	"time"

	"github.com/tuncloud/deploy-gateway/internal/store"
)

func runningRollout() *store.Operation {
	return &store.Operation{
		OperationID: "op_01hxyzabc",
		Repository:  "tuncloud/backend",
		Actor:       "octocat",
		RunID:       "4711",
		Action:      "deployment.rollout",
		Namespace:   "backend",
		Deployment:  "backend-api",
		Container:   "api",
		Image:       "ghcr.io/org/api:v2.1.0",
		Status:      store.StatusRunning,
		RequestedAt: time.Date(2026, 8, 17, 10, 0, 0, 0, time.UTC),
	}
}

func terminal(op *store.Operation, status store.OperationStatus, after time.Duration) *store.Operation {
	done := op.RequestedAt.Add(after)
	cp := *op
	cp.Status = status
	cp.CompletedAt = &done
	return &cp
}

func TestRenderStartedRollout(t *testing.T) {
	got := render(runningRollout())

	for _, want := range []string{
		"🟡", "rollout", "backend/backend-api", "ghcr.io/org/api:v2.1.0", "@octocat",
		`<a href="https://github.com/tuncloud/backend/actions/runs/4711">run #4711</a>`,
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing %q in:\n%s", want, got)
		}
	}
	if strings.Contains(got, "op_01hxyzabc") {
		t.Fatalf("started message must not carry the elapsed/op line:\n%s", got)
	}
}

func TestRenderSucceededAddsElapsedAndOperationID(t *testing.T) {
	got := render(terminal(runningRollout(), store.StatusSucceeded, 42*time.Second))

	for _, want := range []string{"✅", "42s", "op_01hxyzabc"} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing %q in:\n%s", want, got)
		}
	}
}

func TestRenderFailedAddsCodeAndMessage(t *testing.T) {
	op := terminal(runningRollout(), store.StatusFailed, 10*time.Minute)
	op.ErrorCode = "ROLLOUT_FAILED"
	op.ErrorMessage = "progress deadline exceeded"

	got := render(op)

	for _, want := range []string{"❌", "ROLLOUT_FAILED", "progress deadline exceeded", "10m0s"} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing %q in:\n%s", want, got)
		}
	}
}

func TestRenderTimeoutUsesClockMarker(t *testing.T) {
	op := terminal(runningRollout(), store.StatusTimeout, time.Hour)
	op.ErrorCode = "TIMEOUT"

	if got := render(op); !strings.Contains(got, "⏱") {
		t.Fatalf("timeout marker missing:\n%s", got)
	}
}

func TestRenderRestartOmitsImageLine(t *testing.T) {
	op := runningRollout()
	op.Action = "deployment.restart"
	op.Image = ""
	op.Container = ""

	got := render(op)

	if strings.Contains(got, "ghcr.io") {
		t.Fatalf("restart message must not carry an image:\n%s", got)
	}
	if !strings.Contains(got, "restart") {
		t.Fatalf("action missing:\n%s", got)
	}
}

func TestRenderRunLinkIncludesAttemptAndIsOmittedWithoutRunID(t *testing.T) {
	op := runningRollout()
	op.RunAttempt = "2"
	if want := "https://github.com/tuncloud/backend/actions/runs/4711/attempts/2"; !strings.Contains(render(op), want) {
		t.Fatalf("missing %q in:\n%s", want, render(op))
	}

	op.RunID = ""
	if got := render(op); strings.Contains(got, "actions/runs") {
		t.Fatalf("no run id → no link, got:\n%s", got)
	}
}

func TestRenderEscapesHTML(t *testing.T) {
	op := terminal(runningRollout(), store.StatusFailed, time.Second)
	op.ErrorMessage = `container <api> failed & exited`
	op.Actor = "a<b>c"

	got := render(op)

	if strings.Contains(got, "<api>") || strings.Contains(got, "a<b>c") {
		t.Fatalf("unescaped markup reached the message:\n%s", got)
	}
	for _, want := range []string{"&lt;api&gt;", "&amp;", "a&lt;b&gt;c"} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing escaped %q in:\n%s", want, got)
		}
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/notify/ -run TestRender -v`

Expected: FAIL — `undefined: render`.

- [ ] **Step 3: Implement the renderer**

Create `internal/notify/format.go`:

```go
package notify

import (
	"strings"
	"time"

	"github.com/tuncloud/deploy-gateway/internal/store"
)

// esc escapes only the three characters Telegram's HTML parse mode reserves.
// html.EscapeString is deliberately not used: it emits numeric entities for
// quotes, which Telegram renders literally.
var esc = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace

func marker(status store.OperationStatus) string {
	switch status {
	case store.StatusSucceeded:
		return "✅"
	case store.StatusFailed:
		return "❌"
	case store.StatusTimeout:
		return "⏱"
	default:
		return "🟡"
	}
}

// runLink is the GitHub Actions run this operation came from, empty when the
// identity carried no run id.
func runLink(op *store.Operation) string {
	if op.RunID == "" || op.Repository == "" {
		return ""
	}
	url := "https://github.com/" + op.Repository + "/actions/runs" + "/" + op.RunID
	if op.RunAttempt != "" {
		url += "/attempts/" + op.RunAttempt
	}
	return `<a href="` + esc(url) + `">run #` + esc(op.RunID) + `</a>`
}

func elapsed(op *store.Operation) string {
	if op.CompletedAt == nil {
		return ""
	}
	return op.CompletedAt.Sub(op.RequestedAt).Round(time.Second).String()
}

// render builds the HTML body for an operation. The same function serves the
// started message and the terminal one: status drives every difference.
func render(op *store.Operation) string {
	var lines []string

	title := marker(op.Status) + " <b>" + esc(strings.TrimPrefix(op.Action, "deployment.")) + "</b> · " +
		esc(op.Namespace+"/"+op.Deployment)
	if op.ErrorCode != "" {
		title += " — " + esc(op.ErrorCode)
	}
	lines = append(lines, title)

	if op.Image != "" {
		lines = append(lines, "<code>"+esc(op.Image)+"</code>")
	}
	if op.ErrorMessage != "" {
		lines = append(lines, esc(op.ErrorMessage))
	}

	who := "@" + esc(op.Actor)
	if link := runLink(op); link != "" {
		who += " · " + link
	}
	lines = append(lines, who)

	if d := elapsed(op); d != "" {
		lines = append(lines, d+" · <code>"+esc(op.OperationID)+"</code>")
	}

	return strings.Join(lines, "\n")
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/notify/ -v`

Expected: PASS (all transport and render tests).

- [ ] **Step 5: Commit**

```bash
git add internal/notify/format.go internal/notify/format_test.go
git commit -m "notify: render operations as telegram HTML messages"
```

---

### Task 4: Notifier facade with the edit-in-place handle

**Files:**
- Create: `internal/notify/notify.go`
- Test: `internal/notify/notify_test.go`

**Interfaces:**
- Consumes: `newTransport`, `(*transport).send`, `(*transport).edit` (Task 2); `render` (Task 3).
- Produces, for Task 5 (exported):
  - `type Notifier interface { Started(op *store.Operation) *Message; Resolved(op *store.Operation, msg *Message) }`
  - `type Message struct` — opaque handle; a nil `*Message` is valid
  - `type Config struct { BotToken, ChatID, APIBase string }`
  - `func New(cfg Config, log *slog.Logger) Notifier`
  - `func Disabled() Notifier`

- [ ] **Step 1: Write the failing tests**

Create `internal/notify/notify_test.go`:

```go
package notify

import (
	"log/slog"
	"net/http"
	"testing"
	"time"
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
```

Add the `store` import to this file's import block: `"github.com/tuncloud/deploy-gateway/internal/store"` (used via `store.StatusSucceeded` and friends).

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/notify/ -run 'TestStarted|TestResolved|TestDisabled|TestNew' -v`

Expected: FAIL — `undefined: telegram`, `undefined: Disabled`, `undefined: New`.

- [ ] **Step 3: Implement the facade**

Create `internal/notify/notify.go`:

```go
package notify

import (
	"context"
	"log/slog"
	"time"

	"github.com/tuncloud/deploy-gateway/internal/store"
)

// handleWait bounds how long a terminal notification waits for the started
// message's id before giving up and posting a fresh message instead.
const handleWait = 10 * time.Second

// Notifier turns operations into chat messages. Every method is best-effort
// and non-blocking: delivery never affects an operation's outcome, and no
// method returns an error.
type Notifier interface {
	// Started announces a running operation. It returns immediately; the send
	// happens in the background.
	Started(op *store.Operation) *Message
	// Resolved edits the started message in place, or posts a fresh one when
	// msg is nil or its send never landed.
	Resolved(op *store.Operation, msg *Message)
}

// Message is the in-flight handle to a message sent for a running operation.
// A nil *Message is valid and means "nothing to edit".
type Message struct {
	ready chan struct{}
	id    int64
}

func newMessage() *Message { return &Message{ready: make(chan struct{})} }

// settle records the sent message id (0 when the send failed). Called once.
func (m *Message) settle(id int64) {
	m.id = id
	close(m.ready)
}

// wait returns the telegram message id, or 0 when the send failed, never
// happened, or did not finish within timeout.
func (m *Message) wait(timeout time.Duration) int64 {
	if m == nil {
		return 0
	}
	select {
	case <-m.ready:
		return m.id
	case <-time.After(timeout):
		return 0
	}
}

type Config struct {
	BotToken string
	ChatID   string
	APIBase  string
}

// New returns a Telegram notifier, or the no-op notifier when either
// credential is missing.
func New(cfg Config, log *slog.Logger) Notifier {
	if cfg.BotToken == "" || cfg.ChatID == "" {
		log.Info("telegram notifications disabled")
		return Disabled()
	}
	base := cfg.APIBase
	if base == "" {
		base = "https://api.telegram.org"
	}
	log.Info("telegram notifications enabled", "chat_id", cfg.ChatID)
	return &telegram{tp: newTransport(base, cfg.BotToken, log), chatID: cfg.ChatID, log: log}
}

type telegram struct {
	tp     *transport
	chatID string
	log    *slog.Logger
}

func (t *telegram) Started(op *store.Operation) *Message {
	// render on the caller's goroutine: the operation must not be read
	// concurrently with the manager's own copy of it
	text := render(op)
	opID := op.OperationID
	msg := newMessage()
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), callTimeout)
		defer cancel()
		id, err := t.tp.send(ctx, t.chatID, text)
		if err != nil {
			t.log.Warn("telegram start notification failed", "operation_id", opID, "err", err)
		}
		msg.settle(id)
	}()
	return msg
}

func (t *telegram) Resolved(op *store.Operation, msg *Message) {
	text := render(op)
	opID := op.OperationID
	go func() {
		id := msg.wait(handleWait)
		ctx, cancel := context.WithTimeout(context.Background(), callTimeout)
		defer cancel()
		if id == 0 {
			// no message to edit: sweeper path, restarted gateway, failed send
			if _, err := t.tp.send(ctx, t.chatID, text); err != nil {
				t.log.Warn("telegram terminal notification failed", "operation_id", opID, "err", err)
			}
			return
		}
		if err := t.tp.edit(ctx, t.chatID, id, text); err != nil {
			t.log.Warn("telegram terminal edit failed", "operation_id", opID, "err", err)
		}
	}()
}

// Disabled returns a notifier that does nothing, used when Telegram is not
// configured so no caller needs a nil check.
func Disabled() Notifier { return disabled{} }

type disabled struct{}

func (disabled) Started(*store.Operation) *Message   { return nil }
func (disabled) Resolved(*store.Operation, *Message) {}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/notify/ -race -v`

Expected: PASS with no race reports.

- [ ] **Step 5: Vet and commit**

```bash
go vet ./internal/notify/
git add internal/notify/notify.go internal/notify/notify_test.go
git commit -m "notify: notifier facade with edit-in-place message handle"
```

---

### Task 5: Wire the notifier into the operation manager

**Files:**
- Modify: `internal/operation/manager.go` (constructor, both entry points, all three terminal helpers, `watchRollout`, `evalOnce`)
- Modify: `internal/operation/reconcile.go:45-69` (`resolveRunning` call sites)
- Modify: `internal/operation/manager_test.go:38`, `:269` (constructor arg)
- Modify: `internal/operation/reconcile_unit_test.go:48`, `:65`, `:80` (constructor arg)
- Modify: `internal/api/server_test.go:72`, `:346` (constructor arg)
- Create: `internal/operation/notify_test.go`

**Interfaces:**
- Consumes: `notify.Notifier`, `notify.Message`, `notify.Disabled()` (Task 4).
- Produces: `operation.NewManager(k kube.Kube, st store.Store, n notify.Notifier, log *slog.Logger, defaultDeadline time.Duration) *Manager` — the notifier is the third parameter. Task 6 calls it from `main`.

- [ ] **Step 1: Write the failing tests**

Create `internal/operation/notify_test.go`:

```go
package operation_test

import (
	"context"
	"log/slog"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"

	"github.com/tuncloud/deploy-gateway/internal/notify"
	"github.com/tuncloud/deploy-gateway/internal/operation"
	"github.com/tuncloud/deploy-gateway/internal/store"
)

// fakeNotifier records what the manager announced. It returns a nil handle,
// which the real Message type accepts everywhere.
type fakeNotifier struct {
	mu       sync.Mutex
	started  []*store.Operation
	resolved []*store.Operation
}

func (f *fakeNotifier) Started(op *store.Operation) *notify.Message {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.started = append(f.started, op)
	return nil
}

func (f *fakeNotifier) Resolved(op *store.Operation, _ *notify.Message) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.resolved = append(f.resolved, op)
}

func (f *fakeNotifier) counts() (int, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.started), len(f.resolved)
}

func (f *fakeNotifier) lastResolved() *store.Operation {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.resolved) == 0 {
		return nil
	}
	return f.resolved[len(f.resolved)-1]
}

// alreadyTerminalStore simulates losing the terminal-write race to another
// resolver (watcher vs sweeper vs lazy GET).
type alreadyTerminalStore struct{ store.Store }

func (alreadyTerminalStore) UpdateTerminal(context.Context, string, store.TerminalUpdate) error {
	return store.ErrAlreadyTerminal
}

func TestRolloutAnnouncesStartAfterPatch(t *testing.T) {
	ctx := context.Background()
	fk := &rolloutFakeKube{containers: []corev1.Container{{Name: "app"}}}
	fn := &fakeNotifier{}
	m := operation.NewManager(fk, store.NewInMemory(), fn, slog.Default(), time.Minute)

	if _, err := m.Rollout(ctx, identity(), "ns", "api", "", "img:v2"); err != nil {
		t.Fatal(err)
	}

	started, _ := fn.counts()
	if started != 1 {
		t.Fatalf("started notifications = %d, want 1", started)
	}
	if got := fn.started[0].Image; got != "img:v2" {
		t.Fatalf("announced image = %q, want img:v2", got)
	}
}

func TestPatchFailureNotifiesTerminalOnly(t *testing.T) {
	ctx := context.Background()
	fk := &rolloutFakeKube{containers: []corev1.Container{{Name: "app"}}, failRollout: true}
	fn := &fakeNotifier{}
	m := operation.NewManager(fk, store.NewInMemory(), fn, slog.Default(), time.Minute)

	if _, err := m.Rollout(ctx, identity(), "ns", "api", "", "img:v2"); err == nil {
		t.Fatal("patch failure must surface error")
	}

	started, resolved := fn.counts()
	if started != 0 {
		t.Fatalf("started notifications = %d, want 0 (patch never landed)", started)
	}
	if resolved != 1 {
		t.Fatalf("resolved notifications = %d, want 1", resolved)
	}
	last := fn.lastResolved()
	if last.Status != store.StatusFailed || last.ErrorCode != "K8S_PATCH_FAILED" {
		t.Fatalf("notified op = %s/%s, want failed/K8S_PATCH_FAILED", last.Status, last.ErrorCode)
	}
	if last.CompletedAt == nil {
		t.Fatal("notified op must carry CompletedAt so the message can show elapsed time")
	}
}

func TestTerminalRaceLoserDoesNotNotify(t *testing.T) {
	ctx := context.Background()
	fk := &rolloutFakeKube{containers: []corev1.Container{{Name: "app"}}, failRollout: true}
	fn := &fakeNotifier{}
	m := operation.NewManager(fk, alreadyTerminalStore{store.NewInMemory()}, fn, slog.Default(), time.Minute)

	if _, err := m.Rollout(ctx, identity(), "ns", "api", "", "img:v2"); err == nil {
		t.Fatal("patch failure must surface error")
	}

	if _, resolved := fn.counts(); resolved != 0 {
		t.Fatalf("resolved notifications = %d, want 0 (another writer already notified)", resolved)
	}
}

func TestSweepResolutionNotifiesOnce(t *testing.T) {
	ctx := context.Background()
	fn := &fakeNotifier{}
	st := store.NewInMemory()
	m := operation.NewManager(&getErrKube{getErr: context.DeadlineExceeded}, st, fn, slog.Default(), time.Minute)

	st.PutOperation(ctx, staleRunningOp())
	m.ReconcileSweep(ctx)

	started, resolved := fn.counts()
	if started != 0 {
		t.Fatalf("started notifications = %d, want 0 (sweeper announces nothing)", started)
	}
	if resolved != 1 {
		t.Fatalf("resolved notifications = %d, want 1", resolved)
	}
	if got := fn.lastResolved().Status; got != store.StatusTimeout {
		t.Fatalf("notified status = %s, want timeout", got)
	}
}

// A real notifier whose every call fails must leave the operation record
// untouched: delivery is best-effort, the audit table is the source of truth.
func TestUndeliverableNotificationsDoNotAffectTheOperation(t *testing.T) {
	ctx := context.Background()
	fk := &rolloutFakeKube{containers: []corev1.Container{{Name: "app"}}, failRollout: true}
	st := store.NewInMemory()
	// nothing is listening on port 1, so every send fails after its retries
	dead := notify.New(notify.Config{
		BotToken: "t", ChatID: "-1", APIBase: "http://127.0.0.1:1",
	}, slog.Default())
	m := operation.NewManager(fk, st, dead, slog.Default(), time.Minute)

	opID, err := m.Rollout(ctx, identity(), "ns", "api", "", "img:v2")
	if err == nil {
		t.Fatal("patch failure must surface error")
	}

	op, err := st.GetOperation(ctx, opID)
	if err != nil {
		t.Fatal(err)
	}
	if op.Status != store.StatusFailed || op.ErrorCode != "K8S_PATCH_FAILED" {
		t.Fatalf("op = %s/%s, want failed/K8S_PATCH_FAILED", op.Status, op.ErrorCode)
	}
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./internal/operation/ -run 'TestRolloutAnnounces|TestPatchFailureNotifies|TestTerminalRace|TestSweepResolution|TestUndeliverable' -v`

Expected: FAIL — `NewManager` takes 4 arguments, not 5.

- [ ] **Step 3: Add the notifier to the Manager**

In `internal/operation/manager.go`, add `"github.com/tuncloud/deploy-gateway/internal/notify"` to the imports, then replace the struct and constructor:

```go
type Manager struct {
	kube            kube.Kube
	store           store.Store
	notify          notify.Notifier
	log             *slog.Logger
	defaultDeadline time.Duration
}

func NewManager(k kube.Kube, st store.Store, n notify.Notifier, log *slog.Logger, defaultDeadline time.Duration) *Manager {
	if defaultDeadline <= 0 {
		defaultDeadline = 10 * time.Minute
	}
	if n == nil {
		n = notify.Disabled()
	}
	return &Manager{kube: k, store: st, notify: n, log: log, defaultDeadline: defaultDeadline}
}
```

- [ ] **Step 4: Rewrite the terminal helpers to notify on the winning write**

In `internal/operation/manager.go`, replace `failOperation`, `completeOperation`, and `timeoutOperation` with these, and add `applyTerminal`:

```go
// applyTerminal returns a copy of op with the terminal update applied, so a
// notification renders final status, error and elapsed time without re-reading
// the store.
func applyTerminal(op *store.Operation, upd store.TerminalUpdate) *store.Operation {
	cp := *op
	cp.Status = upd.Status
	cp.ErrorCode = upd.ErrorCode
	cp.ErrorMessage = upd.ErrorMessage
	completed := upd.CompletedAt
	cp.CompletedAt = &completed
	return &cp
}

// resolve performs the single terminal write and notifies only when this
// writer won: UpdateTerminal returns ErrAlreadyTerminal to everyone else, so
// exactly one of watcher, sweeper or lazy GET sends the message.
func (m *Manager) resolve(op *store.Operation, msg *notify.Message, what string, upd store.TerminalUpdate) {
	if err := m.store.UpdateTerminal(context.Background(), op.OperationID, upd); err != nil {
		m.logTerminalWriteErr(what, op.OperationID, err)
		return
	}
	m.notify.Resolved(applyTerminal(op, upd), msg)
}

func (m *Manager) failOperation(op *store.Operation, msg *notify.Message, code, errMsg string) {
	m.resolve(op, msg, "mark operation failed", store.TerminalUpdate{
		Status: store.StatusFailed, Event: "FAILED",
		ErrorCode: code, ErrorMessage: errMsg, CompletedAt: time.Now().UTC(),
	})
}

func (m *Manager) completeOperation(op *store.Operation, msg *notify.Message, reason string) {
	m.resolve(op, msg, "mark operation succeeded", store.TerminalUpdate{
		Status: store.StatusSucceeded, Event: "SUCCEEDED", CompletedAt: time.Now().UTC(),
	})
	m.log.Info("rollout succeeded", "operation_id", op.OperationID, "reason", reason)
}

func (m *Manager) timeoutOperation(op *store.Operation, msg *notify.Message, errMsg string) {
	m.resolve(op, msg, "mark operation timeout", store.TerminalUpdate{
		Status: store.StatusTimeout, Event: "TIMEOUT",
		ErrorCode: "TIMEOUT", ErrorMessage: errMsg, CompletedAt: time.Now().UTC(),
	})
}
```

- [ ] **Step 5: Update the entry points and the watcher**

Still in `internal/operation/manager.go`:

In `Restart`, replace the patch-failure branch and the tail:

```go
	if err := m.kube.RestartDeployment(ctx, namespace, deployment); err != nil {
		m.failOperation(op, nil, "K8S_PATCH_FAILED", err.Error())
		return op.OperationID, fmt.Errorf("patch deployment: %w", err)
	}

	m.log.Info("restart started",
		"operation_id", op.OperationID, "repository", id.Repository,
		"namespace", namespace, "deployment", deployment, "run_id", id.RunID)

	msg := m.notify.Started(op)
	go m.watchRollout(op, msg)
	return op.OperationID, nil
```

In `Rollout`, the same shape:

```go
	if err := m.kube.RolloutDeployment(ctx, namespace, deployment, container, image); err != nil {
		m.failOperation(op, nil, "K8S_PATCH_FAILED", err.Error())
		return op.OperationID, fmt.Errorf("patch deployment: %w", err)
	}

	m.log.Info("rollout started",
		"operation_id", op.OperationID, "repository", id.Repository,
		"namespace", namespace, "deployment", deployment,
		"container", container, "image", image, "run_id", id.RunID)

	msg := m.notify.Started(op)
	go m.watchRollout(op, msg)
	return op.OperationID, nil
```

In `recordFailedRollout`, replace the final `m.failOperation(op.OperationID, code, msg)` call:

```go
	m.failOperation(op, nil, code, msg)
	return op.OperationID
```

Note the parameter named `msg` in `recordFailedRollout` is the error message string — pass `nil` for the handle as shown, and do not rename the parameter.

Change `watchRollout` and `evalOnce` to carry the handle:

```go
func (m *Manager) watchRollout(op *store.Operation, msg *notify.Message) {
```

and inside it, every terminal call:

```go
			m.timeoutOperation(op, msg, "watch deadline exceeded before rollout resolved")
```
```go
			if m.evalOnce(ctx, op, msg) {
```
```go
				m.timeoutOperation(op, msg, "watch deadline exceeded")
```
```go
			if ev.State == kube.RolloutComplete {
				m.completeOperation(op, msg, ev.Reason)
```
```go
			if ev.State == kube.RolloutFailed {
				m.failOperation(op, msg, "ROLLOUT_FAILED", ev.Reason)
```
```go
			m.timeoutOperation(op, msg, "watch deadline exceeded after reconnect")
```

and:

```go
func (m *Manager) evalOnce(ctx context.Context, op *store.Operation, msg *notify.Message) bool {
	dep, err := m.kube.GetDeployment(ctx, op.Namespace, op.Deployment)
	if err != nil {
		m.log.Warn("re-get deployment", "operation_id", op.OperationID, "err", err)
		return false
	}
	ev := kube.EvaluateRollout(dep)
	switch ev.State {
	case kube.RolloutComplete:
		m.completeOperation(op, msg, ev.Reason)
		return true
	case kube.RolloutFailed:
		m.failOperation(op, msg, "ROLLOUT_FAILED", ev.Reason)
		return true
	}
	return false
}
```

- [ ] **Step 6: Update the reconciler**

In `internal/operation/reconcile.go`, `resolveRunning` has the full operation and no handle:

```go
		m.timeoutOperation(op, nil, "deployment no longer readable while operation running: "+err.Error())
		return
	}
	ev := kube.EvaluateRollout(dep)
	switch ev.State {
	case kube.RolloutComplete:
		m.completeOperation(op, nil, ev.Reason)
	case kube.RolloutFailed:
		m.failOperation(op, nil, "ROLLOUT_FAILED", ev.Reason)
	default:
		m.timeoutOperation(op, nil, "operation stale and rollout still not terminal: "+ev.Reason)
	}
```

- [ ] **Step 7: Update every existing NewManager call site**

Insert `notify.Disabled()` as the third argument, adding the `notify` import to each file:

- `internal/operation/manager_test.go:38` → `operation.NewManager(k, st, notify.Disabled(), slog.Default(), 30*time.Second)`
- `internal/operation/manager_test.go:269` → `operation.NewManager(k, st, notify.Disabled(), slog.Default(), time.Minute)`
- `internal/operation/reconcile_unit_test.go:48`, `:65`, `:80` → `operation.NewManager(&getErrKube{...}, st, notify.Disabled(), slog.Default(), time.Minute)`
- `internal/api/server_test.go:72` → `operation.NewManager(k, st, notify.Disabled(), slog.Default(), time.Minute)`
- `internal/api/server_test.go:346` → `operation.NewManager(&fakeKube{}, st, notify.Disabled(), log, time.Minute)`

`cmd/gateway/main.go:62` is updated in Task 6; until then the build of `./cmd/...` fails, which is expected.

- [ ] **Step 8: Run the operation and api tests**

Run: `KUBEBUILDER_ASSETS=$(setup-envtest use 1.30.x -p path) go test ./internal/... -race`

Expected: PASS, including the four new notification tests.

- [ ] **Step 9: Commit**

```bash
git add internal/operation internal/api/server_test.go
git commit -m "operation: notify on start and on the winning terminal write"
```

---

### Task 6: Configuration and documentation

**Files:**
- Modify: `cmd/gateway/main.go:62` and the surrounding wiring
- Modify: `README.md`

**Interfaces:**
- Consumes: `notify.New(notify.Config{...}, logger)` (Task 4) and the 5-argument `operation.NewManager` (Task 5).
- Produces: the deployed configuration surface — `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID`, `TELEGRAM_API_BASE`.

- [ ] **Step 1: Wire the notifier in main**

In `cmd/gateway/main.go`, add `"github.com/tuncloud/deploy-gateway/internal/notify"` to the imports and replace the manager construction:

```go
	notifier := notify.New(notify.Config{
		BotToken: os.Getenv("TELEGRAM_BOT_TOKEN"),
		ChatID:   os.Getenv("TELEGRAM_CHAT_ID"),
		APIBase:  envOr("TELEGRAM_API_BASE", "https://api.telegram.org"),
	}, logger)

	ops := operation.NewManager(k, st, notifier, logger, 10*time.Minute)
```

`notify.New` logs whether notifications are enabled, so `main` needs no branch of its own.

- [ ] **Step 2: Verify the whole module builds**

Run: `go build ./... && go vet ./...`

Expected: no output.

- [ ] **Step 3: Run the full suite**

Run: `KUBEBUILDER_ASSETS=$(setup-envtest use 1.30.x -p path) go test ./... -race`

Expected: PASS.

- [ ] **Step 4: Document the behavior change and the new configuration**

In `README.md`, replace the third bullet under `POST /v1/deployments/rollout`:

```markdown
- Rolling the same image again still rolls: the patch also stamps
  `kubectl.kubernetes.io/restartedAt`, so the pod template always changes and
  pods are always replaced — required for mutable tags (`:latest`, `:staging`).
```

Then add this section after **Usage from a repository**:

```markdown
## Notifications

Set both variables to post a Telegram message per deploy. Unset, notifications
are disabled and the gateway logs `telegram notifications disabled` at startup.

| Variable | Purpose |
|---|---|
| `TELEGRAM_BOT_TOKEN` | bot token, from a Secret |
| `TELEGRAM_CHAT_ID` | destination chat (e.g. `-1001234567890`) |
| `TELEGRAM_API_BASE` | override the API host; defaults to `https://api.telegram.org` |

```bash
kubectl -n platform-system create secret generic deploy-gateway-telegram \
  --from-literal=bot-token='123456:ABC-DEF...'
```

```yaml
env:
  - name: TELEGRAM_BOT_TOKEN
    valueFrom:
      secretKeyRef:
        name: deploy-gateway-telegram
        key: bot-token
  - name: TELEGRAM_CHAT_ID
    value: "-1001234567890"
```

One message is posted when a deploy starts and edited in place when it
resolves:

```
🟡 rollout · backend/backend-api      →   ✅ rollout · backend/backend-api
ghcr.io/org/api:v2.1.0                    ghcr.io/org/api:v2.1.0
@octocat · run #4711                      @octocat · run #4711
                                          42s · op_01hxyzabc
```

Delivery is best-effort: sends are retried up to three times on rate limits and
5xx, and a notification that never lands is logged and dropped. It never
changes an operation's status or an API response — the audit table remains the
source of truth. Operations resolved by the reconciler or after a gateway
restart post a fresh terminal message instead of editing. Policy denials are
not notified.
```

In the **Security** section, add:

```markdown
- The Telegram bot token is never logged: it sits in the API request path, so
  request URLs and transport errors are never surfaced.
```

- [ ] **Step 5: Commit**

```bash
git add cmd/gateway/main.go README.md
git commit -m "docs+wiring: telegram notification config and same-tag rollout behavior"
```

---

## Verification

After Task 6, the following must all hold:

```bash
go build ./...
go vet ./...
KUBEBUILDER_ASSETS=$(setup-envtest use 1.30.x -p path) go test ./... -race
git status   # clean
```

Manual check against a real cluster (optional, requires a configured gateway):
roll a deployment to the tag it is already running and confirm the pods restart
and the Telegram message transitions from 🟡 to ✅ in place.
