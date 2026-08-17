# Same-tag rollouts and Telegram notifications

Date: 2026-08-17
Status: approved for planning

## Problem

**Same-tag rollouts silently do nothing.** `RolloutDeployment` patches only
`spec.template.spec.containers[].image`. When the requested image string equals
the running one, the pod template is unchanged, so Kubernetes creates no new
generation. `EvaluateRollout` then sees `observedGeneration >= generation` with
all replicas ready and reports the operation **succeeded** — without a single
pod being replaced. Workflows that push a mutable tag (`:latest`, `:staging`, a
re-pushed release tag) get a green check for a deploy that never happened.

**Deploy outcomes are invisible outside the audit table.** An operation's fate
lives in DynamoDB and the gateway's logs. Finding out whether a deploy landed
means polling `GET /v1/operations/{id}` or reading logs.

## Goals

1. A rollout always rolls, whether or not the image tag moved.
2. Every deploy posts one Telegram message when it starts, edited in place when
   it resolves.
3. Notification failures never affect an operation's outcome or the API
   response.

## Non-goals

- **Policy denials are not notified.** They remain in the audit table and logs.
- **Per-repository or per-namespace chat routing.** One global chat.
- **Durable delivery.** No outbox, no persistence of pending messages. A
  message lost to a gateway restart stays lost; the audit table remains the
  source of truth.
- No changes to the DynamoDB schema, the `store.Store` interface, or
  `policy.yaml`.

## Part 1 — Same-tag rollout

### Change

`RolloutDeployment` stamps the same restart annotation `RestartDeployment`
already uses, in the same strategic-merge patch:

```go
patch := fmt.Sprintf(
    `{"spec":{"template":{"metadata":{"annotations":{"kubectl.kubernetes.io/restartedAt":%q}},`+
    `"spec":{"containers":[{"name":%q,"image":%q}]}}}}`,
    now, container, image)
```

One patch, one generation bump. The pod template now always changes, so
`Generation` always increments and `EvaluateRollout` reports *progressing*
(`observedGeneration < generation`) instead of succeeding against pre-patch
state. The watcher logic in `watchRollout` and `EvaluateRollout` is untouched.

The annotation key is `kubectl.kubernetes.io/restartedAt` for both actions —
kubectl-compatible, and no second annotation key enters the pod template.

### Timestamp precision

Both `RestartDeployment` and `RolloutDeployment` move from `time.RFC3339` to
`time.RFC3339Nano`. At second resolution, two operations within the same second
produce an identical annotation value, no template change, and the
silent-success bug returns in miniature. `RFC3339Nano` is still valid RFC3339
and kubectl treats the value as an opaque string.

### Rejected alternatives

- **Opt-in `force` flag** — leaves the silent-success trap in place for anyone
  who forgets it.
- **Read-then-compare, force only when unchanged** — an extra API read and a
  TOCTOU race for an outcome identical to always stamping.
- **Reject same-tag rollouts with 409** — makes mutable-tag workflows
  impossible.

### Tests

- envtest: rolling the *same* image twice yields two distinct `Generation`
  values and a changed pod-template hash. This is the regression that would
  have caught current behavior.
- envtest: rolling a *different* image still updates the container image and
  leaves other containers untouched.
- Unit: the patch body is valid JSON containing both the annotation and the
  container image.

## Part 2 — Notifier

New package `internal/notify`. Its only job is turning an operation into a chat
message. It never reads or writes the store and never returns an error to its
caller.

### Interface

```go
type Notifier interface {
    // Started announces a running operation. Returns immediately; the send
    // happens in the background.
    Started(op *store.Operation) *Message
    // Resolved edits the started message in place, or posts a fresh one when
    // msg is nil or its send never landed.
    Resolved(op *store.Operation, msg *Message)
}

// Message is the in-flight handle to a sent message.
type Message struct {
    ready chan struct{} // closed when the send attempt finishes
    id    int64         // telegram message_id; 0 if the send failed
}
```

`Started` must return before the network call completes, but `Resolved` needs
the `message_id` that call produces. The handle bridges the two: `Resolved`
runs in its own goroutine, waits on `ready` with a bounded timeout (10s), then
calls `editMessageText` when it has a non-zero id and `sendMessage` when it
does not.

The handle lives on the watcher goroutine's stack. There is no shared map of
pending messages and nothing to evict; a slow or failed send degrades to a
second message rather than a leak.

### Delivery

- `POST https://api.telegram.org/bot<token>/sendMessage` and `/editMessageText`.
- 5s timeout per attempt.
- Up to 3 attempts on HTTP 429 and 5xx, honoring `parameters.retry_after` from
  the Telegram error body. Telegram rate-limits group chats at roughly 20
  messages per minute, so retry is load-bearing, not defensive.
- 4xx other than 429 is not retried.
- After the final attempt, log `slog.Warn` and stop. No error propagates.

### Security

The bot token is in the request **path**. The notifier logs endpoint names
only — never a full URL, never the token, never response bodies that might echo
it. This matches the existing rule that JWTs are never logged, stored, or
echoed.

### Configuration

| Variable | Required | Notes |
|---|---|---|
| `TELEGRAM_BOT_TOKEN` | to enable | from a Kubernetes Secret |
| `TELEGRAM_CHAT_ID` | to enable | one global destination |
| `TELEGRAM_API_BASE` | no | defaults to `https://api.telegram.org`; tests point it at an `httptest` server |

With either required variable unset, `notify.Disabled()` returns a no-op
implementation and `main` logs `telegram notifications disabled` at startup.
No nil checks anywhere else; existing tests stay silent without modification.

## Part 3 — Wiring

### Dependency

`operation.Manager` gains a `notify.Notifier` field supplied through
`NewManager`, alongside `kube` and `store`. Existing test call sites pass
`notify.Disabled()`.

### Firing points

`Started` is called after a **successful** patch in both `Restart` and
`Rollout` — a patch that never landed must not announce a deploy. The returned
handle is passed into the watcher: `go m.watchRollout(op, msg)`.

`completeOperation`, `failOperation`, and `timeoutOperation` become the single
notification point. Each takes the `*store.Operation` and the optional handle
instead of a bare `opID`; every call site already holds the full operation.
Each applies its `TerminalUpdate` to an in-memory copy of the operation before
notifying, so the message carries final status, error fields, and elapsed time.

### Exactly-once

A terminal helper notifies **only when `store.UpdateTerminal` returns nil**.
The store already refuses a second terminal write with `ErrAlreadyTerminal`, so
whichever writer wins the race — watcher, sweeper, or lazy `GET` — is the one
that sends. `ErrAlreadyTerminal` means another writer already notified; skip
silently, as the existing code already does for logging.

### Consequences by path

| Path | Messages |
|---|---|
| Normal rollout or restart | started, edited to terminal |
| Patch fails before watch | one terminal (failure) message, no started |
| Container resolution fails (rollout only) | one terminal (failure) message, no started — `recordFailedRollout` → `failOperation` |
| Resolved by sweeper or lazy GET | started, then a **fresh** terminal message (no handle in memory) |
| Resolved after gateway restart | fresh terminal message only |
| Policy denied | none (non-goal) |

### Message format

HTML parse mode. Every interpolated field is HTML-escaped — Kubernetes reason
strings contain `<`, `>`, and `&`. Link previews disabled.

```
🟡 rollout · backend/backend-api
ghcr.io/org/api:v2.1.0
@octocat · run #4711

✅ rollout · backend/backend-api
ghcr.io/org/api:v2.1.0
@octocat · run #4711
42s · op_01hxyzabc

❌ rollout · backend/backend-api — ROLLOUT_FAILED
progress deadline exceeded
@octocat · run #4711
10m2s · op_01hxyzabc
```

- Status marker: 🟡 running, ✅ succeeded, ❌ failed, ⏱ timeout.
- The image line appears for `deployment.rollout` only.
- `run #N` links to `https://github.com/{repository}/actions/runs/{run_id}`,
  with `/attempts/{run_attempt}` appended when `RunAttempt` is set. The link is
  omitted when `RunID` is empty.
- Elapsed time is `CompletedAt - RequestedAt`, terminal messages only.
- Failed and timed-out messages add the error code on the title line and the
  error message on its own line.

## Testing

**`internal/notify`** against an `httptest` fake Telegram:

- send → edit happy path, asserting `editMessageText` carries the `message_id`
  returned by `sendMessage`.
- Send fails: `Resolved` posts a fresh `sendMessage` instead of editing.
- 429 with `parameters.retry_after` is retried and honored; a persistent 429
  gives up after 3 attempts.
- 400 is not retried.
- HTML escaping of repository, actor, image, and error message.
- `Disabled()` performs no HTTP calls.

**`internal/operation`** against a recording fake notifier:

- `Started` fires exactly once, and only after a successful patch.
- `Resolved` fires exactly once on the terminal transition.
- A lost `UpdateTerminal` race (`ErrAlreadyTerminal`) sends nothing.
- A patch failure sends one terminal message and no started message.
- A notifier that fails every call leaves operation status and HTTP responses
  byte-identical to a run with notifications disabled.

**`internal/kube`** under envtest: the same-image regression from Part 1.

## Documentation

README gains a Notifications section: the three environment variables, a
`kubectl create secret generic` example for the bot token, a sample message,
and an explicit statement that notification failures never fail a deploy. The
Security section notes that the bot token is never logged.
