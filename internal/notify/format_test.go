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
