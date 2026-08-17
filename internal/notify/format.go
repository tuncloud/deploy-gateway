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
