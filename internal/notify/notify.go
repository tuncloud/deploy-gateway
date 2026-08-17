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
