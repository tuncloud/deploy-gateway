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
