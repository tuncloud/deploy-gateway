package store

import (
	"context"
	"errors"
	"time"
)

type OperationStatus string

const (
	StatusRunning   OperationStatus = "running"
	StatusSucceeded OperationStatus = "succeeded"
	StatusFailed    OperationStatus = "failed"
	StatusTimeout   OperationStatus = "timeout"
	StatusDenied    OperationStatus = "denied" // audit-only item for rejected requests
)

var ErrNotFound = errors.New("operation not found")

type AuditEvent struct {
	Event string    `dynamodbav:"event"`
	At    time.Time `dynamodbav:"at"`
}

type Operation struct {
	OperationID     string          `dynamodbav:"operation_id"`
	Repository      string          `dynamodbav:"repository"`
	RepositoryID    string          `dynamodbav:"repository_id"`
	RepositoryOwner string          `dynamodbav:"repository_owner,omitempty"`
	Actor           string          `dynamodbav:"actor,omitempty"`
	Workflow        string          `dynamodbav:"workflow,omitempty"`
	WorkflowRef     string          `dynamodbav:"workflow_ref,omitempty"`
	RunID           string          `dynamodbav:"run_id,omitempty"`
	RunAttempt      string          `dynamodbav:"run_attempt,omitempty"`
	EventName       string          `dynamodbav:"event_name,omitempty"`
	Action          string          `dynamodbav:"action"`
	Namespace       string          `dynamodbav:"namespace"`
	Deployment      string          `dynamodbav:"deployment"`
	NsDep           string          `dynamodbav:"ns_dep"`
	Status          OperationStatus `dynamodbav:"status"`
	ErrorCode       string          `dynamodbav:"error_code,omitempty"`
	ErrorMessage    string          `dynamodbav:"error_message,omitempty"`
	RequestedAt     time.Time       `dynamodbav:"requested_at"`
	CompletedAt     *time.Time      `dynamodbav:"completed_at,omitempty"`
	ExpiresAt       int64           `dynamodbav:"expires_at"`
	Events          []AuditEvent    `dynamodbav:"events"`
}

func (o *Operation) Terminal() bool {
	return o.Status != StatusRunning
}

type TerminalUpdate struct {
	Status       OperationStatus
	Event        string
	ErrorCode    string
	ErrorMessage string
	CompletedAt  time.Time
}

type Store interface {
	PutOperation(ctx context.Context, op *Operation) error
	GetOperation(ctx context.Context, operationID string) (*Operation, error)
	UpdateTerminal(ctx context.Context, operationID string, upd TerminalUpdate) error
	ListRunningPastDeadline(ctx context.Context, olderThan time.Time) ([]*Operation, error)
	Ping(ctx context.Context) error
}
