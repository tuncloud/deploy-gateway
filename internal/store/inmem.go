package store

import (
	"context"
	"sync"
	"time"
)

type inMemory struct {
	mu  sync.Mutex
	ops map[string]*Operation
}

func NewInMemory() Store {
	return &inMemory{ops: map[string]*Operation{}}
}

func (s *inMemory) PutOperation(_ context.Context, op *Operation) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *op
	s.ops[op.OperationID] = &cp
	return nil
}

func (s *inMemory) GetOperation(_ context.Context, id string) (*Operation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	op, ok := s.ops[id]
	if !ok {
		return nil, ErrNotFound
	}
	cp := *op
	return &cp, nil
}

func (s *inMemory) UpdateTerminal(_ context.Context, id string, upd TerminalUpdate) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	op, ok := s.ops[id]
	if !ok {
		return ErrNotFound
	}
	if op.Status != StatusRunning {
		return ErrAlreadyTerminal
	}
	op.Status = upd.Status
	op.ErrorCode = upd.ErrorCode
	op.ErrorMessage = upd.ErrorMessage
	done := upd.CompletedAt
	op.CompletedAt = &done
	op.Events = append(op.Events, AuditEvent{Event: upd.Event, At: time.Now().UTC()})
	return nil
}

func (s *inMemory) ListRunningPastDeadline(_ context.Context, olderThan time.Time) ([]*Operation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*Operation
	for _, op := range s.ops {
		if op.Status == StatusRunning && op.RequestedAt.Before(olderThan) {
			cp := *op
			out = append(out, &cp)
		}
	}
	return out, nil
}

func (s *inMemory) Ping(_ context.Context) error { return nil }
