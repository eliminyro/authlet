package memstore

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/eliminyro/authlet/pkg/storage"
)

func TestCode_SaveAndConsumeOnce(t *testing.T) {
	s := New()
	ctx := context.Background()
	code := storage.AuthCode{CodeHash: "h1", ClientID: "c1", ExpiresAt: time.Now().Add(time.Minute)}
	if err := s.Codes().Save(ctx, code); err != nil {
		t.Fatal(err)
	}
	got, err := s.Codes().ConsumeOnce(ctx, "h1")
	if err != nil {
		t.Fatal(err)
	}
	if got.ClientID != "c1" {
		t.Fatalf("client mismatch: %q", got.ClientID)
	}
	// second consume must fail
	_, err = s.Codes().ConsumeOnce(ctx, "h1")
	if !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("expected ErrNotFound on second consume, got %v", err)
	}
}

func TestCode_ConsumeOnce_IsAtomicUnderConcurrency(t *testing.T) {
	s := New()
	ctx := context.Background()
	_ = s.Codes().Save(ctx, storage.AuthCode{CodeHash: "h1", ExpiresAt: time.Now().Add(time.Minute)})

	var wg sync.WaitGroup
	wins := 0
	var mu sync.Mutex
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := s.Codes().ConsumeOnce(ctx, "h1"); err == nil {
				mu.Lock()
				wins++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if wins != 1 {
		t.Fatalf("expected exactly 1 consumer to win, got %d", wins)
	}
}

func TestCode_ExpiredCodeRejected(t *testing.T) {
	s := New()
	ctx := context.Background()
	_ = s.Codes().Save(ctx, storage.AuthCode{CodeHash: "h1", ExpiresAt: time.Now().Add(-time.Second)})
	_, err := s.Codes().ConsumeOnce(ctx, "h1")
	if !errors.Is(err, storage.ErrAlreadyConsumed) {
		t.Fatalf("expected ErrAlreadyConsumed, got %v", err)
	}
}

// TestCode_ConsumeOnceUnknownReturnsNotFound documents the contract
// from CodeStore.ConsumeOnce: an unknown hash yields ErrNotFound, not
// ErrAlreadyConsumed. The two errors are distinguishable so callers
// that want to log the difference can do so, even though both mean
// "code is no longer valid".
func TestCode_ConsumeOnceUnknownReturnsNotFound(t *testing.T) {
	s := New()
	ctx := context.Background()
	_, err := s.Codes().ConsumeOnce(ctx, "never-saved")
	if !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("expected ErrNotFound for unknown code, got %v", err)
	}
}
