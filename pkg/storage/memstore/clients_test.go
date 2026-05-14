package memstore

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/eliminyro/authlet/pkg/storage"
)

func TestClient_CreateAndGet(t *testing.T) {
	s := New()
	ctx := context.Background()
	if err := s.Clients().Create(ctx, storage.Client{ClientID: "c1", CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	got, err := s.Clients().Get(ctx, "c1")
	if err != nil {
		t.Fatal(err)
	}
	if got.ClientID != "c1" {
		t.Fatalf("got %q want c1", got.ClientID)
	}
}

func TestClient_CreateDuplicateRejected(t *testing.T) {
	s := New()
	ctx := context.Background()
	_ = s.Clients().Create(ctx, storage.Client{ClientID: "c1"})
	err := s.Clients().Create(ctx, storage.Client{ClientID: "c1"})
	if !errors.Is(err, storage.ErrAlreadyExists) {
		t.Fatalf("expected ErrAlreadyExists, got %v", err)
	}
}

func TestClient_TouchUpdatesLastUsed(t *testing.T) {
	s := New()
	ctx := context.Background()
	_ = s.Clients().Create(ctx, storage.Client{ClientID: "c1", CreatedAt: time.Now().Add(-time.Hour).UTC()})
	if err := s.Clients().Touch(ctx, "c1"); err != nil {
		t.Fatal(err)
	}
	got, _ := s.Clients().Get(ctx, "c1")
	if time.Since(got.LastUsedAt) > time.Second {
		t.Fatalf("LastUsedAt not updated: %v", got.LastUsedAt)
	}
}

func TestClient_DeleteExpired(t *testing.T) {
	s := New()
	ctx := context.Background()
	old := time.Now().Add(-100 * 24 * time.Hour).UTC()
	_ = s.Clients().Create(ctx, storage.Client{ClientID: "old", CreatedAt: old, LastUsedAt: old})
	_ = s.Clients().Create(ctx, storage.Client{ClientID: "new", CreatedAt: time.Now().UTC(), LastUsedAt: time.Now().UTC()})
	n, err := s.Clients().DeleteExpired(ctx, time.Now().Add(-90*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("expected 1 deleted, got %d", n)
	}
	if _, err := s.Clients().Get(ctx, "old"); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("expected old deleted, got %v", err)
	}
}
