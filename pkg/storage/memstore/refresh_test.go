package memstore

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/eliminyro/authlet/pkg/storage"
)

func saveRT(s *Store, hash, family string) {
	_ = s.RefreshTokens().Save(context.Background(), storage.RefreshToken{
		TokenHash: hash, FamilyID: family, ExpiresAt: time.Now().Add(time.Hour),
	})
}

func TestRefresh_SaveGet(t *testing.T) {
	s := New()
	saveRT(s, "h1", "fam1")
	got, err := s.RefreshTokens().Get(context.Background(), "h1")
	if err != nil {
		t.Fatal(err)
	}
	if got.FamilyID != "fam1" {
		t.Fatalf("family mismatch: %q", got.FamilyID)
	}
}

func TestRefresh_MarkUsedThenReuseDetected(t *testing.T) {
	s := New()
	ctx := context.Background()
	saveRT(s, "h1", "fam1")
	if err := s.RefreshTokens().MarkUsed(ctx, "h1", "h2"); err != nil {
		t.Fatal(err)
	}
	// second MarkUsed on same hash = reuse
	err := s.RefreshTokens().MarkUsed(ctx, "h1", "h3")
	if !errors.Is(err, storage.ErrAlreadyConsumed) {
		t.Fatalf("expected ErrAlreadyConsumed, got %v", err)
	}
}

func TestRefresh_RevokeFamilyBlocksGet(t *testing.T) {
	s := New()
	ctx := context.Background()
	saveRT(s, "h1", "fam1")
	saveRT(s, "h2", "fam1")
	if err := s.RefreshTokens().RevokeFamily(ctx, "fam1"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RefreshTokens().Get(ctx, "h1"); !errors.Is(err, storage.ErrFamilyRevoked) {
		t.Fatalf("expected ErrFamilyRevoked, got %v", err)
	}
	if _, err := s.RefreshTokens().Get(ctx, "h2"); !errors.Is(err, storage.ErrFamilyRevoked) {
		t.Fatalf("expected ErrFamilyRevoked, got %v", err)
	}
}

func TestRefresh_IsFamilyRevoked(t *testing.T) {
	s := New()
	ctx := context.Background()
	saveRT(s, "h1", "fam1")
	ok, _ := s.RefreshTokens().IsFamilyRevoked(ctx, "fam1")
	if ok {
		t.Fatal("expected false before revoke")
	}
	_ = s.RefreshTokens().RevokeFamily(ctx, "fam1")
	ok, _ = s.RefreshTokens().IsFamilyRevoked(ctx, "fam1")
	if !ok {
		t.Fatal("expected true after revoke")
	}
}

func TestRefresh_DeleteExpired(t *testing.T) {
	s := New()
	ctx := context.Background()
	_ = s.RefreshTokens().Save(ctx, storage.RefreshToken{TokenHash: "old", ExpiresAt: time.Now().Add(-time.Hour)})
	_ = s.RefreshTokens().Save(ctx, storage.RefreshToken{TokenHash: "new", ExpiresAt: time.Now().Add(time.Hour)})
	n, _ := s.RefreshTokens().DeleteExpired(ctx, time.Now())
	if n != 1 {
		t.Fatalf("expected 1 deleted, got %d", n)
	}
}

// TestRefresh_MarkUsedNotFound documents the contract: MarkUsed on an
// unknown hash returns ErrNotFound, distinct from ErrAlreadyConsumed
// (which signals reuse).
func TestRefresh_MarkUsedNotFound(t *testing.T) {
	s := New()
	err := s.RefreshTokens().MarkUsed(context.Background(), "never-saved", "anything")
	if !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}
