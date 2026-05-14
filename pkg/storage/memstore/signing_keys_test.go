package memstore

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/eliminyro/authlet/pkg/storage"
)

func TestSigningKey_InsertAndGetSigner(t *testing.T) {
	s := New()
	ctx := context.Background()
	_ = s.SigningKeys().Insert(ctx, storage.SigningKey{ID: "k1", IsActive: true, CreatedAt: time.Now()})
	got, err := s.SigningKeys().GetSigner(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != "k1" {
		t.Fatalf("got %q", got.ID)
	}
}

func TestSigningKey_InsertDeactivatesPriorActive(t *testing.T) {
	s := New()
	ctx := context.Background()
	_ = s.SigningKeys().Insert(ctx, storage.SigningKey{ID: "k1", IsActive: true, CreatedAt: time.Now()})
	_ = s.SigningKeys().Insert(ctx, storage.SigningKey{ID: "k2", IsActive: true, CreatedAt: time.Now()})
	got, _ := s.SigningKeys().GetSigner(ctx)
	if got.ID != "k2" {
		t.Fatalf("expected k2 active, got %q", got.ID)
	}
}

func TestSigningKey_ListActiveExcludesRetired(t *testing.T) {
	s := New()
	ctx := context.Background()
	_ = s.SigningKeys().Insert(ctx, storage.SigningKey{ID: "k1", IsActive: true, CreatedAt: time.Now()})
	_ = s.SigningKeys().Insert(ctx, storage.SigningKey{ID: "k2", IsActive: true, CreatedAt: time.Now()})
	_ = s.SigningKeys().Retire(ctx, "k1", time.Now().Add(-time.Hour))
	keys, _ := s.SigningKeys().ListActive(ctx)
	if len(keys) != 1 || keys[0].ID != "k2" {
		t.Fatalf("expected only k2, got %+v", keys)
	}
}

func TestSigningKey_GetSignerNoActive(t *testing.T) {
	s := New()
	_, err := s.SigningKeys().GetSigner(context.Background())
	if !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}
