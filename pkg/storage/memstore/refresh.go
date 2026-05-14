package memstore

import (
	"context"
	"sync"
	"time"

	"github.com/eliminyro/authlet/pkg/storage"
)

type refreshStore struct {
	mu      sync.Mutex
	m       map[string]storage.RefreshToken
	revoked map[string]struct{} // family IDs
}

func (r *refreshStore) Save(ctx context.Context, rt storage.RefreshToken) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.m[rt.TokenHash]; ok {
		return storage.ErrAlreadyExists
	}
	r.m[rt.TokenHash] = rt
	return nil
}

func (r *refreshStore) Get(ctx context.Context, hash string) (*storage.RefreshToken, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	rt, ok := r.m[hash]
	if !ok {
		return nil, storage.ErrNotFound
	}
	if _, gone := r.revoked[rt.FamilyID]; gone {
		return nil, storage.ErrFamilyRevoked
	}
	return &rt, nil
}

func (r *refreshStore) MarkUsed(ctx context.Context, hash string, replacedBy string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	rt, ok := r.m[hash]
	if !ok {
		return storage.ErrNotFound
	}
	if rt.ReplacedBy != "" {
		// reuse detection — caller is expected to RevokeFamily next
		return storage.ErrAlreadyConsumed
	}
	rt.ReplacedBy = replacedBy
	r.m[hash] = rt
	return nil
}

func (r *refreshStore) RevokeFamily(ctx context.Context, familyID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.revoked[familyID] = struct{}{}
	return nil
}

func (r *refreshStore) IsFamilyRevoked(ctx context.Context, familyID string) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, ok := r.revoked[familyID]
	return ok, nil
}

func (r *refreshStore) DeleteExpired(ctx context.Context, before time.Time) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	deleted := 0
	for h, rt := range r.m {
		if rt.ExpiresAt.Before(before) {
			delete(r.m, h)
			deleted++
		}
	}
	return deleted, nil
}
