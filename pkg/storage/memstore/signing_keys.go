package memstore

import (
	"context"
	"sync"
	"time"

	"github.com/eliminyro/authlet/pkg/storage"
)

type signingKeyStore struct {
	mu sync.Mutex
	m  []storage.SigningKey
}

func (s *signingKeyStore) ListActive(ctx context.Context) ([]storage.SigningKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	out := make([]storage.SigningKey, 0, len(s.m))
	for _, k := range s.m {
		if k.RetiresAt != nil && k.RetiresAt.Before(now) {
			continue
		}
		out = append(out, k)
	}
	return out, nil
}

func (s *signingKeyStore) GetSigner(ctx context.Context) (storage.SigningKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, k := range s.m {
		if k.IsActive {
			return k, nil
		}
	}
	return storage.SigningKey{}, storage.ErrNotFound
}

func (s *signingKeyStore) Insert(ctx context.Context, k storage.SigningKey) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if k.IsActive {
		for i := range s.m {
			s.m[i].IsActive = false
		}
	}
	s.m = append(s.m, k)
	return nil
}

func (s *signingKeyStore) Retire(ctx context.Context, id string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, k := range s.m {
		if k.ID == id {
			s.m[i].IsActive = false
			t := at
			s.m[i].RetiresAt = &t
			return nil
		}
	}
	return storage.ErrNotFound
}
