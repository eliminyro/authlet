package memstore

import (
	"context"
	"sync"
	"time"

	"github.com/eliminyro/authlet/pkg/storage"
)

type clientStore struct {
	mu sync.Mutex
	m  map[string]storage.Client
}

func (c *clientStore) Create(ctx context.Context, cl storage.Client) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.m[cl.ClientID]; ok {
		return storage.ErrAlreadyExists
	}
	c.m[cl.ClientID] = cl
	return nil
}

func (c *clientStore) Get(ctx context.Context, id string) (*storage.Client, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	cl, ok := c.m[id]
	if !ok {
		return nil, storage.ErrNotFound
	}
	return &cl, nil
}

func (c *clientStore) Touch(ctx context.Context, id string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	cl, ok := c.m[id]
	if !ok {
		return storage.ErrNotFound
	}
	cl.LastUsedAt = time.Now().UTC()
	c.m[id] = cl
	return nil
}

func (c *clientStore) DeleteExpired(ctx context.Context, olderThan time.Time) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	deleted := 0
	for id, cl := range c.m {
		// 90-day sliding window: delete if LastUsedAt is older than olderThan
		ref := cl.LastUsedAt
		if ref.IsZero() {
			ref = cl.CreatedAt
		}
		if ref.Before(olderThan) {
			delete(c.m, id)
			deleted++
		}
	}
	return deleted, nil
}
