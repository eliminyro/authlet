package memstore

import (
	"context"
	"sync"
	"time"

	"github.com/eliminyro/authlet/pkg/storage"
)

type codeStore struct {
	mu sync.Mutex
	m  map[string]storage.AuthCode
}

func (c *codeStore) Save(ctx context.Context, code storage.AuthCode) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.m[code.CodeHash]; ok {
		return storage.ErrAlreadyExists
	}
	c.m[code.CodeHash] = code
	return nil
}

func (c *codeStore) ConsumeOnce(ctx context.Context, codeHash string) (*storage.AuthCode, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	code, ok := c.m[codeHash]
	if !ok {
		return nil, storage.ErrNotFound
	}
	delete(c.m, codeHash)
	if time.Now().After(code.ExpiresAt) {
		return nil, storage.ErrAlreadyConsumed
	}
	return &code, nil
}

func (c *codeStore) DeleteExpired(ctx context.Context, before time.Time) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	deleted := 0
	for h, code := range c.m {
		if code.ExpiresAt.Before(before) {
			delete(c.m, h)
			deleted++
		}
	}
	return deleted, nil
}
