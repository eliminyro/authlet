// Package memstore is the in-memory reference implementation of pkg/storage.
// It is goroutine-safe but not persistent. Useful for tests and cmd/authletd.
package memstore

import (
	"github.com/eliminyro/authlet/pkg/storage"
)

// Store is the umbrella in-memory storage. It composes one struct per
// sub-store and exposes each via the storage.Storage interface.
type Store struct {
	clients *clientStore
	codes   *codeStore
}

// New constructs an empty in-memory Store with all sub-stores initialised.
func New() *Store {
	return &Store{
		clients: &clientStore{m: map[string]storage.Client{}},
		codes:   &codeStore{m: map[string]storage.AuthCode{}},
	}
}

// Clients returns the in-memory ClientStore.
func (s *Store) Clients() storage.ClientStore { return s.clients }

// Codes returns the in-memory CodeStore.
func (s *Store) Codes() storage.CodeStore { return s.codes }
