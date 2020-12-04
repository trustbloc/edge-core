/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package mockstore

import (
	"fmt"
	"sync"

	"github.com/trustbloc/edge-core/pkg/storage"
)

// Provider mock store provider.
type Provider struct {
	Store              *MockStore
	ErrCreateStore     error
	ErrOpenStoreHandle error
	FailNameSpace      string
}

// NewMockStoreProvider new store provider instance.
func NewMockStoreProvider() *Provider {
	return &Provider{Store: &MockStore{
		Store: make(map[string][]byte),
	}}
}

// CreateStore creates a new store with the given name.
func (p *Provider) CreateStore(name string) error {
	return p.ErrCreateStore
}

// OpenStore opens and returns a store for given name space.
func (p *Provider) OpenStore(name string) (storage.Store, error) {
	if name == p.FailNameSpace {
		return nil, fmt.Errorf("failed to open store for name space %s", name)
	}

	return p.Store, p.ErrOpenStoreHandle
}

// Close closes all stores created under this store provider.
func (p *Provider) Close() error {
	return nil
}

// CloseStore closes store for given name space.
func (p *Provider) CloseStore(name string) error {
	return nil
}

// MockStore represents a mock store.
type MockStore struct {
	Store                   map[string][]byte
	lock                    sync.RWMutex
	ErrPut                  error
	ErrPutBulk              error
	ErrGet                  error
	ErrBulkGet              error
	ErrGetAll               error
	ErrCreateIndex          error
	ErrQuery                error
	ErrDelete               error
	ResultsIteratorToReturn storage.ResultsIterator
}

// Put stores the key-value pair.
func (s *MockStore) Put(k string, v []byte) error {
	if k == "" {
		return storage.ErrKeyRequired
	}

	s.lock.Lock()
	s.Store[k] = v
	s.lock.Unlock()

	return s.ErrPut
}

// PutBulk stores the key-value pairs in the order given in the array. The end result is equivalent to calling
// Put(k,v) on each key-value pair individually in a loop.
func (s *MockStore) PutBulk(keys []string, values [][]byte) error {
	if len(keys) != len(values) {
		return storage.ErrKeysAndValuesDifferentLengths
	}

	s.lock.Lock()
	defer s.lock.Unlock()

	for i := 0; i < len(keys); i++ {
		if keys[i] == "" {
			return storage.ErrKeyRequired
		}

		s.Store[keys[i]] = values[i]
	}

	return s.ErrPutBulk
}

// Get fetches the value associated with the given key.
func (s *MockStore) Get(k string) ([]byte, error) {
	s.lock.RLock()
	defer s.lock.RUnlock()

	val, ok := s.Store[k]
	if !ok {
		return nil, storage.ErrValueNotFound
	}

	return val, s.ErrGet
}

// GetBulk fetches the values associated with the given keys. This method works in an all-or-nothing manner.
// It returns an error if any of the keys don't exist. If even one key is missing, then no values are returned.
func (s *MockStore) GetBulk(keys ...string) ([][]byte, error) {
	if keys == nil {
		return nil, storage.ErrGetBulkKeysStringSliceNil
	}

	storedValues := make([][]byte, len(keys))

	s.lock.RLock()
	defer s.lock.RUnlock()

	for i, key := range keys {
		v, exists := s.Store[key]
		if !exists {
			return nil, fmt.Errorf("no value found for key %s: %w", key, storage.ErrValueNotFound)
		}

		storedValues[i] = v
	}

	return storedValues, s.ErrBulkGet
}

// GetAll fetches all the key-value pairs within this store.
func (s *MockStore) GetAll() (map[string][]byte, error) {
	return s.Store, s.ErrGetAll
}

// CreateIndex returns a mocked error.
func (s *MockStore) CreateIndex(createIndexRequest storage.CreateIndexRequest) error {
	return s.ErrCreateIndex
}

// Query returns a mocked error.
func (s *MockStore) Query(query string) (storage.ResultsIterator, error) {
	return s.ResultsIteratorToReturn, s.ErrQuery
}

// Delete deletes the key-value pair associated with k.
func (s *MockStore) Delete(k string) error {
	s.lock.Lock()
	delete(s.Store, k)
	s.lock.Unlock()

	return s.ErrDelete
}
