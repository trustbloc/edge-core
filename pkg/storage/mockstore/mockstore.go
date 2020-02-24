/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package mockstore

import (
	"errors"
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

// Close closes all stores created under this store provider
func (p *Provider) Close() error {
	return nil
}

// CloseStore closes store for given name space
func (p *Provider) CloseStore(name string) error {
	return nil
}

// MockStore mock store.
type MockStore struct {
	Store  map[string][]byte
	lock   sync.RWMutex
	ErrPut error
	ErrGet error
	ErrItr error
}

// Put stores the key and the record
func (s *MockStore) Put(k string, v []byte) error {
	if k == "" {
		return errors.New("key is mandatory")
	}

	s.lock.Lock()
	s.Store[k] = v
	s.lock.Unlock()

	return s.ErrPut
}

// Get fetches the record based on key
func (s *MockStore) Get(k string) ([]byte, error) {
	s.lock.RLock()
	defer s.lock.RUnlock()

	val, ok := s.Store[k]
	if !ok {
		return nil, storage.ErrValueNotFound
	}

	return val, s.ErrGet
}

// MockIterator is the mock implementation of storage iterator
type MockIterator struct {
	currentIndex int
	currentItem  []string
	items        [][]string
	err          error
}

func (s *MockIterator) isExhausted() bool {
	return len(s.items) == 0 || len(s.items) == s.currentIndex
}

// Next moves pointer to next value of iterator.
// It returns false if the iterator is exhausted.
func (s *MockIterator) Next() bool {
	if s.isExhausted() {
		return false
	}

	s.currentItem = s.items[s.currentIndex]
	s.currentIndex++

	return true
}

// Release releases associated resources.
func (s *MockIterator) Release() {
	s.currentIndex = 0
	s.items = make([][]string, 0)
	s.currentItem = make([]string, 0)
}

// Error returns error in iterator.
func (s *MockIterator) Error() error {
	return s.err
}

// Key returns the key of the current key/value pair.
func (s *MockIterator) Key() []byte {
	if len(s.items) == 0 || len(s.currentItem) == 0 {
		return nil
	}

	return []byte(s.currentItem[0])
}

// Value returns the value of the current key/value pair.
func (s *MockIterator) Value() []byte {
	if len(s.items) == 0 || len(s.currentItem) < 1 {
		return nil
	}

	return []byte(s.currentItem[1])
}
