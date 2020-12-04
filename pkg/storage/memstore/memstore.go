/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package memstore

import (
	"fmt"
	"sync"

	"github.com/trustbloc/edge-core/pkg/storage"
)

const getBulkKeyNotFound = "no value found for key %s: %w"

// Provider represents an MemStore implementation of the storage.Provider interface.
type Provider struct {
	dbs map[string]*MemStore
	mux sync.RWMutex
}

// NewProvider instantiates Provider.
func NewProvider() *Provider {
	return &Provider{dbs: make(map[string]*MemStore)}
}

// CreateStore creates a new store with the given name.
func (p *Provider) CreateStore(name string) error {
	p.mux.Lock()
	defer p.mux.Unlock()

	_, exists := p.dbs[name]
	if exists {
		return storage.ErrDuplicateStore
	}

	store := MemStore{db: make(map[string][]byte)}

	p.dbs[name] = &store

	return nil
}

// OpenStore opens an existing store with the given name and returns it.
func (p *Provider) OpenStore(name string) (storage.Store, error) {
	p.mux.RLock()
	defer p.mux.RUnlock()

	store, exists := p.dbs[name]
	if !exists {
		return nil, storage.ErrStoreNotFound
	}

	return store, nil
}

// CloseStore closes a previously opened store.
func (p *Provider) CloseStore(name string) error {
	p.mux.Lock()
	defer p.mux.Unlock()

	store, exists := p.dbs[name]
	if !exists {
		return storage.ErrStoreNotFound
	}

	delete(p.dbs, name)

	store.close()

	return nil
}

// Close closes the provider.
func (p *Provider) Close() error {
	p.mux.Lock()
	defer p.mux.Unlock()

	for _, memStore := range p.dbs {
		memStore.db = make(map[string][]byte)
	}

	p.dbs = make(map[string]*MemStore)

	return nil
}

// MemStore is a simple DB that's stored in memory. Useful for demos or testing. Not designed to be performant.
type MemStore struct {
	db  map[string][]byte
	mux sync.RWMutex
}

// Put stores the given key-value pair in the store.
func (m *MemStore) Put(k string, v []byte) error {
	m.mux.Lock()
	defer m.mux.Unlock()

	m.db[k] = v

	return nil
}

// PutBulk stores the key-value pairs in the order given in the array. The end result is equivalent to calling
// Put(k,v) on each key-value pair individually in a loop.
func (m *MemStore) PutBulk(keys []string, values [][]byte) error {
	if len(keys) != len(values) {
		return storage.ErrKeysAndValuesDifferentLengths
	}

	m.mux.Lock()
	defer m.mux.Unlock()

	for i := 0; i < len(keys); i++ {
		m.db[keys[i]] = values[i]
	}

	return nil
}

// Get retrieves the value in the store associated with the given key.
func (m *MemStore) Get(k string) ([]byte, error) {
	m.mux.RLock()
	defer m.mux.RUnlock()

	v, exists := m.db[k]
	if !exists {
		return nil, storage.ErrValueNotFound
	}

	return v, nil
}

// GetBulk fetches the values associated with the given keys. This method works in an all-or-nothing manner.
// It returns an error if any of the keys don't exist. If even one key is missing, then no values are returned.
func (m *MemStore) GetBulk(keys ...string) ([][]byte, error) {
	if keys == nil {
		return nil, storage.ErrGetBulkKeysStringSliceNil
	}

	storedValues := make([][]byte, len(keys))

	m.mux.RLock()
	defer m.mux.RUnlock()

	for i, key := range keys {
		v, exists := m.db[key]
		if !exists {
			return nil, fmt.Errorf(getBulkKeyNotFound, key, storage.ErrValueNotFound)
		}

		storedValues[i] = v
	}

	return storedValues, nil
}

// GetAll fetches all the key-value pairs within this store.
func (m *MemStore) GetAll() (map[string][]byte, error) {
	return m.db, nil
}

// CreateIndex is not supported in memstore, and calling it will always return an error.
func (m *MemStore) CreateIndex(createIndexRequest storage.CreateIndexRequest) error {
	return storage.ErrIndexingNotSupported
}

// Query is not supported in memstore, and calling it will always return an error.
func (m *MemStore) Query(query string) (storage.ResultsIterator, error) {
	return nil, storage.ErrQueryingNotSupported
}

func (m *MemStore) close() {
	m.mux.Lock()
	defer m.mux.Unlock()

	m.db = make(map[string][]byte)
}

// Delete deletes the key-value pair associated with k.
func (m *MemStore) Delete(k string) error {
	m.mux.Lock()
	defer m.mux.Unlock()

	_, exists := m.db[k]
	if !exists {
		return storage.ErrValueNotFound
	}

	delete(m.db, k)

	return nil
}
