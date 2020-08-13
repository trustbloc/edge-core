/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package memstore

import (
	"sync"

	"github.com/trustbloc/edge-core/pkg/storage"
)

// Provider represents an MemStore implementation of the storage.Provider interface
type Provider struct {
	dbs map[string]*MemStore
	mux sync.RWMutex
}

// NewProvider instantiates Provider
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
