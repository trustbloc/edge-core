/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package memstore

import (
	"github.com/trustbloc/edge-core/pkg/storage"
)

// Provider represents an MemStore implementation of the storage.Provider interface
type Provider struct {
	dbs map[string]*MemStore
}

// NewProvider instantiates Provider
func NewProvider() *Provider {
	return &Provider{dbs: make(map[string]*MemStore)}
}

// CreateStore creates a new store with the given name.
func (p *Provider) CreateStore(name string) error {
	store := MemStore{db: make(map[string][]byte)}

	p.dbs[name] = &store

	return nil
}

// OpenStore opens an existing store with the given name and returns it.
func (p *Provider) OpenStore(name string) (storage.Store, error) {
	store, exists := p.dbs[name]
	if !exists {
		return nil, storage.ErrStoreNotFound
	}

	return store, nil
}

// CloseStore closes a previously opened store.
func (p *Provider) CloseStore(name string) error {
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
	for _, memStore := range p.dbs {
		memStore.db = make(map[string][]byte)
	}

	p.dbs = make(map[string]*MemStore)

	return nil
}

// MemStore is a simple DB that's stored in memory. Useful for demos or testing. Not designed to be performant.
type MemStore struct {
	db map[string][]byte
}

// Put stores the given key-value pair in the store.
func (m *MemStore) Put(k string, v []byte) error {
	m.db[k] = v

	return nil
}

// Get retrieves the value in the store associated with the given key.
func (m *MemStore) Get(k string) ([]byte, error) {
	v, exists := m.db[k]
	if !exists {
		return nil, storage.ErrValueNotFound
	}

	return v, nil
}

func (m *MemStore) close() {
	m.db = make(map[string][]byte)
}
