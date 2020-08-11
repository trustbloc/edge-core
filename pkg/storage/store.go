/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package storage

import "errors"

// ErrDuplicateStore is used when an attempt is made to create a duplicate store.
var ErrDuplicateStore = errors.New("store already exists")

// ErrStoreNotFound is used when a given store was not found in a provider.
var ErrStoreNotFound = errors.New("store not found")

// ErrValueNotFound is used when an attempt is made to retrieve a value using a key that isn't in the store.
var ErrValueNotFound = errors.New("store does not have a value associated with this key")

// ErrIndexingNotSupported is used when create index is not supported by the store implementation.
var ErrIndexingNotSupported = errors.New("indexing is not supported")

// ErrQueryingNotSupported  is used when querying is not supported by the store implementation.
var ErrQueryingNotSupported = errors.New("querying is not supported")

// ErrKeyRequired is returned when an attempt is made to call a method with an empty key when it's not allowed.
var ErrKeyRequired = errors.New("key is mandatory")

// EndKeySuffix end key suffix
const EndKeySuffix = "!!"

// DeleteFailureErrMsg is used when there's a failure during a key-value pair deletion from a store.
const DeleteFailureErrMsg = "failure during deletion: %w"

// Provider represents a storage provider.
type Provider interface {
	// CreateStore creates a new store with the given name.
	CreateStore(name string) error

	// OpenStore opens an existing store and returns it.
	OpenStore(name string) (Store, error)

	// CloseStore closes the store with the given name.
	CloseStore(name string) error

	// Close closes all stores created under this store provider.
	Close() error
}

// CreateIndexRequest represents the information that a store needs to create a
// new user-specified index.
type CreateIndexRequest struct {
	// IndexStorageLocation is the place where the index (and any associated configuration data) is stored.
	// The usage of this depends on the implementation.
	IndexStorageLocation string
	// IndexName is the user-defined name that should be assigned to this new index.
	IndexName string
	// WhatToIndex are the field(s) that you want to index.
	// The syntax for this string depends on the implementation.
	WhatToIndex string
}

// Store represents a storage database.
type Store interface {
	// Put stores the key-value pair.
	Put(k string, v []byte) error

	// Get fetches the value associated with the given key.
	Get(k string) ([]byte, error)

	// CreateIndex creates an index in the store based on the provided CreateIndexRequest.
	CreateIndex(createIndexRequest CreateIndexRequest) error

	// Query queries the store for data based on the provided query string, the format of
	// which will be dependent on what the underlying store requires.
	Query(query string) (ResultsIterator, error)

	// Delete deletes the key-value pair associated with k.
	Delete(k string) error
}

// ResultsIterator represents an iterator that can be used to iterate over all the stored key-value pairs.
type ResultsIterator interface {
	// Next moves the pointer to the next value in the iterator. It returns false if the iterator is exhausted.
	Next() (bool, error)

	// Release releases associated resources. Release should always result in success
	// and can be called multiple times without causing an error.
	Release() error

	// Key returns the key of the current key-value pair.
	Key() (string, error)

	// Value returns the value of the current key-value pair.
	Value() ([]byte, error)
}
