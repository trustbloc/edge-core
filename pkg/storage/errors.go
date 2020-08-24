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

// ErrGetAllNotSupported is used when the get all function is not supported by the store implementation.
var ErrGetAllNotSupported = errors.New("getting all key-value pairs is not supported")

// ErrKeyRequired is returned when an attempt is made to call a method with an empty key when it's not allowed.
var ErrKeyRequired = errors.New("key is mandatory")
