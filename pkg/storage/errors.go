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

// ErrPutBulkNotImplemented is returned when PutBulk is not implemented by the store implementation.
var ErrPutBulkNotImplemented = errors.New("put bulk not implemented")

// ErrGetBulkNotImplemented is returned when GetBulk is not implemented by the store implementation.
var ErrGetBulkNotImplemented = errors.New("get bulk not implemented")

// ErrNilKeys is returned when PutBulk is called with a nil keys slice.
var ErrNilKeys = errors.New("keys slice cannot be nil")

// ErrNilValues is returned when PutBulk is called with a nil values slice.
var ErrNilValues = errors.New("values slice cannot be nil")

// ErrKeysAndValuesDifferentLengths is returned when an attempt is made to call the PutBulk method with
// differently sized keys and values arrays.
var ErrKeysAndValuesDifferentLengths = errors.New("keys and values must be the same length")

// ErrGetBulkKeysStringSliceNil is returned when an attempt is made to call the GetBulk method with a nil slice of
// strings.
var ErrGetBulkKeysStringSliceNil = errors.New("keys string slice cannot be nil")
