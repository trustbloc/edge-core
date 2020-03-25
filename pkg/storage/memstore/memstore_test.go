/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package memstore

import (
	"testing"

	"github.com/trustbloc/edge-core/pkg/storage"

	"github.com/stretchr/testify/require"
)

const testStoreName = "teststore"

func TestProvider_CreateStore(t *testing.T) {
	t.Run("Successfully create a new store", func(t *testing.T) {
		provider := NewProvider()

		err := provider.CreateStore(testStoreName)
		require.NoError(t, err)
	})
	t.Run("Attempt to create a duplicate store", func(t *testing.T) {
		provider := NewProvider()

		err := provider.CreateStore(testStoreName)
		require.NoError(t, err)

		err = provider.CreateStore(testStoreName)
		require.Equal(t, storage.ErrDuplicateStore, err)
	})
}

func TestMemStore_OpenStore(t *testing.T) {
	t.Run("Successfully open an existing store", func(t *testing.T) {
		provider := NewProvider()

		err := provider.CreateStore(testStoreName)
		require.NoError(t, err)

		newStore, err := provider.OpenStore(testStoreName)
		require.NoError(t, err)
		require.IsType(t, &MemStore{}, newStore)
	})
	t.Run("Attempt to open a non-existent store", func(t *testing.T) {
		provider := NewProvider()

		newStore, err := provider.OpenStore(testStoreName)
		require.Nil(t, newStore)
		require.Equal(t, storage.ErrStoreNotFound, err)
	})
}

func TestProvider_CloseStore(t *testing.T) {
	t.Run("Successfully close store", func(t *testing.T) {
		provider := NewProvider()

		err := provider.CreateStore(testStoreName)
		require.NoError(t, err)

		newStore, err := provider.OpenStore(testStoreName)
		require.NoError(t, err)

		err = newStore.Put("something", []byte("value"))
		require.NoError(t, err)

		err = provider.CreateStore("store2")
		require.NoError(t, err)

		_, err = provider.OpenStore("store2")
		require.NoError(t, err)

		err = provider.CloseStore(testStoreName)
		require.NoError(t, err)

		_, err = newStore.Get("something")
		require.Equal(t, storage.ErrValueNotFound, err)

		require.Equal(t, 1, len(provider.dbs))
	})
	t.Run("Attempt to close a non-existent store", func(t *testing.T) {
		provider := NewProvider()

		err := provider.CloseStore(testStoreName)
		require.Equal(t, storage.ErrStoreNotFound, err)
	})
}

func TestProvider_Close(t *testing.T) {
	provider := NewProvider()

	err := provider.CreateStore(testStoreName)
	require.NoError(t, err)

	_, err = provider.OpenStore(testStoreName)
	require.NoError(t, err)

	err = provider.CreateStore("store2")
	require.NoError(t, err)

	_, err = provider.OpenStore("store2")
	require.NoError(t, err)

	err = provider.Close()
	require.NoError(t, err)

	require.Equal(t, 0, len(provider.dbs))
}

func TestMemStore_Put(t *testing.T) {
	store := MemStore{db: map[string][]byte{}}

	err := store.Put("someKey", []byte("someValue"))
	require.NoError(t, err)

	value, exists := store.db["someKey"]
	require.True(t, exists)
	require.Equal(t, "someValue", string(value))
}

func TestMemStore_Get(t *testing.T) {
	store := MemStore{db: make(map[string][]byte)}

	store.db["testKey"] = []byte("testValue")

	value, err := store.Get("testKey")
	require.NoError(t, err)

	require.Equal(t, []byte("testValue"), value)
}

func TestMemStore_CreateIndex(t *testing.T) {
	memStore := &MemStore{}
	err := memStore.CreateIndex(storage.CreateIndexRequest{})
	require.Equal(t, errIndexingNotSupported, err)
}

func TestMemStore_Query(t *testing.T) {
	memStore := &MemStore{}
	itr, err := memStore.Query("")
	require.Equal(t, errQueryingNotSupported, err)
	require.Nil(t, itr)
}
