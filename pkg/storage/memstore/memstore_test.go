/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package memstore // nolint:testpackage // references internal implementation details

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/edge-core/pkg/storage"
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
		require.EqualError(t, err, storage.ErrDuplicateStore.Error())
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
		require.EqualError(t, err, storage.ErrStoreNotFound.Error())
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
		require.EqualError(t, err, storage.ErrValueNotFound.Error())

		require.Equal(t, 1, len(provider.dbs))
	})
	t.Run("Attempt to close a non-existent store", func(t *testing.T) {
		provider := NewProvider()

		err := provider.CloseStore(testStoreName)
		require.EqualError(t, err, storage.ErrStoreNotFound.Error())
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

func TestMemStore_PutBulk(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		store := MemStore{db: map[string][]byte{}}

		err := store.PutBulk([]string{"someKey", "someKey2"}, [][]byte{[]byte("someValue"), []byte("someValue2")})
		require.NoError(t, err)

		value, exists := store.db["someKey"]
		require.True(t, exists)
		require.Equal(t, "someValue", string(value))

		value, exists = store.db["someKey2"]
		require.True(t, exists)
		require.Equal(t, "someValue2", string(value))
	})
	t.Run("Failure: keys and values are different lengths", func(t *testing.T) {
		store := MemStore{db: map[string][]byte{}}

		err := store.PutBulk([]string{"someKey", "someKey2"}, [][]byte{[]byte("someValue")})
		require.EqualError(t, err, storage.ErrKeysAndValuesDifferentLengths.Error())
	})
}

func TestMemStore_Get(t *testing.T) {
	store := MemStore{db: make(map[string][]byte)}

	store.db["testKey"] = []byte("testValue")

	value, err := store.Get("testKey")
	require.NoError(t, err)

	require.Equal(t, []byte("testValue"), value)
}

func TestMemStore_GetBulk(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		store := MemStore{db: make(map[string][]byte)}

		store.db["testKey"] = []byte("testValue")
		store.db["testKey2"] = []byte("testValue2")

		values, err := store.GetBulk("testKey", "testKey2")
		require.NoError(t, err)

		require.Equal(t, []byte("testValue"), values[0])
		require.Equal(t, []byte("testValue2"), values[1])
	})
	t.Run("Failure: key not found", func(t *testing.T) {
		store := MemStore{db: make(map[string][]byte)}

		values, err := store.GetBulk("testKey", "testKey2")
		require.EqualError(t, err, fmt.Errorf(getBulkKeyNotFound, "testKey", storage.ErrValueNotFound).Error())
		require.Nil(t, values)
	})
	t.Run("Failure: key not found, called with a single key", func(t *testing.T) {
		store := MemStore{db: make(map[string][]byte)}

		values, err := store.GetBulk("testKey")
		require.EqualError(t, err, fmt.Errorf(getBulkKeyNotFound, "testKey", storage.ErrValueNotFound).Error())
		require.Nil(t, values)
	})
	t.Run("Failure: nil argument", func(t *testing.T) {
		store := MemStore{db: make(map[string][]byte)}

		values, err := store.GetBulk(nil...)
		require.EqualError(t, err, storage.ErrGetBulkKeysStringSliceNil.Error())
		require.Nil(t, values)
	})
}

func TestMemStore_GetAll(t *testing.T) {
	store := MemStore{db: make(map[string][]byte)}

	store.db["testKey"] = []byte("testValue")
	store.db["testKey2"] = []byte("testValue2")

	allValues, err := store.GetAll()
	require.NoError(t, err)
	require.Equal(t, allValues["testKey"], []byte("testValue"))
	require.Equal(t, allValues["testKey2"], []byte("testValue2"))
	require.Len(t, allValues, 2)
}

func TestMemStore_CreateIndex(t *testing.T) {
	memStore := &MemStore{}
	err := memStore.CreateIndex(storage.CreateIndexRequest{})
	require.EqualError(t, err, storage.ErrIndexingNotSupported.Error())
}

func TestMemStore_Query(t *testing.T) {
	memStore := &MemStore{}
	itr, err := memStore.Query("")
	require.EqualError(t, err, storage.ErrQueryingNotSupported.Error())
	require.Nil(t, itr)
}

func TestMemStore_Remove(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		testKey := "testKey"
		testValue := []byte("value1")

		prov := NewProvider()

		err := prov.CreateStore(testStoreName)
		require.NoError(t, err)

		store, err := prov.OpenStore(testStoreName)
		require.NoError(t, err)

		err = store.Put(testKey, testValue)
		require.NoError(t, err)

		err = store.Delete(testKey)
		require.NoError(t, err)

		// Verify that the key-value pair was actually deleted
		doc, err := store.Get(testKey)
		require.EqualError(t, err, storage.ErrValueNotFound.Error())
		require.Empty(t, doc)
	})
	t.Run("Key-value pair does not exist", func(t *testing.T) {
		testKey := "testKey"

		prov := NewProvider()

		err := prov.CreateStore(testStoreName)
		require.NoError(t, err)

		store, err := prov.OpenStore(testStoreName)
		require.NoError(t, err)

		err = store.Delete(testKey)
		require.Truef(t, errors.Is(err, storage.ErrValueNotFound),
			`"%s" does not contain the expected error "%s"`, err, storage.ErrValueNotFound)
	})
}
