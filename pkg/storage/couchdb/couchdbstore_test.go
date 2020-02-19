/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package couchdbstore

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/trustbloc/edge-core/pkg/storage"

	"github.com/go-kivik/kivik"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

const (
	couchDBURL       = "localhost:5984"
	testStoreName    = "teststore"
	testDocKey       = "sampleDBKey"
	testJSONValue    = `{"JSONKey":"JSONValue"}`
	testNonJSONValue = "Some arbitrary data"
)

// For these unit tests to run, you must ensure you have a CouchDB instance running at the URL specified in couchDBURL.
// 'make unit-test' from the terminal will take care of this for you.
// To run the tests manually, start an instance by running docker run -p 5984:5984 couchdb:2.3.1 from a terminal.

func TestMain(m *testing.M) {
	err := waitForCouchDBToStart()
	if err != nil {
		logrus.Errorf(err.Error() +
			". Make sure you start a couchDB instance using" +
			" 'docker run -p 5984:5984 couchdb:2.3.1' before running the unit tests")
		os.Exit(1)
	}

	os.Exit(m.Run())
}

func waitForCouchDBToStart() error {
	client, err := kivik.New("couch", couchDBURL)
	if err != nil {
		return err
	}

	timeout := time.After(5 * time.Second)

	for {
		select {
		case <-timeout:
			return fmt.Errorf("timeout: couldn't reach CouchDB server")
		default:
			_, err = client.AllDBs(context.Background())
			if err == nil {
				return nil
			}
		}
	}
}

func TestNewProvider(t *testing.T) {
	t.Run("Valid URL provided", func(t *testing.T) {
		provider, err := NewProvider(couchDBURL)
		require.NoError(t, err)
		require.NotNil(t, provider)
	})
	t.Run("Blank URL provided", func(t *testing.T) {
		provider, err := NewProvider("")
		require.Equal(t, blankHostErrMsg, err.Error())
		require.Nil(t, provider)
	})

	t.Run("Unreachable URL provided", func(t *testing.T) {
		provider, err := NewProvider("%")
		require.Equal(t, `parse http://%: invalid URL escape "%"`, err.Error())
		require.Nil(t, provider)
	})
}

func TestProvider_CreateStore(t *testing.T) {
	t.Run("Successfully create a new store", func(t *testing.T) {
		provider := initializeTest(t)

		err := provider.CreateStore(testStoreName)
		require.NoError(t, err)
	})
	t.Run("Attempt to create a store that already exists", func(t *testing.T) {
		provider := initializeTest(t)

		err := provider.CreateStore(testStoreName)
		require.NoError(t, err)

		err = provider.CreateStore(testStoreName)
		require.Equal(t, "Precondition Failed: The database could not be created, the file already exists.",
			err.Error())
	})
	t.Run("Attempt to create a store with an incompatible name", func(t *testing.T) {
		provider := initializeTest(t)

		err := provider.CreateStore("BadName")
		require.Equal(t, "Bad Request: Name: 'BadName'. Only lowercase characters (a-z), digits (0-9),"+
			" and any of the characters _, $, (, ), +, -, and / are allowed. Must begin with a letter.", err.Error())
	})
}

func TestProvider_OpenStore(t *testing.T) {
	t.Run("Successfully open an existing store - already in cache", func(t *testing.T) {
		provider := initializeTest(t)

		newStore := createAndOpenTestStore(t, provider)
		require.IsType(t, &CouchDBStore{}, newStore)

		// The OpenStore call will cache the store in the provider.
		store, err := provider.OpenStore(testStoreName)
		require.NoError(t, err)

		require.Equal(t, 1, len(provider.dbs))
		require.NotNil(t, store)
		require.Equal(t, newStore, store)
	})
	t.Run("Successfully open an existing store - not in cache", func(t *testing.T) {
		provider := initializeTest(t)

		newStore := createAndOpenTestStore(t, provider)
		require.IsType(t, &CouchDBStore{}, newStore)

		require.Equal(t, 1, len(provider.dbs))
		store := provider.dbs[testStoreName]
		require.NotNil(t, store)
		require.Equal(t, newStore, store)
	})
	t.Run("Attempt to open a non-existent store", func(t *testing.T) {
		provider := initializeTest(t)

		newStore, err := provider.OpenStore(testStoreName)
		require.Nil(t, newStore)
		require.Equal(t, storage.ErrStoreNotFound, err)
	})
	t.Run("Attempt to open a store with a blank name", func(t *testing.T) {
		provider := initializeTest(t)

		newStore, err := provider.OpenStore("")
		require.Nil(t, newStore)
		require.Equal(t, "kivik: dbName required", err.Error())
	})
}

func TestProvider_CloseStore(t *testing.T) {
	t.Run("Successfully close a store", func(t *testing.T) {
		provider := initializeTest(t)

		_ = createAndOpenTestStore(t, provider)

		err := provider.CloseStore(testStoreName)
		require.NoError(t, err)
	})
	t.Run("Attempt to close a non-existent store", func(t *testing.T) {
		provider := initializeTest(t)

		err := provider.CloseStore(testStoreName)
		require.Equal(t, storage.ErrStoreNotFound, err)
	})
}

func TestProvider_Close(t *testing.T) {
	provider := initializeTest(t)

	_ = createAndOpenTestStore(t, provider)

	err := provider.Close()
	require.NoError(t, err)
}

func TestCouchDBStore_Put(t *testing.T) {
	t.Run("Value is JSON", func(t *testing.T) {
		provider := initializeTest(t)

		store := createAndOpenTestStore(t, provider)

		err := store.Put(testDocKey, []byte(testJSONValue))
		require.NoError(t, err)
	})

	t.Run("Value is not JSON", func(t *testing.T) {
		provider := initializeTest(t)

		store := createAndOpenTestStore(t, provider)

		err := store.Put(testDocKey, []byte(testNonJSONValue))
		require.NoError(t, err)
	})
}

func TestCouchDBStore_Get(t *testing.T) {
	t.Run("Document found, original data was JSON and is preserved as such", func(t *testing.T) {
		provider := initializeTest(t)

		store := createAndOpenTestStore(t, provider)

		err := store.Put(testDocKey, []byte(testJSONValue))
		require.NoError(t, err)

		value, err := store.Get(testDocKey)
		require.NoError(t, err)
		require.Equal(t, testJSONValue, string(value))
	})
	t.Run("Document found, original data was not JSON and so was saved as a CouchDB attachment."+
		" Original data is still preserved", func(t *testing.T) {
		provider := initializeTest(t)

		store := createAndOpenTestStore(t, provider)

		err := store.Put(testDocKey, []byte(testNonJSONValue))
		require.NoError(t, err)

		value, err := store.Get(testDocKey)
		require.NoError(t, err)
		require.Equal(t, testNonJSONValue, string(value))
	})
	t.Run("Document not found", func(t *testing.T) {
		provider := initializeTest(t)

		store := createAndOpenTestStore(t, provider)

		value, err := store.Get(testDocKey)
		require.Nil(t, value)
		require.Equal(t, storage.ErrValueNotFound.Error(), err.Error())
	})
}

func TestCouchDBStore_getDataFromAttachment(t *testing.T) {
	t.Run("Attachment found", func(t *testing.T) {
		provider := initializeTest(t)

		_ = createAndOpenTestStore(t, provider)

		_, err := provider.dbs[testStoreName].db.Put(context.Background(), testDocKey,
			wrapTextAsCouchDBAttachment([]byte(testNonJSONValue)))
		require.NoError(t, err)

		data, err := provider.dbs[testStoreName].getDataFromAttachment(testDocKey)
		require.NoError(t, err)
		require.Equal(t, testNonJSONValue, string(data))
	})
	t.Run("Attachment not found", func(t *testing.T) {
		provider := initializeTest(t)

		_ = createAndOpenTestStore(t, provider)

		_, err := provider.dbs[testStoreName].db.Put(context.Background(), testDocKey, []byte(testJSONValue))
		require.NoError(t, err)

		data, err := provider.dbs[testStoreName].getDataFromAttachment(testDocKey)
		require.Nil(t, data)
		require.Equal(t, "Not Found: Document is missing attachment", err.Error())
	})
}

func initializeTest(t *testing.T) *Provider {
	provider, err := NewProvider(couchDBURL)
	require.NoError(t, err)

	resetCouchDB(t, provider)

	return provider
}

// Wipes out the test database that may still exist from a previous test.
func resetCouchDB(t *testing.T, p *Provider) {
	err := p.couchDBClient.DestroyDB(context.Background(), testStoreName)

	if err != nil {
		require.Equal(t, "Not Found: Database does not exist.", err.Error())
	}
}

func createAndOpenTestStore(t *testing.T, provider *Provider) storage.Store {
	err := provider.CreateStore(testStoreName)
	require.NoError(t, err)

	newStore, err := provider.OpenStore(testStoreName)
	require.NotNil(t, newStore)
	require.NoError(t, err)

	return newStore
}
