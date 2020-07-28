/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package couchdbstore

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/go-kivik/kivik"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/edge-core/pkg/storage"
)

const (
	couchDBURL                 = "localhost:5984"
	testStoreName              = "teststore"
	testDocKey                 = "sampleDBKey"
	testDocKey2                = "sampleDBKey2"
	testJSONValue              = `{"JSONKey":"JSONValue"}`
	testJSONValue1             = `{"JSONKey1":"JSONValue1"}`
	testJSONValue2             = `{"JSONKey2":"JSONValue2"}`
	testJSONWithMultipleFields = `{"employeeID":1234,"name":"Mr. Trustbloc"}`
	testNonJSONValue           = "1"
	testNonJSONValue1          = "2"
	testIndexName              = "TestIndex"
	testDesignDoc              = "TestDesignDoc"
)

// For these unit tests to run, you must ensure you have a CouchDB instance running at the URL specified in couchDBURL.
// 'make unit-test' from the terminal will take care of this for you.
// To run the tests manually, start an instance by running docker run -p 5984:5984 couchdb:2.3.1 from a terminal.

func TestMain(m *testing.M) {
	err := waitForCouchDBToStart()
	if err != nil {
		log.Errorf(err.Error() +
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
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid URL escape")
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
		require.Equal(t, storage.ErrDuplicateStore.Error(), err.Error())
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
		provider := initializeTest(t, WithDBPrefix("prefixdb"))

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

		err := store.Put(testDocKey, []byte(testJSONValue1))
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

		err = store.Put(testDocKey, []byte(testJSONValue1))
		require.NoError(t, err)

		value, err = store.Get(testDocKey)
		require.NoError(t, err)
		require.Equal(t, testJSONValue1, string(value))
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

		err = store.Put(testDocKey, []byte(testNonJSONValue1))
		require.NoError(t, err)

		value, err = store.Get(testDocKey)
		require.NoError(t, err)
		require.Equal(t, testNonJSONValue1, string(value))
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

		_, err := provider.dbs[testStoreName].db.Put(context.Background(), testDocKey, []byte(testJSONValue1))
		require.NoError(t, err)

		data, err := provider.dbs[testStoreName].getDataFromAttachment(testDocKey)
		require.Nil(t, data)
		require.Equal(t, "Not Found: Document is missing attachment", err.Error())
	})
}

func TestCouchDBStore_CreateIndex(t *testing.T) {
	t.Run("Successfully create index", func(t *testing.T) {
		provider := initializeTest(t)
		store := createAndOpenTestStore(t, provider)

		err := createIndex(store, `{"fields": ["SomeField"]}`)
		require.NoError(t, err)

		couchDBStore, ok := store.(*CouchDBStore)
		require.True(t, ok)

		indexes, err := couchDBStore.db.GetIndexes(context.Background())
		require.NoError(t, err)
		require.Equal(t, testIndexName, indexes[1].Name)
	})
	t.Run("Fail to create index - invalid index request", func(t *testing.T) {
		provider := initializeTest(t)
		store := createAndOpenTestStore(t, provider)

		err := createIndex(store, `{"fields": [""]}`)
		require.EqualError(t, err, "Bad Request: Invalid sort field: <<>>")
	})
}

func TestCouchDBStore_Query(t *testing.T) {
	t.Run("Successfully query using index", func(t *testing.T) {
		provider := initializeTest(t)
		store := createAndOpenTestStore(t, provider)

		err := store.Put(testDocKey, []byte(testJSONWithMultipleFields))
		require.NoError(t, err)

		err = createIndex(store, `{"fields": ["employeeID"]}`)
		require.NoError(t, err)

		var logContents bytes.Buffer
		log.SetOutput(&logContents)

		itr, err := store.Query(`{
		   "selector": {
		       "employeeID": 1234
		   },
			"use_index": ["` + testDesignDoc + `", "` + testIndexName + `"]
		}`)
		require.NoError(t, err)

		ok, err := itr.Next()
		require.NoError(t, err)
		require.True(t, ok)

		value, err := itr.Value()
		require.NoError(t, err)
		require.Equal(t, testJSONWithMultipleFields, string(value))

		ok, err = itr.Next()
		require.NoError(t, err)
		require.False(t, ok)

		// Check to make sure an "index not used" warning didn't get logged
		require.Empty(t, logContents.String())

		err = itr.Release()
		require.NoError(t, err)
	})
	t.Run("Successfully query using index, but the index isn't used because it's not valid for the query",
		func(t *testing.T) {
			provider := initializeTest(t)
			store := createAndOpenTestStore(t, provider)

			err := store.Put(testDocKey, []byte(testJSONWithMultipleFields))
			require.NoError(t, err)

			err = createIndex(store, `{"fields": ["name"]}`)
			require.NoError(t, err)

			var logContents bytes.Buffer
			log.SetOutput(&logContents)

			itr, err := store.Query(`{
		   "selector": {
		       "employeeID": 1234
		   },
			"use_index": ["` + testDesignDoc + `", "` + testIndexName + `"]
		}`)
			require.NoError(t, err)

			ok, err := itr.Next()
			require.NoError(t, err)
			require.True(t, ok)

			require.NoError(t, err)
			value, err := itr.Value()
			require.NoError(t, err)
			require.Equal(t, testJSONWithMultipleFields, string(value))

			ok, err = itr.Next()
			require.NoError(t, err)
			require.False(t, ok)

			// Confirm that an "index not used" warning got logged
			// Note that Kivik only sets the warning valueafter all the rows have been iterated through.
			require.Contains(t, logContents.String(), "_design/"+testDesignDoc+", "+testIndexName+" was not used because "+
				"it is not a valid index for this query.")
			err = itr.Release()
			require.NoError(t, err)
		})
	t.Run("Fail to query - invalid query JSON", func(t *testing.T) {
		provider := initializeTest(t)
		store := createAndOpenTestStore(t, provider)

		itr, err := store.Query(``)
		require.EqualError(t, err, "Bad Request: invalid UTF-8 JSON")
		require.Nil(t, itr)
	})
}

func TestCouchDBStore_ResultsIterator(t *testing.T) {
	t.Run("Successfully iterate over all documents", func(t *testing.T) {
		provider := initializeTest(t)

		store := createAndOpenTestStore(t, provider)

		rawData := make(map[string][]byte)
		rawData[testDocKey] = []byte(testJSONValue)
		rawData[testDocKey2] = []byte(testJSONValue2)
		rawData["key3"] = []byte("This value will be stored as an attachment, as opposed to the two values above. " +
			"This will allow both cases to be tested here.")

		for k, v := range rawData {
			err := store.Put(k, v)
			require.NoError(t, err)
		}

		couchDBStore, ok := store.(*CouchDBStore)
		require.True(t, ok)

		rows, err := couchDBStore.db.AllDocs(context.Background(), kivik.Options{"include_docs": true})
		require.NoError(t, err)

		itr := couchDBResultsIterator{resultRows: rows, store: couchDBStore}

		nextOK, nextErr := itr.Next()
		require.NoError(t, nextErr)
		count := 1
		for nextOK {
			key, keyErr := itr.Key()
			require.NoError(t, keyErr)
			val, ok := rawData[key]
			require.True(t, ok)
			itrValue, valueErr := itr.Value()
			require.NoError(t, valueErr)
			require.Equal(t, val, itrValue)
			nextOK, nextErr = itr.Next()
			if count == 3 {
				require.NoError(t, nextErr)
				require.False(t, nextOK)
			} else {
				require.NoError(t, nextErr)
				require.True(t, ok)
				count++
			}
		}
		require.Equal(t, len(rawData), count)

		err = itr.Release()
		require.NoError(t, err)
	})
	t.Run("No data in iterator", func(t *testing.T) {
		provider := initializeTest(t)
		store := createAndOpenTestStore(t, provider)

		couchDBStore, ok := store.(*CouchDBStore)
		require.True(t, ok)

		rows, err := couchDBStore.db.AllDocs(context.Background(), kivik.Options{"include_docs": true})
		require.NoError(t, err)

		itr := couchDBResultsIterator{resultRows: rows, store: couchDBStore}

		ok, err = itr.Next()
		require.NoError(t, err)
		require.False(t, ok)
		// Kivik closes its iterator automatically when its exhausted.
		// When calling itr.Value(), we should expect an error telling us that it's already closed.
		value, err := itr.Value()
		require.EqualError(t, err, "kivik: Iterator is closed")
		require.Nil(t, value)
		err = itr.Release()
		require.NoError(t, err)
	})
}

func initializeTest(t *testing.T, opts ...Option) *Provider {
	provider, err := NewProvider(couchDBURL, opts...)
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

func createIndex(store storage.Store, whatToIndex string) error {
	createIndexRequest := storage.CreateIndexRequest{
		IndexStorageLocation: testDesignDoc,
		IndexName:            testIndexName,
		WhatToIndex:          whatToIndex,
	}

	return store.CreateIndex(createIndexRequest)
}
