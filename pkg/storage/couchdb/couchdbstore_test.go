/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package couchdbstore

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"testing"
	"time"

	"github.com/go-kivik/kivik"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/edge-core/pkg/log"
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
	testDBPrefix               = "dbprefix"
)

var testLogger = &TestLogger{} //nolint: gochecknoglobals
var errFailingMarshal = errors.New("failingMarshal always fails")
var errFailingReadAll = errors.New("failingReadAll always fails")
var errFailingUnquote = errors.New("failingUnquote always fails")

// For these unit tests to run, you must ensure you have a CouchDB instance running at the URL specified in couchDBURL.
// 'make unit-test' from the terminal will take care of this for you.
// To run the tests manually, start an instance by running docker run -p 5984:5984 couchdb:2.3.1 from a terminal.

type TestLogger struct {
	logContents string
}

func (t *TestLogger) Fatalf(msg string, _ ...interface{}) {
	t.logContents = msg
}

func (t *TestLogger) Panicf(msg string, _ ...interface{}) {
	t.logContents = msg
}

func (t *TestLogger) Debugf(msg string, _ ...interface{}) {
	t.logContents = msg
}

func (t *TestLogger) Infof(msg string, _ ...interface{}) {
	t.logContents = msg
}

func (t *TestLogger) Warnf(msg string, _ ...interface{}) {
	t.logContents = msg
}

func (t *TestLogger) Errorf(msg string, _ ...interface{}) {
	t.logContents = msg
}

type testLoggerProvider struct {
}

func (t *testLoggerProvider) GetLogger(string) log.Logger {
	return testLogger
}

func TestMain(m *testing.M) {
	err := waitForCouchDBToStart()
	if err != nil {
		logger.Errorf(err.Error() +
			". Make sure you start a couchDB instance using" +
			" 'docker run -p 5984:5984 couchdb:2.3.1' before running the unit tests")
		os.Exit(1)
	}

	log.Initialize(&testLoggerProvider{})

	log.SetLevel(logModuleName, log.DEBUG)

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
		require.EqualError(t, err, errBlankHost.Error())
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
		require.Truef(t, errors.Is(err, storage.ErrDuplicateStore),
			`"%s" does not contain the expected error "%s"`, err, storage.ErrDuplicateStore)
	})
	t.Run("Attempt to create a store with an incompatible name", func(t *testing.T) {
		provider := initializeTest(t)

		err := provider.CreateStore("BadName")
		require.Error(t, err)
		require.Contains(t, err.Error(),
			"Bad Request: Name: 'BadName'. Only lowercase characters (a-z), digits (0-9),"+
				" and any of the characters _, $, (, ), +, -, and / are allowed. Must begin with a letter.")
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
		require.EqualError(t, err, storage.ErrStoreNotFound.Error())
	})
	t.Run("Attempt to open a store with a blank name", func(t *testing.T) {
		provider := initializeTest(t)

		newStore, err := provider.OpenStore("")
		require.Nil(t, newStore)
		require.Error(t, err)
		require.Contains(t, err.Error(), "kivik: dbName required")
	})
}

func TestProvider_CloseStore(t *testing.T) {
	t.Run("Successfully close a store", func(t *testing.T) {
		provider := initializeTest(t, WithDBPrefix(testDBPrefix))

		_ = createAndOpenTestStore(t, provider)

		err := provider.CloseStore(testStoreName)
		require.NoError(t, err)
	})
	t.Run("Attempt to close a non-existent store", func(t *testing.T) {
		provider := initializeTest(t)

		err := provider.CloseStore(testStoreName)
		require.EqualError(t, err, storage.ErrStoreNotFound.Error())
	})
}

func TestProvider_Close(t *testing.T) {
	provider := initializeTest(t)

	_ = createAndOpenTestStore(t, provider)

	err := provider.Close()
	require.NoError(t, err)
}

func TestCouchDBStore_Put(t *testing.T) {
	t.Run("Success: value is JSON", func(t *testing.T) {
		provider := initializeTest(t)

		store := createAndOpenTestStore(t, provider)

		err := store.Put(testDocKey, []byte(testJSONValue1))
		require.NoError(t, err)
	})
	t.Run("Success: value is not JSON", func(t *testing.T) {
		provider := initializeTest(t)

		store := createAndOpenTestStore(t, provider)

		err := store.Put(testDocKey, []byte(testNonJSONValue))
		require.NoError(t, err)
	})
	t.Run("Error while adding rev ID", func(t *testing.T) {
		provider := initializeTest(t)

		store := createAndOpenTestStore(t, provider)

		err := store.Put(testDocKey, []byte(testJSONValue1))
		require.NoError(t, err)

		couchDBStore, ok := store.(*CouchDBStore)
		require.True(t, ok, "failed to assert store as a *CouchDBStore")

		couchDBStore.marshal = failingMarshal

		err = store.Put(testDocKey, []byte(testJSONValue1))
		require.EqualError(t, err, "failure while adding rev ID: failure while unmarshalling put "+
			"value with newly added rev ID: failingMarshal always fails")
	})
}

func TestCouchDBStore_GetAll(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		provider := initializeTest(t)

		store := createAndOpenTestStore(t, provider)

		err := store.Put(testDocKey, []byte(testJSONValue))
		require.NoError(t, err)

		err = store.Put(testDocKey2, []byte(testJSONValue2))
		require.NoError(t, err)

		allValues, err := store.GetAll()
		require.NoError(t, err)
		require.Equal(t, allValues[testDocKey], []byte(testJSONValue))
		require.Equal(t, allValues[testDocKey2], []byte(testJSONValue2))
		require.Len(t, allValues, 2)
	})
	t.Run("Success, but no key-value pairs exist", func(t *testing.T) {
		provider := initializeTest(t)

		store := createAndOpenTestStore(t, provider)

		allValues, err := store.GetAll()
		require.NoError(t, err)
		require.Empty(t, allValues)
	})
	t.Run("Failed to get all docs: database does not exist", func(t *testing.T) {
		provider := initializeTest(t)

		store := createAndOpenTestStore(t, provider)

		err := provider.couchDBClient.DestroyDB(context.Background(), testStoreName)
		require.NoError(t, err)

		values, err := store.GetAll()
		require.EqualError(t, err, "failure while getting all docs: Not Found: Database does not exist.")
		require.Nil(t, values)
	})
	t.Run("Failure while unquoting key", func(t *testing.T) {
		provider := initializeTest(t)

		store := createAndOpenTestStore(t, provider)

		err := store.Put(testDocKey, []byte(testJSONValue))
		require.NoError(t, err)

		couchDBStore, ok := store.(*CouchDBStore)
		require.True(t, ok, "failed to assert store as a couchDBStore")

		couchDBStore.unquote = failingUnquote

		allValues, err := store.GetAll()
		require.EqualError(t, err, "failure while getting all key-value pairs: "+
			"failure while unquoting key: failingUnquote always fails")
		require.Nil(t, allValues)
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
		require.Truef(t, errors.Is(err, storage.ErrValueNotFound),
			`"%s" does not contain the expected error "%s"`, err, storage.ErrValueNotFound)
	})
	t.Run("Failure while getting stored value from raw doc", func(t *testing.T) {
		provider := initializeTest(t)

		store := createAndOpenTestStore(t, provider)

		err := store.Put(testDocKey, []byte(testJSONValue))
		require.NoError(t, err)

		couchDBStore, ok := store.(*CouchDBStore)
		require.True(t, ok, "failed to assert store as a *CouchDBStore")

		couchDBStore.marshal = failingMarshal

		value, err := couchDBStore.Get(testDocKey)
		require.EqualError(t, err, "failure while getting stored value from raw doc: failure while "+
			"marshalling stripped doc: failingMarshal always fails")
		require.Nil(t, value)
	})
	t.Run("Failure while getting data from attachment", func(t *testing.T) {
		provider := initializeTest(t)

		store := createAndOpenTestStore(t, provider)

		err := store.Put(testDocKey, []byte(testNonJSONValue))
		require.NoError(t, err)

		couchDBStore, ok := store.(*CouchDBStore)
		require.True(t, ok, "failed to assert store as a *CouchDBStore")

		couchDBStore.readAll = failingReadAll

		value, err := store.Get(testDocKey)
		require.EqualError(t, err, "failure while getting stored value from raw doc: failure while "+
			"getting data from attachment: failure while reading attachment content: failingReadAll always fails")
		require.Nil(t, value)
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
		require.Error(t, err)
		require.Contains(t, err.Error(), "Not Found: Document is missing attachment")
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
		require.Error(t, err)
		require.Contains(t, err.Error(), "kivik: Iterator is closed")
		require.Nil(t, value)
		err = itr.Release()
		require.NoError(t, err)
	})
	t.Run("Failure while getting stored value from raw doc", func(t *testing.T) {
		provider := initializeTest(t)

		store := createAndOpenTestStore(t, provider)

		rawData := make(map[string][]byte)
		rawData[testDocKey] = []byte(testJSONValue)

		for k, v := range rawData {
			err := store.Put(k, v)
			require.NoError(t, err)
		}

		couchDBStore, ok := store.(*CouchDBStore)
		require.True(t, ok)

		couchDBStore.marshal = failingMarshal

		rows, err := couchDBStore.db.AllDocs(context.Background(), kivik.Options{"include_docs": true})
		require.NoError(t, err)

		itr := couchDBResultsIterator{resultRows: rows, store: couchDBStore}

		nextOK, nextErr := itr.Next()
		require.NoError(t, nextErr)
		require.True(t, nextOK)
		itrValue, valueErr := itr.Value()
		require.EqualError(t, valueErr, "failure while getting stored value from raw doc: "+
			"failure while marshalling stripped doc: failingMarshal always fails")
		require.Nil(t, itrValue)

		err = itr.Release()
		require.NoError(t, err)
	})
}

func TestCouchDBStore_Remove(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		provider := initializeTest(t)

		store := createAndOpenTestStore(t, provider)

		err := store.Put(testDocKey, []byte(testJSONValue1))
		require.NoError(t, err)

		err = store.Delete(testDocKey)
		require.NoError(t, err)
	})
	t.Run("Document not found", func(t *testing.T) {
		provider := initializeTest(t)

		store := createAndOpenTestStore(t, provider)

		err := store.Delete(testDocKey)
		require.Truef(t, errors.Is(err, storage.ErrValueNotFound),
			`"%s" does not contain the expected error "%s"`, err, storage.ErrValueNotFound)
	})
}

func TestCouchDBStore_addRevID(t *testing.T) {
	t.Run("Fail to unmarshal", func(t *testing.T) {
		value, err := (&CouchDBStore{}).addRevID(nil, "")
		require.EqualError(t, err, "failure while unmarshalling put value: unexpected end of JSON input")
		require.Nil(t, value)
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

	err = p.couchDBClient.DestroyDB(context.Background(), testDBPrefix+"_"+testStoreName)
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

func failingMarshal(_ interface{}) ([]byte, error) {
	return nil, errFailingMarshal
}

func failingReadAll(_ io.Reader) ([]byte, error) {
	return nil, errFailingReadAll
}

func failingUnquote(_ string) (string, error) {
	return "", errFailingUnquote
}
