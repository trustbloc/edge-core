/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package couchdbstore // nolint:testpackage // references internal implementation details

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"testing"
	"time"

	"github.com/cenkalti/backoff"
	"github.com/go-kivik/kivik/v3"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/edge-core/pkg/log"
	"github.com/trustbloc/edge-core/pkg/log/mocklogger"
	"github.com/trustbloc/edge-core/pkg/storage"
)

const (
	couchDBURL                  = "admin:password@localhost:5984"
	couchDBURLNotReady          = "localhost:5900"
	numRetries                  = 30
	testStoreName               = "teststore"
	testDocKey1                 = "sampleDBKey1"
	testDocKey2                 = "sampleDBKey2"
	testDocKey3                 = "sampleDBKey3"
	testDocKey4                 = "sampleDBKey4"
	testDocKey5                 = "sampleDBKey5"
	testDocKey6                 = "sampleDBKey6"
	testDocKey7                 = "sampleDBKey7"
	testDocKey8                 = "sampleDBKey8"
	testDocKey9                 = "sampleDBKey9"
	testDocKey10                = "sampleDBKey10"
	testDocKey11                = "sampleDBKey11"
	testJSONValue1              = `{"JSONKey1":"JSONValue1"}`
	testJSONValue2              = `{"JSONKey2":"JSONValue2"}`
	testJSONValue3              = `{"JSONKey3":"JSONValue3"}`
	testJSONValue4              = `{"JSONKey4":"JSONValue4"}`
	testJSONValue5              = `{"JSONKey5":"JSONValue5"}`
	testJSONValue6              = `{"JSONKey6":"JSONValue6"}`
	testJSONValue7              = `{"JSONKey7":"JSONValue7"}`
	testJSONValue8              = `{"JSONKey8":"JSONValue8"}`
	testJSONValue9              = `{"JSONKey9":"JSONValue9"}`
	testJSONValue10             = `{"JSONKey10":"JSONValue10"}`
	testJSONValue11             = `{"JSONKey11":"JSONValue11"}`
	testJSONWithMultipleFields  = `{"employeeID":1234,"name":"Mr. Trustbloc"}`
	testJSONWithMultipleFields2 = `{"employeeID":1234,"name":"Mr. Bloctrust"}`
	testJSONWithMultipleFields3 = `{"employeeID":1234,"name":"Mr. Trustcolb"}`
	testNonJSONValue1           = "1"
	testNonJSONValue2           = "2"
	testNonJSONValue3           = "3"
	testNonJSONValue4           = "4"
	testNonJSONValue5           = "5"
	testNonJSONValue6           = "6"
	testNonJSONValue7           = "7"
	testNonJSONValue8           = "8"
	testNonJSONValue9           = "9"
	testNonJSONValue10          = "10"
	testNonJSONValue11          = "11"
	testIndexName               = "TestIndex"
	testDesignDoc               = "TestDesignDoc"
	testDBPrefix                = "dbprefix"
)

// nolint:gochecknoglobals // test globals
var (
	mockLoggerProvider = mocklogger.Provider{MockLogger: &mocklogger.MockLogger{}}
	errFailingMarshal  = errors.New("failingMarshal always fails")
	errFailingReadAll  = errors.New("failingReadAll always fails")
	errFailingUnquote  = errors.New("failingUnquote always fails")
)

type mockKivikClient struct{}

func (m mockKivikClient) DBExists(ctx context.Context, dbName string, options ...kivik.Options) (bool, error) {
	return false, nil
}

// For these unit tests to run, you must ensure you have a CouchDB instance running at the URL specified in couchDBURL.
// 'make unit-test' from the terminal will take care of this for you.
// To run the tests manually, start an instance by running
// 'docker run -p 5984:5984 --name CouchDBStoreTest
// -v "$pwd"/scripts/couchdb-config/config.ini:/opt/couchdb/etc/local.d/config.ini
// -e COUCHDB_USER=admin -e COUCHDB_PASSWORD=password couchdb:3.1.0' from a terminal.

func TestMain(m *testing.M) {
	err := waitForCouchDBToStart()
	if err != nil {
		logger.Errorf(err.Error() +
			". Make sure you start a couchDB instance using" +
			" 'docker run -p 5984:5984 --name CouchDBStoreTest " +
			" -v {path to edge-core}/scripts/couchdb-config/config.ini:/opt/couchdb/etc/local.d/config.ini " +
			" -e COUCHDB_USER=admin -e COUCHDB_PASSWORD=password couchdb:3.1.0' before running the unit tests")
		os.Exit(1)
	}

	log.Initialize(&mockLoggerProvider)

	log.SetLevel(logModuleName, log.DEBUG)

	os.Exit(m.Run())
}

func waitForCouchDBToStart() error {
	client, err := kivik.New("couch", couchDBURL)
	if err != nil {
		return err
	}

	if err := checkCouchDBReady(client); err != nil {
		return err
	}

	return nil
}

func checkCouchDBReady(client *kivik.Client) error {
	return backoff.Retry(func() error {
		err := pingCouchDB(client)
		if err != nil {
			return err
		}

		return nil
	}, backoff.WithMaxRetries(backoff.NewConstantBackOff(time.Second), numRetries))
}

func TestNewProvider(t *testing.T) {
	t.Run("Valid URL provided", func(t *testing.T) {
		provider, err := NewProvider(couchDBURL)
		require.NoError(t, err)
		require.NotNil(t, provider)
	})
	t.Run("Fail to ping couchDB - error while checking if '_users' db exists", func(t *testing.T) {
		_, err := NewProvider(couchDBURLNotReady)
		require.NotNil(t, err)
		require.Contains(t, err.Error(), "failure while probing couchDB for '_users' DB")
	})
	t.Run("Fail to ping couchDB - '_users' db is not ready", func(t *testing.T) {
		err := pingCouchDB(&mockKivikClient{})
		require.NotNil(t, err)
		require.Equal(t, errors.New(couchDBNotReadyErrMsg), err)
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

		err := store.Put(testDocKey1, []byte(testJSONValue2))
		require.NoError(t, err)
	})
	t.Run("Success: value is not JSON", func(t *testing.T) {
		provider := initializeTest(t)

		store := createAndOpenTestStore(t, provider)

		err := store.Put(testDocKey1, []byte(testNonJSONValue1))
		require.NoError(t, err)
	})
	t.Run("Success: put after delete", func(t *testing.T) {
		provider := initializeTest(t)

		store := createAndOpenTestStore(t, provider)

		err := store.Put(testDocKey1, []byte(testJSONValue2))
		require.NoError(t, err)

		err = store.Delete(testDocKey1)
		require.NoError(t, err)

		err = store.Put(testDocKey1, []byte(testJSONValue2))
		require.NoError(t, err)
	})
	t.Run("Error while getting rev ID - database does not exist", func(t *testing.T) {
		provider := initializeTest(t)

		store := createAndOpenTestStore(t, provider)
		err := provider.couchDBClient.DestroyDB(context.Background(), testStoreName)
		require.NoError(t, err)

		err = store.Put(testDocKey1, []byte(testJSONValue2))
		require.NotNil(t, err)
		require.Contains(t, err.Error(), "failure while getting rev ID")
	})
	t.Run("Error while adding rev ID", func(t *testing.T) {
		provider := initializeTest(t)

		store := createAndOpenTestStore(t, provider)

		err := store.Put(testDocKey1, []byte(testJSONValue2))
		require.NoError(t, err)

		couchDBStore, ok := store.(*CouchDBStore)
		require.True(t, ok, "failed to assert store as a *CouchDBStore")

		couchDBStore.marshal = failingMarshal

		err = store.Put(testDocKey1, []byte(testJSONValue2))
		require.EqualError(t, err, "failure while adding rev ID: failure while unmarshalling put "+
			"value with newly added rev ID: failingMarshal always fails")
	})
}

func TestCouchDBStore_PutBulk(t *testing.T) {
	t.Run("Success: values are JSON, all new values", func(t *testing.T) {
		provider := initializeTest(t)

		store := createAndOpenTestStore(t, provider)

		keys := []string{testDocKey1, testDocKey2, testDocKey3}
		values := [][]byte{[]byte(testJSONValue1), []byte(testJSONValue2), []byte(testJSONValue3)}

		err := store.PutBulk(keys, values)
		require.NoError(t, err)

		value, err := store.Get(testDocKey1)
		require.NoError(t, err)
		require.Equal(t, testJSONValue1, string(value))

		value, err = store.Get(testDocKey2)
		require.NoError(t, err)
		require.Equal(t, testJSONValue2, string(value))

		value, err = store.Get(testDocKey3)
		require.NoError(t, err)
		require.Equal(t, testJSONValue3, string(value))
	})
	t.Run("Success: values are JSON, put new values then update all of them", func(t *testing.T) {
		provider := initializeTest(t)

		store := createAndOpenTestStore(t, provider)

		keys := []string{testDocKey1, testDocKey2, testDocKey3}
		values := [][]byte{[]byte(testJSONValue1), []byte(testJSONValue2), []byte(testJSONValue3)}

		err := store.PutBulk(keys, values)
		require.NoError(t, err)

		value, err := store.Get(testDocKey1)
		require.NoError(t, err)
		require.Equal(t, testJSONValue1, string(value))

		value, err = store.Get(testDocKey2)
		require.NoError(t, err)
		require.Equal(t, testJSONValue2, string(value))

		value, err = store.Get(testDocKey3)
		require.NoError(t, err)
		require.Equal(t, testJSONValue3, string(value))

		err = store.PutBulk(keys, values)
		require.NoError(t, err)

		value, err = store.Get(testDocKey1)
		require.NoError(t, err)
		require.Equal(t, testJSONValue1, string(value))

		value, err = store.Get(testDocKey2)
		require.NoError(t, err)
		require.Equal(t, testJSONValue2, string(value))

		value, err = store.Get(testDocKey3)
		require.NoError(t, err)
		require.Equal(t, testJSONValue3, string(value))
	})
	t.Run("Success: values are JSON, put value, then delete it, "+
		"then put again using the deleted key and others, then delete that key and also another key "+
		"from that bulk put, then put all again, then put all yet again",
		func(t *testing.T) {
			provider := initializeTest(t)

			store := createAndOpenTestStore(t, provider)

			err := store.Put(testDocKey1, []byte(testJSONValue2))
			require.NoError(t, err)

			value, err := store.Get(testDocKey1)
			require.NoError(t, err)
			require.Equal(t, testJSONValue2, string(value))

			err = store.Delete(testDocKey1)
			require.NoError(t, err)

			value, err = store.Get(testDocKey1)
			require.EqualError(t, err, "failure while getting raw CouchDB document: failure while scanning "+
				"result rows doc: store does not have a value associated with this key")
			require.Nil(t, value)

			keys := []string{testDocKey1, testDocKey2, testDocKey3}
			values := [][]byte{[]byte(testJSONValue1), []byte(testJSONValue2), []byte(testJSONValue3)}

			err = store.PutBulk(keys, values)
			require.NoError(t, err)

			value, err = store.Get(testDocKey1)
			require.NoError(t, err)
			require.Equal(t, testJSONValue1, string(value))

			value, err = store.Get(testDocKey2)
			require.NoError(t, err)
			require.Equal(t, testJSONValue2, string(value))

			value, err = store.Get(testDocKey3)
			require.NoError(t, err)
			require.Equal(t, testJSONValue3, string(value))

			err = store.Delete(keys[0])
			require.NoError(t, err)

			value, err = store.Get(testDocKey1)
			require.EqualError(t, err, "failure while getting raw CouchDB document: failure while scanning "+
				"result rows doc: store does not have a value associated with this key")
			require.Nil(t, value)

			err = store.Delete(keys[2])
			require.NoError(t, err)

			value, err = store.Get(testDocKey3)
			require.EqualError(t, err, "failure while getting raw CouchDB document: failure while scanning "+
				"result rows doc: store does not have a value associated with this key")
			require.Nil(t, value)

			err = store.PutBulk(keys, values)
			require.NoError(t, err)

			value, err = store.Get(testDocKey1)
			require.NoError(t, err)
			require.Equal(t, testJSONValue1, string(value))

			value, err = store.Get(testDocKey2)
			require.NoError(t, err)
			require.Equal(t, testJSONValue2, string(value))

			value, err = store.Get(testDocKey3)
			require.NoError(t, err)
			require.Equal(t, testJSONValue3, string(value))

			err = store.PutBulk(keys, values)
			require.NoError(t, err)

			value, err = store.Get(testDocKey1)
			require.NoError(t, err)
			require.Equal(t, testJSONValue1, string(value))

			value, err = store.Get(testDocKey2)
			require.NoError(t, err)
			require.Equal(t, testJSONValue2, string(value))

			value, err = store.Get(testDocKey3)
			require.NoError(t, err)
			require.Equal(t, testJSONValue3, string(value))
		})

	// The following tests ensure that when the same key appears in a PutBulk, that the value that ends up "surviving"
	// in the end is always the most recent one in the array. This behaviour is crucial for consistency, as the PutBulk
	// method is supposed to have the same end result as calling Put in a loop (except that PutBulk will be faster since
	// it minimizes REST calls)
	t.Run("Success: values are JSON, updating the same key-value pair multiple times", func(t *testing.T) {
		t.Run("Put 10 new key-value pairs, then do a bulk put where "+
			"some of the later puts override earlier ones",
			func(t *testing.T) {
				provider := initializeTest(t)

				store := createAndOpenTestStore(t, provider)

				keys := []string{
					testDocKey1, testDocKey2, testDocKey3, testDocKey4,
					testDocKey5, testDocKey6, testDocKey7, testDocKey8, testDocKey9, testDocKey10,
				}
				values := [][]byte{
					[]byte(testJSONValue1), []byte(testJSONValue2), []byte(testJSONValue3),
					[]byte(testJSONValue4), []byte(testJSONValue5), []byte(testJSONValue6), []byte(testJSONValue7),
					[]byte(testJSONValue8), []byte(testJSONValue9), []byte(testJSONValue10),
				}

				err := store.PutBulk(keys, values)
				require.NoError(t, err)

				value, err := store.Get(testDocKey1)
				require.NoError(t, err)
				require.Equal(t, testJSONValue1, string(value))

				value, err = store.Get(testDocKey2)
				require.NoError(t, err)
				require.Equal(t, testJSONValue2, string(value))

				value, err = store.Get(testDocKey3)
				require.NoError(t, err)
				require.Equal(t, testJSONValue3, string(value))

				value, err = store.Get(testDocKey4)
				require.NoError(t, err)
				require.Equal(t, testJSONValue4, string(value))

				value, err = store.Get(testDocKey5)
				require.NoError(t, err)
				require.Equal(t, testJSONValue5, string(value))

				value, err = store.Get(testDocKey6)
				require.NoError(t, err)
				require.Equal(t, testJSONValue6, string(value))

				value, err = store.Get(testDocKey7)
				require.NoError(t, err)
				require.Equal(t, testJSONValue7, string(value))

				value, err = store.Get(testDocKey8)
				require.NoError(t, err)
				require.Equal(t, testJSONValue8, string(value))

				value, err = store.Get(testDocKey9)
				require.NoError(t, err)
				require.Equal(t, testJSONValue9, string(value))

				value, err = store.Get(testDocKey10)
				require.NoError(t, err)
				require.Equal(t, testJSONValue10, string(value))

				keys = []string{
					testDocKey1, testDocKey2, testDocKey1, testDocKey4,
					testDocKey5, testDocKey6, testDocKey7, testDocKey2, testDocKey9, testDocKey11, testDocKey1,
				}
				values = [][]byte{
					[]byte(testJSONValue1), []byte(testJSONValue8), []byte(testJSONValue3),
					[]byte(testJSONValue4), []byte(testJSONValue10), []byte(testJSONValue6), []byte(testJSONValue7),
					[]byte(testJSONValue1), []byte(testJSONValue9), []byte(testJSONValue11), []byte(testJSONValue10),
				}

				err = store.PutBulk(keys, values)
				require.NoError(t, err)

				// Now make sure that the last values were the ones that ended up being stored in CouchDB
				value, err = store.Get(testDocKey1)
				require.NoError(t, err)
				require.Equal(t, testJSONValue10, string(value))

				value, err = store.Get(testDocKey2)
				require.NoError(t, err)
				require.Equal(t, testJSONValue1, string(value))

				value, err = store.Get(testDocKey3)
				require.NoError(t, err)
				require.Equal(t, testJSONValue3, string(value))

				value, err = store.Get(testDocKey4)
				require.NoError(t, err)
				require.Equal(t, testJSONValue4, string(value))

				value, err = store.Get(testDocKey5)
				require.NoError(t, err)
				require.Equal(t, testJSONValue10, string(value))

				value, err = store.Get(testDocKey6)
				require.NoError(t, err)
				require.Equal(t, testJSONValue6, string(value))

				value, err = store.Get(testDocKey7)
				require.NoError(t, err)
				require.Equal(t, testJSONValue7, string(value))

				value, err = store.Get(testDocKey8)
				require.NoError(t, err)
				require.Equal(t, testJSONValue8, string(value))

				value, err = store.Get(testDocKey9)
				require.NoError(t, err)
				require.Equal(t, testJSONValue9, string(value))

				value, err = store.Get(testDocKey10)
				require.NoError(t, err)
				require.Equal(t, testJSONValue10, string(value))

				value, err = store.Get(testDocKey11)
				require.NoError(t, err)
				require.Equal(t, testJSONValue11, string(value))
			})
	})
	t.Run("Success: values are not JSON, updating the same key-value pair multiple times", func(t *testing.T) {
		t.Run("Put 10 new key-value pairs, then do a bulk put where "+
			"some of the later puts override earlier ones",
			func(t *testing.T) {
				provider := initializeTest(t)

				store := createAndOpenTestStore(t, provider)

				keys := []string{
					testDocKey1, testDocKey2, testDocKey3, testDocKey4,
					testDocKey5, testDocKey6, testDocKey7, testDocKey8, testDocKey9, testDocKey10,
				}
				values := [][]byte{
					[]byte(testNonJSONValue1), []byte(testNonJSONValue2), []byte(testNonJSONValue3),
					[]byte(testNonJSONValue4), []byte(testNonJSONValue5), []byte(testNonJSONValue6),
					[]byte(testNonJSONValue7), []byte(testNonJSONValue8), []byte(testNonJSONValue9),
					[]byte(testNonJSONValue10),
				}

				err := store.PutBulk(keys, values)
				require.NoError(t, err)

				keys = []string{
					testDocKey1, testDocKey2, testDocKey1, testDocKey4,
					testDocKey5, testDocKey6, testDocKey7, testDocKey2, testDocKey9, testDocKey11, testDocKey1,
				}
				values = [][]byte{
					[]byte(testNonJSONValue1), []byte(testNonJSONValue8), []byte(testNonJSONValue3),
					[]byte(testNonJSONValue4), []byte(testNonJSONValue10), []byte(testNonJSONValue6),
					[]byte(testNonJSONValue7), []byte(testNonJSONValue1), []byte(testNonJSONValue9),
					[]byte(testNonJSONValue11), []byte(testNonJSONValue10),
				}

				err = store.PutBulk(keys, values)
				require.NoError(t, err)

				// Now make sure that the last values were the ones that ended up being stored in CouchDB
				value, err := store.Get(testDocKey1)
				require.NoError(t, err)
				require.Equal(t, testNonJSONValue10, string(value))

				value, err = store.Get(testDocKey2)
				require.NoError(t, err)
				require.Equal(t, testNonJSONValue1, string(value))

				value, err = store.Get(testDocKey3)
				require.NoError(t, err)
				require.Equal(t, testNonJSONValue3, string(value))

				value, err = store.Get(testDocKey4)
				require.NoError(t, err)
				require.Equal(t, testNonJSONValue4, string(value))

				value, err = store.Get(testDocKey5)
				require.NoError(t, err)
				require.Equal(t, testNonJSONValue10, string(value))

				value, err = store.Get(testDocKey6)
				require.NoError(t, err)
				require.Equal(t, testNonJSONValue6, string(value))

				value, err = store.Get(testDocKey7)
				require.NoError(t, err)
				require.Equal(t, testNonJSONValue7, string(value))

				value, err = store.Get(testDocKey8)
				require.NoError(t, err)
				require.Equal(t, testNonJSONValue8, string(value))

				value, err = store.Get(testDocKey9)
				require.NoError(t, err)
				require.Equal(t, testNonJSONValue9, string(value))

				value, err = store.Get(testDocKey10)
				require.NoError(t, err)
				require.Equal(t, testNonJSONValue10, string(value))

				value, err = store.Get(testDocKey11)
				require.NoError(t, err)
				require.Equal(t, testNonJSONValue11, string(value))
			})
	})
	t.Run("Failure: keys and values are different lengths", func(t *testing.T) {
		provider := initializeTest(t)

		store := createAndOpenTestStore(t, provider)

		keys := []string{testDocKey1, testDocKey2}
		values := [][]byte{[]byte(testJSONValue1), []byte(testJSONValue2), []byte(testJSONValue3)}

		err := store.PutBulk(keys, values)
		require.EqualError(t, err, storage.ErrKeysAndValuesDifferentLengths.Error())
	})
	t.Run("Failure: keys slice is nil", func(t *testing.T) {
		provider := initializeTest(t)

		store := createAndOpenTestStore(t, provider)

		values := [][]byte{[]byte(testJSONValue1), []byte(testJSONValue2), []byte(testJSONValue3)}

		err := store.PutBulk(nil, values)
		require.EqualError(t, err, storage.ErrNilKeys.Error())
	})
	t.Run("Failure: values slice is nil", func(t *testing.T) {
		provider := initializeTest(t)

		store := createAndOpenTestStore(t, provider)

		keys := []string{testDocKey1, testDocKey2}

		err := store.PutBulk(keys, nil)
		require.EqualError(t, err, storage.ErrNilValues.Error())
	})
	t.Run("Failure: blank key", func(t *testing.T) {
		provider := initializeTest(t)

		store := createAndOpenTestStore(t, provider)

		keys := []string{testDocKey1, testDocKey2, ""}
		values := [][]byte{[]byte(testJSONValue1), []byte(testJSONValue2), []byte(testJSONValue3)}

		err := store.PutBulk(keys, values)
		require.EqualError(t, err, fmt.Errorf(blankKeyErrMsg, 2).Error())
	})
	t.Run("Failure: database does not exist", func(t *testing.T) {
		provider := initializeTest(t)

		store := createAndOpenTestStore(t, provider)

		err := provider.couchDBClient.DestroyDB(context.Background(), testStoreName)
		require.NoError(t, err)

		keys := []string{testDocKey1, testDocKey2, testDocKey3}
		values := [][]byte{[]byte(testJSONValue1), []byte(testJSONValue2), []byte(testJSONValue3)}

		err = store.PutBulk(keys, values)
		require.EqualError(t, err, "failure while getting rev ID: failure while getting raw CouchDB "+
			"documents: Not Found: Database does not exist.")
	})
}

func TestCouchDBStore_Get(t *testing.T) {
	t.Run("Document found, original data was JSON and is preserved as such", func(t *testing.T) {
		provider := initializeTest(t)

		store := createAndOpenTestStore(t, provider)

		err := store.Put(testDocKey1, []byte(testJSONValue1))
		require.NoError(t, err)

		value, err := store.Get(testDocKey1)
		require.NoError(t, err)
		require.Equal(t, testJSONValue1, string(value))

		err = store.Put(testDocKey1, []byte(testJSONValue2))
		require.NoError(t, err)

		value, err = store.Get(testDocKey1)
		require.NoError(t, err)
		require.Equal(t, testJSONValue2, string(value))
	})
	t.Run("Document found, original data was not JSON and so was saved as a CouchDB attachment."+
		" Original data is still preserved", func(t *testing.T) {
		provider := initializeTest(t)

		store := createAndOpenTestStore(t, provider)

		err := store.Put(testDocKey1, []byte(testNonJSONValue1))
		require.NoError(t, err)

		value, err := store.Get(testDocKey1)
		require.NoError(t, err)
		require.Equal(t, testNonJSONValue1, string(value))

		err = store.Put(testDocKey1, []byte(testNonJSONValue2))
		require.NoError(t, err)

		value, err = store.Get(testDocKey1)
		require.NoError(t, err)
		require.Equal(t, testNonJSONValue2, string(value))
	})
	t.Run("Document not found", func(t *testing.T) {
		provider := initializeTest(t)

		store := createAndOpenTestStore(t, provider)

		value, err := store.Get(testDocKey1)
		require.Nil(t, value)
		require.Truef(t, errors.Is(err, storage.ErrValueNotFound),
			`"%s" does not contain the expected error "%s"`, err, storage.ErrValueNotFound)
	})
	t.Run("Failure while getting stored value from raw doc", func(t *testing.T) {
		provider := initializeTest(t)

		store := createAndOpenTestStore(t, provider)

		err := store.Put(testDocKey1, []byte(testJSONValue1))
		require.NoError(t, err)

		couchDBStore, ok := store.(*CouchDBStore)
		require.True(t, ok, "failed to assert store as a *CouchDBStore")

		couchDBStore.marshal = failingMarshal

		value, err := couchDBStore.Get(testDocKey1)
		require.EqualError(t, err, "failure while getting stored value from raw doc: failure while "+
			"marshalling stripped doc: failingMarshal always fails")
		require.Nil(t, value)
	})
	t.Run("Failure while getting data from attachment", func(t *testing.T) {
		provider := initializeTest(t)

		store := createAndOpenTestStore(t, provider)

		err := store.Put(testDocKey1, []byte(testNonJSONValue1))
		require.NoError(t, err)

		couchDBStore, ok := store.(*CouchDBStore)
		require.True(t, ok, "failed to assert store as a *CouchDBStore")

		couchDBStore.readAll = failingReadAll

		value, err := store.Get(testDocKey1)
		require.EqualError(t, err, "failure while getting stored value from raw doc: failure while "+
			"getting data from attachment: failure while reading attachment content: failingReadAll always fails")
		require.Nil(t, value)
	})
}

func TestCouchDBStore_GetBulk(t *testing.T) {
	t.Run("All data found, original data was JSON and is preserved as such", func(t *testing.T) {
		provider := initializeTest(t)

		store := createAndOpenTestStore(t, provider)

		err := store.Put(testDocKey1, []byte(testJSONValue1))
		require.NoError(t, err)

		err = store.Put(testDocKey2, []byte(testJSONValue2))
		require.NoError(t, err)

		values, err := store.GetBulk(testDocKey1, testDocKey2)
		require.NoError(t, err)
		require.Equal(t, testJSONValue1, string(values[0]))
		require.Equal(t, testJSONValue2, string(values[1]))
	})
	t.Run("All data found, original data was not JSON and so was saved as a CouchDB attachment."+
		" Original data is still preserved", func(t *testing.T) {
		provider := initializeTest(t)

		store := createAndOpenTestStore(t, provider)

		err := store.Put(testDocKey1, []byte(testNonJSONValue1))
		require.NoError(t, err)

		err = store.Put(testDocKey2, []byte(testNonJSONValue2))
		require.NoError(t, err)

		values, err := store.GetBulk(testDocKey1, testDocKey2)
		require.NoError(t, err)
		require.Equal(t, testNonJSONValue1, string(values[0]))
		require.Equal(t, testNonJSONValue2, string(values[1]))

		err = store.Put(testDocKey1, []byte(testNonJSONValue2))
		require.NoError(t, err)

		err = store.Put(testDocKey2, []byte(testNonJSONValue3))
		require.NoError(t, err)

		values, err = store.GetBulk(testDocKey1, testDocKey2)
		require.NoError(t, err)
		require.Equal(t, testNonJSONValue2, string(values[0]))
		require.Equal(t, testNonJSONValue3, string(values[1]))
	})
	t.Run("All data found, data was stored in CouchDB as a mix of JSON and CouchDB attachments and was "+
		"converted back to their original format as expected", func(t *testing.T) {
		provider := initializeTest(t)

		store := createAndOpenTestStore(t, provider)

		err := store.Put(testDocKey1, []byte(testJSONValue1))
		require.NoError(t, err)

		err = store.Put(testDocKey2, []byte(testNonJSONValue2))
		require.NoError(t, err)

		err = store.Put(testDocKey3, []byte(testNonJSONValue3))
		require.NoError(t, err)

		err = store.Put(testDocKey4, []byte(testJSONValue4))
		require.NoError(t, err)

		err = store.Put(testDocKey5, []byte(testNonJSONValue5))
		require.NoError(t, err)

		err = store.Put(testDocKey6, []byte(testJSONValue6))
		require.NoError(t, err)

		values, err := store.GetBulk(testDocKey1, testDocKey2, testDocKey3, testDocKey4, testDocKey5, testDocKey6)
		require.NoError(t, err)
		require.Equal(t, testJSONValue1, string(values[0]))
		require.Equal(t, testNonJSONValue2, string(values[1]))
		require.Equal(t, testNonJSONValue3, string(values[2]))
		require.Equal(t, testJSONValue4, string(values[3]))
		require.Equal(t, testNonJSONValue5, string(values[4]))
		require.Equal(t, testJSONValue6, string(values[5]))
	})
	t.Run("Value (stored as JSON) not found", func(t *testing.T) {
		provider := initializeTest(t)

		store := createAndOpenTestStore(t, provider)

		err := store.Put(testDocKey1, []byte(testJSONValue1))
		require.NoError(t, err)

		values, err := store.GetBulk(testDocKey1, testDocKey2)
		require.EqualError(t, err,
			fmt.Errorf(failureWhileGettingStoredValuesFromRawDocs,
				fmt.Errorf(getBulkKeyNotFound, testDocKey2, storage.ErrValueNotFound)).Error())
		require.Nil(t, values)
	})

	t.Run("Value (stored as JSON) not found after being deleted", func(t *testing.T) {
		provider := initializeTest(t)

		store := createAndOpenTestStore(t, provider)

		err := store.Put(testDocKey1, []byte(testJSONValue1))
		require.NoError(t, err)

		err = store.Put(testDocKey2, []byte(testJSONValue2))
		require.NoError(t, err)

		err = store.Delete(testDocKey2)
		require.NoError(t, err)

		values, err := store.GetBulk(testDocKey1, testDocKey2)
		require.EqualError(t, err,
			fmt.Errorf(failureWhileGettingStoredValuesFromRawDocs,
				fmt.Errorf(getBulkKeyNotFound, testDocKey2, storage.ErrValueNotFound)).Error())
		require.Nil(t, values)
	})
	t.Run("Value (stored as an attachment) not found", func(t *testing.T) {
		provider := initializeTest(t)

		store := createAndOpenTestStore(t, provider)

		err := store.Put(testDocKey1, []byte(testNonJSONValue1))
		require.NoError(t, err)

		values, err := store.GetBulk(testDocKey1, testDocKey2)
		require.EqualError(t, err,
			fmt.Errorf(failureWhileGettingStoredValuesFromRawDocs,
				fmt.Errorf(getBulkKeyNotFound, testDocKey2, storage.ErrValueNotFound)).Error())
		require.Nil(t, values)
	})
	t.Run("Value (stored as an attachment) not found after being deleted", func(t *testing.T) {
		provider := initializeTest(t)

		store := createAndOpenTestStore(t, provider)

		err := store.Put(testDocKey1, []byte(testNonJSONValue1))
		require.NoError(t, err)

		err = store.Put(testDocKey2, []byte(testNonJSONValue2))
		require.NoError(t, err)

		err = store.Delete(testDocKey2)
		require.NoError(t, err)

		values, err := store.GetBulk(testDocKey1, testDocKey2)
		require.EqualError(t, err,
			fmt.Errorf(failureWhileGettingStoredValuesFromRawDocs,
				fmt.Errorf(getBulkKeyNotFound, testDocKey2, storage.ErrValueNotFound)).Error())
		require.Nil(t, values)
	})
	t.Run("Database not found", func(t *testing.T) {
		provider := initializeTest(t)

		store := createAndOpenTestStore(t, provider)

		err := provider.couchDBClient.DestroyDB(context.Background(), testStoreName)
		require.NoError(t, err)

		keys := []string{testDocKey1, testDocKey2, testDocKey3}

		values, err := store.GetBulk(keys...)
		require.EqualError(t, err, "failure while getting raw CouchDB documents: Not Found: "+
			"Database does not exist.")
		require.Nil(t, values)
	})
	t.Run("Failure while getting stored value from raw doc", func(t *testing.T) {
		provider := initializeTest(t)

		store := createAndOpenTestStore(t, provider)

		err := store.Put(testDocKey1, []byte(testJSONValue1))
		require.NoError(t, err)

		err = store.Put(testDocKey2, []byte(testJSONValue2))
		require.NoError(t, err)

		couchDBStore, ok := store.(*CouchDBStore)
		require.True(t, ok, "failed to assert store as a *CouchDBStore")

		couchDBStore.marshal = failingMarshal

		values, err := store.GetBulk(testDocKey1, testDocKey2)
		require.EqualError(t, err,
			fmt.Errorf(failureWhileGettingStoredValuesFromRawDocs,
				fmt.Errorf(failureWhileMarshallingStrippedDoc, errFailingMarshal)).Error())
		require.Nil(t, values)
	})
	t.Run("Failure while getting data from attachment", func(t *testing.T) {
		provider := initializeTest(t)

		store := createAndOpenTestStore(t, provider)

		err := store.Put(testDocKey1, []byte(testNonJSONValue1))
		require.NoError(t, err)

		err = store.Put(testDocKey2, []byte(testNonJSONValue2))
		require.NoError(t, err)

		couchDBStore, ok := store.(*CouchDBStore)
		require.True(t, ok, "failed to assert store as a *CouchDBStore")

		couchDBStore.readAll = failingReadAll

		values, err := store.GetBulk(testDocKey1, testDocKey2)
		require.EqualError(t, err,
			fmt.Errorf(failureWhileGettingStoredValuesFromRawDocs,
				fmt.Errorf(failureWhileGettingDataFromAttachment,
					fmt.Errorf(failureWhileReadingAttachmentContent, errFailingReadAll))).Error())
		require.Nil(t, values)
	})
	t.Run("Failure: nil argument", func(t *testing.T) {
		provider := initializeTest(t)

		store := createAndOpenTestStore(t, provider)

		err := store.Put(testDocKey1, []byte(testJSONValue1))
		require.NoError(t, err)

		values, err := store.GetBulk(nil...)
		require.EqualError(t, err, storage.ErrGetBulkKeysStringSliceNil.Error())
		require.Nil(t, values)
	})
	t.Run("Value not found, bulk get called with only one key", func(t *testing.T) {
		provider := initializeTest(t)

		store := createAndOpenTestStore(t, provider)

		values, err := store.GetBulk(testDocKey1)
		require.EqualError(t, err,
			fmt.Errorf(failureWhileGettingStoredValuesFromRawDocs,
				fmt.Errorf(getBulkKeyNotFound, testDocKey1, storage.ErrValueNotFound)).Error())
		require.Nil(t, values)
	})
}

func TestCouchDBStore_GetAll(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		provider := initializeTest(t)

		store := createAndOpenTestStore(t, provider)

		// Creating an index will create a design document.
		// This test ensures that it gets filtered out of the results, as expected.
		err := createIndex(store, `{"fields": ["SomeField"]}`)
		require.NoError(t, err)

		err = store.Put(testDocKey1, []byte(testJSONValue1))
		require.NoError(t, err)

		err = store.Put(testDocKey2, []byte(testJSONValue3))
		require.NoError(t, err)

		allValues, err := store.GetAll()
		require.NoError(t, err)
		require.Equal(t, allValues[testDocKey1], []byte(testJSONValue1))
		require.Equal(t, allValues[testDocKey2], []byte(testJSONValue3))
		require.Len(t, allValues, 2)

		require.Contains(t, mockLoggerProvider.MockLogger.AllLogContents,
			fmt.Sprintf(designDocumentFilteredOutLogMsg, "_design/TestDesignDoc"))
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

		err := store.Put(testDocKey1, []byte(testJSONValue1))
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

func TestCouchDBStore_getDataFromAttachment(t *testing.T) {
	t.Run("Attachment found", func(t *testing.T) {
		provider := initializeTest(t)

		_ = createAndOpenTestStore(t, provider)

		_, err := provider.dbs[testStoreName].db.Put(context.Background(), testDocKey1,
			wrapTextAsCouchDBAttachment([]byte(testNonJSONValue1)))
		require.NoError(t, err)

		data, err := provider.dbs[testStoreName].getDataFromAttachment(testDocKey1)
		require.NoError(t, err)
		require.Equal(t, testNonJSONValue1, string(data))
	})
	t.Run("Attachment not found", func(t *testing.T) {
		provider := initializeTest(t)

		_ = createAndOpenTestStore(t, provider)

		_, err := provider.dbs[testStoreName].db.Put(context.Background(), testDocKey1, []byte(testJSONValue2))
		require.NoError(t, err)

		data, err := provider.dbs[testStoreName].getDataFromAttachment(testDocKey1)
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
	t.Run("Successfully query using index - no paging necessary", func(t *testing.T) {
		provider := initializeTest(t)
		store := createAndOpenTestStore(t, provider)

		err := store.Put(testDocKey1, []byte(testJSONWithMultipleFields))
		require.NoError(t, err)

		err = createIndex(store, `{"fields": ["employeeID"]}`)
		require.NoError(t, err)

		// If no limit is specified in the query, then CouchDB uses a default of 25.
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
	t.Run("Successfully query using index - use bookmark for paging to get all documents", func(t *testing.T) {
		provider := initializeTest(t)
		store := createAndOpenTestStore(t, provider)

		err := store.Put(testDocKey1, []byte(testJSONWithMultipleFields))
		require.NoError(t, err)

		err = store.Put(testDocKey2, []byte(testJSONWithMultipleFields2))
		require.NoError(t, err)

		err = store.Put(testDocKey3, []byte(testJSONWithMultipleFields3))
		require.NoError(t, err)

		err = createIndex(store, `{"fields": ["employeeID"]}`)
		require.NoError(t, err)

		itr, err := store.Query(`{
		   "selector": {
		       "employeeID": 1234
		   },
			"use_index": ["` + testDesignDoc + `", "` + testIndexName + `"],
			"limit": 2
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
		require.True(t, ok)

		value, err = itr.Value()
		require.NoError(t, err)
		require.Equal(t, testJSONWithMultipleFields2, string(value))

		ok, err = itr.Next()
		require.NoError(t, err)
		require.False(t, ok)

		bookmark := itr.Bookmark()
		require.NotEmpty(t, bookmark)

		err = itr.Release()
		require.NoError(t, err)

		// Do another query using the bookmark to get the remaining result.

		itr, err = store.Query(`{
		   "selector": {
		       "employeeID": 1234
		   },
			"use_index": ["` + testDesignDoc + `", "` + testIndexName + `"],
			"limit": 2,
			"bookmark": "` + bookmark + `"
		}`)
		require.NoError(t, err)

		ok, err = itr.Next()
		require.NoError(t, err)
		require.True(t, ok)

		value, err = itr.Value()
		require.NoError(t, err)
		require.Equal(t, testJSONWithMultipleFields3, string(value))

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

			err := store.Put(testDocKey1, []byte(testJSONWithMultipleFields))
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

			require.Contains(t, mockLoggerProvider.MockLogger.WarnLogContents,
				"_design/TestDesignDoc, TestIndex was not used because it is not a valid index for this query.")
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
		rawData[testDocKey1] = []byte(testJSONValue1)
		rawData[testDocKey2] = []byte(testJSONValue3)
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
		rawData[testDocKey1] = []byte(testJSONValue1)

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

		err := store.Put(testDocKey1, []byte(testJSONValue2))
		require.NoError(t, err)

		err = store.Delete(testDocKey1)
		require.NoError(t, err)
	})
	t.Run("Document not found", func(t *testing.T) {
		provider := initializeTest(t)

		store := createAndOpenTestStore(t, provider)

		err := store.Delete(testDocKey1)
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
