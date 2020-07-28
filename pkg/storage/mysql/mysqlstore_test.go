/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package mysql

import (
	"database/sql"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cenkalti/backoff"
	_ "github.com/go-sql-driver/mysql"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/edge-core/pkg/storage"
)

const (
	sqlStoreDBURL = "root:my-secret-pw@tcp(127.0.0.1:3306)/"
	testIndexName = "TestIndex"
)

var _ storage.Provider = (*Provider)(nil)
var _ storage.Store = (*sqlDBStore)(nil)
var _ storage.ResultsIterator = (*sqlDBResultsIterator)(nil)

// For these unit tests to run, you must ensure you have a SQL DB instance running at the URL specified in
// sqlStoreDBURL. 'make unit-test' from the terminal will take care of this for you.
// To run the tests manually, start an instance by running the following command in the terminal
// docker run -p 3306:3306 --name MySQLStoreTest -e MYSQL_ROOT_PASSWORD=my-secret-pw -d mysql:8.0.20

func TestMain(m *testing.M) {
	err := waitForSQLDBToStart()
	if err != nil {
		fmt.Printf(err.Error() +
			". Make sure you start a sqlStoreDB instance using" +
			" 'docker run -p 3306:3306 mysql:8.0.20' before running the unit tests\n")
		os.Exit(1)
	}

	os.Exit(m.Run())
}

func waitForSQLDBToStart() error {
	const retries = 30

	err := backoff.RetryNotify(
		func() error {
			db, openErr := sql.Open("mysql", sqlStoreDBURL)
			if openErr != nil {
				return openErr
			}

			return db.Ping()
		},
		backoff.WithMaxRetries(backoff.NewConstantBackOff(time.Second), retries),
		func(retryErr error, t time.Duration) {
			fmt.Printf(
				"failed to connect to MySQL, will sleep for %s before trying again : %s\n",
				t, retryErr)
		},
	)
	if err != nil {
		return fmt.Errorf(
			"failed to connect to MySQL at %s after %s : %w",
			sqlStoreDBURL, retries*time.Second, err)
	}

	return nil
}

func TestProvider_CreateStore(t *testing.T) {
	t.Run("creates store with prefix", func(t *testing.T) {
		prov, err := NewProvider(sqlStoreDBURL, WithDBPrefix(randomPrefix()))
		require.NoError(t, err)

		name := "test"
		err = prov.CreateStore(name)
		require.NoError(t, err)
	})
	t.Run("creates store without prefix", func(t *testing.T) {
		prov, err := NewProvider(sqlStoreDBURL)
		require.NoError(t, err)

		name := randomPrefix()
		err = prov.CreateStore(name)
		require.NoError(t, err)
	})
	t.Run("fails if name is missing", func(t *testing.T) {
		prov, err := NewProvider(sqlStoreDBURL, WithDBPrefix(randomPrefix()))
		require.NoError(t, err)
		err = prov.CreateStore("")
		require.Error(t, err)
	})
	t.Run("fails on invalid URL", func(t *testing.T) {
		prov, err := NewProvider(sqlStoreDBURL, WithDBPrefix(randomPrefix()))
		require.NoError(t, err)
		prov.dbURL = "INVALID"
		err = prov.CreateStore("test")
		require.Error(t, err)
	})
	t.Run("fails on invalid table name", func(t *testing.T) {
		prov, err := NewProvider(sqlStoreDBURL, WithDBPrefix(randomPrefix()))
		require.NoError(t, err)
		err = prov.CreateStore(";INVALID")
		require.Error(t, err)
	})
}

func TestSQLDBStore(t *testing.T) {
	t.Run("Test sql db store put and get", func(t *testing.T) {
		prov, err := NewProvider(sqlStoreDBURL, WithDBPrefix("prefixdb"))
		require.NoError(t, err)
		err = prov.CreateStore("test")
		require.NoError(t, err)
		store, err := prov.OpenStore("test")
		require.NoError(t, err)

		const key = "did:example:124"
		data := []byte("value")

		err = store.Put(key, data)
		require.NoError(t, err)

		doc, err := store.Get(key)
		require.NoError(t, err)
		require.NotEmpty(t, doc)
		require.Equal(t, data, doc)

		// test update
		data = []byte(`{"key1":"value1"}`)
		err = store.Put(key, data)
		require.NoError(t, err)

		doc, err = store.Get(key)
		require.NoError(t, err)
		require.NotEmpty(t, doc)
		require.Equal(t, data, doc)

		did2 := "did:example:789"
		_, err = store.Get(did2)
		require.Error(t, err)
		require.Contains(t, storage.ErrValueNotFound.Error(), err.Error())

		// nil key
		_, err = store.Get("")
		require.Error(t, err)
		require.Equal(t, "key is mandatory", err.Error())

		// nil key
		err = store.Put("", data)
		require.Error(t, err)
		require.Equal(t, "key is mandatory", err.Error())

		err = prov.Close()
		require.NoError(t, err)
	})

	t.Run("Test sql multi store put and get", func(t *testing.T) {
		prov, err := NewProvider(sqlStoreDBURL, WithDBPrefix("prefixdb"))
		require.NoError(t, err)
		const commonKey = "did:example:1"
		data := []byte("value1")

		_, err = prov.OpenStore("")
		require.Error(t, err)
		require.Equal(t, err.Error(), "store name is required")

		// create store 1 & store 2
		err = prov.CreateStore("store1")
		require.NoError(t, err)
		store1, err := prov.OpenStore("store1")
		require.NoError(t, err)

		err = prov.CreateStore("store2")
		require.NoError(t, err)
		store2, err := prov.OpenStore("store2")
		require.NoError(t, err)

		// put in store 1
		err = store1.Put(commonKey, data)
		require.NoError(t, err)

		// get in store 1 - found
		doc, err := store1.Get(commonKey)
		require.NoError(t, err)
		require.NotEmpty(t, doc)
		require.Equal(t, data, doc)

		// put in store 2
		err = store2.Put(commonKey, data)
		require.NoError(t, err)

		// get in store 2 - found
		doc, err = store2.Get(commonKey)
		require.NoError(t, err)
		require.NotEmpty(t, doc)
		require.Equal(t, data, doc)

		// create new store 3 with same name as store1
		store3, err := prov.OpenStore("store1")
		require.NoError(t, err)

		// get in store 3 - found
		doc, err = store3.Get(commonKey)
		require.NoError(t, err)
		require.NotEmpty(t, doc)
		require.Equal(t, data, doc)

		// store length
		require.Len(t, prov.dbs, 2)
	})
	t.Run("Test put, get, delete, iterator error", func(t *testing.T) {
		db, err := sql.Open("mysql", "root:@tcp(127.0.0.1:45454)/")
		require.NoError(t, err)

		storeErr := &sqlDBStore{
			db: db,
		}
		const commonKey = "did:example:1"
		data := []byte("value1")
		// put err
		err = storeErr.Put(commonKey, data)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to insert key and value record")

		// get err
		rows, err := storeErr.Get(commonKey)
		require.Error(t, err)
		require.Nil(t, rows)
		require.Contains(t, err.Error(), "failed to get row")
	})
	t.Run("Test sql db store failures", func(t *testing.T) {
		prov, err := NewProvider("")
		require.Error(t, err)
		require.Contains(t, err.Error(), blankDBPathErrMsg)
		require.Nil(t, prov)

		// Invalid db path
		_, err = NewProvider("root:@tcp(127.0.0.1:45454)")
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to open MySQL")

		prov, err = NewProvider(sqlStoreDBURL)
		require.NoError(t, err)

		store, err := prov.OpenStore("sample")
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to use db")
		require.Nil(t, store)
	})
	t.Run("Test the open new connection error", func(t *testing.T) {
		prov, err := NewProvider(sqlStoreDBURL)
		require.NoError(t, err)

		// invalid db url
		prov.dbURL = "fake-url"

		_, err = prov.OpenStore("testErr")
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to create new connection fake-url")

		//  valid but not available db url
		prov.dbURL = "root:my-secret-pw@tcp(127.0.0.1:3307)/"

		_, err = prov.OpenStore("testErr")
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to use db testErr")
	})
	t.Run("Test sqlDB multi store close by name", func(t *testing.T) {
		prov, err := NewProvider(sqlStoreDBURL, WithDBPrefix(randomPrefix()))
		require.NoError(t, err)

		const commonKey = "did:example:1"
		data := []byte("value1")

		storeNames := []string{"store_1", "store_2", "store_3", "store_4", "store_5"}
		storesToClose := []string{"store_1", "store_3", "store_5"}

		for _, name := range storeNames {
			e := prov.CreateStore(name)
			require.NoError(t, e)
			store, e := prov.OpenStore(name)
			require.NoError(t, e)

			e = store.Put(commonKey, data)
			require.NoError(t, e)
		}

		for _, name := range storeNames {
			store, e := prov.OpenStore(name)
			require.NoError(t, e)

			dataRead, e := store.Get(commonKey)
			require.NoError(t, e)
			require.Equal(t, data, dataRead)
		}

		// verify store length
		require.Len(t, prov.dbs, 5)

		for _, name := range storesToClose {
			store, e := prov.OpenStore(name)
			require.NoError(t, e)
			require.NotNil(t, store)

			e = prov.CloseStore(name)
			require.NoError(t, e)
		}

		// verify store length
		require.Len(t, prov.dbs, 2)

		// try to close non existing db
		err = prov.CloseStore("store_x")
		require.Error(t, err)
		require.Contains(t, err.Error(), "store not found")

		// verify store length
		require.Len(t, prov.dbs, 2)

		err = prov.Close()
		require.NoError(t, err)

		// verify store length
		require.Empty(t, prov.dbs)

		// try close all again
		err = prov.Close()
		require.NoError(t, err)
	})
	t.Run("Test result iterator key", func(t *testing.T) {
		rows := sql.Rows{}
		resItr := sqlDBResultsIterator{&rows, result{}, nil}
		res, err := resItr.Key()
		require.Error(t, err)
		require.Equal(t, "", res)
		require.Contains(t, err.Error(), "failed to scan the SQL rows while getting key")
	})
	t.Run("Test result iterator value", func(t *testing.T) {
		rows := sql.Rows{}
		resItr := sqlDBResultsIterator{&rows, result{}, nil}
		res, err := resItr.Value()
		require.Error(t, err)
		require.Nil(t, res)
		require.Contains(t, err.Error(), "failed to scan the SQL rows while getting value")
	})
}

func TestMySqlDBStore_query(t *testing.T) {
	var storeName = "testIterator"

	prov, e := NewProvider(sqlStoreDBURL)
	require.NoError(t, e)
	e = prov.CreateStore(storeName)
	require.NoError(t, e)
	store, e := prov.OpenStore(storeName)
	require.NoError(t, e)

	const valPrefix = "val-for-%s"

	keys := []string{"abc_123", "abc_124", "abc_125", "abc_126", "jkl_123", "mno_123"}

	for _, key := range keys {
		e := store.Put(key, []byte(fmt.Sprintf(valPrefix, key)))

		require.NoError(t, e)
	}

	t.Run("Test sql db store query", func(t *testing.T) {
		itr, err := store.Query("SELECT * FROM testIterator WHERE `key` >=  'abc_' AND `key` < 'abc!!' " +
			"order by `key`")
		require.NoError(t, err)
		verifyItr(t, itr, 4, "abc_")

		itr, err = store.Query("SELECT * FROM testIterator WHERE `key` >=  '' AND `key` < '' " +
			"order by `key`")
		require.NoError(t, err)
		verifyItr(t, itr, 0, "")

		itr, err = store.Query("SELECT * FROM testIterator WHERE `key` >=  'abc' AND `key` < 'mno!!' " +
			"order by `key`")
		require.NoError(t, err)
		verifyItr(t, itr, 6, "")

		itr, err = store.Query("SELECT * FROM testIterator WHERE `key` >=  'abc_' AND `key` < 'mno_123' " +
			"order by `key`")
		require.NoError(t, err)
		verifyItr(t, itr, 5, "")

		itr, err = store.Query("SELECT * FROM testIterator WHERE `key` = 'abc_124'")
		require.NoError(t, err)
		verifyItr(t, itr, 1, "")

		itr, e := store.Query(`""`)
		require.Error(t, e)
		require.Nil(t, itr)
		require.Contains(t, e.Error(), "failed to query rows")
	})
	t.Run("Successfully query using index", func(t *testing.T) {
		err := createIndex(store, "`key`", storeName)
		require.NoError(t, err)
		//nolint: gosec
		itr, err := store.Query("SELECT * FROM " + storeName + "" +
			" USE INDEX (" + testIndexName + ") WHERE `key` = 'abc_124'")
		require.NoError(t, err)

		ok, e := itr.Next()
		require.NoError(t, e)
		require.True(t, ok)

		value, e := itr.Value()
		require.NoError(t, e)
		require.Equal(t, "val-for-abc_124", string(value))

		ok, err = itr.Next()
		require.NoError(t, err)
		require.False(t, ok)

		err = itr.Release()
		require.NoError(t, err)
	})
	t.Run("Successfully query using index on two columns",
		func(t *testing.T) {
			err := createIndex(store, "`key`, value(255)", storeName)
			require.NoError(t, err)

			//nolint: gosec
			itr, err := store.Query("SELECT * FROM " + storeName + "" +
				" USE INDEX (" + testIndexName + ") WHERE `key` = 'abc_124'")
			require.NoError(t, err)

			ok, err := itr.Next()
			require.NoError(t, err)
			require.True(t, ok)

			require.NoError(t, err)
			value, err := itr.Value()
			require.NoError(t, err)
			require.Equal(t, "val-for-abc_124", string(value))

			ok, err = itr.Next()
			require.NoError(t, err)
			require.False(t, ok)

			err = itr.Release()
			require.NoError(t, err)
		})
}
func TestMySqlDBStore_CreateIndex(t *testing.T) {
	var storeName = "store2"

	prov, err := NewProvider(sqlStoreDBURL)
	require.NoError(t, err)
	err = prov.CreateStore(storeName)
	require.NoError(t, err)
	store, err := prov.OpenStore(storeName)
	require.NoError(t, err)

	t.Run("Successfully create index", func(t *testing.T) {
		sqlDBStore, ok := store.(*sqlDBStore)
		require.True(t, ok)

		err = createIndex(store, "`key`", storeName)
		require.NoError(t, err)

		rows, err := sqlDBStore.db.Query("SELECT DISTINCT INDEX_NAME FROM INFORMATION_SCHEMA.STATISTICS" +
			" WHERE TABLE_NAME = 'store2';")
		require.NoError(t, err)

		var IndexName string
		for rows.Next() {
			err := rows.Scan(&IndexName)
			require.NoError(t, err)
		}
		require.Equal(t, testIndexName, IndexName)
	})
	t.Run("Fail to get index", func(t *testing.T) {
		sqlDBStore, ok := store.(*sqlDBStore)
		require.True(t, ok)

		db, err := sql.Open("mysql", "root:@tcp(127.0.0.1:45454)/")
		require.NoError(t, err)

		sqlDBStore.db = db

		req := storage.CreateIndexRequest{
			IndexStorageLocation: storeName,
			IndexName:            testIndexName,
			WhatToIndex:          "`key`",
		}
		err = sqlDBStore.CreateIndex(req)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to get indexes")
	})
	t.Run("Fail to prepare get index statement", func(t *testing.T) {
		sqlDBStore, ok := store.(*sqlDBStore)
		require.True(t, ok)

		db, err := sql.Open("mysql", "root:@tcp(127.0.0.1:45454)/")
		require.NoError(t, err)

		sqlDBStore.db = db
		indexes, err := sqlDBStore.getIndexes()
		require.Nil(t, indexes)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to prepare index statement")
	})
	t.Run("Fail to drop existing index", func(t *testing.T) {
		sqlDBStore, ok := store.(*sqlDBStore)
		require.True(t, ok)

		indexes := []string{"test", "test_2"}
		err := sqlDBStore.dropExistingIndex(indexes, storage.CreateIndexRequest{IndexName: "test"})
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to drop an existing index")
	})

	t.Run("Fail to create index - invalid index request", func(t *testing.T) {
		prov, err := NewProvider(sqlStoreDBURL)
		require.NoError(t, err)
		err = prov.CreateStore("store1")
		require.NoError(t, err)
		store, err := prov.OpenStore("store1")
		require.NoError(t, err)

		err = createIndex(store, ``, "store1")
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to create index Error")
	})
}
func verifyItr(t *testing.T, itr storage.ResultsIterator, count int, prefix string) {
	var vals []string

	ok, err := itr.Next()
	require.NoError(t, err)

	for ok {
		if prefix != "" {
			k, e := itr.Key()
			require.NoError(t, e)
			require.True(t, strings.HasPrefix(k, prefix))
		}

		val, e := itr.Value()
		require.NoError(t, e)

		vals = append(vals, string(val))

		ok, err = itr.Next()
		require.NoError(t, err)
	}

	require.Len(t, vals, count)

	err = itr.Release()
	require.NoError(t, err)
	require.False(t, ok)
}

func createIndex(store storage.Store, whatToIndex, storageLocation string) error {
	createIndexRequest := storage.CreateIndexRequest{
		IndexStorageLocation: storageLocation,
		IndexName:            testIndexName,
		WhatToIndex:          whatToIndex,
	}

	return store.CreateIndex(createIndexRequest)
}

func randomPrefix() string {
	s := uuid.New().String()
	return fmt.Sprintf("test%s", s[strings.LastIndex(s, "-")+1:])
}
