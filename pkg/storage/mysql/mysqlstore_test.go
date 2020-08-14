/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package mysql

import (
	"database/sql"
	"errors"
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

var errMockResultRowsAffected = errors.New("mockResult always fails")

type mockResult struct {
}

func (m mockResult) LastInsertId() (int64, error) {
	panic("implement me")
}

func (m mockResult) RowsAffected() (int64, error) {
	return -1, errMockResultRowsAffected
}

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
		require.Contains(t, err.Error(), storage.ErrValueNotFound.Error())

		// nil key
		_, err = store.Get("")
		require.Error(t, err)
		require.EqualError(t, err, storage.ErrKeyRequired.Error())

		// nil key
		err = store.Put("", data)
		require.Error(t, err)
		require.EqualError(t, err, storage.ErrKeyRequired.Error())

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
		require.EqualError(t, err, "store name is required")

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
		require.Contains(t, err.Error(),
			"failure while executing insert statement on table : dial tcp 127.0.0.1:45454: "+
				"connect: connection refused")

		// get err
		rows, err := storeErr.Get(commonKey)
		require.Error(t, err)
		require.Nil(t, rows)
		require.EqualError(t, err,
			"failure while querying row: dial tcp 127.0.0.1:45454: connect: connection refused")
	})
	t.Run("Test sql db store failures", func(t *testing.T) {
		prov, err := NewProvider("")
		require.Error(t, err)
		require.EqualError(t, err, errBlankDBPath.Error())
		require.Nil(t, prov)

		// Invalid db path
		_, err = NewProvider("root:@tcp(127.0.0.1:45454)")
		require.Error(t, err)
		require.Contains(t, err.Error(), "failure while opening MySQL connection")

		prov, err = NewProvider(sqlStoreDBURL)
		require.NoError(t, err)

		store, err := prov.OpenStore("sample")
		require.Error(t, err)
		require.EqualError(t, err,
			`failure while executing USE query on DB sample: Error 1049: Unknown database 'sample'`)
		require.Nil(t, store)
	})
	t.Run("Test the open new connection error", func(t *testing.T) {
		prov, err := NewProvider(sqlStoreDBURL)
		require.NoError(t, err)

		// invalid db url
		prov.dbURL = "fake-url"

		_, err = prov.OpenStore("testErr")
		require.Error(t, err)
		require.EqualError(t, err,
			"failure while opening MySQL connection using url fake-url: invalid DSN: "+
				"missing the slash separating the database name")

		//  valid but not available db url
		prov.dbURL = "root:my-secret-pw@tcp(127.0.0.1:3307)/"

		_, err = prov.OpenStore("testErr")
		require.Error(t, err)
		require.EqualError(t, err,
			"failure while executing USE query on DB testErr: dial tcp 127.0.0.1:3307: "+
				"connect: connection refused")
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
		require.Empty(t, res)
		require.EqualError(t, err, "failure while scanning rows: sql: Scan called without calling Next")
	})
	t.Run("Test result iterator value", func(t *testing.T) {
		rows := sql.Rows{}
		resItr := sqlDBResultsIterator{&rows, result{}, nil}
		res, err := resItr.Value()
		require.Error(t, err)
		require.Nil(t, res)
		require.EqualError(t, err, "failure while scanning rows: sql: Scan called without calling Next")
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
		require.EqualError(t, e,
			`failure while executing query: Error 1064: You have an error in your SQL syntax; `+
				`check the manual that corresponds to your MySQL server version for the right syntax to`+
				` use near '""' at line 1`)
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

		rows, errQuery := sqlDBStore.db.Query("SELECT DISTINCT INDEX_NAME FROM INFORMATION_SCHEMA.STATISTICS" +
			" WHERE TABLE_NAME = 'store2';")
		require.NoError(t, errQuery)

		var IndexName string
		for rows.Next() {
			errScan := rows.Scan(&IndexName)
			require.NoError(t, errScan)
		}
		require.Equal(t, testIndexName, IndexName)
	})
	t.Run("Fail to get index", func(t *testing.T) {
		sqlDBStore, ok := store.(*sqlDBStore)
		require.True(t, ok)

		db, errOpen := sql.Open("mysql", "root:@tcp(127.0.0.1:45454)/")
		require.NoError(t, errOpen)

		sqlDBStore.db = db

		req := storage.CreateIndexRequest{
			IndexStorageLocation: storeName,
			IndexName:            testIndexName,
			WhatToIndex:          "`key`",
		}
		errOpen = sqlDBStore.CreateIndex(req)
		require.Error(t, errOpen)
		require.EqualError(t, errOpen,
			"failure while getting indexes: failure while preparing index statement: "+
				"dial tcp 127.0.0.1:45454: connect: connection refused")
	})
	t.Run("Fail to prepare get index statement", func(t *testing.T) {
		sqlDBStore, ok := store.(*sqlDBStore)
		require.True(t, ok)

		db, errOpen := sql.Open("mysql", "root:@tcp(127.0.0.1:45454)/")
		require.NoError(t, errOpen)

		sqlDBStore.db = db
		indexes, errOpen := sqlDBStore.getIndexes()
		require.Nil(t, indexes)
		require.Error(t, errOpen)
		require.EqualError(t, errOpen,
			"failure while preparing index statement: dial tcp 127.0.0.1:45454: "+
				"connect: connection refused")
	})
	t.Run("Fail to drop existing index", func(t *testing.T) {
		err = prov.CreateStore("store3")
		require.NoError(t, err)
		store, err := prov.OpenStore("store3")
		require.NoError(t, err)
		sqlDBStore, ok := store.(*sqlDBStore)
		require.True(t, ok)

		indexes := []string{"test", "test_2"}
		err = sqlDBStore.dropExistingIndex(indexes, storage.CreateIndexRequest{IndexName: "test"})
		require.Error(t, err)
		require.EqualError(t, err, `failure while executing drop index statement: Error 1064: You have`+
			` an error in your SQL syntax; check the manual that corresponds to your MySQL server version `+
			`for the right syntax to use near 'DROP INDEX test' at line 1`)
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
		require.EqualError(t, err, `failure while executing create index statement: Error 1064: `+
			`You have an error in your SQL syntax; check the manual that corresponds to your MySQL server`+
			` version for the right syntax to use near ')' at line 1`)
	})
}

func TestMySqlDBStore_Remove(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		testKey := "testKey"
		testData := []byte("value1")

		prov, err := NewProvider(sqlStoreDBURL)
		require.NoError(t, err)

		err = prov.CreateStore("testStore")
		require.NoError(t, err)

		store, err := prov.OpenStore("testStore")
		require.NoError(t, err)

		err = store.Put(testKey, testData)
		require.NoError(t, err)

		err = store.Delete(testKey)
		require.NoError(t, err)

		// Verify that the key-value pair was actually deleted
		doc, err := store.Get(testKey)
		require.Truef(t, errors.Is(err, storage.ErrValueNotFound),
			`"%s" does not contain the expected error "%s"`, err, storage.ErrValueNotFound)
		require.Empty(t, doc)
	})
	t.Run("Empty key", func(t *testing.T) {
		prov, err := NewProvider(sqlStoreDBURL)
		require.NoError(t, err)

		err = prov.CreateStore("testStore")
		require.NoError(t, err)

		store, err := prov.OpenStore("testStore")
		require.NoError(t, err)

		err = store.Delete("")
		require.EqualError(t, err, storage.ErrKeyRequired.Error())
	})
	t.Run("Key not found", func(t *testing.T) {
		prov, err := NewProvider(sqlStoreDBURL)
		require.NoError(t, err)

		err = prov.CreateStore("testStore")
		require.NoError(t, err)

		store, err := prov.OpenStore("testStore")
		require.NoError(t, err)

		err = store.Delete("ThisIsNotAStoredKey")
		require.Truef(t, errors.Is(err, errNoRowsAffectedByDeleteQuery),
			`"%s" does not contain the expected error "%s"`, err, errNoRowsAffectedByDeleteQuery)
	})
	t.Run("Fail to delete row", func(t *testing.T) {
		prov, err := NewProvider(sqlStoreDBURL)
		require.NoError(t, err)

		err = prov.CreateStore("testStore")
		require.NoError(t, err)

		store, err := prov.OpenStore("testStore")
		require.NoError(t, err)

		sqlStore, ok := store.(*sqlDBStore)
		require.True(t, ok, "unable to assert store as a sqlStore")

		sqlStore.tableName = "someNonExistentTable"

		err = store.Delete("SomeKey")
		require.EqualError(t, err,
			"failure while executing delete statement: Error 1146: Table "+
				"'testStore.someNonExistentTable' doesn't exist")
	})
}

func TestMySqlDBStore_checkDeleteResult(t *testing.T) {
	t.Run("Failure while retrieving number of rows affected", func(t *testing.T) {
		err := checkDeleteResult(mockResult{})
		require.Truef(t, errors.Is(err, errMockResultRowsAffected),
			`"%s" does not contain the expected error "%s"`, err, errMockResultRowsAffected)
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
