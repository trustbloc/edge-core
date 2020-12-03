/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package mysql

import (
	"database/sql"
	"fmt"
	"strings"
	"sync"

	// Add as per the documentation - https://github.com/go-sql-driver/mysql
	_ "github.com/go-sql-driver/mysql"

	"github.com/trustbloc/edge-core/pkg/storage"
)

const (
	createDBQuery = "CREATE DATABASE IF NOT EXISTS "
)

// Option configures the couchdb provider.
type Option func(opts *Provider)

// WithDBPrefix option is for adding prefix to db name.
func WithDBPrefix(dbPrefix string) Option {
	return func(opts *Provider) {
		opts.dbPrefix = dbPrefix
	}
}

// Provider represents a MySQL DB implementation of the storage.Provider interface.
type Provider struct {
	dbURL    string
	dbs      map[string]*sqlDBStore
	dbPrefix string
	sync.RWMutex
}

type sqlDBStore struct {
	db        *sql.DB
	tableName string
}

type result struct {
	key   string
	value []byte
}

// NewProvider instantiates Provider.
// Example DB Path root:my-secret-pw@tcp(127.0.0.1:3306)/.
// This provider's CreateStore(name) implementation creates stores that are backed by a table under a schema
// with the same name as the table. The fully qualified name of the table is thus `name.name`. The fully qualified
// name of the table needs to be used with the store's `Query()` method.
func NewProvider(dbPath string, opts ...Option) (p *Provider, err error) {
	if dbPath == "" {
		return nil, errBlankDBPath
	}

	db, err := sql.Open("mysql", dbPath)
	if err != nil {
		return nil, fmt.Errorf(failureWhileOpeningMySQLConnectionErrMsg, dbPath, err)
	}

	defer func() {
		closeErr := db.Close()
		if closeErr != nil {
			if err == nil {
				err = fmt.Errorf(failureWhileClosingMySQLConnection, closeErr)
			} else {
				secondErr := fmt.Sprintf("Additional error: %s",
					fmt.Errorf(failureWhileClosingMySQLConnection, closeErr))
				err = fmt.Errorf("error while creating new provider: %w. %s", err, secondErr)
			}
		}
	}()

	err = db.Ping()
	if err != nil {
		return nil, fmt.Errorf(failureWhilePingingMySQLErrMsg, dbPath, err)
	}

	p = &Provider{
		dbURL: dbPath,
		dbs:   map[string]*sqlDBStore{},
	}

	for _, opt := range opts {
		opt(p)
	}

	return p, nil
}

// CreateStore creates a store with the given name.
func (p *Provider) CreateStore(name string) (err error) {
	if name == "" {
		return errBlankStoreName
	}

	if p.dbPrefix != "" {
		name = p.dbPrefix + "_" + name
	}

	db, err := sql.Open("mysql", p.dbURL)
	if err != nil {
		return fmt.Errorf(failureWhileOpeningMySQLConnectionErrMsg, p.dbURL, err)
	}

	defer func() {
		closeErr := db.Close()
		if closeErr != nil {
			if err == nil {
				err = fmt.Errorf(failureWhileClosingMySQLConnection, closeErr)
			} else {
				secondErr := fmt.Sprintf("Additional error: %s",
					fmt.Errorf(failureWhileClosingMySQLConnection, closeErr))
				err = fmt.Errorf("error while creating new store: %w. %s", err, secondErr)
			}
		}
	}()

	// creating the database
	_, err = db.Exec(createDBQuery + name)
	if err != nil {
		return fmt.Errorf(failureWhileCreatingDBErrMsg, name, err)
	}

	// key has max varchar size it can accommodate as per mysql 8.0 spec
	createTableStmt := fmt.Sprintf(
		"Create TABLE IF NOT EXISTS `%s`.`%s` (`key` varchar(255) NOT NULL ,`value` BLOB, PRIMARY KEY (`key`))",
		name, name)

	// creating key-value table inside the database
	_, err = db.Exec(createTableStmt)
	if err != nil {
		return fmt.Errorf(failureWhileCreatingTableErrMsg, name, err)
	}

	return nil
}

// OpenStore opens and returns a new DB with the given namespace.
func (p *Provider) OpenStore(name string) (s storage.Store, openErr error) {
	p.Lock()
	defer p.Unlock()

	if name == "" {
		return nil, errBlankStoreName
	}

	if p.dbPrefix != "" {
		name = p.dbPrefix + "_" + name
	}

	// Opening new db connection
	newDBConn, err := sql.Open("mysql", p.dbURL)
	if err != nil {
		return nil, fmt.Errorf(failureWhileOpeningMySQLConnectionErrMsg, p.dbURL, err)
	}

	// Use Query is used to select the created database.
	// Without this, DDL operations are not permitted.
	// nolint:rowserrcheck // will be fixed in https://github.com/trustbloc/edge-core/issues/86
	rows, err := newDBConn.Query(
		"SELECT 1 FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA = ? AND TABLE_NAME = ? LIMIT 1", name, name)
	if err != nil {
		return nil, fmt.Errorf(failureWhileQueryingForTableErrMsg, name, err)
	}

	defer func() {
		closeErr := rows.Close()
		if closeErr != nil {
			if openErr != nil {
				openErr = fmt.Errorf("%w: failed to close rows: %s", openErr, closeErr)

				return
			}

			openErr = fmt.Errorf("failed to close rows: %w", closeErr)
		}
	}()

	if !rows.Next() {
		return nil, fmt.Errorf(failureStoreDoesNotExistErrMsg, name)
	}

	store := &sqlDBStore{
		db:        newDBConn,
		tableName: fmt.Sprintf("`%s`.`%s`", name, name),
	}

	p.dbs[name] = store

	return store, nil
}

// Close closes the provider.
func (p *Provider) Close() error {
	p.Lock()
	defer p.Unlock()

	for _, store := range p.dbs {
		err := store.db.Close()
		if err != nil {
			return fmt.Errorf(failureWhileClosingMySQLConnection, err)
		}
	}

	p.dbs = make(map[string]*sqlDBStore)

	return nil
}

// CloseStore closes a previously opened store.
func (p *Provider) CloseStore(name string) error {
	p.Lock()
	defer p.Unlock()

	if p.dbPrefix != "" {
		name = p.dbPrefix + "_" + name
	}

	store, exists := p.dbs[name]
	if !exists {
		return storage.ErrStoreNotFound
	}

	delete(p.dbs, name)

	err := store.db.Close()
	if err != nil {
		return fmt.Errorf(failureWhileClosingMySQLConnection, err)
	}

	return nil
}

// Put stores the key and the value.
func (s *sqlDBStore) Put(k string, v []byte) error {
	if k == "" {
		return storage.ErrKeyRequired
	}

	// create upsert query to insert the record, checking whether the key is already mapped to a value in the store.
	// todo issue-38 to address sql injection warning
	// nolint:gosec // issue-38 to address sql injection warning
	createStmt := "INSERT INTO " + s.tableName + " VALUES (?, ?) ON DUPLICATE KEY UPDATE value=?"
	// executing the prepared insert statement
	_, err := s.db.Exec(createStmt, k, v, v)
	if err != nil {
		return fmt.Errorf(failureWhileExecutingInsertStatementErrMsg, s.tableName, err)
	}

	return nil
}

func (*sqlDBStore) PutAll(keys []string, values [][]byte) error {
	return storage.ErrPutAllNotImplemented
}

// GetAll is not implemented.
func (s *sqlDBStore) GetAll() (map[string][]byte, error) {
	return nil, storage.ErrGetAllNotSupported
}

// Get fetches the value based on key.
func (s *sqlDBStore) Get(k string) ([]byte, error) {
	if k == "" {
		return nil, storage.ErrKeyRequired
	}

	var value []byte
	// select query to fetch the value by key
	// todo issue-38 to address sql injection warning
	// nolint:gosec // issue-38 to address sql injection warning
	err := s.db.QueryRow("SELECT `value` FROM "+s.tableName+" "+
		" WHERE `key` = ?", k).Scan(&value)
	if err != nil {
		if strings.Contains(err.Error(), valueNotFoundErrMsgFromMySQL) {
			return nil, fmt.Errorf(failureWhileQueryingRowErrMsg, storage.ErrValueNotFound)
		}

		return nil, fmt.Errorf(failureWhileQueryingRowErrMsg, err)
	}

	return value, nil
}

type sqlDBResultsIterator struct {
	resultRows *sql.Rows
	result     result
	err        error
}

func (s *sqlDBStore) CreateIndex(createIndexRequest storage.CreateIndexRequest) error {
	// get all the created indexes
	indexes, err := s.getIndexes()
	if err != nil {
		return fmt.Errorf(failureWhileGettingIndexesErrMsg, err)
	}
	// if an index exits, drop it as sql throws duplicate key_name error
	err = s.dropExistingIndex(indexes, createIndexRequest)
	if err != nil {
		return fmt.Errorf(failureWhileDroppingIndexesErrMsg, err)
	}
	// create an index
	// todo issue-38 to sanitize input
	createIndexStmt := "CREATE INDEX " + createIndexRequest.IndexName + " ON " +
		createIndexRequest.IndexStorageLocation + " (" + createIndexRequest.WhatToIndex + ")"

	_, err = s.db.Exec(createIndexStmt)
	if err != nil {
		return fmt.Errorf(failureWhileExecutingCreateIndexStatementErrMsg, err)
	}

	return nil
}

func (s *sqlDBStore) Query(findQuery string) (storage.ResultsIterator, error) {
	// nolint:rowserrcheck,sqlclosecheck // will be fixed in https://github.com/trustbloc/edge-core/issues/86
	resultRows, err := s.db.Query(findQuery)
	if err != nil {
		return nil, fmt.Errorf(failureWhileQueryDBErrMsg, err)
	}

	return &sqlDBResultsIterator{resultRows: resultRows}, nil
}

func (s *sqlDBStore) Delete(k string) error {
	if k == "" {
		return storage.ErrKeyRequired
	}

	// TODO address SQL injection warning #38
	// nolint:gosec // issue-38 to address sql injection warning
	result, err := s.db.Exec("DELETE FROM "+s.tableName+" WHERE `key`= ?", k)
	if err != nil {
		return fmt.Errorf(failureWhileDeleteFromTableErrMsg, err)
	}

	err = checkDeleteResult(result)
	if err != nil {
		return fmt.Errorf(failureWhileCheckingDeleteResultErrMsg, err)
	}

	return nil
}

// Key returns the key of the current key-value pair.
func (i *sqlDBResultsIterator) Key() (string, error) {
	err := i.resultRows.Scan(&i.result.key, &i.result.value)
	if err != nil {
		return "", fmt.Errorf(failureWhilleScanningRowsErrMsg, err)
	}

	return i.result.key, nil
}

// Value returns the value of the current key-value pair.
func (i *sqlDBResultsIterator) Value() ([]byte, error) {
	err := i.resultRows.Scan(&i.result.key, &i.result.value)
	if err != nil {
		return nil, fmt.Errorf(failureWhilleScanningRowsErrMsg, err)
	}

	return i.result.value, nil
}

func (i *sqlDBResultsIterator) Next() (bool, error) {
	nextCallResult := i.resultRows.Next()

	return nextCallResult, i.resultRows.Err()
}

func (i *sqlDBResultsIterator) Release() error {
	if err := i.resultRows.Close(); err != nil {
		return fmt.Errorf(failureWhileReleasingResultRows, err)
	}

	return nil
}

// TODO (#51): Refactor querying to work more generically while supporting pagination.
func (i *sqlDBResultsIterator) Bookmark() string {
	return ""
}

func (s *sqlDBStore) getIndexes() ([]string, error) {
	getIndexStmt := "SELECT DISTINCT INDEX_NAME FROM INFORMATION_SCHEMA.STATISTICS WHERE TABLE_NAME= ?"

	// nolint:sqlclosecheck // will be fixed in https://github.com/trustbloc/edge-core/issues/86
	indexStmt, err := s.db.Prepare(getIndexStmt)
	if err != nil {
		return nil, fmt.Errorf(failureWhilePreparingIndexStatementErrMsg, err)
	}

	// nolint:rowserrcheck,sqlclosecheck // will be fixed in https://github.com/trustbloc/edge-core/issues/86
	rows, err := indexStmt.Query(s.tableName)
	if err != nil {
		return nil, fmt.Errorf(failureWhileExecutingSelectIndexStatementErrMsg, err)
	}

	var index string

	var indexes []string
	// Tables by default have a clustered index named as PRIMARY and can contain more than one index
	for rows.Next() {
		err := rows.Scan(&index)
		if err != nil {
			return nil, fmt.Errorf(failureWhilleScanningRowsErrMsg, err)
		}

		indexes = append(indexes, index)
	}

	return indexes, nil
}

func (s *sqlDBStore) dropExistingIndex(indexes []string, createIndexRequest storage.CreateIndexRequest) error {
	// todo issue-38 to sanitize input
	for i := range indexes {
		if indexes[i] == createIndexRequest.IndexName {
			dropIndexStmt := "ALTER TABLE " + createIndexRequest.IndexStorageLocation + " DROP INDEX " +
				createIndexRequest.IndexName

			_, err := s.db.Exec(dropIndexStmt)
			if err != nil {
				return fmt.Errorf(failureWhileExecutingDropIndexStatementErrMsg, err)
			}
		}
	}

	return nil
}

func checkDeleteResult(result sql.Result) error {
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf(failureWhileGettingRowsAffectedErrMsg, err)
	}

	if rowsAffected == 0 {
		return errNoRowsAffectedByDeleteQuery
	}

	return nil
}
