/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package mysql

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"sync"

	// Add as per the documentation - https://github.com/go-sql-driver/mysql
	_ "github.com/go-sql-driver/mysql"

	"github.com/trustbloc/edge-core/pkg/storage"
)

// Option configures the couchdb provider
type Option func(opts *Provider)

// WithDBPrefix option is for adding prefix to db name
func WithDBPrefix(dbPrefix string) Option {
	return func(opts *Provider) {
		opts.dbPrefix = dbPrefix
	}
}

// Provider represents a MySQL DB implementation of the storage.Provider interface
type Provider struct {
	dbURL    string
	db       *sql.DB
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

const (
	blankDBPathErrMsg         = "DB URL for new mySQL DB provider can't be blank"
	failToCloseProviderErrMsg = "failed to close provider"
	sqlDBNotFound             = "no rows"
	createDBQuery             = "CREATE DATABASE IF NOT EXISTS "
	useDBQuery                = "USE "
)

// NewProvider instantiates Provider
func NewProvider(dbPath string, opts ...Option) (*Provider, error) {
	if dbPath == "" {
		return nil, errors.New(blankDBPathErrMsg)
	}

	// Example DB Path root:my-secret-pw@tcp(127.0.0.1:3306)/
	db, err := sql.Open("mysql", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open connection: %w", err)
	}

	p := &Provider{
		dbURL: dbPath,
		db:    db,
		dbs:   map[string]*sqlDBStore{}}

	for _, opt := range opts {
		opt(p)
	}

	return p, nil
}

// OpenStore opens and returns a new db with the given name space
func (p *Provider) OpenStore(name string) (storage.Store, error) {
	p.Lock()
	defer p.Unlock()

	if name == "" {
		return nil, errors.New("store name is required")
	}

	if p.dbPrefix != "" {
		name = p.dbPrefix + "_" + name
	}
	// creating the database
	_, err := p.db.Exec(createDBQuery + name)
	if err != nil {
		return nil, fmt.Errorf("failed to create db %s: %w", name, err)
	}

	// Opening new db connection
	newDBConn, err := sql.Open("mysql", p.dbURL)
	if err != nil {
		return nil, fmt.Errorf("failed to create new connection %s: %w", p.dbURL, err)
	}

	// Use Query is used to select the created database without this DDL operations are not permitted
	_, err = newDBConn.Exec(useDBQuery + name)
	if err != nil {
		return nil, fmt.Errorf("failed to use db %s: %w", name, err)
	}

	// key has max varchar size it can accommodate as per mysql 8.0 spec
	createTableStmt := "CREATE Table IF NOT EXISTS " + name +
		"(`key` varchar(255) NOT NULL ,`value` BLOB, PRIMARY KEY (`key`));"

	// creating key-value table inside the database
	_, err = newDBConn.Exec(createTableStmt)
	if err != nil {
		return nil, fmt.Errorf("failed to create table %s: %w", name, err)
	}

	store := &sqlDBStore{
		db:        newDBConn,
		tableName: name}

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
			return fmt.Errorf(failToCloseProviderErrMsg+": %w", err)
		}
	}

	if err := p.db.Close(); err != nil {
		return err
	}

	p.dbs = make(map[string]*sqlDBStore)

	return nil
}

// CloseStore closes a previously opened store
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

	return store.db.Close()
}

// Put stores the key and the value
func (s *sqlDBStore) Put(k string, v []byte) error {
	if k == "" {
		return errors.New("key is mandatory")
	}

	//nolint: gosec
	// create upsert query to insert the record, checking whether the key is already mapped to a value in the store.
	// todo issue-38 to address sql injection warning
	createStmt := "INSERT INTO " + s.tableName + " VALUES (?, ?) ON DUPLICATE KEY UPDATE value=?"
	// executing the prepared insert statement
	_, err := s.db.Exec(createStmt, k, v, v)
	if err != nil {
		return fmt.Errorf("failed to insert key and value record into %s %w ", s.tableName, err)
	}

	return nil
}

// Get fetches the value based on key
func (s *sqlDBStore) Get(k string) ([]byte, error) {
	if k == "" {
		return nil, errors.New("key is mandatory")
	}

	var value []byte
	//nolint: gosec
	// select query to fetch the value by key
	// todo issue-38 to address sql injection warning
	err := s.db.QueryRow("SELECT `value` FROM "+s.tableName+" "+
		" WHERE `key` = ?", k).Scan(&value)
	if err != nil {
		if strings.Contains(err.Error(), sqlDBNotFound) {
			return nil, storage.ErrValueNotFound
		}

		return nil, fmt.Errorf("failed to get row %w", err)
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
		return fmt.Errorf("failed to get indexes: %s", err)
	}
	// if an index exits, drop it as sql throws duplicate key_name error
	err = s.dropExistingIndex(indexes, createIndexRequest)
	if err != nil {
		return fmt.Errorf("failed to drop an existing index: %s", err)
	}
	// create an index
	// todo issue-38 to sanitize input
	createIndexStmt := "CREATE INDEX " + createIndexRequest.IndexName + " ON " +
		createIndexRequest.IndexStorageLocation + " (" + createIndexRequest.WhatToIndex + ")"

	_, err = s.db.Exec(createIndexStmt)
	if err != nil {
		return fmt.Errorf("failed to create index %w", err)
	}

	return nil
}

func (s *sqlDBStore) getIndexes() ([]string, error) {
	getIndexStmt := "SELECT DISTINCT INDEX_NAME FROM INFORMATION_SCHEMA.STATISTICS WHERE TABLE_NAME= ?"

	indexStmt, err := s.db.Prepare(getIndexStmt)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare index statement: %w", err)
	}

	rows, err := indexStmt.Query(s.tableName)
	if err != nil {
		return nil, fmt.Errorf("failed to query select index statement: %w", err)
	}

	var index string

	var indexes []string
	// Tables by default have a clustered index named as PRIMARY and can contain more than one index
	for rows.Next() {
		err := rows.Scan(&index)
		if err != nil {
			return nil, fmt.Errorf("failed to scan the rows: %w", err)
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
				return fmt.Errorf("failed to drop an existing index: %w", err)
			}
		}
	}

	return nil
}

func (s *sqlDBStore) Query(findQuery string) (storage.ResultsIterator, error) {
	resultRows, err := s.db.Query(findQuery)
	if err != nil {
		return nil, fmt.Errorf("failed to query rows %w", err)
	}

	return &sqlDBResultsIterator{resultRows: resultRows}, nil
}

// Key returns the key of the current key-value pair.
func (i *sqlDBResultsIterator) Key() (string, error) {
	err := i.resultRows.Scan(&i.result.key, &i.result.value)
	if err != nil {
		return "", fmt.Errorf("failed to scan the SQL rows while getting key: %w", err)
	}

	return i.result.key, nil
}

// Value returns the value of the current key-value pair.
func (i *sqlDBResultsIterator) Value() ([]byte, error) {
	err := i.resultRows.Scan(&i.result.key, &i.result.value)
	if err != nil {
		return nil, fmt.Errorf("failed to scan the SQL rows while getting value: %w", err)
	}

	return i.result.value, nil
}

func (i *sqlDBResultsIterator) Next() (bool, error) {
	nextCallResult := i.resultRows.Next()

	return nextCallResult, i.resultRows.Err()
}

func (i *sqlDBResultsIterator) Release() error {
	if err := i.resultRows.Close(); err != nil {
		return fmt.Errorf("failed to release result rows: %w", i.err)
	}

	return nil
}
