/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package couchdbstore

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"strconv"
	"strings"
	"sync"

	_ "github.com/go-kivik/couchdb" // The CouchDB driver
	"github.com/go-kivik/kivik"

	"github.com/trustbloc/edge-core/pkg/log"
	"github.com/trustbloc/edge-core/pkg/storage"
)

const (
	logModuleName = "edge-core-couchdbstore"

	blankHostErrMsg           = "hostURL for new CouchDB provider can't be blank"
	failToCloseProviderErrMsg = "failed to close provider"
	couchDBNotFoundErr        = "Not Found: missing"
	getRevisionFailureErrMsg  = "failure while getting revision: %w"
	getRawDocFailureErrMsg    = "failure while getting raw CouchDB document: %w"
)

var errMissingRevisionField = errors.New("the retrieved CouchDB document is missing the _rev field")
var errFailToAssertRevAsString = errors.New("failed to assert the retrieved revision as a string")

var logger = log.New(logModuleName)

// Option configures the couchdb provider
type Option func(opts *Provider)

// WithDBPrefix option is for adding prefix to db name
func WithDBPrefix(dbPrefix string) Option {
	return func(opts *Provider) {
		opts.dbPrefix = dbPrefix
	}
}

// Provider represents an CouchDB implementation of the storage.Provider interface
type Provider struct {
	hostURL       string
	couchDBClient *kivik.Client
	dbs           map[string]*CouchDBStore
	dbPrefix      string
	mux           sync.RWMutex
}

// NewProvider instantiates Provider
func NewProvider(hostURL string, opts ...Option) (*Provider, error) {
	if hostURL == "" {
		return nil, errors.New(blankHostErrMsg)
	}

	client, err := kivik.New("couch", hostURL)
	if err != nil {
		return nil, err
	}

	p := &Provider{hostURL: hostURL, couchDBClient: client, dbs: map[string]*CouchDBStore{}}

	for _, opt := range opts {
		opt(p)
	}

	return p, nil
}

// CreateStore creates a new store with the given name.
func (p *Provider) CreateStore(name string) error {
	p.mux.Lock()

	if p.dbPrefix != "" {
		name = p.dbPrefix + "_" + name
	}

	err := p.couchDBClient.CreateDB(context.Background(), name)

	p.mux.Unlock()

	if err != nil && err.Error() == "Precondition Failed: The database could not be created, the file already exists." {
		return storage.ErrDuplicateStore
	}

	return err
}

// OpenStore opens an existing store with the given name and returns it.
func (p *Provider) OpenStore(name string) (storage.Store, error) {
	p.mux.Lock()
	defer p.mux.Unlock()

	if p.dbPrefix != "" {
		name = p.dbPrefix + "_" + name
	}

	// Check cache first
	cachedStore, existsInCache := p.dbs[name]
	if existsInCache {
		return cachedStore, nil
	}

	// If it's not in the cache, then let's ask the CouchDB server if it exists
	existsOnServer, err := p.couchDBClient.DBExists(context.Background(), name)
	if err != nil {
		return nil, err
	}

	if !existsOnServer {
		return nil, storage.ErrStoreNotFound
	}

	db := p.couchDBClient.DB(context.Background(), name)

	// db.Err() won't return an error if the database doesn't exist, hence the need for the explicit DBExists call above
	if dbErr := db.Err(); dbErr != nil {
		return nil, dbErr
	}

	store := &CouchDBStore{db: db}

	p.dbs[name] = store

	return store, nil
}

// CloseStore closes a previously opened store.
func (p *Provider) CloseStore(name string) error {
	p.mux.Lock()
	defer p.mux.Unlock()

	if p.dbPrefix != "" {
		name = p.dbPrefix + "_" + name
	}

	store, exists := p.dbs[name]
	if !exists {
		return storage.ErrStoreNotFound
	}

	delete(p.dbs, name)

	return store.db.Close(context.Background())
}

// Close closes the provider.
func (p *Provider) Close() error {
	p.mux.Lock()
	defer p.mux.Unlock()

	for _, store := range p.dbs {
		err := store.db.Close(context.Background())
		if err != nil {
			return fmt.Errorf(failToCloseProviderErrMsg+": %w", err)
		}
	}

	return p.couchDBClient.Close(context.Background())
}

// CouchDBStore represents a CouchDB-backed database.
type CouchDBStore struct {
	db *kivik.DB
}

// Put stores the given key-value pair in the store.
func (c *CouchDBStore) Put(k string, v []byte) error {
	var valueToPut []byte
	if isJSON(v) {
		valueToPut = v
	} else {
		valueToPut = wrapTextAsCouchDBAttachment(v)
	}

	revID, err := c.getRevID(k)
	if err != nil {
		return err
	}

	if revID != "" {
		valueToPut, err = c.addRevID(valueToPut, revID)
		if err != nil {
			return err
		}
	}

	_, err = c.db.Put(context.Background(), k, valueToPut)
	if err != nil {
		return fmt.Errorf("failed to store data: %w", err)
	}

	return nil
}

func isJSON(textToCheck []byte) bool {
	var js map[string]interface{}
	return json.Unmarshal(textToCheck, &js) == nil
}

// Kivik has a PutAttachment method, but it requires creating a document first and then adding an attachment after.
// We want to do it all in one step, hence this manual stuff below.
func wrapTextAsCouchDBAttachment(textToWrap []byte) []byte {
	encodedTextToWrap := base64.StdEncoding.EncodeToString(textToWrap)
	return []byte(`{"_attachments": {"data": {"data": "` + encodedTextToWrap + `", "content_type": "text/plain"}}}`)
}

// Get retrieves the value in the store associated with the given key.
func (c *CouchDBStore) Get(k string) ([]byte, error) {
	rawDoc, err := c.getRawDoc(k)
	if err != nil {
		return nil, err
	}

	return c.getStoredValueFromRawDoc(rawDoc, k)
}

func (c *CouchDBStore) addRevID(valueToPut []byte, revID string) ([]byte, error) {
	var m map[string]interface{}
	if err := json.Unmarshal(valueToPut, &m); err != nil {
		return nil, fmt.Errorf("failed to unmarshal put value: %w", err)
	}

	m["_rev"] = revID

	newValue, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal put value: %w", err)
	}

	return newValue, nil
}

// get rev ID
func (c *CouchDBStore) getRevID(k string) (string, error) {
	rawDoc := make(map[string]interface{})

	row := c.db.Get(context.Background(), k)

	err := row.ScanDoc(&rawDoc)
	if err != nil {
		if strings.Contains(err.Error(), couchDBNotFoundErr) {
			return "", nil
		}

		return "", err
	}

	return rawDoc["_rev"].(string), nil
}

// CreateIndex creates an index based on the provided CreateIndexRequest.
// createIndexRequest.IndexStorageLocation refers to the design doc that the index should get placed in.
// createIndexRequest.IndexName is the name for the index that will be stored in CouchDB.
// createIndexRequest.WhatToIndex must be a valid index object as defined here:
//   http://docs.couchdb.org/en/stable/api/database/find.html#db-index
func (c *CouchDBStore) CreateIndex(createIndexRequest storage.CreateIndexRequest) error {
	return c.db.CreateIndex(context.Background(), createIndexRequest.IndexStorageLocation,
		createIndexRequest.IndexName, createIndexRequest.WhatToIndex)
}

// Query executes a query using the CouchDB _find endpoint.
func (c *CouchDBStore) Query(findQuery string) (storage.ResultsIterator, error) {
	resultRows, err := c.db.Find(context.Background(), findQuery)
	if err != nil {
		return nil, err
	}

	return &couchDBResultsIterator{store: c, resultRows: resultRows}, nil
}

// Delete deletes the key-value pair associated with k.
func (c *CouchDBStore) Delete(k string) error {
	revString, err := c.getRevision(k)
	if err != nil {
		return fmt.Errorf(storage.DeleteFailureErrMsg, err)
	}

	_, err = c.db.Delete(context.Background(), k, revString)
	if err != nil {
		return fmt.Errorf(storage.DeleteFailureErrMsg, err)
	}

	return nil
}

type couchDBResultsIterator struct {
	store      *CouchDBStore
	resultRows *kivik.Rows
}

// Next moves the pointer to the next value in the iterator. It returns false if the iterator is exhausted.
// Note that the Kivik library automatically closes the kivik.Rows iterator if the iterator is exhaused.
func (i *couchDBResultsIterator) Next() (bool, error) {
	nextCallResult := i.resultRows.Next()

	// Kivik only guarantees that this value will be set after all the rows have been iterated through.
	warningMsg := i.resultRows.Warning()

	if warningMsg != "" {
		logger.Warnf(warningMsg)
	}

	return nextCallResult, i.resultRows.Err()
}

// Release releases associated resources. Release should always result in success
// and can be called multiple times without causing an error.
func (i *couchDBResultsIterator) Release() error {
	return i.resultRows.Close()
}

// Key returns the key of the current key-value pair.
func (i *couchDBResultsIterator) Key() (string, error) {
	key := i.resultRows.Key()
	if key != "" {
		// The returned key is a raw JSON string. It needs to be unescaped:
		return strconv.Unquote(key)
	}

	return key, nil
}

// Value returns the value of the current key-value pair.
func (i *couchDBResultsIterator) Value() ([]byte, error) {
	rawDoc := make(map[string]interface{})

	err := i.resultRows.ScanDoc(&rawDoc)

	if err != nil {
		return nil, err
	}

	key, err := i.Key()
	if err != nil {
		return nil, err
	}

	return i.store.getStoredValueFromRawDoc(rawDoc, key)
}

func (c *CouchDBStore) getStoredValueFromRawDoc(rawDoc map[string]interface{}, k string) ([]byte, error) {
	_, containsAttachment := rawDoc["_attachments"]
	if containsAttachment {
		return c.getDataFromAttachment(k)
	}

	// Strip out the CouchDB-specific fields
	delete(rawDoc, "_id")
	delete(rawDoc, "_rev")

	strippedJSON, err := json.Marshal(rawDoc)
	if err != nil {
		return nil, err
	}

	return strippedJSON, nil
}

func (c *CouchDBStore) getRevision(k string) (string, error) {
	rawDoc, err := c.getRawDoc(k)
	if err != nil {
		return "", fmt.Errorf(getRevisionFailureErrMsg, err)
	}

	rev, containsRev := rawDoc["_rev"]
	if !containsRev {
		return "", fmt.Errorf(getRevisionFailureErrMsg, errMissingRevisionField)
	}

	revString, ok := rev.(string)
	if !ok {
		return "", fmt.Errorf(getRevisionFailureErrMsg, errFailToAssertRevAsString)
	}

	return revString, nil
}

func (c *CouchDBStore) getRawDoc(k string) (map[string]interface{}, error) {
	rawDoc := make(map[string]interface{})

	row := c.db.Get(context.Background(), k)

	err := row.ScanDoc(&rawDoc)
	if err != nil {
		if strings.Contains(err.Error(), couchDBNotFoundErr) {
			return nil, fmt.Errorf(getRawDocFailureErrMsg, storage.ErrValueNotFound)
		}

		return nil, fmt.Errorf(getRawDocFailureErrMsg, err)
	}

	return rawDoc, nil
}

func (c *CouchDBStore) getDataFromAttachment(k string) ([]byte, error) {
	attachment, err := c.db.GetAttachment(context.Background(), k, "data")
	if err != nil {
		return nil, err
	}

	data, err := ioutil.ReadAll(attachment.Content)
	if err != nil {
		return nil, err
	}

	return data, nil
}
