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
	"io"
	"io/ioutil"
	"strconv"
	"strings"
	"sync"

	_ "github.com/go-kivik/couchdb" // The CouchDB driver
	"github.com/go-kivik/kivik"
	"github.com/go-kivik/kivik/driver"

	"github.com/trustbloc/edge-core/pkg/log"
	"github.com/trustbloc/edge-core/pkg/storage"
)

const (
	logModuleName = "edge-core-couchdbstore"

	designDocumentFilteredOutLogMsg = "Getting all documents from a CouchDB store. " +
		"A document with id %s was filtered out since it's a CouchDB design document."
)

var logger = log.New(logModuleName)

type marshalFunc func(interface{}) ([]byte, error)
type readAllFunc func(io.Reader) ([]byte, error)
type unquoteFunc func(string) (string, error)

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
		return nil, errBlankHost
	}

	client, err := kivik.New("couch", hostURL)
	if err != nil {
		return nil, fmt.Errorf(failToInstantiateKivikClientErrMsg, err)
	}

	err = pingCouchDB(client)
	if err != nil {
		return nil, fmt.Errorf(failToPingCouchDB, err)
	}

	p := &Provider{hostURL: hostURL, couchDBClient: client, dbs: map[string]*CouchDBStore{}}

	for _, opt := range opts {
		opt(p)
	}

	return p, nil
}

func pingCouchDB(pinger driver.Pinger) error {
	ready, err := pinger.Ping(context.Background())
	if err != nil {
		return err
	}

	if !ready {
		return errors.New(dbNotReadyErrMsg)
	}

	return nil
}

// CreateStore creates a new store with the given name.
func (p *Provider) CreateStore(name string) error {
	p.mux.Lock()

	if p.dbPrefix != "" {
		name = p.dbPrefix + "_" + name
	}

	err := p.couchDBClient.CreateDB(context.Background(), name)

	p.mux.Unlock()

	if err != nil {
		if err.Error() == duplicateDBErrMsgFromKivik {
			// Replace CouchDB "duplicate DB" error message with our own
			// generic error that can checked for with errors.Is()
			return fmt.Errorf(failureDuringCouchDBCreateDBCall, storage.ErrDuplicateStore)
		}

		return fmt.Errorf(failureDuringCouchDBCreateDBCall, err)
	}

	return nil
}

// OpenStore opens an existing store with the given name and returns it.
// If the store has been previously opened, it will be returned it from the local cache.
// Note that if the underlying database was deleted by an external force, (i.e. not by using the CloseStore() method)
// then this local cache will be invalid. To make it valid again, either a new Provider object needs to be created,
// or Provider.CreateStore() needs to be called again with the same store name. TODO address this: #51
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
		return nil, fmt.Errorf(dbExistsCheckFailure, err)
	}

	if !existsOnServer {
		return nil, storage.ErrStoreNotFound
	}

	db := p.couchDBClient.DB(context.Background(), name)

	// db.Err() won't return an error if the database doesn't exist, hence the need for the explicit DBExists call above
	if dbErr := db.Err(); dbErr != nil {
		return nil, fmt.Errorf(failureWhileConnectingToDBErrMsg, dbErr)
	}

	store := &CouchDBStore{db: db, marshal: json.Marshal, readAll: ioutil.ReadAll, unquote: strconv.Unquote}

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

	err := store.db.Close(context.Background())
	if err != nil {
		return fmt.Errorf(failureDuringCouchDBCloseCall, err)
	}

	return nil
}

// Close closes the provider.
func (p *Provider) Close() error {
	p.mux.Lock()
	defer p.mux.Unlock()

	for _, store := range p.dbs {
		err := store.db.Close(context.Background())
		if err != nil {
			return fmt.Errorf(failureDuringCouchDBCloseCall, err)
		}
	}

	err := p.couchDBClient.Close(context.Background())
	if err != nil {
		return fmt.Errorf(failureWhileClosingKivikClient, err)
	}

	return nil
}

// CouchDBStore represents a CouchDB-backed database.
type CouchDBStore struct {
	db      *kivik.DB
	marshal marshalFunc
	readAll readAllFunc
	unquote unquoteFunc
}

// Put stores the given key-value pair in the store.
// If an existing document is found, it will be overwritten.
func (c *CouchDBStore) Put(k string, v []byte) error {
	var valueToPut []byte
	if isJSON(v) {
		valueToPut = v
	} else {
		valueToPut = wrapTextAsCouchDBAttachment(v)
	}

	revID, err := c.getRevID(k)
	if err != nil && !errors.Is(err, storage.ErrValueNotFound) &&
		!strings.Contains(err.Error(), docDeletedErrMsgFromKivik) {
		return fmt.Errorf(getRevIDFailureErrMsg, err)
	}

	if revID != "" {
		valueToPut, err = c.addRevID(valueToPut, revID)
		if err != nil {
			return fmt.Errorf(failureWhileAddingRevID, err)
		}
	}

	_, err = c.db.Put(context.Background(), k, valueToPut)
	if err != nil {
		return fmt.Errorf(failureDuringCouchDBPutCall, err)
	}

	return nil
}

// GetAll fetches all the key-value pairs within this store.
// TODO: #61 Add support for pagination
func (c *CouchDBStore) GetAll() (map[string][]byte, error) {
	rows, err := c.db.AllDocs(context.Background(), kivik.Options{"include_docs": true})
	if err != nil {
		return nil, fmt.Errorf(failureWhileGettingAllDocs, err)
	}

	allKeyValuePairs, err := c.getAllKeyValuePairs(rows)
	if err != nil {
		return nil, fmt.Errorf(failureWhileGettingAllKeyValuePairs, err)
	}

	return allKeyValuePairs, nil
}

// Get retrieves the value in the store associated with the given key.
func (c *CouchDBStore) Get(k string) ([]byte, error) {
	rawDoc, err := c.getRawDoc(k)
	if err != nil {
		return nil, fmt.Errorf(getRawDocFailureErrMsg, err)
	}

	value, err := c.getStoredValueFromRawDoc(rawDoc, k)
	if err != nil {
		return nil, fmt.Errorf(failureWhileGettingStoredValueFromRawDoc, err)
	}

	return value, nil
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
	revString, err := c.getRevID(k)
	if err != nil {
		return fmt.Errorf(getRevIDFailureErrMsg, err)
	}

	_, err = c.db.Delete(context.Background(), k, revString)
	if err != nil {
		return fmt.Errorf(failureDuringCouchDBDeleteCall, err)
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

	err := i.resultRows.Err()
	if err != nil {
		return nextCallResult, fmt.Errorf(failureDuringIterationOfResultRows, err)
	}

	return nextCallResult, nil
}

// Release releases associated resources. Release should always result in success
// and can be called multiple times without causing an error.
func (i *couchDBResultsIterator) Release() error {
	err := i.resultRows.Close()
	if err != nil {
		return fmt.Errorf(failureWhenClosingResultRows, err)
	}

	return nil
}

// Key returns the key of the current key-value pair.
// A nil error likely means that the key list is exhausted.
func (i *couchDBResultsIterator) Key() (string, error) {
	key := i.resultRows.Key()
	if key != "" {
		// The returned key is a raw JSON string. It needs to be unescaped:
		str, err := strconv.Unquote(key)
		if err != nil {
			return "", fmt.Errorf(failureWhileUnquotingKey, err)
		}

		return str, nil
	}

	return "", nil
}

// Value returns the value of the current key-value pair.
func (i *couchDBResultsIterator) Value() ([]byte, error) {
	rawDoc := make(map[string]interface{})

	err := i.resultRows.ScanDoc(&rawDoc)
	if err != nil {
		return nil, fmt.Errorf(failureWhileScanningResultRowsDoc, err)
	}

	key, err := i.Key()
	if err != nil {
		return nil, fmt.Errorf(failureWhileGettingKeyFromIterator, err)
	}

	value, err := i.store.getStoredValueFromRawDoc(rawDoc, key)
	if err != nil {
		return nil, fmt.Errorf(failureWhileGettingStoredValueFromRawDoc, err)
	}

	return value, nil
}

func (c *CouchDBStore) getAllKeyValuePairs(rows *kivik.Rows) (map[string][]byte, error) {
	allKeyValuePairs := make(map[string][]byte)

	for rows.Next() {
		key := rows.Key()
		// The returned key is a raw JSON string. It needs to be unescaped:
		key, err := c.unquote(key)
		if err != nil {
			return nil, fmt.Errorf(failureWhileUnquotingKey, err)
		}

		if strings.HasPrefix(key, "_design") {
			logger.Debugf(designDocumentFilteredOutLogMsg, key)
		} else {
			rawDoc := make(map[string]interface{})

			err = rows.ScanDoc(&rawDoc)
			if err != nil {
				return nil, fmt.Errorf(failureWhileScanningResultRowsDoc, err)
			}

			documentBytes, err := c.getStoredValueFromRawDoc(rawDoc, key)
			if err != nil {
				return nil, fmt.Errorf(failureWhileGettingStoredValueFromRawDoc, err)
			}

			allKeyValuePairs[key] = documentBytes
		}
	}

	return allKeyValuePairs, nil
}

func (c *CouchDBStore) getStoredValueFromRawDoc(rawDoc map[string]interface{}, k string) ([]byte, error) {
	_, containsAttachment := rawDoc["_attachments"]
	if containsAttachment {
		data, err := c.getDataFromAttachment(k)
		if err != nil {
			return nil, fmt.Errorf(failureWhileGettingDataFromAttachment, err)
		}

		return data, nil
	}

	// Strip out the CouchDB-specific fields
	delete(rawDoc, "_id")
	delete(rawDoc, "_rev")

	strippedJSON, err := c.marshal(rawDoc)
	if err != nil {
		return nil, fmt.Errorf(failureWhileMarshallingStrippedDoc, err)
	}

	return strippedJSON, nil
}

func (c *CouchDBStore) getRawDoc(k string) (map[string]interface{}, error) {
	rawDoc := make(map[string]interface{})

	row := c.db.Get(context.Background(), k)

	err := row.ScanDoc(&rawDoc)
	if err != nil {
		if strings.Contains(err.Error(), docNotFoundErrMsgFromKivik) {
			return nil, fmt.Errorf(failureWhileScanningResultRowsDoc, storage.ErrValueNotFound)
		}

		return nil, fmt.Errorf(failureWhileScanningResultRowsDoc, err)
	}

	return rawDoc, nil
}

func (c *CouchDBStore) getRevID(k string) (string, error) {
	rawDoc, err := c.getRawDoc(k)
	if err != nil {
		return "", fmt.Errorf(getRawDocFailureErrMsg, err)
	}

	revID, containsRevID := rawDoc["_rev"]
	if !containsRevID {
		return "", errMissingRevIDField
	}

	revIDString, ok := revID.(string)
	if !ok {
		return "", errFailToAssertRevIDAsString
	}

	return revIDString, nil
}

func (c *CouchDBStore) getDataFromAttachment(k string) ([]byte, error) {
	attachment, err := c.db.GetAttachment(context.Background(), k, "data")
	if err != nil {
		return nil, fmt.Errorf(failureDuringCouchDBGetAttachmentCall, err)
	}

	data, err := c.readAll(attachment.Content)
	if err != nil {
		return nil, fmt.Errorf(failureWhileReadingAttachmentContent, err)
	}

	return data, nil
}

func (c *CouchDBStore) addRevID(valueToPut []byte, revID string) ([]byte, error) {
	var m map[string]interface{}
	if err := json.Unmarshal(valueToPut, &m); err != nil {
		return nil, fmt.Errorf(failureWhileUnmarshallingPutValue, err)
	}

	m["_rev"] = revID

	newValue, err := c.marshal(m)
	if err != nil {
		return nil, fmt.Errorf(failureWhileMarshallingPutValueWithNewlyAddedRevID, err)
	}

	return newValue, nil
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
