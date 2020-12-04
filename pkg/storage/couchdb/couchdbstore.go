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

	// The CouchDB driver.
	_ "github.com/go-kivik/couchdb/v3"
	"github.com/go-kivik/kivik/v3"

	"github.com/trustbloc/edge-core/pkg/log"
	"github.com/trustbloc/edge-core/pkg/storage"
)

const (
	couchDBUsersTable = "_users"

	logModuleName = "edge-core-couchdbstore"

	designDocumentFilteredOutLogMsg = "Getting all documents from a CouchDB store. " +
		"A document with id %s was filtered out since it's a CouchDB design document."

	getBulkKeyNotFound = "no value found for key %s: %w"
)

var logger = log.New(logModuleName)

type (
	marshalFunc func(interface{}) ([]byte, error)
	readAllFunc func(io.Reader) ([]byte, error)
	unquoteFunc func(string) (string, error)
)

// Option configures the couchdb provider.
type Option func(opts *Provider)

// WithDBPrefix option is for adding prefix to db name.
func WithDBPrefix(dbPrefix string) Option {
	return func(opts *Provider) {
		opts.dbPrefix = dbPrefix
	}
}

type kivikClient interface {
	DBExists(ctx context.Context, dbName string, options ...kivik.Options) (bool, error)
}

// Provider represents an CouchDB implementation of the storage.Provider interface.
type Provider struct {
	hostURL       string
	couchDBClient *kivik.Client
	dbs           map[string]*CouchDBStore
	dbPrefix      string
	mux           sync.RWMutex
}

// NewProvider instantiates Provider.
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

func pingCouchDB(client kivikClient) error {
	exists, err := client.DBExists(context.Background(), couchDBUsersTable)
	if err != nil {
		return fmt.Errorf(failToProbeUsersDB, err)
	}

	if !exists {
		return errors.New(couchDBNotReadyErrMsg)
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
// or Provider.CreateStore() needs to be called again with the same store name. TODO address this: #51.
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
	if err != nil && !errors.Is(err, storage.ErrValueNotFound) {
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

// PutBulk stores the key-value pairs in the order given in the array. The end result is equivalent to calling
// Put(k,v) on each key-value pair individually in a loop, but should be faster since this method minimizes REST calls.
// There is one exception to this equivalency referenced above: in order to minimize REST calls, duplicate keys
// are removed (along with their associated values), with only the final one remaining. This means that CouchDB will
// not have any history of those intermediate updates, which it would have had you just used Put(k,v) in a loop.
// TODO (#120): Add an option to preserve CouchDB history (at the expense of speed).
func (c *CouchDBStore) PutBulk(keys []string, values [][]byte) error {
	err := validateKeysAndValues(keys, values)
	if err != nil {
		return err
	}

	// If CouchDB receives the same key multiple times, it will just keep the first change and disregard the rest.
	// We want the opposite behaviour - we need it to only keep the last change and disregard the earlier ones as if
	// they've been overwritten.
	keys, values = removeDuplicatesKeepingOnlyLast(keys, values)

	valuesToPut := make([][]byte, len(keys))

	revIDs, err := c.getRevIDs(keys)
	if err != nil {
		return fmt.Errorf(getRevIDFailureErrMsg, err)
	}

	for i, revID := range revIDs {
		valuesToPut[i], err = c.addIDAndRevID(values[i], keys[i], revID)
		if err != nil {
			return fmt.Errorf(failureWhileAddingRevID, err)
		}
	}

	valuesToPutAsInterfaces := make([]interface{}, len(valuesToPut))
	for i, valueToPut := range valuesToPut {
		valuesToPutAsInterfaces[i] = valueToPut
	}

	_, err = c.db.BulkDocs(context.Background(), valuesToPutAsInterfaces)
	if err != nil {
		return fmt.Errorf(failureWhileDoingBulkDocsCall, err)
	}

	return nil
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

// GetBulk fetches the values associated with the given keys. This method works in an all-or-nothing manner.
// It returns an error if any of the keys don't exist. If even one key is missing, then no values are returned.
// The end result is equivalent to calling Get(k,v) on each key-value pair individually in a loop,
// but should be faster since this method minimizes REST calls as long as the values were stored as JSON instead of
// attachments.
// If values are stored as attachments, then there are still optimizations that could be done - see TODO #124.
func (c *CouchDBStore) GetBulk(keys ...string) ([][]byte, error) {
	if keys == nil {
		return nil, storage.ErrGetBulkKeysStringSliceNil
	}

	rawDocs, err := c.getRawDocs(keys)
	if err != nil {
		return nil, fmt.Errorf(getRawDocsFailureErrMsg, err)
	}

	values, err := c.getStoredValuesFromRawDocs(rawDocs, keys)
	if err != nil {
		return nil, fmt.Errorf(failureWhileGettingStoredValuesFromRawDocs, err)
	}

	return values, nil
}

// GetAll fetches all the key-value pairs within this store.
// TODO: #61 Add support for pagination.
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

// Bookmark returns the bookmark value returned by the CouchDB query, if there is one.
// Use this bookmark to query CouchDB again for the rest of your documents.
// Kivik only sets this value after all result rows have been enumerated through by Next.
// Note that the CouchDB documentation says that the presence of a bookmark doesn't guarantee
// that there are more results. To determine this, instead you should compare the number of results returned
// with the page size requested. If the number of results returned is less than the page size, then there are no more.
// See https://docs.couchdb.org/en/stable/api/database/find.html#pagination for more information.
func (i *couchDBResultsIterator) Bookmark() string {
	return i.resultRows.Bookmark()
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

func (c *CouchDBStore) getStoredValuesFromRawDocs(rawDocs []map[string]interface{}, keys []string) ([][]byte, error) {
	storedValues := make([][]byte, len(keys))

	for i, rawDoc := range rawDocs {
		if rawDoc == nil {
			return nil, fmt.Errorf(getBulkKeyNotFound, keys[i], storage.ErrValueNotFound)
		}

		// CouchDB still returns a raw document is the key has been deleted, so if this is a "deleted" raw document
		// then we need to return the "value not found" error in order to maintain consistent behaviour with
		// other storage implementations.
		isDeleted, containsIsDeleted := rawDoc["_deleted"]
		if containsIsDeleted {
			isDeletedBool, ok := isDeleted.(bool)
			if !ok {
				return nil, errFailToAssertDeletedAsBool
			}

			if isDeletedBool {
				return nil, fmt.Errorf(getBulkKeyNotFound, keys[i], storage.ErrValueNotFound)
			}
		}

		// TODO (#124): The getDataFromAttachment call will do a REST call to the CouchDB server.
		//  We should get all the attachments as once in a bulk REST call.
		_, containsAttachment := rawDoc["_attachments"]
		if containsAttachment {
			data, err := c.getDataFromAttachment(keys[i])
			if err != nil {
				return nil, fmt.Errorf(failureWhileGettingDataFromAttachment, err)
			}

			storedValues[i] = data

			continue
		}

		// Strip out the CouchDB-specific fields
		delete(rawDoc, "_id")
		delete(rawDoc, "_rev")

		strippedJSON, err := c.marshal(rawDoc)
		if err != nil {
			return nil, fmt.Errorf(failureWhileMarshallingStrippedDoc, err)
		}

		storedValues[i] = strippedJSON
	}

	return storedValues, nil
}

func (c *CouchDBStore) getRawDoc(k string) (map[string]interface{}, error) {
	rawDoc := make(map[string]interface{})

	row := c.db.Get(context.Background(), k)

	err := row.ScanDoc(&rawDoc)
	if err != nil {
		if strings.Contains(err.Error(), docNotFoundErrMsgFromKivik) ||
			strings.Contains(err.Error(), docDeletedErrMsgFromKivik) {
			return nil, fmt.Errorf(failureWhileScanningResultRowsDoc, storage.ErrValueNotFound)
		}

		return nil, fmt.Errorf(failureWhileScanningResultRowsDoc, err)
	}

	return rawDoc, nil
}

// getRawDocs returns the raw documents from CouchDB using a bulk REST call.
// If a document is not found, then the raw document will be nil. It is not considered an error.
func (c *CouchDBStore) getRawDocs(keys []string) ([]map[string]interface{}, error) {
	rawDocs := make([]map[string]interface{}, len(keys))

	bulkGetReferences := make([]kivik.BulkGetReference, len(keys))

	for i, key := range keys {
		bulkGetReferences[i].ID = key
	}

	// TODO (#121): See if it's possible to just grab the reference IDs directly instead of pulling down the entire
	// raw documents.
	rows, err := c.db.BulkGet(context.Background(), bulkGetReferences)
	if err != nil {
		return nil, err
	}

	ok := rows.Next()

	if !ok {
		return nil, errors.New("bulk get from CouchDB was unexpectedly empty")
	}

	for i := 0; i < len(rawDocs); i++ {
		err := rows.ScanDoc(&rawDocs[i])
		// In the getRawDoc method, Kivik actually returns a different error message if a document was deleted.
		// When doing a bulk get, instead Kivik doesn't return an error message, and we have to check the "_deleted"
		// field in the raw doc. This is done in the getRevIDs method.
		if err != nil && !strings.Contains(err.Error(), bulkGetDocNotFoundErrMsgFromKivik) {
			return nil, fmt.Errorf(failureWhileScanningResultRowsDoc, err)
		}

		ok := rows.Next()

		// ok is expected to be false on the last doc.
		if i < len(rawDocs)-1 {
			if !ok {
				return nil, errors.New("got fewer docs from CouchDB than expected")
			}
		} else {
			if ok {
				return nil, errors.New("got more docs from CouchDB than expected")
			}
		}
	}

	return rawDocs, nil
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

func (c *CouchDBStore) getRevIDs(keys []string) ([]string, error) {
	rawDocs, err := c.getRawDocs(keys)
	if err != nil {
		return nil, fmt.Errorf(getRawDocsFailureErrMsg, err)
	}

	revIDStrings := make([]string, len(rawDocs))

	for i, rawDoc := range rawDocs {
		if rawDoc == nil {
			continue
		}

		// If we're writing over what is currently a deleted document (from CouchDB's point of view),
		// then we must ensure we don't include a revision ID, otherwise CouchDB keeps the document in a "deleted"
		// state and it won't be retrievable.
		isDeleted, containsIsDeleted := rawDoc["_deleted"]
		if containsIsDeleted {
			isDeletedBool, ok := isDeleted.(bool)
			if !ok {
				return nil, errFailToAssertDeletedAsBool
			}

			if isDeletedBool {
				continue
			}
		}

		revID, containsRevID := rawDoc["_rev"]
		if !containsRevID {
			return nil, errMissingRevIDField
		}

		revIDString, ok := revID.(string)
		if !ok {
			return nil, errFailToAssertRevIDAsString
		}

		revIDStrings[i] = revIDString
	}

	return revIDStrings, nil
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

func (c *CouchDBStore) addIDAndRevID(valueToPut []byte, id, revID string) ([]byte, error) {
	if isJSON(valueToPut) {
		var valueToPutMap map[string]interface{}
		if err := json.Unmarshal(valueToPut, &valueToPutMap); err != nil {
			return nil, fmt.Errorf(failureWhileUnmarshallingPutValue, err)
		}

		valueToPutMap["_id"] = id
		if revID != "" {
			valueToPutMap["_rev"] = revID
		}

		valueWithIDAndRevIDFields, err := json.Marshal(valueToPutMap)
		if err != nil {
			return nil, fmt.Errorf(failureWhileMarshallingPutValueWithNewlyAddedIDAndRevID, err)
		}

		return valueWithIDAndRevIDFields, nil
	}

	return wrapTextAsCouchDBAttachmentWithIDAndRevID(id, revID, valueToPut), nil
}

func validateKeysAndValues(keys []string, values [][]byte) error {
	if keys == nil {
		return storage.ErrNilKeys
	}

	if values == nil {
		return storage.ErrNilValues
	}

	if len(keys) != len(values) {
		return storage.ErrKeysAndValuesDifferentLengths
	}

	for i, key := range keys {
		if key == "" {
			return fmt.Errorf(blankKeyErrMsg, i)
		}
	}

	return nil
}

// Unfortunately there's no computationally fast way of removing an element from a slice while maintaining order.
func removeDuplicatesKeepingOnlyLast(keys []string, values [][]byte) ([]string, [][]byte) {
	indexOfKeyToCheck := len(keys) - 1

	for indexOfKeyToCheck > 0 {
		var indicesToRemove []int

		keyToCheck := keys[indexOfKeyToCheck]
		for i := indexOfKeyToCheck - 1; i >= 0; i-- {
			if keys[i] == keyToCheck {
				indicesToRemove = append(indicesToRemove, i)
			}
		}

		for _, indexToRemove := range indicesToRemove {
			keys = append(keys[:indexToRemove], keys[indexToRemove+1:]...)
			values = append(values[:indexToRemove], values[indexToRemove+1:]...)
		}

		// At this point, we now know that any duplicates of keys[indexOfKeyToCheck] are removed, and only the last
		// instance of it remains.

		// Now we need to check the next key in order to ensure it's unique.
		// If this puts the index out of bounds, then we're done.
		indexOfKeyToCheck = indexOfKeyToCheck - len(indicesToRemove) - 1
	}

	return keys, values
}

func isJSON(textToCheck []byte) bool {
	var js map[string]interface{}

	return json.Unmarshal(textToCheck, &js) == nil
}

// Kivik has a PutAttachment method, but it requires creating a document first and then adding an attachment after.
// We want to do it all in one step, hence this manual stuff below.
// If key is provided, then the returned document will have its _id field set to it, otherwise it's left up to the
// CouchDB server to generate one.
func wrapTextAsCouchDBAttachment(textToWrap []byte) []byte {
	encodedTextToWrap := base64.StdEncoding.EncodeToString(textToWrap)

	return []byte(`{"_attachments":{"data":{"data":"` + encodedTextToWrap + `","content_type":"text/plain"}}}`)
}

// Kivik has a PutAttachment method, but it requires creating a document first and then adding an attachment after.
// We want to do it all in one step, hence this manual stuff below.
// If key is provided, then the returned document will have its _id field set to it, otherwise it's left up to the
// CouchDB server to generate one.
func wrapTextAsCouchDBAttachmentWithIDAndRevID(id, revID string, textToWrap []byte) []byte {
	encodedTextToWrap := base64.StdEncoding.EncodeToString(textToWrap)

	if revID == "" {
		return []byte(`{"_id":"` + id + `","_attachments":{"data":{"data":"` + encodedTextToWrap +
			`","content_type":"text/plain"}}}`)
	}

	return []byte(`{"_id":"` + id + `","_rev":"` + revID + `","_attachments": {"data": {"data": "` +
		encodedTextToWrap + `", "content_type": "text/plain"}}}`)
}
