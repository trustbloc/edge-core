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
	"sync"

	_ "github.com/go-kivik/couchdb" // The CouchDB driver
	"github.com/go-kivik/kivik"

	"github.com/trustbloc/edge-core/pkg/storage"
)

// Provider represents an CouchDB implementation of the storage.Provider interface
type Provider struct {
	hostURL       string
	couchDBClient *kivik.Client
	dbs           map[string]*CouchDBStore
	mux           sync.RWMutex
}

const (
	blankHostErrMsg           = "hostURL for new CouchDB provider can't be blank"
	failToCloseProviderErrMsg = "failed to close provider"
)

// NewProvider instantiates Provider
func NewProvider(hostURL string) (*Provider, error) {
	if hostURL == "" {
		return nil, errors.New(blankHostErrMsg)
	}

	client, err := kivik.New("couch", hostURL)
	if err != nil {
		return nil, err
	}

	return &Provider{hostURL: hostURL, couchDBClient: client, dbs: map[string]*CouchDBStore{}}, nil
}

// CreateStore creates a new store with the given name.
func (p *Provider) CreateStore(name string) error {
	p.mux.Lock()
	defer p.mux.Unlock()

	err := p.couchDBClient.CreateDB(context.Background(), name)

	return err
}

// OpenStore opens an existing store with the given name and returns it.
func (p *Provider) OpenStore(name string) (storage.Store, error) {
	p.mux.Lock()
	defer p.mux.Unlock()

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

	_, err := c.db.Put(context.Background(), k, valueToPut)
	if err != nil {
		return err
	}

	return nil
}

func isJSON(textToCheck []byte) bool {
	var js json.RawMessage
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
	destinationData := make(map[string]interface{})

	row := c.db.Get(context.Background(), k)

	err := row.ScanDoc(&destinationData)
	if err != nil {
		if err.Error() == "Not Found: missing" {
			return nil, storage.ErrValueNotFound
		}

		return nil, err
	}

	_, containsAttachment := destinationData["_attachments"]
	if containsAttachment {
		return c.getDataFromAttachment(k)
	}

	// Stripping out the CouchDB-specific fields
	delete(destinationData, "_id")
	delete(destinationData, "_rev")

	strippedJSON, err := json.Marshal(destinationData)
	if err != nil {
		return nil, err
	}

	return strippedJSON, nil
}

func (c *CouchDBStore) getDataFromAttachment(k string) ([]byte, error) {
	// Original data was not JSON and so it was stored as an attachment
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
