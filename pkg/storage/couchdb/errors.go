/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package couchdbstore

import "errors"

const (
	// Error messages we return.
	couchDBNotReadyErrMsg = "couchDB '_users' DB does not yet exist - CouchDB might " +
		"not be fully initialized"
	failToProbeUsersDB                                 = "failure while probing couchDB for '_users' DB: %w"
	failToPingCouchDB                                  = "failure while pinging couchDB: %w"
	failToInstantiateKivikClientErrMsg                 = "failure while instantiate Kivik CouchDB client: %w"
	dbExistsCheckFailure                               = "failure while checking if the database exists: %w"
	failureDuringCouchDBCreateDBCall                   = "failure during CouchDB create DB call: %w"
	failureWhileConnectingToDBErrMsg                   = "failure while connecting to DB: %w"
	failureDuringCouchDBCloseCall                      = "failure during CouchDB close call: %w"
	failureDuringCouchDBPutCall                        = "failure during CouchDB put document call: %w"
	failureWhileClosingKivikClient                     = "failure while closing Kivik CouchDB client: %w"
	failureWhileAddingRevID                            = "failure while adding rev ID: %w"
	failureWhileUnmarshallingPutValue                  = "failure while unmarshalling put value: %w"
	failureWhileMarshallingPutValueWithNewlyAddedRevID = "failure while unmarshalling put value " +
		"with newly added rev ID: %w"
	getRevIDFailureErrMsg                    = "failure while getting rev ID: %w"
	getRawDocFailureErrMsg                   = "failure while getting raw CouchDB document: %w"
	failureDuringCouchDBDeleteCall           = "failure during CouchDB delete document call: %w"
	failureWhileScanningResultRowsDoc        = "failure while scanning result rows doc: %w"
	failureWhileGettingStoredValueFromRawDoc = "failure while getting stored value from raw doc: %w"
	failureWhileMarshallingStrippedDoc       = "failure while marshalling stripped doc: %w"
	failureWhileGettingDataFromAttachment    = "failure while getting data from attachment: %w"
	failureDuringCouchDBGetAttachmentCall    = "failure during CouchDB get attachment call: %w"
	failureWhileReadingAttachmentContent     = "failure while reading attachment content: %w"
	failureDuringIterationOfResultRows       = "failure during iteration of result rows: %w"
	failureWhenClosingResultRows             = "failure when closing result rows: %w"
	failureWhileUnquotingKey                 = "failure while unquoting key: %w"
	failureWhileGettingKeyFromIterator       = "failure while getting key from iterator: %w"
	failureWhileGettingAllDocs               = "failure while getting all docs: %w"
	failureWhileGettingAllKeyValuePairs      = "failure while getting all key-value pairs: %w"

	// Error messages returned from Kivik CouchDB client that we directly check for.
	duplicateDBErrMsgFromKivik = "Precondition Failed: The database could not be created, the file already exists."
	docNotFoundErrMsgFromKivik = "Not Found: missing"
	docDeletedErrMsgFromKivik  = "Not Found: deleted"
)

var (
	errBlankHost                 = errors.New("hostURL for new CouchDB provider can't be blank")
	errMissingRevIDField         = errors.New("the retrieved CouchDB document is missing the _rev field")
	errFailToAssertRevIDAsString = errors.New("failed to assert the retrieved rev ID as a string")
)
