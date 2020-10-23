/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package mysql

import "errors"

const (
	// Error messages we return.
	failureWhileOpeningMySQLConnectionErrMsg        = "failure while opening MySQL connection using url %s: %w"
	failureWhileClosingMySQLConnection              = "failure while closing MySQL DB connection: %w"
	failureWhilePingingMySQLErrMsg                  = "failure while pinging MySQL at url %s : %w"
	failureWhileCreatingDBErrMsg                    = "failure while creating DB %s: %w"
	failureWhileQueryingForTableErrMsg              = "failed to query mysql for existence of table '%s': %w"
	failureStoreDoesNotExistErrMsg                  = "store '%s' does not exist"
	failureWhileCreatingTableErrMsg                 = "failure while creating table %s: %w"
	failureWhileExecutingInsertStatementErrMsg      = "failure while executing insert statement on table %s: %w"
	failureWhileQueryingRowErrMsg                   = "failure while querying row: %w"
	failureWhileGettingIndexesErrMsg                = "failure while getting indexes: %w"
	failureWhileDroppingIndexesErrMsg               = "failure while dropping indexes: %w"
	failureWhilePreparingIndexStatementErrMsg       = "failure while preparing index statement: %w"
	failureWhileExecutingCreateIndexStatementErrMsg = "failure while executing create index statement: %w"
	failureWhileExecutingSelectIndexStatementErrMsg = "failure while executing select index statement: %w"
	failureWhilleScanningRowsErrMsg                 = "failure while scanning rows: %w"
	failureWhileExecutingDropIndexStatementErrMsg   = "failure while executing drop index statement: %w"
	failureWhileQueryDBErrMsg                       = "failure while executing query: %w"
	failureWhileDeleteFromTableErrMsg               = "failure while executing delete statement: %w"
	failureWhileCheckingDeleteResultErrMsg          = "failure while checking delete result: %w"
	failureWhileGettingRowsAffectedErrMsg           = "failure while getting rows affected: %w"
	failureWhileReleasingResultRows                 = "failure to release result rows: %w"

	// Error messages returned from MySQL that we directly check for.
	valueNotFoundErrMsgFromMySQL = "no rows"
)

var (
	errBlankDBPath                 = errors.New("DB URL for new mySQL DB provider can't be blank")
	errBlankStoreName              = errors.New("store name is required")
	errNoRowsAffectedByDeleteQuery = errors.New("key not found (no rows were affected by delete query)")
)
