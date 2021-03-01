// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/trustbloc/edge-core

go 1.13

require (
	github.com/cenkalti/backoff v2.2.1+incompatible
	github.com/go-kivik/couchdb/v3 v3.2.5
	github.com/go-kivik/kivik/v3 v3.2.3
	github.com/go-sql-driver/mysql v1.5.0
	github.com/google/uuid v1.1.2
	github.com/hashicorp/vault v1.2.1-0.20200911125421-dba37adcb55a
	github.com/hyperledger/aries-framework-go v0.1.6-0.20210301162042-93c9922aa4cf
	github.com/igor-pavlenko/httpsignatures-go v0.0.21
	github.com/piprate/json-gold v0.3.1-0.20201222165305-f4ce31c02ca3
	github.com/spf13/cobra v0.0.6
	github.com/stretchr/testify v1.7.0
	golang.org/x/net v0.0.0-20201202161906-c7110b5ffcbb // indirect
)

replace github.com/kilic/bls12-381 => github.com/trustbloc/bls12-381 v0.0.0-20201104214312-31de2a204df8
