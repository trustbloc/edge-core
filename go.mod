// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/trustbloc/edge-core

go 1.13

require (
	github.com/cenkalti/backoff v2.2.1+incompatible
	github.com/flimzy/diff v0.1.7 // indirect
	github.com/flimzy/testy v0.1.17 // indirect
	github.com/go-kivik/couchdb v2.0.0+incompatible
	github.com/go-kivik/kivik v2.0.0+incompatible
	github.com/go-kivik/kiviktest v2.0.0+incompatible // indirect
	github.com/go-sql-driver/mysql v1.5.0
	github.com/google/uuid v1.1.2
	github.com/gopherjs/gopherjs v0.0.0-20200217142428-fce0ec30dd00 // indirect
	github.com/hashicorp/vault v1.2.1-0.20200911125421-dba37adcb55a
	github.com/hyperledger/aries-framework-go v0.1.5-0.20201120141223-c70cf578d36b
	github.com/igor-pavlenko/httpsignatures-go v0.0.21
	github.com/piprate/json-gold v0.3.0
	github.com/spf13/cobra v0.0.6
	github.com/stretchr/testify v1.6.1
	gitlab.com/flimzy/testy v0.2.1 // indirect
)

replace github.com/kilic/bls12-381 => github.com/trustbloc/bls12-381 v0.0.0-20201104214312-31de2a204df8
