/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

// emptyRes model
//
// swagger:response emptyRes
type emptyRes struct { // nolint:unused,deadcode // struct used only to generate openapi spec
}

// changeLogSpecReq model
//
// swagger:parameters changeLogSpecReq
type changeLogSpecReq struct { // nolint:unused,deadcode // struct used only to generate openapi spec
	// in: body
	Body struct {
		// The new log specification
		//
		// Required: true
		// Example: module1=debug:module2=critical:error
		Spec string `json:"spec"`
	}
}

// getLogSpecRes model
//
// swagger:response getLogSpecRes
type getLogSpecRes struct { // nolint:unused,deadcode // struct used only to generate openapi spec
	// in: body
	logSpec
}
