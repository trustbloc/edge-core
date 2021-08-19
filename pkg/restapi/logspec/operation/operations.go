/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/trustbloc/edge-core/pkg/internal/support"
	"github.com/trustbloc/edge-core/pkg/log"
	commhttp "github.com/trustbloc/edge-core/pkg/restapi/internal/common/http"
)

const (
	logSpecEndpoint = "/logspec"

	invalidLogSpec = `Invalid log spec. It needs to be in the following format: ` +
		`ModuleName1=Level1:ModuleName2=Level2:ModuleNameN=LevelN:AllOtherModuleDefaultLevel
Valid log levels: critical,error,warn,info,debug
Error: %s`

	multipleDefaultValues = "multiple default values found"
)

// Handler represents an HTTP handler for each controller API endpoint.
type Handler interface {
	Path() string
	Method() string
	Handle() http.HandlerFunc
}

// StringBuilder represents a type that can build up a string to be used as the response for a get log spec call.
type StringBuilder interface {
	Write(p []byte) (int, error)
	String() string
	Reset()
}

type errorResponse struct {
	Message string `json:"errMessage,omitempty"`
}

type logSpec struct {
	Spec string `json:"spec"`
}

// GetRESTHandlers gets all controller API handlers available for this service.
func GetRESTHandlers() []Handler {
	return []Handler{
		support.NewHTTPHandler(logSpecEndpoint, http.MethodPut, logSpecPutHandler),
		support.NewHTTPHandler(logSpecEndpoint, http.MethodGet, logSpecGetHandler),
	}
}

// Change Log Specification swagger:route PUT /logspec changeLogSpecReq.
//
// Changes the current log specification.
// Format: ModuleName1=Level1:ModuleName2=Level2:ModuleNameN=LevelN:AllOtherModuleDefaultLevel
// Valid log levels: critical,error,warn,info,debug
//
// Note that this will not work properly if a module name contains an '=' character.
//
// Responses:
//    default: genericError
//        200: emptyRes
func logSpecPutHandler(rw http.ResponseWriter, req *http.Request) {
	changeLogSpec(rw, req)
}

// Get Current Log Specification swagger:route GET /logspec getLogSpecReq
//
// Gets the current log specification.
// Format: ModuleName1=Level1:ModuleName2=Level2:ModuleNameN=LevelN:AllOtherModuleDefaultLevel
//
// Responses:
//    default: emptyRes
//        200: getLogSpecRes
func logSpecGetHandler(rw http.ResponseWriter, _ *http.Request) {
	getLogSpec(rw)
}

func changeLogSpec(rw http.ResponseWriter, req *http.Request) {
	var incomingLogSpec logSpec

	err := json.NewDecoder(req.Body).Decode(&incomingLogSpec)
	if err != nil {
		commhttp.WriteErrorResponse(rw, http.StatusBadRequest, fmt.Sprintf(invalidLogSpec, err))

		return
	}

	err = log.SetSpec(incomingLogSpec.Spec)
	if err != nil {
		commhttp.WriteErrorResponse(rw, http.StatusBadRequest, fmt.Sprintf(invalidLogSpec, err))

		return
	}
}

func getLogSpec(rw http.ResponseWriter) {
	commhttp.WriteResponse(rw, logSpec{Spec: log.GetSpec()})
}
