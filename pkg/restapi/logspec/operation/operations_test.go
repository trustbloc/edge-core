/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation // nolint:testpackage // references internal implementation details

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/edge-core/pkg/log"
)

const testLogSpec = `{"spec":"module1=debug:module2=critical:error"}`

func TestLogSpecPut(t *testing.T) {
	t.Run("Successfully set logging levels", func(t *testing.T) {
		resetLoggingLevels()

		// nolint:noctx // context not required for tests
		req, err := http.NewRequest(http.MethodPut, "", bytes.NewBuffer([]byte(testLogSpec)))
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		logSpecPutHandler(rr, req)

		require.Equal(t, http.StatusOK, rr.Code)

		require.Equal(t, log.DEBUG, log.GetLevel("module1"))
		require.Equal(t, log.CRITICAL, log.GetLevel("module2"))
		require.Equal(t, log.ERROR, log.GetLevel(""))
	})
	t.Run("Empty request body", func(t *testing.T) {
		resetLoggingLevels()

		// nolint:noctx // context not required for tests
		req, err := http.NewRequest(http.MethodPut, "", bytes.NewBuffer(nil))
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		changeLogSpec(rr, req)
		require.Equal(t, http.StatusBadRequest, rr.Code)

		var response errorResponse

		err = json.Unmarshal(rr.Body.Bytes(), &response)
		require.NoError(t, err)

		require.Equal(t, fmt.Sprintf(invalidLogSpec, "EOF"), response.Message)

		// Log levels should remain at the default setting of "info"
		require.Equal(t, log.INFO, log.GetLevel("module1"))
		require.Equal(t, log.INFO, log.GetLevel("module1"))
		require.Equal(t, log.INFO, log.GetLevel(""))
	})
	t.Run("Invalid log spec: default log level type is invalid", func(t *testing.T) {
		resetLoggingLevels()

		req, err := http.NewRequest(http.MethodPut, "", bytes.NewBuffer([]byte(`{"spec":"InvalidLogLevel"}`)))
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		changeLogSpec(rr, req)

		require.Equal(t, http.StatusBadRequest, rr.Code)

		var response errorResponse

		err = json.Unmarshal(rr.Body.Bytes(), &response)
		require.NoError(t, err)

		require.Equal(t, fmt.Sprintf(invalidLogSpec, "logger: invalid log level"), response.Message)

		// Log levels should remain at the default setting of "info"
		require.Equal(t, log.INFO, log.GetLevel("module1"))
		require.Equal(t, log.INFO, log.GetLevel("module2"))
		require.Equal(t, log.INFO, log.GetLevel(""))
	})
	t.Run("Invalid log spec: module log level type is invalid", func(t *testing.T) {
		resetLoggingLevels()

		req, err := http.NewRequest(http.MethodPut, "",
			bytes.NewBuffer([]byte(`{"spec":"Module1=InvalidLogLevel"}`)))
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		changeLogSpec(rr, req)

		require.Equal(t, http.StatusBadRequest, rr.Code)

		var response errorResponse

		err = json.Unmarshal(rr.Body.Bytes(), &response)
		require.NoError(t, err)

		require.Equal(t, fmt.Sprintf(invalidLogSpec, "logger: invalid log level"), response.Message)

		// Log levels should remain at the default setting of "info"
		require.Equal(t, log.INFO, log.GetLevel("module1"))
		require.Equal(t, log.INFO, log.GetLevel("module2"))
		require.Equal(t, log.INFO, log.GetLevel(""))
	})
	t.Run("Invalid log spec: multiple default log levels", func(t *testing.T) {
		resetLoggingLevels()

		// nolint:noctx // context not required for tests
		req, err := http.NewRequest(http.MethodPut, "", bytes.NewBuffer([]byte(`{"spec":"debug:debug"}`)))
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		changeLogSpec(rr, req)

		var response errorResponse

		err = json.Unmarshal(rr.Body.Bytes(), &response)
		require.NoError(t, err)

		require.Equal(t, fmt.Sprintf(invalidLogSpec, multipleDefaultValues), response.Message)

		// Log levels should remain at the default setting of "info"
		require.Equal(t, log.INFO, log.GetLevel("module1"))
		require.Equal(t, log.INFO, log.GetLevel("module2"))
		require.Equal(t, log.INFO, log.GetLevel(""))
	})
}

func TestLogSpecGet(t *testing.T) {
	t.Run("Successfully get logging levels", func(t *testing.T) {
		resetLoggingLevels()

		rr := httptest.NewRecorder()

		logSpecGetHandler(rr, nil)

		require.Equal(t, http.StatusOK, rr.Code)

		var logSpecResponse logSpec
		err := json.Unmarshal(rr.Body.Bytes(), &logSpecResponse)
		require.NoError(t, err)

		// The two expected strings below are equivalent. Depending on the order of the entries
		//  in the underlying log levels map, either is a possible (and valid) result.
		gotExpectedLevels := logSpecResponse.Spec == "module1=INFO:module2=INFO:INFO" ||
			logSpecResponse.Spec == "module2=INFO:module1=INFO:INFO"
		require.True(t, gotExpectedLevels)
	})
}

func resetLoggingLevels() {
	log.SetLevel("module1", log.INFO)
	log.SetLevel("module2", log.INFO)
	log.SetLevel("", log.INFO)
}
