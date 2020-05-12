/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package retry

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

var errTest = errors.New("sample error")

func TestRetry(t *testing.T) {
	t.Run("Success - first attempt - no retries", func(t *testing.T) {
		funcTester := retryFuncTester{}

		params := Params{}

		err := Retry(funcTester.testRetryFunc, &params)
		require.NoError(t, err)
	})
	t.Run("Success on the second retry", func(t *testing.T) {
		funcTester := retryFuncTester{retriesBeforeSuccess: 2}

		params := Params{MaxRetries: 2}

		err := Retry(funcTester.testRetryFunc, &params)
		require.NoError(t, err)
	})
	t.Run("All retries exhausted", func(t *testing.T) {
		funcTester := retryFuncTester{retriesBeforeSuccess: 3}

		params := Params{MaxRetries: 2}

		err := Retry(funcTester.testRetryFunc, &params)
		require.Equal(t, err, errTest)
	})
}

type retryFuncTester struct {
	retryCount           int
	retriesBeforeSuccess int
}

func (r *retryFuncTester) testRetryFunc() error {
	if r.retryCount == r.retriesBeforeSuccess {
		return nil
	}

	r.retryCount++

	return errTest
}
