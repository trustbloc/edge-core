/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package retry_test

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/edge-core/pkg/utils/retry"
)

var errTest = errors.New("sample error")

func TestRetry(t *testing.T) {
	t.Run("Success - first attempt - no retries", func(t *testing.T) {
		funcTester := retryFuncTester{}

		params := retry.Params{}

		err := retry.Retry(funcTester.testRetryFunc, &params)
		require.NoError(t, err)
	})
	t.Run("Success on the second retry", func(t *testing.T) {
		funcTester := retryFuncTester{retriesBeforeSuccess: 2}

		params := retry.Params{MaxRetries: 2}

		err := retry.Retry(funcTester.testRetryFunc, &params)
		require.NoError(t, err)
	})
	t.Run("All retries exhausted", func(t *testing.T) {
		funcTester := retryFuncTester{retriesBeforeSuccess: 3}

		params := retry.Params{MaxRetries: 2}

		err := retry.Retry(funcTester.testRetryFunc, &params)
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
