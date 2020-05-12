/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package retry

import (
	"time"
)

// Params are used to define how retry attempts are handled.
type Params struct {
	MaxRetries     uint
	InitialBackoff time.Duration
	BackoffFactor  float64
}

// Invocation represents a function that is desired to be retried until it succeeds (i.e. it returns nil).
type Invocation func() error

// Retry retries the given Invocation based on the given Params until it returns no error, at which point this
// function returns no error as well.
// If the retry attempts are exhausted, this function returns the most recent error returned from the given Invocation.
func Retry(invocation Invocation, params *Params) error {
	var err error

	backoff := params.InitialBackoff

	// There is always a mandatory initial attempt at running funcToRetry.
	// The delays only start if this attempt failed and params.MaxRetries is at least 1.
	for retries := uint(0); retries <= params.MaxRetries; retries++ {
		if retries != 0 {
			time.Sleep(backoff)
		}

		err = invocation()
		if err == nil {
			return nil
		}

		if retries != 0 && retries < params.MaxRetries {
			backoff = time.Duration(float64(backoff) * params.BackoffFactor)
		}
	}

	return err
}
