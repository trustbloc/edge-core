/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package retry

import (
	"errors"
	"fmt"
)

// Shows how to wrap a sample function into an invocation for use with the Retry function.
func Example() {
	var marsWeather string

	fetcher := weatherFetcher{}

	// InitialBackoff and BackoffFactor are set to zero here in order to ensure this example runs quickly,
	// but normally you would want to pick reasonable values.
	retryParams := Params{
		MaxRetries:     5,
		InitialBackoff: 0,
		BackoffFactor:  0,
	}

	err := Retry(func() error {
		var weatherCallErr error
		marsWeather, weatherCallErr = fetcher.getWeatherOnMars()

		return weatherCallErr
	}, &retryParams)
	if err != nil {
		fmt.Println("exhausted all retries. Last error was: " + err.Error())
	}

	fmt.Println(marsWeather)

	// Output: -80 degrees and sunny
}

type weatherFetcher struct {
	timesRun int
}

// A simulated REST API call that you may expect to fail sometimes.
func (w *weatherFetcher) getWeatherOnMars() (string, error) {
	if w.timesRun == 4 {
		return "-80 degrees and sunny", nil
	}

	w.timesRun++

	return "", errors.New("interference from space debris")
}
