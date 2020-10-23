/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package httpsig_test

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/edge-core/pkg/httpsig"
)

func TestParseSignatureHeader(t *testing.T) {
	t.Run("5.2.2 parses initial contents", func(t *testing.T) {
		result, err := httpsig.ParseSignatureHeader(`keyId="test-key-b", algorithm="rsa-sha256", ` +
			`created=1402170695, expires=1402170995, ` +
			`headers="(request-target) (created) host date cache-control x-emptyheader x-example", ` +
			`signature="T1l3tWH2cSP31nfuvc3nVaHQ6IAu9YLEXg2pCeEOJETXnlWbgKtBTa"`)
		require.NoError(t, err)
		require.Equal(t, "test-key-b", result.KeyID)
		require.Equal(t, "rsa-sha256", result.Algorithm)
		require.Equal(t, unixTime(t, "1402170695"), result.Created)
		require.Equal(t, unixTime(t, "1402170995"), result.Expires)
		for _, h := range strings.Split("host date cache-control x-emptyheader x-example", " ") {
			require.Contains(t, result.Headers, h)
		}
		require.Equal(t, "T1l3tWH2cSP31nfuvc3nVaHQ6IAu9YLEXg2pCeEOJETXnlWbgKtBTa", result.Signature)
	})

	t.Run("fails on non-defined parameters", func(t *testing.T) {
		_, err := httpsig.ParseSignatureHeader(`invalid="some_value"`)
		require.Error(t, err)
	})

	t.Run("4. fails on incorrect parameter format", func(t *testing.T) {
		_, err := httpsig.ParseSignatureHeader(`created=123=456`)
		require.Error(t, err)
	})

	t.Run("2.2 (created) must be an integer string", func(t *testing.T) {
		_, err := httpsig.ParseSignatureHeader(`created=abc`)
		require.Error(t, err)
		_, err = httpsig.ParseSignatureHeader(`created="123"`)
		require.Error(t, err)
	})

	t.Run("2.3 (expires) must be an integer string", func(t *testing.T) {
		_, err := httpsig.ParseSignatureHeader(`expires=abc`)
		require.Error(t, err)
		_, err = httpsig.ParseSignatureHeader(`expires="123"`)
		require.Error(t, err)
	})

	t.Run("4.1 headers must be a quoted string", func(t *testing.T) {
		_, err := httpsig.ParseSignatureHeader(`headers=test`)
		require.Error(t, err)
	})

	t.Run("4.1 default value for 'headers' is '(created)'", func(t *testing.T) {
		result, err := httpsig.ParseSignatureHeader(`keyId="key-abc", signature="123l;kajsdlfkj"`)
		require.NoError(t, err)
		require.Len(t, result.Headers, 1)
		require.Contains(t, result.Headers, "(created)")
	})

	t.Run("4.1 keyId is REQUIRED", func(t *testing.T) {
		_, err := httpsig.ParseSignatureHeader(`signature="abc"`)
		require.Error(t, err)
	})

	t.Run("4.1 signature is REQUIRED", func(t *testing.T) {
		_, err := httpsig.ParseSignatureHeader(`keyId="abc"`)
		require.Error(t, err)
	})

	t.Run("4.1 default value for 'algorithm' is 'hs2019'", func(t *testing.T) {
		result, err := httpsig.ParseSignatureHeader(`keyId="key-abc", signature="123l;kajsdlfkj"`)
		require.NoError(t, err)
		require.Equal(t, "hs2019", result.Algorithm)
	})
}

func unixTime(t *testing.T, val string) *time.Time {
	t.Helper()

	i, err := strconv.ParseInt(val, 10, 64)
	require.NoError(t, err)

	tm := time.Unix(i, 0)

	return &tm
}
