/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package httpsig_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/edge-core/pkg/httpsig"
)

func TestCreateSignatureInput(t *testing.T) {
	t.Run("3.2.2 example", func(t *testing.T) {
		request := httptest.NewRequest(http.MethodGet, "http://example.org/foo", nil)
		request.Header.Set("Date", "Tue, 07 Jun 2014 20:51:35 GMT")
		request.Header.Set("X-Example", "Example header\n    with some whitespace.")
		request.Header.Set("X-EmptyHeader", "")
		request.Header.Set("Cache-Control", "max-age=60")
		request.Header.Add("Cache-Control", "must-revalidate")
		request.Header.Set("Host", "example.org")
		result, err := httpsig.CreateSignatureInput(
			params(t, `keyId="test-key-b", created=1402170695, expires=1402170995, `+
				`headers="(request-target) (created) (expires) host date cache-control x-emptyheader x-example", `+
				`signature="abc123"`),
			request,
		)
		require.NoError(t, err)
		expected := strings.Join(
			[]string{
				"(request-target): get /foo",
				"(created): 1402170695",
				"(expires): 1402170995",
				"host: example.org",
				"date: Tue, 07 Jun 2014 20:51:35 GMT",
				"cache-control: max-age=60, must-revalidate",
				"x-emptyheader: ",
				"x-example: Example header\n    with some whitespace.",
			},
			"\n",
		)
		require.Equal(t, expected, result)
	})

	t.Run("3.2.2 (created)", func(t *testing.T) {
		t.Run("error: covered but missing content", func(t *testing.T) {
			_, err := httpsig.CreateSignatureInput(
				params(t, `keyId="test-key-b", expires=1402170995, `+
					`headers="(request-target) (created) (expires) host date cache-control x-emptyheader x-example", `+
					`signature="abc123"`),
				nil,
			)
			require.Error(t, err)
		})

		t.Run("error: invalid algorithm", func(t *testing.T) {
			algorithms := []string{"rsa", "hmac", "ecdsa"}
			for i := range algorithms {
				algorithm := fmt.Sprintf(`algorithm="%s"`, algorithms[i])
				input := algorithm + `, keyId="test-key-b", created=1402170695, expires=1402170995, ` +
					`headers="(request-target) (created) (expires) host date cache-control x-emptyheader x-example", ` +
					`signature="abc123"`
				_, err := httpsig.CreateSignatureInput(params(t, input), nil)
				require.Error(t, err)
			}
		})
	})

	t.Run("3.2.2 (expires)", func(t *testing.T) {
		t.Run("error: covered but missing content", func(t *testing.T) {
			_, err := httpsig.CreateSignatureInput(
				params(t, `keyId="test-key-b", created=1402170695, `+
					`headers="(request-target) (created) (expires) host date cache-control x-emptyheader x-example", `+
					`signature="abc123"`),
				nil,
			)
			require.Error(t, err)
		})

		t.Run("error: invalid algorithm", func(t *testing.T) {
			algorithms := []string{"rsa", "hmac", "ecdsa"}
			for i := range algorithms {
				algorithm := fmt.Sprintf(`algorithm="%s"`, algorithms[i])
				input := algorithm + `, keyId="test-key-b", created=1402170695, expires=1402170995, ` +
					`headers="(request-target) (created) (expires) host date cache-control x-emptyheader x-example", ` +
					`signature="abc123"`
				_, err := httpsig.CreateSignatureInput(params(t, input), nil)
				require.Error(t, err)
			}
		})

		t.Run("HTTP Headers", func(t *testing.T) {
			t.Run("2.1 strips leading and trailing whitespace from HTTP headers", func(t *testing.T) {
				request := httptest.NewRequest(http.MethodGet, "http://example.org/foo", nil)
				request.Header.Set("X-EXAMPLE", " \t  test         \n")
				result, err := httpsig.CreateSignatureInput(
					params(t, `keyId="test-key-b", signature="0q92uorijlqwelf", headers="x-example"`),
					request,
				)
				require.NoError(t, err)
				require.Equal(t, "x-example: test", result)
			})

			t.Run("3.2.2 error: identifier for header field that is not present", func(t *testing.T) {
				_, err := httpsig.CreateSignatureInput(
					params(t, `keyId="test-key-b", signature="abc123", headers="x-not-present"`),
					httptest.NewRequest(http.MethodGet, "http://example.org/foo", nil),
				)
				require.Error(t, err)
			})
		})
	})
}

func params(t *testing.T, val string) *httpsig.SignatureHeaderParams {
	t.Helper()

	params, err := httpsig.ParseSignatureHeader(val)
	require.NoError(t, err)

	return params
}
