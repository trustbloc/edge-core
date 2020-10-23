/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package httpsig

import (
	"fmt"
	"net/http"
	"net/textproto"
	"strconv"
	"strings"
)

// use these canonicalizers only if they are referenced in the `headers` signature header param.
func nonHTTPHeaderContentIdentifierCanonicalizers() map[string]func(*SignatureHeaderParams, *http.Request) string {
	return map[string]func(*SignatureHeaderParams, *http.Request) string{
		"(created)": func(s *SignatureHeaderParams, _ *http.Request) string {
			return strconv.FormatInt(s.Created.Unix(), 10)
		},
		"(expires)": func(s *SignatureHeaderParams, _ *http.Request) string {
			return strconv.FormatInt(s.Expires.Unix(), 10)
		},
		"(request-target)": func(_ *SignatureHeaderParams, r *http.Request) string {
			return strings.ToLower(r.Method) + " " + strings.ToLower(r.URL.Path)
		},
	}
}

// https://tools.ietf.org/html/draft-ietf-httpbis-message-signatures-00#section-2.1.
func canonicalizeHTTPHeaderValue(header string, r *http.Request) (string, error) {
	// Section 3.2.2: If Covered Content contains an identifier for a header field that is
	// not present or malformed in the message, the implementation MUST
	// produce an error.
	if _, found := r.Header[textproto.CanonicalMIMEHeaderKey(header)]; !found {
		return "", fmt.Errorf(
			"covered content contains an identifier for a header field that is not present: %s", header)
	}

	// 1. Create an ordered list of the field values of each instance of the header field in the message,
	//    in the order that they occur (or will occur) in the message.
	// As per https://tools.ietf.org/html/rfc2616#section-4.2, golang retains the order of a header's values:
	// https://golang.org/src/net/textproto/reader.go?s=12794:12847#L474.
	values := r.Header.Values(header)

	// 2. Strip leading and trailing whitespace from each item in the list.
	for i := range values {
		value := values[i]
		values[i] = strings.TrimSpace(value)
	}

	// 3.Concatenate the list items together, with a comma "","" and space "" "" between each item.
	//   The resulting string is the canonicalized value.
	return strings.Join(values, ", "), nil
}
