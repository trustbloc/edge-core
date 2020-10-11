/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package httpsig

import (
	"fmt"
	"net/http"
	"strings"
)

// CreateSignatureInput as per https://tools.ietf.org/html/draft-ietf-httpbis-message-signatures-00#section-3.2.2.
func CreateSignatureInput(params *SignatureHeaderParams, r *http.Request) (string, error) {
	err := ensureConsistentSignatureInput(params)
	if err != nil {
		return "", fmt.Errorf("invalid signature header params: %w", err)
	}

	var input []string

	coveredContent := params.Headers

	for i := range coveredContent {
		var (
			canonicalValue string
			err            error
		)

		contentIdentifier := coveredContent[i]

		canonicalizeNonHTTPHeader, nonHTTP := nonHTTPHeaderContentIdentifierCanonicalizers()[contentIdentifier]
		switch nonHTTP {
		case true:
			canonicalValue = canonicalizeNonHTTPHeader(params, r)
		default:
			canonicalValue, err = canonicalizeHTTPHeaderValue(contentIdentifier, r)
			if err != nil {
				return "", fmt.Errorf("failed to canonicalize http header %s: %w", contentIdentifier, err)
			}
		}

		// An identifier's entry is a US-ASCII string consisting of the
		// lowercased identifier followed with a colon "":"", a space "" "", and
		// the identifier's canonicalized value
		entry := fmt.Sprintf("%s: %s", strings.ToLower(contentIdentifier), canonicalValue)
		input = append(input, entry)
	}

	// the signer concatenates together
	// entries for each identifier in the signature's Covered Content in the
	// order it occurs in the list, with each entry separated by a newline
	// ""\n"".
	return strings.Join(input, "\n"), nil
}

// Section 3.2.2: If Covered Content contains "(created)" and the signature's Creation
// Time is undefined or covered content contains "(expires)" and the signature  does not have an Expiration Time
//  or the signature's Algorithm name starts with "rsa", "hmac", or "ecdsa" an implementation MUST produce an error.
//
// Validation of the presence of a referenced HTTP header is delegated to `canonicalizeHTTPHeaderValue`.
func ensureConsistentSignatureInput(p *SignatureHeaderParams) error {
	validators := map[string]func(*SignatureHeaderParams) error{
		"(created)": func(p *SignatureHeaderParams) error {
			if p.Created == nil {
				return fmt.Errorf("undefined content for (created)")
			}

			return nil
		},
		"(expires)": func(p *SignatureHeaderParams) error {
			if p.Expires == nil {
				return fmt.Errorf("undefined ontent for (expires)")
			}

			return nil
		},
	}

	for header, validate := range validators {
		if stringsContain(p.Headers, header) {
			err := validate(p)
			if err != nil {
				return err
			}

			switch {
			case strings.HasPrefix(p.Algorithm, "rsa"), strings.HasPrefix(p.Algorithm, "hmac"),
				strings.HasPrefix(p.Algorithm, "ecdsa"):
				return fmt.Errorf("invalid algorithm %s for content identifier %s", p.Algorithm, header)
			}
		}
	}

	return nil
}

func stringsContain(strs []string, v string) bool {
	for i := range strs {
		if v == strs[i] {
			return true
		}
	}

	return false
}
