/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package httpsig

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// SignatureHeaderParams holds parameters of the signature header:
// https://tools.ietf.org/html/draft-ietf-httpbis-message-signatures-00#section-4.1.
type SignatureHeaderParams struct {
	Algorithm string
	Created   *time.Time
	Expires   *time.Time
	KeyID     string
	Signature string
	Headers   []string
}

// ParseSignatureHeader will parse the value of the `Signature` HTTP header as per
// https://tools.ietf.org/html/draft-ietf-httpbis-message-signatures-00#section-4.
func ParseSignatureHeader(sigHeaderVal string) (*SignatureHeaderParams, error) {
	pairs := strings.Split(sigHeaderVal, ",")
	kv := make(map[string]string)

	for i := range pairs {
		header, value, err := format(pairs[i])
		if err != nil {
			return nil, fmt.Errorf("failed to parse a signature parameter: %w", err)
		}

		kv[header] = value
	}

	return params(kv)
}

// https://tools.ietf.org/html/draft-ietf-httpbis-message-signatures-00#section-4
// ABNF: sig-param = token BWS "=" BWS ( token / quoted-string ).
func format(sigParam string) (string, string, error) {
	const numParts = 2

	kv := strings.Split(sigParam, "=")
	if len(kv) != numParts {
		return "", "", fmt.Errorf("invalid sigParam format: %s", sigParam)
	}

	param := strings.TrimSpace(kv[0])
	value := strings.TrimSpace(kv[1])

	return param, value, nil
}

func params(kv map[string]string) (*SignatureHeaderParams, error) {
	p := &SignatureHeaderParams{}

	for k, v := range kv {
		parse, valid := signatureHeaderParamParser()[k]
		if !valid {
			return nil, fmt.Errorf("unrecognized signature parameter: [%s=%s]", k, v)
		}

		err := parse(p, v)
		if err != nil {
			return nil, fmt.Errorf("failed to parse value [%s] for k [%s]: %w", v, k, err)
		}
	}

	setDefaultValues(p)

	return p, ensureRequiredParams(p)
}

// https://tools.ietf.org/html/draft-ietf-httpbis-message-signatures-00#section-4.1
func ensureRequiredParams(s *SignatureHeaderParams) error {
	if s.KeyID == "" {
		return fmt.Errorf("keyId is required")
	}

	if s.Signature == "" {
		return fmt.Errorf("signature is required")
	}

	return nil
}

// Default values as per https://tools.ietf.org/html/draft-ietf-httpbis-message-signatures-00#section-4.1.
func setDefaultValues(s *SignatureHeaderParams) {
	if len(s.Headers) == 0 {
		s.Headers = []string{"(created)"}
	}

	if s.Algorithm == "" {
		s.Algorithm = "hs2019"
	}
}

// https://tools.ietf.org/html/draft-ietf-httpbis-message-signatures-00#section-3.1
func signatureHeaderParamParser() map[string]func(*SignatureHeaderParams, string) error {
	return map[string]func(*SignatureHeaderParams, string) error{
		"algorithm": func(s *SignatureHeaderParams, v string) error {
			var err error

			s.Algorithm, err = parseQuotedString(v)

			return err
		},
		"keyId": func(s *SignatureHeaderParams, v string) error {
			var err error

			s.KeyID, err = parseQuotedString(v)

			return err
		},
		"signature": func(s *SignatureHeaderParams, v string) error {
			var err error

			s.Signature, err = parseQuotedString(v)

			return err
		},
		"created": func(s *SignatureHeaderParams, v string) error {
			var err error

			s.Created, err = parseUnixTime(v)

			return err
		},
		"expires": func(s *SignatureHeaderParams, v string) error {
			var err error

			s.Expires, err = parseUnixTime(v)

			return err
		},
		"headers": func(s *SignatureHeaderParams, v string) error {
			coveredContent, err := parseQuotedString(v)
			if err != nil {
				return fmt.Errorf("failed to parse covered content: %w", err)
			}

			s.Headers = strings.Split(coveredContent, " ")

			return nil
		},
	}
}

func parseQuotedString(v string) (string, error) {
	if !strings.HasPrefix(v, `"`) || !strings.HasSuffix(v, `"`) {
		return "", fmt.Errorf("invalid quoted-string format: %s", v)
	}

	return strings.TrimSuffix(strings.TrimPrefix(v, `"`), `"`), nil
}

func parseUnixTime(v string) (*time.Time, error) {
	i, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return nil, err
	}

	t := time.Unix(i, 0)

	return &t, nil
}
