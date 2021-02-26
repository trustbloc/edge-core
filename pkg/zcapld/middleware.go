/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package zcapld

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/kms/localkms"
	httpsig "github.com/igor-pavlenko/httpsignatures-go"
)

const (
	// CapabilityInvocationHTTPHeader is the HTTP header expected on zcap'ed HTTP requests.
	CapabilityInvocationHTTPHeader = "capability-invocation"
	signatureHeader                = "signature"
	capabilityParam                = "capability"
	actionParam                    = "action"
	keyIDParam                     = "keyId"
)

const ariesDIDKeyCustomHTTPSigAlgorithm = "https://github.com/hyperledger/aries-framework-go/zcaps"

// VDRResolver represents VDR resolver.
type VDRResolver interface {
	Resolve(did string, opts ...vdr.ResolveOption) (*did.DocResolution, error)
}

// HTTPSigAuthConfig configures the HTTP auth handler.
type HTTPSigAuthConfig struct {
	CapabilityResolver CapabilityResolver
	KeyResolver        KeyResolver
	VDRResolver        VDRResolver
	VerifierOptions    []VerificationOption
	Secrets            httpsig.Secrets
	ErrConsumer        func(error)
	KMS                kms.KeyManager
	Crypto             crypto.Crypto
}

// InvocationExpectations are set by the application's context as parameters to expect for any given invocation.
type InvocationExpectations struct {
	Target         string
	RootCapability string
	Action         string
}

// AriesDIDKeySecrets is a secrets storage that can return did:key httpsignatures.Secrets.
// Based on workaround suggested by library authors here: https://github.com/igor-pavlenko/httpsignatures-go/issues/5.
type AriesDIDKeySecrets struct {
}

// Get returns a did:key secret.
func (a *AriesDIDKeySecrets) Get(keyID string) (httpsig.Secret, error) {
	return httpsig.Secret{
		KeyID:     keyID,
		Algorithm: ariesDIDKeyCustomHTTPSigAlgorithm,
	}, nil
}

// AriesDIDKeySignatureHashAlgorithm is a custom httpsignatures.SignatureHashAlgorithm composed of
// the aries framework's KMS and Crypto apis, and designed to work with did:key.
// Based on workaround suggested by library authors here: https://github.com/igor-pavlenko/httpsignatures-go/issues/5.
type AriesDIDKeySignatureHashAlgorithm struct {
	Crypto   crypto.Crypto
	KMS      kms.KeyManager
	Resolver VDRResolver
}

// Algorithm returns this algorithm's name.
func (a *AriesDIDKeySignatureHashAlgorithm) Algorithm() string {
	return ariesDIDKeyCustomHTTPSigAlgorithm
}

// Create signs data with the secret.
func (a *AriesDIDKeySignatureHashAlgorithm) Create(secret httpsig.Secret, data []byte) ([]byte, error) {
	key, err := NewDIDKeyResolver(a.Resolver).Resolve(secret.KeyID)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve did:key URL %s: %w", secret.KeyID, err)
	}

	// TODO we are assuming curve: https://github.com/trustbloc/edge-core/issues/108.
	// TODO we shouldn't be using a `localkms` function: https://github.com/trustbloc/edge-core/issues/109.
	kid, err := localkms.CreateKID(key.Value, kms.ED25519)
	if err != nil {
		return nil, fmt.Errorf("failed to create KID from did:key: %w", err)
	}

	kh, err := a.KMS.Get(kid)
	if err != nil {
		return nil, fmt.Errorf("failed to get key handle for kid %s: %w", kid, err)
	}

	sig, err := a.Crypto.Sign(data, kh)
	if err != nil {
		return nil, fmt.Errorf("failed to sign data: %w", err)
	}

	return sig, nil
}

// Verify verifies the signature over data with the secret.
func (a *AriesDIDKeySignatureHashAlgorithm) Verify(secret httpsig.Secret, data, signature []byte) error {
	key, err := NewDIDKeyResolver(a.Resolver).Resolve(secret.KeyID)
	if err != nil {
		return fmt.Errorf("failed to resolve did:key URL %s: %w", secret.KeyID, err)
	}

	kh, err := a.KMS.PubKeyBytesToHandle(key.Value, kms.ED25519)
	if err != nil {
		return fmt.Errorf("failed to convert did:key pubkey to aries kms handle: %w", err)
	}

	err = a.Crypto.Verify(signature, data, kh)
	if err != nil {
		return fmt.Errorf("failed to verify signature: %w", err)
	}

	return nil
}

// NewHTTPSigAuthHandler authenticates and authorizes a request before forwarding to 'next'.
// Authentication scheme: https://tools.ietf.org/html/draft-ietf-httpbis-message-signatures-00.
// Authorization scheme: https://w3c-ccg.github.io/zcap-ld/.
func NewHTTPSigAuthHandler(
	config *HTTPSigAuthConfig, expect *InvocationExpectations, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authZHandleFunc(w, r, config, expect, next)
	}
}

// TODO ability to configure allowed expiry time and clock skew: https://github.com/trustbloc/edge-core/issues/103.
func authZHandleFunc(w http.ResponseWriter, r *http.Request,
	config *HTTPSigAuthConfig, expect *InvocationExpectations, next http.HandlerFunc) {
	hs := httpSig(config)

	err := hs.Verify(r)
	if err != nil {
		maybeConsumeError(config.ErrConsumer, fmt.Errorf("failed to verify http signature: %w", err))
		http.Error(w, "unauthorized", http.StatusUnauthorized)

		return
	}

	zcap, keyID, action, err := parseProofParams(r)
	if err != nil {
		maybeConsumeError(config.ErrConsumer, fmt.Errorf("failed to parse proof params: %w", err))
		http.Error(w, "bad request", http.StatusBadRequest)

		return
	}

	verifier, err := NewVerifier(config.CapabilityResolver, config.KeyResolver, config.VerifierOptions...)
	if err != nil {
		maybeConsumeError(config.ErrConsumer, fmt.Errorf("middleware failed to init verifier: %w", err))
		http.Error(w, fmt.Sprintf("failed to init zcap verifier: %s", err.Error()), http.StatusInternalServerError)

		return
	}

	err = verifier.Verify(
		&Proof{
			Capability:         zcap,
			CapabilityAction:   action,
			VerificationMethod: keyID,
		},
		&CapabilityInvocation{
			ExpectedTarget:         expect.Target,
			ExpectedAction:         expect.Action,
			ExpectedRootCapability: expect.RootCapability,
			VerificationMethod: &VerificationMethod{
				ID:         keyID,
				Controller: keyID,
			},
		},
	)
	if err != nil {
		maybeConsumeError(config.ErrConsumer, fmt.Errorf("failed to verify zcap: %w", err))
		http.Error(w, "unauthorized", http.StatusUnauthorized)

		return
	}

	next(w, r)
}

func httpSig(config *HTTPSigAuthConfig) *httpsig.HTTPSignatures {
	hs := httpsig.NewHTTPSignatures(config.Secrets)

	// setting these:
	// nolint:lll // should not break the link below into separate lines
	// https://github.com/digitalbazaar/http-signature-zcap-verify/blob/aead239ea7567c501fac1f0baf901784be276536/main.js#L30-L34
	hs.SetDefaultSignatureHeaders([]string{
		"(key-id)", "(created)", "(expires)", "(request-target)", "host", CapabilityInvocationHTTPHeader,
	})

	hs.SetSignatureHashAlgorithm(&AriesDIDKeySignatureHashAlgorithm{
		Crypto:   config.Crypto,
		KMS:      config.KMS,
		Resolver: config.VDRResolver,
	})

	return hs
}

func maybeConsumeError(consumer func(error), err error) {
	if consumer != nil {
		consumer(err)
	}
}

func parseProofParams(r *http.Request) (zcap *Capability, keyID, action string, err error) {
	zcap, action, err = parseInvocationHeader(r)
	if err != nil {
		return nil, "", "", fmt.Errorf("failed to parse capability-invocation header: %w", err)
	}

	keyID, err = parseKeyID(r)
	if err != nil {
		return nil, "", "", fmt.Errorf("failed to parse keyID: %w", err)
	}

	return zcap, keyID, action, nil
}

// assume the same format as the Bearer authentication scheme:
// https://tools.ietf.org/html/rfc6750#section-2.1
func parseInvocationHeader(r *http.Request) (*Capability, string, error) {
	value := strings.TrimSpace(strings.Join(r.Header.Values(CapabilityInvocationHTTPHeader), ", "))

	if value == "" {
		return nil, "", fmt.Errorf(`"%s" header is missing`, CapabilityInvocationHTTPHeader)
	}

	scheme := strings.ToLower(value[:4])

	if scheme != "zcap" {
		return nil, "", fmt.Errorf("invalid invocation scheme: %s", scheme)
	}

	zcap, action, err := parseInvocation(value[5:])
	if err != nil {
		return nil, "", fmt.Errorf("failed to parse invocation header: %w", err)
	}

	if action == "" {
		return nil, "", fmt.Errorf(`"%s" header is missing`, actionParam)
	}

	return zcap, action, nil
}

// TODO make algorithm more robust: https://github.com/trustbloc/edge-core/issues/102.
func parseInvocation(invocation string) (*Capability, string, error) {
	const (
		equalityOp = "="
		delim      = ","
		numParts   = 2
	)

	var (
		zcap   *Capability
		action string
		err    error
	)

	keyValues := strings.Split(invocation, delim)

	for i := range keyValues {
		kv := strings.SplitN(keyValues[i], equalityOp, numParts)
		if len(kv) != numParts {
			return nil, "", fmt.Errorf("invalid key=value format: %s", keyValues[i])
		}

		k := kv[0]
		v := kv[1]

		switch k {
		case capabilityParam:
			var str string

			str, err = parseQuotedString(v)
			if err != nil {
				return nil, "", fmt.Errorf("'capability' invocation header param value is not a quoted-string: %w", err)
			}

			zcap, err = DecompressZCAP(str)
			if err != nil {
				return nil, "", fmt.Errorf("failed to parse capability invocation header param value: %w", err)
			}
		case actionParam:
			action, err = parseQuotedString(v)
			if err != nil {
				return nil, "", fmt.Errorf("'action' invocation header param value is not a quoted-string: %w", err)
			}
		default:
			return nil, "", fmt.Errorf("unrecognized invocation header param: k=%s v=%s", k, v)
		}
	}

	return zcap, action, nil
}

func parseQuotedString(value string) (string, error) {
	if !strings.HasPrefix(value, `"`) || !strings.HasSuffix(value, `"`) {
		return "", fmt.Errorf("value is not a quoted-string: %s", value)
	}

	return strings.TrimSuffix(strings.TrimPrefix(value, `"`), `"`), nil
}

// DecompressZCAP uncompresses base64 encoded string into capability.
func DecompressZCAP(value string) (zcap *Capability, err error) {
	decoded, err := base64.URLEncoding.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("failed to base64URL-decode value %s: %w", value, err)
	}

	reader, err := gzip.NewReader(bytes.NewBuffer(decoded))
	if err != nil {
		return nil, fmt.Errorf("failed to init gzip reader: %w", err)
	}

	defer func() {
		closeErr := reader.Close()
		if closeErr != nil {
			if err != nil {
				err = fmt.Errorf("%w: failed to close gzip reader: %s", err, closeErr.Error())
			}

			err = fmt.Errorf("failed to close gzip reader: %w", closeErr)
		}
	}()

	buf := bytes.NewBuffer(nil)

	_, err = buf.ReadFrom(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read gunzipped capability: %w", err)
	}

	zcap, err = ParseCapability(buf.Bytes())
	if err != nil {
		return nil, fmt.Errorf("failed to parse zcap: %w", err)
	}

	return zcap, err
}

// CompressZCAP compresses capability into base64 encoded string.
func CompressZCAP(zcap *Capability) (string, error) {
	raw, err := json.Marshal(zcap)
	if err != nil {
		return "", err
	}

	compressed := bytes.NewBuffer(nil)

	w := gzip.NewWriter(compressed)

	_, err = w.Write(raw)
	if err != nil {
		return "", err
	}

	err = w.Close()
	if err != nil {
		return "", err
	}

	return base64.URLEncoding.EncodeToString(compressed.Bytes()), nil
}

// TODO refactor this algorithm: https://github.com/trustbloc/edge-core/issues/104.
func parseKeyID(r *http.Request) (string, error) {
	const (
		numParts   = 2
		delim      = ","
		equalityOp = "="
	)

	value := strings.Join(r.Header.Values(signatureHeader), fmt.Sprintf("%s ", delim))
	keyValues := strings.Split(value, delim)

	for i := range keyValues {
		kv := strings.Split(keyValues[i], equalityOp)
		if len(kv) != numParts {
			return "", fmt.Errorf("malformed signature header param: %s", keyValues[i])
		}

		k := kv[0]
		v := kv[1]

		if k == keyIDParam {
			keyID, err := parseQuotedString(v)
			if err != nil {
				return "", fmt.Errorf("value of keyId is not a quoted-string [%s]: %w", v, err)
			}

			return keyID, nil
		}
	}

	return "", fmt.Errorf("no %s parameter found for %s header", keyIDParam, signatureHeader)
}
