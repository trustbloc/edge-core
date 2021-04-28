/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package zcapld_test

import (
	"fmt"
	"testing"

	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jsonld"
	ariesver "github.com/hyperledger/aries-framework-go/pkg/doc/signature/verifier"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util/signature"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries"
	"github.com/hyperledger/aries-framework-go/pkg/framework/context"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/fingerprint"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/edge-core/pkg/zcapld"
)

type agent struct {
	t *testing.T
	*context.Provider
}

func (a *agent) signer() signature.Signer {
	a.t.Helper()

	s, err := signature.NewCryptoSigner(a.Crypto(), a.KMS(), kms.ED25519)
	require.NoError(a.t, err)

	return s
}

func newAgent(t *testing.T) *agent {
	t.Helper()

	a, err := aries.New()
	require.NoError(t, err)

	ctx, err := a.Context()
	require.NoError(t, err)

	return &agent{
		Provider: ctx,
		t:        t,
	}
}

func didKeyURL(sigSigner signature.Signer) string {
	_, u := fingerprint.CreateDIDKey(sigSigner.PublicKeyBytes())

	return u
}

func keyID(sigSigner signature.Signer) string {
	// source: https://github.com/multiformats/multicodec/blob/master/table.csv.
	const ed25519pub = 0xed // Ed25519 public key in multicodec table

	thumb := fingerprint.KeyFingerprint(ed25519pub, sigSigner.PublicKeyBytes())

	return fmt.Sprintf("did:key:%s", thumb)
}

func keyValue(t *testing.T, sigSigner signature.Signer) *ariesver.PublicKey {
	t.Helper()

	jwk, err := jose.JWKFromKey(sigSigner.PublicKey())
	require.NoError(t, err)

	return &ariesver.PublicKey{
		Type:  "JwsVerificationKey2020",
		Value: sigSigner.PublicKeyBytes(),
		JWK:   jwk,
	}
}

func createTestJSONLDDocumentLoader(t *testing.T) *jsonld.DocumentLoader {
	t.Helper()

	loader, err := jsonld.NewDocumentLoader(mem.NewProvider())
	require.NoError(t, err)

	return loader
}

func compressZCAP(t *testing.T, zcap *zcapld.Capability) string {
	t.Helper()

	res, err := zcapld.CompressZCAP(zcap)
	require.NoError(t, err)

	return res
}
