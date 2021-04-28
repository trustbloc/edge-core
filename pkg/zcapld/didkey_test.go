/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package zcapld_test

import (
	"testing"

	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/jsonld"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/ed25519signature2018"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/fingerprint"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/edge-core/pkg/zcapld"
)

func TestE2E(t *testing.T) {
	signer := testSigner(t, kms.ED25519)
	loader := createTestJSONLDDocumentLoader(t)
	_, didKeyURL := fingerprint.CreateDIDKey(signer.PublicKeyBytes())

	// issue new zcap with a did:key URL as verificationMethod
	zcap, err := zcapld.NewCapability(
		&zcapld.Signer{
			SignatureSuite:     ed25519signature2018.New(suite.WithSigner(signer)),
			SuiteType:          ed25519signature2018.SignatureType,
			VerificationMethod: didKeyURL,
			ProcessorOpts:      []jsonld.ProcessorOpts{jsonld.WithDocumentLoader(loader)},
		},
		zcapld.WithInvoker(didKeyURL),
	)
	require.NoError(t, err)

	// verify zcap with a did:key URL as verificationMethod
	verifier, err := zcapld.NewVerifier(
		zcapld.SimpleCapabilityResolver{zcap.ID: zcap},
		zcapld.NewDIDKeyResolver(nil),
		zcapld.WithLDDocumentLoaders(loader),
		zcapld.WithSignatureSuites(
			ed25519signature2018.New(suite.WithVerifier(ed25519signature2018.NewPublicKeyVerifier())),
		),
	)
	require.NoError(t, err)
	err = verifier.Verify(
		&zcapld.Proof{
			Capability:         zcap,
			VerificationMethod: didKeyURL,
		},
		&zcapld.CapabilityInvocation{
			ExpectedRootCapability: zcap.ID,
			VerificationMethod: &zcapld.VerificationMethod{
				ID:         didKeyURL,
				Controller: didKeyURL,
			},
		},
	)
	require.NoError(t, err)
}
