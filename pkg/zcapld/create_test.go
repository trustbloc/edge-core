/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package zcapld_test

import (
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/jsonld"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/ed25519signature2018"
	ariesver "github.com/hyperledger/aries-framework-go/pkg/doc/signature/verifier"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/edge-core/pkg/zcapld"
)

func TestParseCapability(t *testing.T) {
	t.Run("parses a capability", func(t *testing.T) {
		expected := &zcapld.Capability{
			ID:            uuid.New().String(),
			Context:       zcapld.SecurityContextV2,
			Invoker:       uuid.New().String(),
			Controller:    uuid.New().String(),
			Delegator:     uuid.New().String(),
			Parent:        uuid.New().String(),
			AllowedAction: []string{uuid.New().String()},
			InvocationTarget: zcapld.InvocationTarget{
				ID:   uuid.New().String(),
				Type: "urn:edv:document",
			},
			Caveats: []zcapld.Caveat{
				{
					Type:     zcapld.CaveatTypeExpiry,
					Duration: 100,
				},
			},
			Proof: []verifiable.Proof{{
				"type":               "Ed25519Signature2018",
				"created":            "2020-10-07T21:59:06Z",
				"verificationMethod": uuid.New().String(),
				"proofPurpose":       "capabilityDelegation",
				"capabilityChain":    []interface{}{uuid.New().String()},
				"jws":                uuid.New().String(),
			}},
		}
		result, err := zcapld.ParseCapability(marshal(t, expected))
		require.NoError(t, err)
		require.Equal(t, expected, result)
	})

	t.Run("fails if document is malformed", func(t *testing.T) {
		_, err := zcapld.ParseCapability([]byte("{"))
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to unmarshal zcap")
	})
}

func TestNewCapability(t *testing.T) {
	t.Run("creates new capability with proof", func(t *testing.T) {
		expected := &zcapld.Capability{
			ID:            uuid.New().String(),
			Invoker:       uuid.New().String(),
			Controller:    uuid.New().String(),
			Delegator:     uuid.New().String(),
			Parent:        uuid.New().String(),
			AllowedAction: []string{uuid.New().String()},
			Caveats: []zcapld.Caveat{
				{
					Type:     zcapld.CaveatTypeExpiry,
					Duration: 100,
				},
			},
			InvocationTarget: zcapld.InvocationTarget{
				ID:   uuid.New().String(),
				Type: uuid.New().String(),
			},
		}
		capabilityChain := []interface{}{fmt.Sprintf("urn:zcap:%s", uuid.New().String())}
		signer := testSigner(t, kms.ED25519)
		challenge := uuid.New().String()
		domain := uuid.New().String()
		verificationMethod := keyID(signer)
		result, err := zcapld.NewCapability(
			&zcapld.Signer{
				SignatureSuite:     ed25519signature2018.New(suite.WithSigner(signer)),
				SuiteType:          ed25519signature2018.SignatureType,
				VerificationMethod: verificationMethod,
				ProcessorOpts:      []jsonld.ProcessorOpts{jsonld.WithDocumentLoader(testLDDocumentLoader)},
			},
			zcapld.WithID(expected.ID),
			zcapld.WithParent(expected.Parent),
			zcapld.WithInvoker(expected.Invoker),
			zcapld.WithController(expected.Controller),
			zcapld.WithDelegator(expected.Delegator),
			zcapld.WithAllowedActions(expected.AllowedAction...),
			zcapld.WithCaveats(expected.Caveats...),
			zcapld.WithInvocationTarget(expected.InvocationTarget.ID, expected.InvocationTarget.Type),
			zcapld.WithChallenge(challenge),
			zcapld.WithDomain(domain),
			zcapld.WithCapabilityChain(capabilityChain...),
		)
		require.NoError(t, err)
		require.NotNil(t, result)
		require.Equal(t, zcapld.SecurityContextV2, result.Context)
		require.Equal(t, expected.ID, result.ID)
		require.Equal(t, expected.Invoker, result.Invoker)
		require.Equal(t, expected.Controller, result.Controller)
		require.Equal(t, expected.Delegator, result.Delegator)
		require.Equal(t, expected.Parent, result.Parent)
		require.Equal(t, expected.AllowedAction, result.AllowedAction)
		require.Equal(t, expected.InvocationTarget.ID, result.InvocationTarget.ID)
		require.Len(t, result.Proof, 1)
		proof := result.Proof[0]
		require.Equal(t, ed25519signature2018.SignatureType, proof["type"])
		require.Contains(t, proof, "created")
		require.Equal(t, verificationMethod, proof["verificationMethod"])
		require.Equal(t, zcapld.ProofPurpose, proof["proofPurpose"])
		require.Equal(t, capabilityChain, proof["capabilityChain"])
	})

	t.Run("sets default ID", func(t *testing.T) {
		signer := testSigner(t, kms.ED25519)
		result, err := zcapld.NewCapability(&zcapld.Signer{
			SignatureSuite:     ed25519signature2018.New(suite.WithSigner(signer)),
			SuiteType:          ed25519signature2018.SignatureType,
			VerificationMethod: keyID(signer),
		})
		require.NoError(t, err)
		require.NotEmpty(t, result.ID)
	})

	t.Run("proof is verifiable", func(t *testing.T) {
		signer := testSigner(t, kms.ED25519)
		zcap, err := zcapld.NewCapability(&zcapld.Signer{
			SignatureSuite:     ed25519signature2018.New(suite.WithSigner(signer)),
			SuiteType:          ed25519signature2018.SignatureType,
			VerificationMethod: keyID(signer),
		})
		require.NoError(t, err)
		ver, err := ariesver.New(
			zcapld.SimpleKeyResolver{keyID(signer): keyValue(t, signer)},
			ed25519signature2018.New(suite.WithVerifier(ed25519signature2018.NewPublicKeyVerifier())),
		)
		require.NoError(t, err)
		err = ver.Verify(marshal(t, zcap), jsonld.WithDocumentLoader(testLDDocumentLoader))
		require.NoError(t, err)
	})

	t.Run("error: signer not provided", func(t *testing.T) {
		_, err := zcapld.NewCapability(nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "must provide a signer")
	})

	t.Run("error: fails if signature suites are not provided", func(t *testing.T) {
		signer := testSigner(t, kms.ED25519)
		_, err := zcapld.NewCapability(&zcapld.Signer{
			SignatureSuite:     ed25519signature2018.New(suite.WithSigner(signer)),
			SuiteType:          "",
			VerificationMethod: keyID(signer),
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "signature type is missing")
	})
}
