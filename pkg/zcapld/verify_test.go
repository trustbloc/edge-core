/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package zcapld_test

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/proof"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/signer"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/ed25519signature2018"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/jsonwebsignature2020"
	ariesver "github.com/hyperledger/aries-framework-go/pkg/doc/signature/verifier"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util/signature"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/kms/localkms"
	mockkms "github.com/hyperledger/aries-framework-go/pkg/mock/kms"
	"github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock/noop"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/edge-core/pkg/zcapld"
)

// nolint:gochecknoglobals // loading jsonld context from files only once in order to remove network dependencies.
var testLDDocumentLoader = createTestJSONLDDocumentLoader()

func TestNewVerifier(t *testing.T) {
	t.Run("success: returns verifier", func(t *testing.T) {
		v, err := zcapld.NewVerifier(
			zcapld.SimpleCapabilityResolver{},
			zcapld.SimpleKeyResolver{},
			zcapld.WithSignatureSuites(suites()...),
			zcapld.WithLDDocumentLoaders(testLDDocumentLoader),
		)
		require.NoError(t, err)
		require.NotNil(t, v)
	})
}

func TestVerifier_Verify(t *testing.T) {
	t.Run("success: valid non-delegatable read/write zcap", func(t *testing.T) {
		root, rootSigner := selfSignedRootCapability(t, kms.ED25519, ed25519signature2018.SignatureType)
		invoker := keyID(testSigner(t, kms.ED25519))
		capability := capability(t,
			rootSigner, ed25519signature2018.SignatureType,
			withInvoker(invoker), withParent(root.ID), withVerMethod(keyID(rootSigner)),
			withCapabilityChain([]interface{}{root.ID}))
		verifier := verifier(t,
			zcapld.SimpleCapabilityResolver{root.ID: root},
			zcapld.SimpleKeyResolver{
				keyID(rootSigner): keyValue(t, rootSigner),
			},
		)
		err := verifier.Verify(
			&zcapld.Proof{
				Capability:         capability,
				CapabilityAction:   "read",
				VerificationMethod: capability.Invoker,
			},
			invocation(capability.Invoker, expectRootCapability(root.ID)),
		)
		require.NoError(t, err)
	})

	t.Run("signature suite and key type compatibility", func(t *testing.T) {
		testCases := []struct {
			kmsKty   kms.KeyType
			sigSuite string
		}{
			{
				kmsKty:   kms.ED25519,
				sigSuite: ed25519signature2018.SignatureType,
			},
			{
				kmsKty:   kms.ED25519,
				sigSuite: "JsonWebSignature2020",
			},
		}

		for _, tc := range testCases {
			root, rootSigner := selfSignedRootCapability(t, tc.kmsKty, tc.sigSuite)
			invoker := keyID(testSigner(t, kms.ED25519))
			capability := capability(t,
				rootSigner, tc.sigSuite,
				withInvoker(invoker), withParent(root.ID), withVerMethod(keyID(rootSigner)),
				withCapabilityChain([]interface{}{root.ID}))
			verifier := verifier(t,
				zcapld.SimpleCapabilityResolver{root.ID: root},
				zcapld.SimpleKeyResolver{
					keyID(rootSigner): keyValue(t, rootSigner),
				},
			)
			err := verifier.Verify(
				&zcapld.Proof{
					Capability:         capability,
					CapabilityAction:   "read",
					VerificationMethod: capability.Invoker,
				},
				invocation(capability.Invoker, expectRootCapability(root.ID)),
			)
			require.NoError(t, err)
		}
	})

	t.Run("success: validates self-invoked root capability", func(t *testing.T) {
		capability, rootSigner := selfSignedSelfInvokingRootCapability(t, kms.ED25519, ed25519signature2018.SignatureType)
		invoker := keyID(rootSigner)
		invocation := invocation(invoker, expectRootCapability(capability.ID))
		invocation.VerificationMethod.ID = capability.Invoker
		verifier := verifier(t,
			zcapld.SimpleCapabilityResolver{capability.ID: capability},
			zcapld.SimpleKeyResolver{
				keyID(rootSigner): keyValue(t, rootSigner),
			},
		)
		err := verifier.Verify(
			&zcapld.Proof{
				Capability:         capability,
				CapabilityAction:   "read",
				VerificationMethod: capability.Invoker,
			},
			invocation,
		)
		require.NoError(t, err)
	})

	t.Run("success: controller as invoker", func(t *testing.T) {
		root, rootSigner := selfSignedRootCapability(t, kms.ED25519, ed25519signature2018.SignatureType)
		controller := keyID(testSigner(t, kms.ED25519))
		capability := capability(t, rootSigner, ed25519signature2018.SignatureType,
			withController(controller), withInvoker(controller), withParent(root.ID),
			withVerMethod(keyID(rootSigner)), withCapabilityChain([]interface{}{root.ID}))
		verifier := verifier(t,
			zcapld.SimpleCapabilityResolver{root.ID: root},
			zcapld.SimpleKeyResolver{
				keyID(rootSigner): keyValue(t, rootSigner),
			},
		)
		err := verifier.Verify(
			&zcapld.Proof{
				Capability:         capability,
				CapabilityAction:   "read",
				VerificationMethod: capability.Controller,
			},
			invocation(capability.Controller, expectRootCapability(root.ID)),
		)
		require.NoError(t, err)
	})

	t.Run("success: capability.ID as invoker", func(t *testing.T) {
		root, rootSigner := selfSignedRootCapability(t, kms.ED25519, ed25519signature2018.SignatureType)
		capability := capability(t,
			rootSigner, ed25519signature2018.SignatureType,
			withParent(root.ID), withVerMethod(keyID(rootSigner)), withCapabilityChain([]interface{}{root.ID}))
		invocation := invocation(capability.ID, expectRootCapability(root.ID))
		verifier := verifier(t,
			zcapld.SimpleCapabilityResolver{root.ID: root},
			zcapld.SimpleKeyResolver{
				keyID(rootSigner): keyValue(t, rootSigner),
			},
		)
		err := verifier.Verify(
			&zcapld.Proof{
				Capability:         capability,
				CapabilityAction:   "read",
				VerificationMethod: capability.ID,
			},
			invocation,
		)
		require.NoError(t, err)
	})

	t.Run("error: invalid signature", func(t *testing.T) {
		root, rootSigner := selfSignedRootCapability(t, kms.ED25519, ed25519signature2018.SignatureType)
		wrongSigner := testSigner(t, kms.ED25519)
		invoker := keyID(testSigner(t, kms.ED25519))
		capability := capability(t,
			wrongSigner, ed25519signature2018.SignatureType,
			withInvoker(invoker), withParent(root.ID), withVerMethod(keyID(rootSigner)),
			withCapabilityChain([]interface{}{root.ID}))
		verifier := verifier(t,
			zcapld.SimpleCapabilityResolver{root.ID: root},
			zcapld.SimpleKeyResolver{
				keyID(rootSigner): keyValue(t, rootSigner),
			},
		)
		err := verifier.Verify(
			&zcapld.Proof{
				Capability:         capability,
				CapabilityAction:   "read",
				VerificationMethod: capability.Invoker,
			},
			invocation(capability.Invoker, expectRootCapability(root.ID)),
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid signature")
	})

	t.Run("error: fails if capability is not provided", func(t *testing.T) {
		err := verifier(t, nil, nil).Verify(&zcapld.Proof{}, nil)
		require.EqualError(t, err, `"capability" was not found in the capability invocation proof`)
	})

	t.Run("error: fails if capability action is not authorized", func(t *testing.T) {
		root, rootSigner := selfSignedRootCapability(t, kms.ED25519, ed25519signature2018.SignatureType)
		capability := capability(t, rootSigner, ed25519signature2018.SignatureType)
		verifier := verifier(t,
			zcapld.SimpleCapabilityResolver{root.ID: root},
			zcapld.SimpleKeyResolver{},
		)
		require.Equal(t, []string{"read", "write"}, capability.AllowedAction)
		err := verifier.Verify(
			&zcapld.Proof{
				Capability:         capability,
				CapabilityAction:   "unauthorized",
				VerificationMethod: capability.Invoker,
			},
			invocation(capability.Invoker),
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), `capability action "unauthorized" is not allowed by the capability`)
	})

	t.Run("error: fails if the intended action differs from the expected action", func(t *testing.T) {
		root, rootSigner := selfSignedRootCapability(t, kms.ED25519, ed25519signature2018.SignatureType)
		capability := capability(t, rootSigner, ed25519signature2018.SignatureType)
		invocation := invocation(capability.Invoker, expectAction("read"))
		verifier := verifier(t,
			zcapld.SimpleCapabilityResolver{root.ID: root},
			zcapld.SimpleKeyResolver{},
		)
		err := verifier.Verify(
			&zcapld.Proof{
				Capability:         capability,
				CapabilityAction:   "write",
				VerificationMethod: capability.Invoker,
			},
			invocation,
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), `capability action "write" does not match the expected capability action of "read"`)
	})

	t.Run("error: unsupported capability embedded in capabilityChain", func(t *testing.T) {
		root, rootSigner := selfSignedRootCapability(t, kms.ED25519, ed25519signature2018.SignatureType)
		capability := capability(t, rootSigner, ed25519signature2018.SignatureType,
			withParent(root.ID), withCapabilityChain([]interface{}{
				map[string]interface{}{
					"embedded": true,
				},
				root.ID,
			}))
		verifier := verifier(t, zcapld.SimpleCapabilityResolver{}, zcapld.SimpleKeyResolver{})
		err := verifier.Verify(
			&zcapld.Proof{
				Capability:         capability,
				CapabilityAction:   "read",
				VerificationMethod: capability.Invoker,
			},
			invocation(capability.Invoker),
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), "embedded capabilities in capabilityChain not supported yet")
	})

	t.Run("error: cycle in the capabilityChain", func(t *testing.T) {
		root, rootSigner := selfSignedRootCapability(t, kms.ED25519, ed25519signature2018.SignatureType)
		capability := capability(t, rootSigner, ed25519signature2018.SignatureType,
			withParent(root.ID), withCapabilityChain([]interface{}{
				root.ID, root.ID,
			}))
		capability.Proof = []verifiable.Proof{{
			"proofPurpose": "capabilityDelegation",
			"capabilityChain": []interface{}{
				capability.Parent,
				capability.Parent,
			},
		}}
		verifier := verifier(t,
			zcapld.SimpleCapabilityResolver{root.ID: root},
			zcapld.SimpleKeyResolver{},
		)
		err := verifier.Verify(
			&zcapld.Proof{
				Capability:         capability,
				CapabilityAction:   "read",
				VerificationMethod: capability.Invoker,
			},
			invocation(capability.Invoker),
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), "the capability chain contains a cycle")
	})

	t.Run("error: missing capabilityChain", func(t *testing.T) {
		root, rootSigner := selfSignedRootCapability(t, kms.ED25519, ed25519signature2018.SignatureType)
		capability := capability(t, rootSigner, ed25519signature2018.SignatureType, withParent(root.ID))
		verifier := verifier(t,
			zcapld.SimpleCapabilityResolver{root.ID: root},
			zcapld.SimpleKeyResolver{},
		)
		err := verifier.Verify(
			&zcapld.Proof{
				Capability:         capability,
				CapabilityAction:   "read",
				VerificationMethod: capability.Invoker,
			},
			invocation(capability.Invoker),
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), "missing proof capabilityChain")
	})

	t.Run("error: unsupported capabilityChain format", func(t *testing.T) {
		root, rootSigner := selfSignedRootCapability(t, kms.ED25519, ed25519signature2018.SignatureType)
		capability := capability(t, rootSigner, ed25519signature2018.SignatureType, withParent(root.ID))
		capability.Proof = []verifiable.Proof{{
			"proofPurpose":    "capabilityDelegation",
			"capabilityChain": []struct{}{},
		}}
		verifier := verifier(t,
			zcapld.SimpleCapabilityResolver{root.ID: root},
			zcapld.SimpleKeyResolver{},
		)
		err := verifier.Verify(
			&zcapld.Proof{
				Capability:         capability,
				CapabilityAction:   "read",
				VerificationMethod: capability.Invoker,
			},
			invocation(capability.Invoker),
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid proof capabilityChain format")
	})

	t.Run("error: no delegatable proofs for capability", func(t *testing.T) {
		root, rootSigner := selfSignedRootCapability(t, kms.ED25519, ed25519signature2018.SignatureType)
		capability := capability(t, rootSigner, ed25519signature2018.SignatureType,
			withParent(root.ID), withProofPurpose("assertionMethod"))
		verifier := verifier(t,
			zcapld.SimpleCapabilityResolver{root.ID: root},
			zcapld.SimpleKeyResolver{},
		)
		err := verifier.Verify(
			&zcapld.Proof{
				Capability:         capability,
				CapabilityAction:   "read",
				VerificationMethod: capability.Invoker,
			},
			invocation(capability.Invoker),
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), "no delegatable proofs found in capability")
	})

	t.Run("error: capability without invoker", func(t *testing.T) {
		root, rootSigner := selfSignedRootCapability(t, kms.ED25519, ed25519signature2018.SignatureType)
		capability := capability(t, rootSigner, ed25519signature2018.SignatureType,
			withParent(root.ID), withID(""), withInvoker(""), withController(""),
			withCapabilityChain([]interface{}{root.ID}))
		verifier := verifier(t,
			zcapld.SimpleCapabilityResolver{root.ID: root},
			zcapld.SimpleKeyResolver{},
		)
		err := verifier.Verify(
			&zcapld.Proof{
				Capability:         capability,
				CapabilityAction:   "read",
				VerificationMethod: capability.Invoker,
			},
			invocation(capability.Invoker, expectRootCapability(root.ID)),
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invoker not found for capability")
	})

	t.Run("error: delegated but non-invocable capability", func(t *testing.T) {
		root, rootSigner := selfSignedRootCapability(t, kms.ED25519, ed25519signature2018.SignatureType)
		delegator := keyID(testSigner(t, kms.ED25519))
		capability := capability(t, rootSigner, ed25519signature2018.SignatureType,
			withDelegator(delegator), withInvoker(""), withParent(root.ID),
			withCapabilityChain([]interface{}{root.ID}))
		verifier := verifier(t,
			zcapld.SimpleCapabilityResolver{root.ID: root},
			zcapld.SimpleKeyResolver{},
		)
		err := verifier.Verify(
			&zcapld.Proof{
				Capability:         capability,
				CapabilityAction:   "read",
				VerificationMethod: capability.Delegator,
			},
			invocation(capability.Invoker, expectRootCapability(root.ID)),
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), "the authorized invoker does not match the verification method or its controller")
	})

	t.Run("error: cannot resolve root capability", func(t *testing.T) {
		root, rootSigner := selfSignedRootCapability(t, kms.ED25519, ed25519signature2018.SignatureType)
		capability := capability(t, rootSigner, ed25519signature2018.SignatureType,
			withParent(root.ID), withCapabilityChain([]interface{}{root.ID}))
		err := verifier(t, zcapld.SimpleCapabilityResolver{}, zcapld.SimpleKeyResolver{}).Verify(
			&zcapld.Proof{
				Capability:         capability,
				CapabilityAction:   "read",
				VerificationMethod: capability.Invoker,
			},
			invocation(capability.Invoker),
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to resolve root capability")
	})

	t.Run("error: capability's target does not match root capability's invocation target", func(t *testing.T) {
		root, rootSigner := selfSignedRootCapability(t, kms.ED25519, ed25519signature2018.SignatureType)
		capability := capability(t, rootSigner, ed25519signature2018.SignatureType,
			withParent(root.ID), withInvocationTarget("http://invalid.com/foo/document/123"),
			withCapabilityChain([]interface{}{root.ID}))
		invocation := invocation(capability.Invoker, expectTarget(capability.InvocationTarget.ID))
		require.NotEqual(t, invocation.ExpectedTarget, root.InvocationTarget.ID)
		verifier := verifier(t,
			zcapld.SimpleCapabilityResolver{root.ID: root},
			zcapld.SimpleKeyResolver{},
		)
		err := verifier.Verify(
			&zcapld.Proof{
				Capability:         capability,
				CapabilityAction:   "read",
				VerificationMethod: capability.Invoker,
			},
			invocation,
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), "expected target does not match root capability target")
	})

	t.Run("error: expected target does not match capability's root capability's invocation target", func(t *testing.T) {
		root, rootSigner := selfSignedRootCapability(t, kms.ED25519, ed25519signature2018.SignatureType)
		capability := capability(t, rootSigner, ed25519signature2018.SignatureType,
			withParent(root.ID), withCapabilityChain([]interface{}{root.ID}))
		invocation := invocation(capability.Invoker, expectRootCapability("https://edv.com/foo/some/other/zcap"))
		require.NotEqual(t, root.InvocationTarget.ID, invocation.ExpectedRootCapability)
		verifier := verifier(t,
			zcapld.SimpleCapabilityResolver{root.ID: root},
			zcapld.SimpleKeyResolver{},
		)
		err := verifier.Verify(
			&zcapld.Proof{
				Capability:         capability,
				CapabilityAction:   "read",
				VerificationMethod: capability.Invoker,
			},
			invocation,
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), "expected root capability does not match actual root capability")
	})

	t.Run("error: no expected root capability on invocation yet root capability's invocation target is not itself", func(t *testing.T) { // nolint:lll // readability
		rootSigner := testSigner(t, kms.ED25519)
		root := capability(t, rootSigner, ed25519signature2018.SignatureType,
			withID("urn:zcap:123"), withInvocationTarget("http://edv.com/foo/document/123"),
			withVerMethod(keyID(rootSigner)), withCapabilityChain([]interface{}{"http://edv.com/foo/document/123"}))
		require.NotEqual(t, root.ID, root.InvocationTarget.ID)
		capability := capability(t, rootSigner, ed25519signature2018.SignatureType,
			withParent(root.ID), withCapabilityChain([]interface{}{root.ID}))
		invocation := invocation(capability.Invoker, expectTarget(root.InvocationTarget.ID))
		verifier := verifier(t,
			zcapld.SimpleCapabilityResolver{root.ID: root},
			zcapld.SimpleKeyResolver{},
		)
		err := verifier.Verify(
			&zcapld.Proof{
				Capability:         capability,
				CapabilityAction:   "read",
				VerificationMethod: capability.Invoker,
			},
			invocation,
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), "the root capability must not specify a different invocation target")
	})

	t.Run("error: no support for multiple capabilityChains", func(t *testing.T) {
		root, rootSigner := selfSignedRootCapability(t, kms.ED25519, ed25519signature2018.SignatureType)
		capability := capability(t, rootSigner, ed25519signature2018.SignatureType,
			withParent(root.ID), withCapabilityChain([]interface{}{root.ID + "123", root.ID}))
		verifier := verifier(t,
			zcapld.SimpleCapabilityResolver{
				root.ID:         root,
				root.ID + "123": root,
			}, zcapld.SimpleKeyResolver{})
		err := verifier.Verify(
			&zcapld.Proof{
				Capability:         capability,
				CapabilityAction:   "read",
				VerificationMethod: capability.Invoker,
			},
			invocation(capability.Invoker, expectRootCapability(root.ID)),
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), "multiple capabilityChains not supported yet")
	})
}

func verifier(t *testing.T, r zcapld.CapabilityResolver, k zcapld.KeyResolver) *zcapld.Verifier {
	t.Helper()

	v, err := zcapld.NewVerifier(r, k,
		zcapld.WithSignatureSuites(suites()...),
		zcapld.WithLDDocumentLoaders(testLDDocumentLoader))
	require.NoError(t, err)

	return v
}

func selfSignedSelfInvokingRootCapability(t *testing.T,
	keyType kms.KeyType, signatureSuite string) (*zcapld.Capability, signature.Signer) {
	capID := fmt.Sprintf("did:key:%s", uuid.New().String())
	sig := testSigner(t, keyType)

	return capability(t,
		sig, signatureSuite, withID(capID), withInvoker(capID), withVerMethod(keyID(sig)),
		withCapabilityChain(
			[]interface{}{fmt.Sprintf("https://foo.com/edvs/documents/%s", uuid.New().String())},
		),
	), sig
}

func selfSignedRootCapability(t *testing.T,
	keyType kms.KeyType, signatureSuite string) (*zcapld.Capability, signature.Signer) {
	sig := testSigner(t, keyType)

	return capability(t,
		sig, signatureSuite,
		withVerMethod(keyID(sig)),
		withCapabilityChain(
			[]interface{}{fmt.Sprintf("https://foo.com/edvs/documents/%s", uuid.New().String())},
		),
	), sig
}

type zcapOptions struct {
	id                 string
	invoker            string
	parent             string
	controller         string
	capabilityChain    []interface{}
	verificationMethod string
	proofPurpose       string
	delegator          string
	invocationTarget   string
}

type zcapOption func(*zcapOptions)

func withID(id string) zcapOption {
	return func(o *zcapOptions) {
		o.id = id
	}
}

func withInvoker(i string) zcapOption {
	return func(o *zcapOptions) {
		o.invoker = i
	}
}

func withParent(p string) zcapOption {
	return func(o *zcapOptions) {
		o.parent = p
	}
}

func withController(c string) zcapOption {
	return func(o *zcapOptions) {
		o.controller = c
	}
}

func withCapabilityChain(c []interface{}) zcapOption {
	return func(o *zcapOptions) {
		o.capabilityChain = c
	}
}

func withVerMethod(m string) zcapOption {
	return func(o *zcapOptions) {
		o.verificationMethod = m
	}
}

func withProofPurpose(p string) zcapOption {
	return func(o *zcapOptions) {
		o.proofPurpose = p
	}
}

func withDelegator(d string) zcapOption {
	return func(o *zcapOptions) {
		o.delegator = d
	}
}

func withInvocationTarget(t string) zcapOption {
	return func(o *zcapOptions) {
		o.invocationTarget = t
	}
}

func capability(t *testing.T, sig verifiable.Signer, sigSuite string, options ...zcapOption) *zcapld.Capability {
	opts := &zcapOptions{
		id:               fmt.Sprintf("urn:zcap:%s", uuid.New().String()),
		proofPurpose:     zcapld.ProofPurpose,
		invocationTarget: "https://foo.com/edvs/z19rnXA8d4TPLPHoSFwnQk256/documents/z19pj5XguLxKdXjxj38o7mDj3",
	}

	for i := range options {
		options[i](opts)
	}

	var ldProofSuite signer.SignatureSuite

	switch sigSuite {
	case ed25519signature2018.SignatureType:
		ldProofSuite = ed25519signature2018.New(suite.WithSigner(sig))
	case "JsonWebSignature2020":
		ldProofSuite = jsonwebsignature2020.New(suite.WithSigner(sig))
	default:
		t.Fatalf("unsupported test signature suite: %s", sigSuite)
	}

	zcap := &zcapld.Capability{
		Context:       zcapld.SecurityContextV2,
		ID:            opts.id,
		Invoker:       opts.invoker,
		Parent:        opts.parent,
		Controller:    opts.controller,
		Delegator:     opts.delegator,
		AllowedAction: []string{"read", "write"},
		InvocationTarget: zcapld.InvocationTarget{
			ID:   opts.invocationTarget,
			Type: "urn:edv:document",
		},
	}

	signZcap(t, zcap, ldProofSuite, sigSuite, opts)

	return zcap
}

type invocationOptions struct {
	expectedTarget  string
	expectedAction  string
	expectedRootCap string
}

type invocationOption func(*invocationOptions)

func expectTarget(t string) invocationOption {
	return func(o *invocationOptions) {
		o.expectedTarget = t
	}
}

func expectAction(a string) invocationOption {
	return func(o *invocationOptions) {
		o.expectedAction = a
	}
}

func expectRootCapability(c string) invocationOption {
	return func(o *invocationOptions) {
		o.expectedRootCap = c
	}
}

func invocation(verificationMethod string, options ...invocationOption) *zcapld.CapabilityInvocation {
	opts := &invocationOptions{expectedAction: "read"}

	for i := range options {
		options[i](opts)
	}

	return &zcapld.CapabilityInvocation{
		ExpectedTarget:         opts.expectedTarget,
		ExpectedAction:         opts.expectedAction,
		ExpectedRootCapability: opts.expectedRootCap,
		VerificationMethod: &zcapld.VerificationMethod{
			ID:         verificationMethod,
			Controller: verificationMethod,
		},
	}
}

func suites() []ariesver.SignatureSuite {
	return []ariesver.SignatureSuite{
		ed25519signature2018.New(suite.WithVerifier(ed25519signature2018.NewPublicKeyVerifier())),
		jsonwebsignature2020.New(suite.WithVerifier(jsonwebsignature2020.NewPublicKeyVerifier())),
	}
}

func testSigner(t *testing.T, kt kms.KeyType) signature.Signer {
	t.Helper()

	k, err := localkms.New(
		"local-lock://custom/master/key/",
		mockkms.NewProviderForKMS(storage.NewMockStoreProvider(), &noop.NoLock{}),
	)
	require.NoError(t, err)

	tc, err := tinkcrypto.New()
	require.NoError(t, err)

	s, err := signature.NewCryptoSigner(tc, k, kt)
	require.NoError(t, err)

	return s
}

func nonce(t *testing.T) []byte {
	n := make([]byte, 256)

	_, err := rand.Reader.Read(n)
	require.NoError(t, err)

	return n
}

func signZcap(t *testing.T,
	zcap *zcapld.Capability, signerSuite signer.SignatureSuite, suiteType string, options *zcapOptions) {
	t.Helper()

	raw := marshal(t, zcap)
	now := time.Now()
	ldSigner := signer.New(signerSuite)

	signedDoc, err := ldSigner.Sign(
		&signer.Context{
			SignatureType:           suiteType,
			SignatureRepresentation: proof.SignatureJWS,
			Created:                 &now,
			Domain:                  uuid.New().String(),
			Nonce:                   nonce(t),
			VerificationMethod:      options.verificationMethod,
			Challenge:               uuid.New().String(),
			Purpose:                 options.proofPurpose,
			CapabilityChain:         options.capabilityChain,
		},
		raw,
	)
	require.NoError(t, err)

	zcap.Proof = parseProof(t, signedDoc)
}

func marshal(t *testing.T, v interface{}) []byte {
	t.Helper()

	bits, err := json.Marshal(v)
	require.NoError(t, err)

	return bits
}

func parseProof(t *testing.T, signedZcap []byte) []verifiable.Proof {
	rawProof := &struct {
		Proof json.RawMessage `json:"proof,omitempty"`
	}{}

	err := json.Unmarshal(signedZcap, rawProof)
	require.NoError(t, err)
	require.NotEmpty(t, rawProof.Proof)

	var singleProof verifiable.Proof

	err = json.Unmarshal(rawProof.Proof, &singleProof)
	if err == nil {
		return []verifiable.Proof{singleProof}
	}

	var composedProof []verifiable.Proof

	err = json.Unmarshal(rawProof.Proof, &composedProof)
	if err == nil {
		return composedProof
	}

	t.Fatalf("failed to parseProof: %s", err.Error())

	return nil
}
