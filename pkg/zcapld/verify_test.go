/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package zcapld_test

import (
	"fmt"
	"testing"

	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/edge-core/pkg/zcapld"
)

func TestNewVerifier(t *testing.T) {
	t.Run("success: returns verifier", func(t *testing.T) {
		v, err := zcapld.NewVerifier(SimpleCapabilityResolver{})
		require.NoError(t, err)
		require.NotNil(t, v)
	})
}

func TestVerifier_Verify(t *testing.T) {
	t.Run("success: valid non-delegatable read/write zcap", func(t *testing.T) {
		capability := capability()
		verifier := verifier(t, SimpleCapabilityResolver{
			rootCapability().ID: rootCapability(),
		})
		err := verifier.Verify(
			&zcapld.Proof{
				Capability:         capability,
				CapabilityAction:   "read",
				VerificationMethod: capability.Invoker,
			},
			invocation(),
		)
		require.NoError(t, err)
	})

	t.Run("success: validates self-invoked root capability", func(t *testing.T) {
		capability := rootCapability()
		capability.Invoker = capability.ID
		invocation := invocation()
		invocation.VerificationMethod.ID = capability.Invoker
		verifier := verifier(t, SimpleCapabilityResolver{
			capability.ID: capability,
		})
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
		verifier := verifier(t, SimpleCapabilityResolver{
			rootCapability().ID: rootCapability(),
		})
		capability := capability()
		capability.Controller = capability.Invoker
		capability.Invoker = ""
		err := verifier.Verify(
			&zcapld.Proof{
				Capability:         capability,
				CapabilityAction:   "read",
				VerificationMethod: capability.Controller,
			},
			invocation(),
		)
		require.NoError(t, err)
	})

	t.Run("success: capability.ID as invoker", func(t *testing.T) {
		capability := capability()
		capability.Invoker = ""
		capability.Controller = ""
		invocation := invocation()
		invocation.VerificationMethod = &zcapld.VerificationMethod{
			ID:         capability.ID,
			Controller: capability.ID,
		}
		verifier := verifier(t, SimpleCapabilityResolver{
			rootCapability().ID: rootCapability(),
		})
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

	t.Run("error: fails if capability is not provided", func(t *testing.T) {
		err := verifier(t, nil).Verify(&zcapld.Proof{}, nil)
		require.EqualError(t, err, `"capability" was not found in the capability invocation proof`)
	})

	t.Run("error: fails if capability action is not authorized", func(t *testing.T) {
		verifier := verifier(t, SimpleCapabilityResolver{
			rootCapability().ID: rootCapability(),
		})
		capability := capability()
		require.Equal(t, []string{"read", "write"}, capability.AllowedAction)
		err := verifier.Verify(
			&zcapld.Proof{
				Capability:         capability,
				CapabilityAction:   "unauthorized",
				VerificationMethod: capability.Invoker,
			},
			invocation(),
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), `capability action "unauthorized" is not allowed by the capability`)
	})

	t.Run("error: fails if the intended action differs from the expected action", func(t *testing.T) {
		capability := capability()
		invocation := invocation()
		require.Equal(t, "read", invocation.ExpectedAction)
		verifier := verifier(t, SimpleCapabilityResolver{
			rootCapability().ID: rootCapability(),
		})
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
		capability := capability()
		capability.Proof = []verifiable.Proof{{
			"proofPurpose": "capabilityDelegation",
			"capabilityChain": []interface{}{
				map[string]interface{}{
					"embedded": true,
				},
				capability.Parent,
			},
		}}
		verifier := verifier(t, SimpleCapabilityResolver{})
		err := verifier.Verify(
			&zcapld.Proof{
				Capability:         capability,
				CapabilityAction:   "read",
				VerificationMethod: capability.Invoker,
			},
			invocation(),
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), "embedded capabilities in capabilityChain not supported yet")
	})

	t.Run("error: cycle in the capabilityChain", func(t *testing.T) {
		capability := capability()
		capability.Proof = []verifiable.Proof{{
			"proofPurpose": "capabilityDelegation",
			"capabilityChain": []interface{}{
				capability.Parent,
				capability.Parent,
			},
		}}
		verifier := verifier(t, SimpleCapabilityResolver{
			rootCapability().ID: rootCapability(),
		})
		err := verifier.Verify(
			&zcapld.Proof{
				Capability:         capability,
				CapabilityAction:   "read",
				VerificationMethod: capability.Invoker,
			},
			invocation(),
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), "the capability chain contains a cycle")
	})

	t.Run("error: missing capabilityChain", func(t *testing.T) {
		capability := capability()
		capability.Proof = []verifiable.Proof{{
			"proofPurpose": "capabilityDelegation",
		}}
		verifier := verifier(t, SimpleCapabilityResolver{
			rootCapability().ID: rootCapability(),
		})
		err := verifier.Verify(
			&zcapld.Proof{
				Capability:         capability,
				CapabilityAction:   "read",
				VerificationMethod: capability.Invoker,
			},
			invocation(),
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), "missing proof capabilityChain")
	})

	t.Run("error: unsupported capabilityChain format", func(t *testing.T) {
		capability := capability()
		capability.Proof = []verifiable.Proof{{
			"proofPurpose":    "capabilityDelegation",
			"capabilityChain": []struct{}{},
		}}
		verifier := verifier(t, SimpleCapabilityResolver{
			rootCapability().ID: rootCapability(),
		})
		err := verifier.Verify(
			&zcapld.Proof{
				Capability:         capability,
				CapabilityAction:   "read",
				VerificationMethod: capability.Invoker,
			},
			invocation(),
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid proof capabilityChain format")
	})

	t.Run("error: no delegatable proofs for capability", func(t *testing.T) {
		capability := capability()
		capability.Proof = []verifiable.Proof{{
			"proofPurpose":    "assertion",
			"capabilityChain": []string{capability.Parent},
		}}
		verifier := verifier(t, SimpleCapabilityResolver{
			capability.Invoker: rootCapability(),
		})
		err := verifier.Verify(
			&zcapld.Proof{
				Capability:         capability,
				CapabilityAction:   "read",
				VerificationMethod: capability.Invoker,
			},
			invocation(),
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), "no delegatable proofs found in capability")
	})

	t.Run("error: capability without invoker", func(t *testing.T) {
		capability := capability()
		capability.ID = ""
		capability.Invoker = ""
		capability.Controller = ""
		verifier := verifier(t, SimpleCapabilityResolver{
			rootCapability().ID: rootCapability(),
		})
		err := verifier.Verify(
			&zcapld.Proof{
				Capability:         capability,
				CapabilityAction:   "read",
				VerificationMethod: capability.Invoker,
			},
			invocation(),
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invoker not found for capability")
	})

	t.Run("error: delegated but non-invocable capability", func(t *testing.T) {
		capability := capability()
		capability.Delegator = capability.Invoker
		capability.Invoker = ""
		verifier := verifier(t, SimpleCapabilityResolver{
			rootCapability().ID: rootCapability(),
		})
		err := verifier.Verify(
			&zcapld.Proof{
				Capability:         capability,
				CapabilityAction:   "read",
				VerificationMethod: capability.Delegator,
			},
			invocation(),
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), "the authorized invoker does not match the verification method or its controller")
	})

	t.Run("error: cannot resolve root capability", func(t *testing.T) {
		err := verifier(t, SimpleCapabilityResolver{}).Verify(
			&zcapld.Proof{
				Capability:         capability(),
				CapabilityAction:   "read",
				VerificationMethod: capability().Invoker,
			},
			invocation(),
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to resolve root capability")
	})

	t.Run("error: capability's target does not match root capability's invocation target", func(t *testing.T) {
		capability := capability()
		capability.InvocationTarget.ID = "https://edv.com/foo/some/other/target"
		rootCapability := rootCapability()
		require.NotEqual(t, capability.InvocationTarget.ID, rootCapability.InvocationTarget.ID)
		invocation := invocation()
		invocation.ExpectedTarget = capability.InvocationTarget.ID
		require.NotEqual(t, invocation.ExpectedTarget, rootCapability.InvocationTarget.ID)
		verifier := verifier(t, SimpleCapabilityResolver{
			rootCapability.ID: rootCapability,
		})
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
		capability := capability()
		rootCapability := rootCapability()
		invocation := invocation()
		invocation.ExpectedRootCapability = "https://edv.com/foot/some/other/root/capability"
		require.NotEqual(t, rootCapability.InvocationTarget.ID, invocation.ExpectedRootCapability)
		verifier := verifier(t, SimpleCapabilityResolver{
			rootCapability.ID: rootCapability,
		})
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
		rootCapability := rootCapability()
		rootCapability.InvocationTarget.ID = "https://edv.com/foo/some/other/document"
		require.NotEqual(t, rootCapability.ID, rootCapability.InvocationTarget.ID)
		invocation := invocation()
		invocation.ExpectedRootCapability = ""
		invocation.ExpectedTarget = rootCapability.InvocationTarget.ID
		verifier := verifier(t, SimpleCapabilityResolver{
			rootCapability.ID: rootCapability,
		})
		err := verifier.Verify(
			&zcapld.Proof{
				Capability:         capability(),
				CapabilityAction:   "read",
				VerificationMethod: capability().Invoker,
			},
			invocation,
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), "the root capability must not specify a different invocation target")
	})

	t.Run("error: no support for multiple capabilityChains", func(t *testing.T) {
		rootCapability := rootCapability()
		capability := capability()
		require.Equal(t, capability.Parent, rootCapability.ID)
		capability.Proof = []verifiable.Proof{{
			"proofPurpose": "capabilityDelegation",
			"capabilityChain": []string{
				rootCapability.ID + "123",
				rootCapability.ID,
			},
		}}
		verifier := verifier(t, SimpleCapabilityResolver{
			rootCapability.ID:         rootCapability,
			rootCapability.ID + "123": rootCapability,
		})
		err := verifier.Verify(
			&zcapld.Proof{
				Capability:         capability,
				CapabilityAction:   "read",
				VerificationMethod: capability.Invoker,
			},
			invocation(),
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), "multiple capabilityChains not supported yet")
	})
}

func verifier(t *testing.T, r zcapld.CapabilityResolver) *zcapld.Verifier {
	t.Helper()

	v, err := zcapld.NewVerifier(r)
	require.NoError(t, err)

	return v
}

func invocation() *zcapld.CapabilityInvocation {
	return &zcapld.CapabilityInvocation{
		ExpectedTarget:         "https://foo.com/edvs/z19rnXA8d4TPLPHoSFwnQk256/documents/z19pj5XguLxKdXjxj38o7mDj3",
		ExpectedAction:         "read",
		ExpectedRootCapability: "https://foo.com/edvs/z19rnXA8d4TPLPHoSFwnQk256/zcaps/documents/z19pj5XguLxKdXjxj38o7mDj3",
		VerificationMethod: &zcapld.VerificationMethod{
			ID:         "did:key:z6MkfYbPxUoctzT3xYQCGEQHsM6aw4hTCQ4AiAmgx4kHJdgo",
			Controller: "did:key:z6MkfYbPxUoctzT3xYQCGEQHsM6aw4hTCQ4AiAmgx4kHJdgo",
		},
	}
}

func capability() *zcapld.Capability {
	return &zcapld.Capability{
		ID:            "urn:zcap:z1A2PQ4RQKnnxhZBJTtACsx4C",
		Invoker:       "did:key:z6MkfYbPxUoctzT3xYQCGEQHsM6aw4hTCQ4AiAmgx4kHJdgo",
		Parent:        "https://foo.com/edvs/z19rnXA8d4TPLPHoSFwnQk256/zcaps/documents/z19pj5XguLxKdXjxj38o7mDj3",
		AllowedAction: []string{"read", "write"},
		InvocationTarget: zcapld.InvocationTarget{
			ID:   "https://foo.com/edvs/z19rnXA8d4TPLPHoSFwnQk256/documents/z19pj5XguLxKdXjxj38o7mDj3",
			Type: "urn:edv:document",
		},
		Proof: []verifiable.Proof{{
			"proofPurpose": "capabilityDelegation",
			"capabilityChain": []string{
				"https://foo.com/edvs/z19rnXA8d4TPLPHoSFwnQk256/zcaps/documents/z19pj5XguLxKdXjxj38o7mDj3",
			},
		}},
	}
}

func rootCapability() *zcapld.Capability {
	return &zcapld.Capability{
		ID: "https://foo.com/edvs/z19rnXA8d4TPLPHoSFwnQk256/zcaps/documents/z19pj5XguLxKdXjxj38o7mDj3",
		InvocationTarget: zcapld.InvocationTarget{
			ID:   "https://foo.com/edvs/z19rnXA8d4TPLPHoSFwnQk256/documents/z19pj5XguLxKdXjxj38o7mDj3",
			Type: "urn.edv.document",
		},
		Proof: []verifiable.Proof{{
			"proofPurpose": "capabilityDelegation",
			"capabilityChain": []string{
				"https://foo.com/edvs/z19rnXA8d4TPLPHoSFwnQk256/documents/z19pj5XguLxKdXjxj38o7mDj3",
			},
		}},
	}
}

type SimpleCapabilityResolver map[string]*zcapld.Capability

func (m SimpleCapabilityResolver) Resolve(uri string) (*zcapld.Capability, error) {
	zcap, ok := m[uri]
	if !ok {
		return nil, fmt.Errorf("uri not found: %s", uri)
	}

	return zcap, nil
}
