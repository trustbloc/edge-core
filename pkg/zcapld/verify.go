/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package zcapld

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/jsonld"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/verifier"
	"github.com/piprate/json-gold/ld"
)

// Verifier verifies zcaps.
type Verifier struct {
	zcaps      CapabilityResolver
	keys       KeyResolver
	verifier   *verifier.DocumentVerifier
	ldProcOpts []jsonld.ProcessorOpts
}

// Proof describes the capability, the action, and the verification method of an invocation.
type Proof struct {
	Capability         *Capability
	CapabilityAction   string
	VerificationMethod string
}

// VerificationOptions holds options for the Verifier.
type VerificationOptions struct {
	LDProcessorOptions []jsonld.ProcessorOpts
	SignatureSuites    []verifier.SignatureSuite
}

// VerificationOption sets an option for the Verifier.
type VerificationOption func(*VerificationOptions)

// WithSignatureSuites sets the signature suites supported by the Verifier.
func WithSignatureSuites(suites ...verifier.SignatureSuite) VerificationOption {
	return func(o *VerificationOptions) {
		o.SignatureSuites = append(o.SignatureSuites, suites...)
	}
}

// WithLDDocumentLoaders sets the JSON-LD document loaders for the Verifier.
func WithLDDocumentLoaders(loaders ...ld.DocumentLoader) VerificationOption {
	return func(o *VerificationOptions) {
		for i := range loaders {
			o.LDProcessorOptions = append(o.LDProcessorOptions, jsonld.WithDocumentLoader(loaders[i]))
		}
	}
}

// NewVerifier returns a new Verifier.
func NewVerifier(
	zcapResolver CapabilityResolver, keyResolver KeyResolver, options ...VerificationOption) (*Verifier, error) {
	opts := &VerificationOptions{}

	for i := range options {
		options[i](opts)
	}

	v, err := verifier.New(keyResolver, opts.SignatureSuites...)
	if err != nil {
		return nil, fmt.Errorf("failed to init document verifier: %w", err)
	}

	return &Verifier{
		zcaps:      zcapResolver,
		keys:       keyResolver,
		verifier:   v,
		ldProcOpts: opts.LDProcessorOptions,
	}, nil
}

// Verify the proof against the invocation.
func (v *Verifier) Verify(proof *Proof, invocation *CapabilityInvocation) error {
	if proof.Capability == nil {
		return errors.New(`"capability" was not found in the capability invocation proof`)
	}

	// 1. get the capability in the security v2 context
	// **We have already resolved and parsed the full capability**

	// 2. verify the capability delegation chain
	err := v.verifyCapabilityChain(proof.Capability, proof.CapabilityAction, invocation)
	if err != nil {
		return fmt.Errorf("invalid capability chain: %w", err)
	}

	// 3. verify the invoker...
	// authorized invoker must match the verification method itself OR
	// the controller of the verification method
	isInvoker, err := isInvoker(proof.Capability, invocation.VerificationMethod)
	if err != nil {
		return fmt.Errorf("isInvoke: %w", err)
	}

	if !isInvoker {
		return errors.New("the authorized invoker does not match the verification method or its controller")
	}

	// Begin ControllerProofPurpose

	// TODO the code here validates the proof's "created" time against an expected time:
	//  nolint:lll // don't want to break the link in two
	//  https://github.com/digitalbazaar/jsonld-signatures/blob/8d91bcb351702dde4863fab660d7ca1e5e90b2a2/lib/purposes/ProofPurpose.js#L49-L57.
	//  Note: the higher layers in bedrock-edv-storage don't actually set `proof.created`, so `created` is always NaN.
	//  Do we really need to verify the proof's date at this layer though? Isn't that the responsibility of a higher
	//  layer, ie the one that parses and verifies the http signature?

	// TODO verify authorization of verificationMethod.ID by controller for proof purpose `capabilityInvocation`.
	//  Controller are probably DIDs. They have a "capabilityInvocation" property (just like DIDs) that has
	//  verificationMethod IDs.

	err = v.verifyProof(proof.Capability)
	if err != nil {
		return fmt.Errorf("failed to verify proof: %w", err)
	}

	return nil
}

// nolint:funlen,gocyclo // TODO decompose verifyCapabilityChain into smaller units
func (v *Verifier) verifyCapabilityChain(
	capability *Capability, intendedAction string, invocation *CapabilityInvocation) error {
	// 1.1. Ensure `capabilityAction`, if given, is allowed; if the capability
	// restricts the actions via `allowedAction` then it must be in the set.
	if len(capability.AllowedAction) > 0 && intendedAction != "" &&
		!stringsContain(capability.AllowedAction, intendedAction) {
		return fmt.Errorf(
			`capability action "%s" is not allowed by the capability; allowed actions are: %+v`,
			intendedAction, capability.AllowedAction)
	}

	if invocation.ExpectedAction != intendedAction {
		return fmt.Errorf(
			`capability action "%s" does not match the expected capability action of "%s"`,
			intendedAction, invocation.ExpectedAction)
	}

	// 3. Validate the capability delegation chain.
	err := capability.validateCapabilityChain()
	if err != nil {
		return fmt.Errorf("invalid capability chain: %w", err)
	}

	// 2. Get the capability delegation chain for the capability.
	capabilityChain, err := capability.capabilityChain()
	if err != nil {
		return fmt.Errorf("failed to fetch capabilityChain: %w", err)
	}

	// 4. Verify root capability (note: it must *always* be dereferenced since
	// it does not need to have a delegation proof to vouch for its authenticity
	// ... dereferencing it prevents adversaries from submitting an invalid
	// root capability that is accepted):
	isRoot := len(capabilityChain) == 0

	var rootURI string

	if isRoot {
		rootURI = capability.ID
	} else {
		untyped := capabilityChain[0]
		capabilityChain = capabilityChain[1:]

		var ok bool

		rootURI, ok = untyped.(string)
		if !ok {
			return fmt.Errorf("invalid rootURI format: %v", untyped)
		}
	}

	root, err := v.zcaps.Resolve(rootURI)
	if err != nil {
		return fmt.Errorf("failed to resolve root capability URI %s: %w", rootURI, err)
	}

	// 4.1. Check the expected target, if one was specified.
	// TODO revisit the datatypes assumed of the invocationTarget.ID in this algo:
	//  https://github.com/digitalbazaar/ocapld.js/blob/8a54398162837b1cf52c82978bc8127e52d02974/lib/utils.js#L115
	if invocation.ExpectedTarget != "" && invocation.ExpectedTarget != root.InvocationTarget.ID {
		return fmt.Errorf(
			`expected target does not match root capability target: expected="%s" target="%s"`,
			invocation.ExpectedTarget, root.InvocationTarget.ID)
	}

	// 4.2. Ensure that the caveats are met on the root capability.
	// TODO verify caveats

	// TODO verify expiry on root capability

	// 4.3. Ensure root capability is expected and has no invocation target.
	if invocation.ExpectedRootCapability != "" && invocation.ExpectedRootCapability != root.ID {
		return fmt.Errorf(
			"expected root capability does not match actual root capability: expected=(%s) actual=(%s)",
			invocation.ExpectedRootCapability, root.ID)
	}

	// TODO weird error condition
	if invocation.ExpectedRootCapability == "" && root.InvocationTarget.ID != root.ID {
		return errors.New("the root capability must not specify a different invocation target")
	}

	if isRoot {
		return nil
	}

	err = v.verifyCapabilityChainAttenuation(root, capability, capabilityChain)
	if err != nil {
		return fmt.Errorf("failed to verify capabilityChain attenuation: %w", err)
	}

	return nil
}

func (v *Verifier) verifyProof(capability *Capability) error {
	bits, err := json.Marshal(capability)
	if err != nil {
		return fmt.Errorf("failed to marshal capability: %w", err)
	}

	err = v.verifier.Verify(bits, v.ldProcOpts...)
	if err != nil {
		return fmt.Errorf("document verifier error: %w", err)
	}

	return nil
}

func (v *Verifier) verifyCapabilityChainAttenuation(
	start *Capability, end *Capability, intermediates []interface{}) error {
	// verify proofs and attenuation
	// traverse in order from start to end
	prev := start

	for i := range intermediates {
		id := fmt.Sprintf("%s", intermediates[i])

		next, err := v.zcaps.Resolve(id)
		if err != nil {
			return fmt.Errorf("failed to resolve capability %s: %w", id, err)
		}

		err = v.verifyProof(next)
		if err != nil {
			return fmt.Errorf("failed to verify proof on capability %s: %w", id, err)
		}

		err = verifyAttenuation(prev, next)
		if err != nil {
			return fmt.Errorf(
				"failed to verify attenuation of zcap %s against parent %s: %w",
				prev.ID, next.ID, err,
			)
		}

		prev = next
	}

	// finally, verify the end capability's attenuation versus its immediate parent
	err := verifyAttenuation(prev, end)
	if err != nil {
		return fmt.Errorf(
			"failed to verify attenuation of zcap %s against parent %s: %w",
			prev.ID, end.ID, err,
		)
	}

	return nil
}

func verifyAttenuation(parent, child *Capability) error {
	for i := range child.AllowedAction {
		if !stringsContain(parent.AllowedAction, child.AllowedAction[i]) {
			return fmt.Errorf("action '%s' not allowed by parent", child.AllowedAction[i])
		}
	}

	return nil
}

func stringsContain(strs []string, s string) bool {
	for i := range strs {
		if s == strs[i] {
			return true
		}
	}

	return false
}

func isInvoker(capability *Capability, verificationMethod *VerificationMethod) (bool, error) {
	invokers, err := capability.invokers()
	if err != nil {
		return false, fmt.Errorf("failed to fetch invokers: %w", err)
	}

	controller := verificationMethod.Controller

	if len(invokers) > 0 {
		return stringsContain(invokers, verificationMethod.ID) ||
			(controller != "" && stringsContain(invokers, controller)), nil
	}

	return false, nil
}
