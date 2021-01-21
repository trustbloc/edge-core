/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package zcapld

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/jsonld"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/proof"
	ariessigner "github.com/hyperledger/aries-framework-go/pkg/doc/signature/signer"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
)

// ParseCapability parses a Capability.
func ParseCapability(raw []byte) (*Capability, error) {
	zcap := &Capability{}

	err := json.Unmarshal(raw, zcap)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal zcap: %w", err)
	}

	return zcap, nil
}

// CapabilityOptions configures capabilities.
type CapabilityOptions struct {
	ID                  string
	Parent              string
	Invoker             string
	Controller          string
	Delegator           string
	AllowedAction       []string
	InvocationTarget    InvocationTarget
	Challenge           string
	Domain              string
	CapabilityChain     []interface{}
	DocumentLoaderCache map[string]interface{}
}

// CapabilityOption configures CapabilityOptions.
type CapabilityOption func(options *CapabilityOptions)

// WithID overrides the default ID (urn:uuid:<uuid value>) used.
func WithID(id string) CapabilityOption {
	return func(o *CapabilityOptions) {
		o.ID = id
	}
}

// WithParent identifies the parent Capability.
func WithParent(p string) CapabilityOption {
	return func(o *CapabilityOptions) {
		o.Parent = p
	}
}

// WithInvoker identifies the invoker of the Capability.
func WithInvoker(i string) CapabilityOption {
	return func(o *CapabilityOptions) {
		o.Invoker = i
	}
}

// WithController identifies the controller of the Capability.
func WithController(c string) CapabilityOption {
	return func(o *CapabilityOptions) {
		o.Controller = c
	}
}

// WithDelegator identifies the delegator of the Capability.
func WithDelegator(d string) CapabilityOption {
	return func(o *CapabilityOptions) {
		o.Delegator = d
	}
}

// WithAllowedActions sets the actions allowed by the Capability.
func WithAllowedActions(actions ...string) CapabilityOption {
	return func(o *CapabilityOptions) {
		o.AllowedAction = actions
	}
}

// WithInvocationTarget sets the invocation target on the Capability.
func WithInvocationTarget(targetID, targetType string) CapabilityOption {
	return func(o *CapabilityOptions) {
		o.InvocationTarget = InvocationTarget{
			ID:   targetID,
			Type: targetType,
		}
	}
}

// WithChallenge sets the challenge to include in the proof.
func WithChallenge(c string) CapabilityOption {
	return func(o *CapabilityOptions) {
		o.Challenge = c
	}
}

// WithDomain sets the domain to include in the proof.
func WithDomain(d string) CapabilityOption {
	return func(o *CapabilityOptions) {
		o.Domain = d
	}
}

// WithCapabilityChain specifies the capabilityChain on the proof for the Capability.
func WithCapabilityChain(chain ...interface{}) CapabilityOption {
	return func(o *CapabilityOptions) {
		o.CapabilityChain = chain
	}
}

// WithDocumentLoaderCache sets cached contexts to be used by JSON-LD context document loader.
func WithDocumentLoaderCache(cache map[string]interface{}) CapabilityOption {
	return func(o *CapabilityOptions) {
		o.DocumentLoaderCache = cache
	}
}

// Signer signs the Capability.
type Signer struct {
	ariessigner.SignatureSuite
	SuiteType          string
	VerificationMethod string
}

// NewCapability constructs a new, signed Capability with the options provided.
func NewCapability(signer *Signer, options ...CapabilityOption) (*Capability, error) {
	if signer == nil {
		return nil, errors.New("must provide a signer")
	}

	opts := &CapabilityOptions{
		ID: fmt.Sprintf("urn:uuid:%s", uuid.New().String()),
	}

	for i := range options {
		options[i](opts)
	}

	zcap := &Capability{
		Context:          SecurityContextV2,
		ID:               opts.ID,
		Invoker:          opts.Invoker,
		Controller:       opts.Controller,
		Delegator:        opts.Delegator,
		Parent:           opts.Parent,
		AllowedAction:    opts.AllowedAction,
		InvocationTarget: opts.InvocationTarget,
	}

	err := signZCAP(zcap, signer, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to sign zcap: %w", err)
	}

	return zcap, nil
}

func signZCAP(zcap *Capability, signer *Signer, options *CapabilityOptions) error {
	raw, err := json.Marshal(zcap)
	if err != nil {
		return fmt.Errorf("failed to marshal zcap: %w", err)
	}

	nonce, err := nonce()
	if err != nil {
		return fmt.Errorf("failed to generate a nonce: %w", err)
	}

	now := time.Now()
	ldSigner := ariessigner.New(signer)

	signedDoc, err := ldSigner.Sign(
		&ariessigner.Context{
			SignatureType:           signer.SuiteType,
			SignatureRepresentation: proof.SignatureJWS,
			Created:                 &now,
			Domain:                  options.Domain,
			Nonce:                   nonce,
			VerificationMethod:      signer.VerificationMethod,
			Challenge:               options.Challenge,
			Purpose:                 ProofPurpose,
			CapabilityChain:         options.CapabilityChain,
		},
		raw,
		jsonld.WithDocumentLoaderCache(options.DocumentLoaderCache),
	)
	if err != nil {
		return fmt.Errorf("document signer failed to sign zcap: %w", err)
	}

	zcap.Proof, err = parseProofs(signedDoc)
	if err != nil {
		return fmt.Errorf("failed to parse proof for zcap: %w", err)
	}

	return nil
}

func nonce() ([]byte, error) {
	n := make([]byte, 64)

	_, err := rand.Reader.Read(n)
	if err != nil {
		return nil, fmt.Errorf("failed to read from crypto/rand: %w", err)
	}

	return n, nil
}

func parseProofs(signedZcap []byte) ([]verifiable.Proof, error) {
	rawProof := &struct {
		Proof json.RawMessage `json:"proof,omitempty"`
	}{}

	err := json.Unmarshal(signedZcap, rawProof)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal zcap to extract proof: %w", err)
	}

	var proofs []verifiable.Proof

	err = json.Unmarshal(rawProof.Proof, &proofs)
	if err != nil {
		return nil, fmt.Errorf("failed to parse proof: %w", err)
	}

	return proofs, nil
}
