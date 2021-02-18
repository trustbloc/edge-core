/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package zcapld

import (
	"errors"
	"fmt"
	"reflect"

	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
)

const (
	// SecurityContextV2 is the JSON-LD context used in ZCAP-LD documents.
	SecurityContextV2 = "https://w3id.org/security/v2"
	// ProofPurpose is the proofPurpose set on proofs in ZCAP-LD documents.
	ProofPurpose = "capabilityDelegation"

	proofPurposeField         = "proofPurpose"
	proofCapabilityChainField = "capabilityChain"
)

// CapabilityInvocation describes the parameters for invocation of a capability.
type CapabilityInvocation struct {
	ExpectedTarget         string
	ExpectedAction         string
	ExpectedRootCapability string
	VerificationMethod     *VerificationMethod // loaded from the http sig's keyId
}

// VerificationMethod to use to verify an invocation.
type VerificationMethod struct {
	ID         string
	Controller string
}

// Capability is a ZCAP.
type Capability struct {
	Context          string             `json:"@context"`
	ID               string             `json:"id"`
	Invoker          string             `json:"invoker,omitempty"`
	Controller       string             `json:"controller,omitempty"`
	Delegator        string             `json:"delegator,omitempty"`
	Parent           string             `json:"parentCapability,omitempty"`
	AllowedAction    []string           `json:"allowedAction,omitempty"`
	InvocationTarget InvocationTarget   `json:"invocationTarget"`
	Caveats          []Caveat           `json:"caveats"`
	Proof            []verifiable.Proof `json:"proof,omitempty"`
}

// InvocationTarget is the target on which the capability applies.
type InvocationTarget struct {
	ID   string
	Type string
}

// invokers are this capability's entities authorized to invoke the invocation target.
func (c *Capability) invokers() ([]string, error) {
	// if neither an invoker, controller, nor id is found on the capability then
	// the capability can not be invoked
	if c.Invoker == "" && c.Controller == "" && c.ID == "" {
		return nil, errors.New("invoker not found for capability")
	}

	// if there's a delegator present and not an invoker, then this capability
	// was intentionally meant to not be invoked:
	// https://github.com/digitalbazaar/ocapld.js/blob/8a54398162837b1cf52c82978bc8127e52d02974/lib/utils.js#L52-L56
	if c.Delegator != "" && c.Invoker == "" {
		return []string{}, nil
	}

	invoker := c.Invoker

	if invoker == "" {
		invoker = c.Controller
	}

	if invoker == "" {
		invoker = c.ID
	}

	// TODO revisit datatypes of invoker and controller. ocapld.js accounts for any of them to be arrays.
	return []string{invoker}, nil
}

// validateCapabilityChain validates the capability chain list, ensuring, for instance, it contains only
// IDs except possibly last entry (which can be a full embedded capability),
// that all IDs are all absolute URLs, and that it contains no cycles.
// https://github.com/digitalbazaar/ocapld.js/blob/8a54398162837b1cf52c82978bc8127e52d02974/lib/utils.js#L299
func (c *Capability) validateCapabilityChain() error {
	chain, err := c.capabilityChain()
	if err != nil {
		return fmt.Errorf("failed to get capabilityChain: %w", err)
	}

	// TODO no logic for this, no test cases either
	if len(chain) == 0 {
		return nil
	}

	uniqueLinks := make(map[string]*struct{})

	for i := range chain {
		link := chain[i]

		id, ok := link.(string)
		if !ok {
			return errors.New("embedded capabilities in capabilityChain not supported yet")
		}

		uniqueLinks[id] = nil
	}

	uniqueLinks[c.ID] = nil

	if len(uniqueLinks) != len(chain)+1 {
		return errors.New("the capability chain contains a cycle")
	}

	return nil
}

// capabilityChain is the chain of capabilities of this zcap.
func (c *Capability) capabilityChain() ([]interface{}, error) {
	// root capability has no chain:
	// https://github.com/digitalbazaar/ocapld.js/blob/8a54398162837b1cf52c82978bc8127e52d02974/lib/utils.js#L196-L199
	if c.Parent == "" {
		return []interface{}{}, nil
	}

	proofs, err := c.delegationProofs()
	if err != nil {
		return nil, fmt.Errorf("capabilityChain: failed to fetch delegationProofs: %w", err)
	}

	if len(proofs) == 0 {
		return nil, fmt.Errorf("no delegatable proofs found in capability %s", c.ID)
	}

	untyped, ok := proofs[0][proofCapabilityChainField]
	if !ok {
		return nil, fmt.Errorf("no capabilityChain in delegatable proof: %+v", proofs[0])
	}

	switch v := untyped.(type) {
	case []interface{}:
		return v, nil
	case []string:
		r := make([]interface{}, len(v))
		for i := range v {
			r[i] = v[i]
		}

		return r, nil
	default:
		return nil, fmt.Errorf("invalid capabilityChain format: %+v", untyped)
	}
}

// delegationProofs are the proofs for delegation on this capability.
func (c *Capability) delegationProofs() ([]verifiable.Proof, error) {
	// if capability has no parent then it is root and has no relevant delegation proofs:
	// https://github.com/digitalbazaar/ocapld.js/blob/8a54398162837b1cf52c82978bc8127e52d02974/lib/utils.js#L167-L170
	if c.Parent == "" {
		return []verifiable.Proof{}, nil
	}

	proofs := make([]verifiable.Proof, 0)

	for i := range c.Proof {
		p := c.Proof[i]

		if p[proofPurposeField] != "capabilityDelegation" {
			continue
		}

		chain, err := proofCapabilityChain(p)
		if err != nil {
			return nil, fmt.Errorf("delegationProofs: failed to fetch capability chain: %w", err)
		}

		if len(chain) == 0 {
			continue
		}

		last := chain[len(chain)-1]

		uri, ok := last.(string)
		if ok && uri == c.Parent {
			proofs = append(proofs, p)

			continue
		}

		if c.ID == c.Parent {
			proofs = append(proofs, p)
		}
	}

	return proofs, nil
}

func proofCapabilityChain(proof verifiable.Proof) ([]interface{}, error) {
	// formal definition of `capabilityChain` is missing, see https://github.com/w3c-ccg/security-vocab/issues/28.
	// going with examples here for now:
	// https://github.com/decentralized-identity/secure-data-store/issues/113#issuecomment-705216470.
	proofChain, ok := proof[proofCapabilityChainField]
	if !ok {
		return nil, errors.New("missing proof capabilityChain")
	}

	switch v := proofChain.(type) {
	case []interface{}:
		return v, nil
	case []string:
		r := make([]interface{}, len(v))

		for i := range v {
			r[i] = v[i]
		}

		return r, nil
	default:
		return nil, fmt.Errorf(
			"invalid proof capabilityChain format: value=%+v type=%s",
			proofChain, reflect.TypeOf(proofChain).String())
	}
}
