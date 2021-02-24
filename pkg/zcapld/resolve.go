/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package zcapld

import (
	"fmt"
	"strings"

	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/verifier"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/vdr"
	vdrkey "github.com/hyperledger/aries-framework-go/pkg/vdr/key"
)

// KeyResolver resolves verification keys.
type KeyResolver interface {
	Resolve(keyID string) (*verifier.PublicKey, error)
}

// CapabilityResolver resolves capabilities.
type CapabilityResolver interface {
	Resolve(uri string) (*Capability, error)
}

// SimpleCapabilityResolver enables in-memory capability resolvers based on maps.
type SimpleCapabilityResolver map[string]*Capability

// Resolve resolves capabilities.
func (s SimpleCapabilityResolver) Resolve(uri string) (*Capability, error) {
	zcap, ok := s[uri]
	if !ok {
		return nil, fmt.Errorf("uri not found: %s", uri)
	}

	return zcap, nil
}

// SimpleKeyResolver enables in-memory key resolvers based on maps.
type SimpleKeyResolver map[string]*verifier.PublicKey

// Resolve resolves keys.
func (s SimpleKeyResolver) Resolve(keyID string) (*verifier.PublicKey, error) {
	key, ok := s[keyID]
	if !ok {
		return nil, fmt.Errorf("keyID not found: %s", keyID)
	}

	return key, nil
}

type dummyProvider struct{}

func (dummyProvider) KMS() kms.KeyManager {
	return nil
}

// NewDIDKeyResolver creates new DID resolver.
func NewDIDKeyResolver(v VDRResolver) *DIDKeyResolver {
	if v != nil {
		return &DIDKeyResolver{VDR: v}
	}

	return &DIDKeyResolver{VDR: vdr.New(dummyProvider{}, vdr.WithVDR(vdrkey.New()))}
}

// DIDKeyResolver resolves verification keys from did:key URLs: https://w3c-ccg.github.io/did-method-key/.
type DIDKeyResolver struct {
	VDR VDRResolver
}

// Resolve expects 'didKeyURL' to be a did:key URL.
// Example: "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH#z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH".
func (d *DIDKeyResolver) Resolve(didKeyURL string) (*verifier.PublicKey, error) {
	const numParts = 2

	parts := strings.Split(didKeyURL, "#")
	if len(parts) != numParts {
		return nil, fmt.Errorf("not a did:key URL: %s", didKeyURL)
	}

	docResolution, err := d.VDR.Resolve(parts[0])
	if err != nil {
		return nil, fmt.Errorf("failed to parse url %s: %w", parts[0], err)
	}

	for _, vm := range docResolution.DIDDocument.VerificationMethods(did.CapabilityDelegation)[did.CapabilityDelegation] {
		if parts[1] == vm.VerificationMethod.ID || didKeyURL == vm.VerificationMethod.ID {
			return &verifier.PublicKey{
				Type:  vm.VerificationMethod.Type,
				Value: vm.VerificationMethod.Value,
				JWK:   vm.VerificationMethod.JSONWebKey(),
			}, nil
		}
	}

	return nil, fmt.Errorf("did:key URL does not reference a key contained in itself: %s", didKeyURL)
}
