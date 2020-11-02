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
	didkey "github.com/hyperledger/aries-framework-go/pkg/vdr/key"
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

// DIDKeyResolver resolves verification keys from did:key URLs: https://w3c-ccg.github.io/did-method-key/.
type DIDKeyResolver struct {
}

// Resolve expects 'didKeyURL' to be a did:key URL.
// Example: "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH#z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH".
func (d *DIDKeyResolver) Resolve(didKeyURL string) (*verifier.PublicKey, error) {
	const numParts = 2

	parts := strings.Split(didKeyURL, "#")
	if len(parts) != numParts {
		return nil, fmt.Errorf("not a did:key URL: %s", didKeyURL)
	}

	doc, err := didkey.New().Read(parts[0])
	if err != nil {
		return nil, fmt.Errorf("failed to parse url %s: %w", parts[0], err)
	}

	for _, vm := range doc.VerificationMethods(did.CapabilityDelegation)[did.CapabilityDelegation] {
		if parts[1] == vm.PublicKey.ID || didKeyURL == vm.PublicKey.ID {
			return &verifier.PublicKey{
				Type:  vm.PublicKey.Type,
				Value: vm.PublicKey.Value,
				JWK:   vm.PublicKey.JSONWebKey(),
			}, nil
		}
	}

	return nil, fmt.Errorf("did:key URL does not reference a key contained in itself: %s", didKeyURL)
}
