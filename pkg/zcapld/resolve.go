/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package zcapld

import (
	"fmt"

	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/verifier"
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
