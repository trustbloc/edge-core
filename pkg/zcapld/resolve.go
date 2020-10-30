/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package zcapld

import "fmt"

// CapabilityResolver resolves capabilities.
type CapabilityResolver interface {
	Resolve(uri string) (*Capability, error)
}

// SimpleCapabilityResolver enables in-memory resolvers based on maps.
type SimpleCapabilityResolver map[string]*Capability

// Resolve resolves capabilities.
func (m SimpleCapabilityResolver) Resolve(uri string) (*Capability, error) {
	zcap, ok := m[uri]
	if !ok {
		return nil, fmt.Errorf("uri not found: %s", uri)
	}

	return zcap, nil
}
