/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

// package base contains a basic Splitter implementation.

package base

import (
	"github.com/hashicorp/vault/shamir"
)

// DefaultNumParts is the default number of splits of a secret.
const DefaultNumParts = 2

// Splitter is an implementation to split a secret into multiple parts and the ability to reconstruct it.
type Splitter struct{}

// Split a secret into numParts (minimum 2) of secret parts and sets a minimum threshold to reconstruct it.
func (b *Splitter) Split(secret []byte, numParts, threshold int) ([][]byte, error) {
	return shamir.Split(secret, numParts, threshold)
}

// Combine the split secretParts into a combined secret. It does not validate if secretParts where split from the
// same original secret. ie the caller of Split() must validate that the returned value of Combine matches the original
// secret.
func (b *Splitter) Combine(secretParts [][]byte) ([]byte, error) {
	return shamir.Combine(secretParts)
}
