/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

// package sss provides security API for splitting a secret into multiple parts.

package sss

// SecretSplitter is a service that splits a secret []byte into multiple parts.
type SecretSplitter interface {
	Split(secret []byte, numParts, threshold int) ([][]byte, error)
	Combine(secretParts [][]byte) ([]byte, error)
}
