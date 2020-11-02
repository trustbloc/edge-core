/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package zcapld_test

import (
	"testing"

	"github.com/google/uuid"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose"
	ariesver "github.com/hyperledger/aries-framework-go/pkg/doc/signature/verifier"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/edge-core/pkg/zcapld"
)

func TestSimpleKeyResolver_Resolve(t *testing.T) {
	t.Run("resolves the key", func(t *testing.T) {
		expected := &ariesver.PublicKey{
			Type:  uuid.New().String(),
			Value: []byte("test bytes"),
			JWK:   &jose.JWK{},
		}
		r := zcapld.SimpleKeyResolver{
			"keyID": expected,
		}
		result, err := r.Resolve("keyID")
		require.NoError(t, err)
		require.Equal(t, expected, result)
	})

	t.Run("fails if key not found", func(t *testing.T) {
		r := zcapld.SimpleKeyResolver{}
		_, err := r.Resolve("not found")
		require.Error(t, err)
	})
}

func TestDIDKeyResolver_Resolve(t *testing.T) {
	t.Run("resolves a verification key from a did:key URL", func(t *testing.T) {
		didKeyURL := "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH#" +
			"z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH"
		r := &zcapld.DIDKeyResolver{}
		result, err := r.Resolve(didKeyURL)
		require.NoError(t, err)
		require.Equal(t, "Ed25519VerificationKey2018", result.Type)
		require.Greater(t, len(result.Value), 0)
	})

	t.Run("fails if url does not have a fragment", func(t *testing.T) {
		_, err := (&zcapld.DIDKeyResolver{}).Resolve("did:key:123")
		require.Error(t, err)
		require.Contains(t, err.Error(), "not a did:key URL")
	})

	t.Run("fails if referenced key is not in the did:key doc", func(t *testing.T) {
		// fragment references a non-existent identifier
		didKeyURL := "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH#INEXISTENT"
		r := &zcapld.DIDKeyResolver{}
		_, err := r.Resolve(didKeyURL)
		require.Error(t, err)
		require.Contains(t, err.Error(), "did:key URL does not reference a key contained in itself")
	})

	t.Run("fails if DID url is not of method 'key'", func(t *testing.T) {
		url := "did:WRONG:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH#" +
			"z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH"
		_, err := (&zcapld.DIDKeyResolver{}).Resolve(url)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to parse url")
	})
}
