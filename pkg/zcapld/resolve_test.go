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
