/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package base_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/edge-core/pkg/sss/base"
)

func TestSplitter(t *testing.T) {
	secret := []byte("randomSecret")

	sss := base.Splitter{}
	secrets, err := sss.Split(secret, base.DefaultNumParts, base.DefaultNumParts)
	require.NoError(t, err)

	t.Run("call Combine with a random part should not match original secret", func(t *testing.T) {
		reconstructed, err := sss.Combine([][]byte{secrets[1], []byte("someRandomPart")[:len(secrets[0])]})
		require.NoError(t, err)
		require.NotEqualValues(t, secret, reconstructed)
	})

	t.Run("call Combine with the original split parts should match original secret", func(t *testing.T) {
		reconstructed, err := sss.Combine(secrets)
		require.NoError(t, err)
		require.EqualValues(t, secret, reconstructed)
	})
}
