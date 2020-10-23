/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package logspec_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/edge-core/pkg/restapi/logspec"
)

func TestController_New(t *testing.T) {
	t.Run("create new controller", func(t *testing.T) {
		controller := logspec.New()
		require.NotNil(t, controller)
	})
}

func TestController_GetOperations(t *testing.T) {
	ops := logspec.New().GetOperations()
	require.Equal(t, 2, len(ops))
}
