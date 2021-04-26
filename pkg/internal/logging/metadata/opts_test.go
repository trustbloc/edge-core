/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package metadata_test

import (
	"fmt"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/edge-core/pkg/internal/logging/metadata"
)

func TestLevels(t *testing.T) {
	module := "sample-module-critical"
	metadata.SetLevel(module, metadata.CRITICAL)
	require.Equal(t, metadata.CRITICAL, metadata.GetLevel(module))
	verifyLevels(t,
		module,
		[]metadata.Level{metadata.CRITICAL},
		[]metadata.Level{metadata.ERROR, metadata.WARNING, metadata.INFO, metadata.DEBUG},
	)

	module = "sample-module-error"
	metadata.SetLevel(module, metadata.ERROR)
	require.Equal(t, metadata.ERROR, metadata.GetLevel(module))
	verifyLevels(t,
		module,
		[]metadata.Level{metadata.CRITICAL, metadata.ERROR},
		[]metadata.Level{metadata.WARNING, metadata.INFO, metadata.DEBUG},
	)

	module = "sample-module-warning"
	metadata.SetLevel(module, metadata.WARNING)
	require.Equal(t, metadata.WARNING, metadata.GetLevel(module))
	verifyLevels(t,
		module,
		[]metadata.Level{metadata.CRITICAL, metadata.ERROR, metadata.WARNING},
		[]metadata.Level{metadata.INFO, metadata.DEBUG},
	)

	module = "sample-module-info"
	metadata.SetLevel(module, metadata.INFO)
	require.Equal(t, metadata.INFO, metadata.GetLevel(module))
	verifyLevels(t,
		module,
		[]metadata.Level{metadata.CRITICAL, metadata.ERROR, metadata.WARNING, metadata.INFO},
		[]metadata.Level{metadata.DEBUG},
	)

	module = "sample-module-debug"
	metadata.SetLevel(module, metadata.DEBUG)
	require.Equal(t, metadata.DEBUG, metadata.GetLevel(module))
	verifyLevels(t,
		module,
		[]metadata.Level{metadata.CRITICAL, metadata.ERROR, metadata.WARNING, metadata.INFO, metadata.DEBUG},
		[]metadata.Level{},
	)
}

func TestGetAllLevels(t *testing.T) {
	sampleModuleCritical := "sample-module-critical"
	metadata.SetLevel(sampleModuleCritical, metadata.CRITICAL)

	sampleModuleWarning := "sample-module-warning"
	metadata.SetLevel(sampleModuleWarning, metadata.WARNING)

	allLogLevels := metadata.GetAllLevels()
	require.Equal(t, metadata.Level(0), allLogLevels[sampleModuleCritical])
	require.Equal(t, metadata.Level(2), allLogLevels[sampleModuleWarning])
}

func TestCallerInfos(t *testing.T) {
	// nolint:gosec // use of weak random num generator is fine for these tests
	module := fmt.Sprintf("sample-module-caller-info-%d-%d", rand.Intn(1000), rand.Intn(1000))

	require.True(t, metadata.IsCallerInfoEnabled(module, metadata.CRITICAL))
	require.True(t, metadata.IsCallerInfoEnabled(module, metadata.DEBUG))
	require.True(t, metadata.IsCallerInfoEnabled(module, metadata.INFO))
	require.True(t, metadata.IsCallerInfoEnabled(module, metadata.ERROR))
	require.True(t, metadata.IsCallerInfoEnabled(module, metadata.WARNING))

	metadata.ShowCallerInfo(module, metadata.CRITICAL)
	metadata.ShowCallerInfo(module, metadata.DEBUG)
	metadata.HideCallerInfo(module, metadata.INFO)
	metadata.HideCallerInfo(module, metadata.ERROR)
	metadata.HideCallerInfo(module, metadata.WARNING)

	require.True(t, metadata.IsCallerInfoEnabled(module, metadata.CRITICAL))
	require.True(t, metadata.IsCallerInfoEnabled(module, metadata.DEBUG))
	require.False(t, metadata.IsCallerInfoEnabled(module, metadata.INFO))
	require.False(t, metadata.IsCallerInfoEnabled(module, metadata.ERROR))
	require.False(t, metadata.IsCallerInfoEnabled(module, metadata.WARNING))

	require.True(t, metadata.IsCallerInfoEnabled(module, metadata.CRITICAL))
	require.True(t, metadata.IsCallerInfoEnabled(module, metadata.DEBUG))
	require.False(t, metadata.IsCallerInfoEnabled(module, metadata.INFO))
	require.False(t, metadata.IsCallerInfoEnabled(module, metadata.ERROR))
	require.False(t, metadata.IsCallerInfoEnabled(module, metadata.WARNING))
}

func verifyLevels(t *testing.T, module string, enabled, disabled []metadata.Level) {
	t.Helper()

	for _, level := range enabled {
		actual := metadata.IsEnabledFor(module, level)
		require.True(t,
			actual, "expected level [%s] to be enabled for module [%s]", metadata.ParseString(level), module)
	}

	for _, level := range disabled {
		actual := metadata.IsEnabledFor(module, level)
		require.False(t,
			actual, "expected level [%s] to be disabled for module [%s]", metadata.ParseString(level), module)
	}
}
