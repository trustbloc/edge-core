/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package log // nolint:testpackage // references internal implementation details

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/edge-core/pkg/internal/logging/metadata"
	"github.com/trustbloc/edge-core/pkg/internal/logging/modlog"
)

// TestDefaultLogger tests default logging feature when no custom logging provider is supplied via 'Initialize()' call.
func TestDefaultLogger(t *testing.T) {
	defer func() { loggerProviderOnce = sync.Once{} }()

	const module = "sample-module"

	// get new logger since Initialize is not called, default logger implementation will be used
	logger := New(module)

	// force logger instance loading to switch output of logger to buffer for testing
	logger.Infof("sample output")
	modlog.SwitchLogOutputToBuffer(logger.instance)

	// verify default logger
	modlog.VerifyDefaultLogging(t, logger, module, metadata.SetLevel)
}

// TestAllLevels tests logging level behaviour
// logging levels can be set per modules, if not set then it will default to 'INFO'.
func TestAllLevels(t *testing.T) {
	module := "sample-module-critical"
	SetLevel(module, CRITICAL)
	require.Equal(t, CRITICAL, GetLevel(module))
	verifyLevels(t, module, []Level{CRITICAL}, []Level{ERROR, WARNING, INFO, DEBUG})

	module = "sample-module-error"
	SetLevel(module, ERROR)
	require.Equal(t, ERROR, GetLevel(module))
	verifyLevels(t, module, []Level{CRITICAL, ERROR}, []Level{WARNING, INFO, DEBUG})

	module = "sample-module-warning"
	SetLevel(module, WARNING)
	require.Equal(t, WARNING, GetLevel(module))
	verifyLevels(t, module, []Level{CRITICAL, ERROR, WARNING}, []Level{INFO, DEBUG})

	module = "sample-module-info"
	SetLevel(module, INFO)
	require.Equal(t, INFO, GetLevel(module))
	verifyLevels(t, module, []Level{CRITICAL, ERROR, WARNING, INFO}, []Level{DEBUG})

	module = "sample-module-debug"
	SetLevel(module, DEBUG)
	require.Equal(t, DEBUG, GetLevel(module))
	verifyLevels(t, module, []Level{CRITICAL, ERROR, WARNING, INFO, DEBUG}, []Level{})
}

func TestGetAllLevels(t *testing.T) {
	sampleModuleCritical := "sample-module-critical"
	SetLevel(sampleModuleCritical, CRITICAL)

	sampleModuleWarning := "sample-module-warning"
	SetLevel(sampleModuleWarning, WARNING)

	allLogLevels := GetAllLevels()
	require.Equal(t, Level(0), allLogLevels[sampleModuleCritical])
	require.Equal(t, Level(2), allLogLevels[sampleModuleWarning])
}

// TestCallerInfos callerinfo behavior which displays caller function details in log lines
// CallerInfo is available in default logger.
// Based on implementation it may not be available for custom logger.
func TestCallerInfos(t *testing.T) {
	module := "sample-module-caller-info"

	ShowCallerInfo(module, CRITICAL)
	ShowCallerInfo(module, DEBUG)
	HideCallerInfo(module, INFO)
	HideCallerInfo(module, ERROR)
	HideCallerInfo(module, WARNING)

	require.True(t, IsCallerInfoEnabled(module, CRITICAL))
	require.True(t, IsCallerInfoEnabled(module, DEBUG))
	require.False(t, IsCallerInfoEnabled(module, INFO))
	require.False(t, IsCallerInfoEnabled(module, ERROR))
	require.False(t, IsCallerInfoEnabled(module, WARNING))
}

// TestLogLevel testing 'LogLevel()' used for parsing log levels from strings.
func TestLogLevel(t *testing.T) {
	verifyLevelsNoError := func(expected Level, levels ...string) {
		for _, level := range levels {
			actual, err := ParseLevel(level)
			require.NoError(t, err, "not supposed to fail while parsing level string [%s]", level)
			require.Equal(t, expected, actual)
		}
	}

	verifyLevelsNoError(CRITICAL, "critical", "CRITICAL", "CriticAL")
	verifyLevelsNoError(ERROR, "error", "ERROR", "ErroR")
	verifyLevelsNoError(WARNING, "warning", "WARNING", "WarninG")
	verifyLevelsNoError(DEBUG, "debug", "DEBUG", "DebUg")
	verifyLevelsNoError(INFO, "info", "INFO", "iNFo")
}

// TestParseLevelError testing 'LogLevel()' used for parsing log levels from strings.
func TestParseLevelError(t *testing.T) {
	verifyLevelError := func(levels ...string) {
		for _, level := range levels {
			_, err := ParseLevel(level)
			require.Error(t, err, "not supposed to succeed while parsing level string [%s]", level)
		}
	}

	verifyLevelError("", "D", "DE BUG", ".")
}

func TestParseString(t *testing.T) {
	criticalLogLevel := ParseString(CRITICAL)
	require.Equal(t, "CRITICAL", criticalLogLevel)

	errorLogLevel := ParseString(ERROR)
	require.Equal(t, "ERROR", errorLogLevel)

	warningLogLevel := ParseString(WARNING)
	require.Equal(t, "WARNING", warningLogLevel)

	infoLogLevel := ParseString(INFO)
	require.Equal(t, "INFO", infoLogLevel)

	debugLogLevel := ParseString(DEBUG)
	require.Equal(t, "DEBUG", debugLogLevel)
}

func TestSetSpecLogSpecPut(t *testing.T) {
	t.Run("Successfully set logging levels", func(t *testing.T) {
		resetLoggingLevels()

		require.NoError(t, SetSpec("module1=debug:module2=critical:error"))

		require.Equal(t, DEBUG, GetLevel("module1"))
		require.Equal(t, CRITICAL, GetLevel("module2"))
		require.Equal(t, ERROR, GetLevel(""))
	})

	t.Run("Successfully set logging levels - no default", func(t *testing.T) {
		resetLoggingLevels()

		require.NoError(t, SetSpec("module1=debug:module2=critical"))

		require.Equal(t, DEBUG, GetLevel("module1"))
		require.Equal(t, CRITICAL, GetLevel("module2"))
		require.Equal(t, INFO, GetLevel(""))
	})

	t.Run("Invalid log spec: default log level type is invalid", func(t *testing.T) {
		resetLoggingLevels()

		err := SetSpec("InvalidLogLevel")
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid log level")

		// Log levels should remain at the default setting of "info"
		require.Equal(t, INFO, GetLevel("module1"))
		require.Equal(t, INFO, GetLevel("module2"))
		require.Equal(t, INFO, GetLevel(""))
	})

	t.Run("Invalid log spec: module log level type is invalid", func(t *testing.T) {
		resetLoggingLevels()

		err := SetSpec("Module1=InvalidLogLevel")
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid log level")

		// Log levels should remain at the default setting of "info"
		require.Equal(t, INFO, GetLevel("module1"))
		require.Equal(t, INFO, GetLevel("module2"))
		require.Equal(t, INFO, GetLevel(""))
	})

	t.Run("Invalid log spec: multiple default log levels", func(t *testing.T) {
		resetLoggingLevels()

		err := SetSpec("debug:debug")
		require.Error(t, err)
		require.Contains(t, err.Error(), "multiple default values found")

		// Log levels should remain at the default setting of "info"
		require.Equal(t, INFO, GetLevel("module1"))
		require.Equal(t, INFO, GetLevel("module2"))
		require.Equal(t, INFO, GetLevel(""))
	})
}

func TestLogSpecGet(t *testing.T) {
	resetLoggingLevels()

	spec := GetSpec()

	t.Logf("Got spec: %s", spec)

	require.Contains(t, spec, "module1=INFO")
	require.Contains(t, spec, "module2=INFO")
	require.Contains(t, spec, ":INFO")
}

func resetLoggingLevels() {
	SetLevel("module1", INFO)
	SetLevel("module2", INFO)
	SetLevel("", INFO)
}

func verifyLevels(t *testing.T, module string, enabled, disabled []Level) {
	t.Helper()

	for _, level := range enabled {
		levelStr := metadata.ParseString(metadata.Level(level))
		require.True(t, IsEnabledFor(module, level),
			"expected level [%s] to be enabled for module [%s]", levelStr, module)
	}

	for _, level := range disabled {
		levelStr := metadata.ParseString(metadata.Level(level))
		require.False(t, IsEnabledFor(module, level),
			"expected level [%s] to be disabled for module [%s]", levelStr, module)
	}
}
