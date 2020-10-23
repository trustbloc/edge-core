/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package metadata_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/edge-core/pkg/internal/logging/metadata"
)

func TestParseLevel(t *testing.T) {
	verifyLevelsNoError := func(expected metadata.Level, levels ...string) {
		for _, level := range levels {
			actual, err := metadata.ParseLevel(level)
			require.NoError(t, err, "not supposed to fail while parsing level string [%s]", level)
			require.Equal(t, expected, actual)
		}
	}

	verifyLevelsNoError(metadata.CRITICAL, "critical", "CRITICAL", "CriticAL")
	verifyLevelsNoError(metadata.ERROR, "error", "ERROR", "ErroR")
	verifyLevelsNoError(metadata.WARNING, "warning", "WARNING", "WarninG")
	verifyLevelsNoError(metadata.DEBUG, "debug", "DEBUG", "DebUg")
	verifyLevelsNoError(metadata.INFO, "info", "INFO", "iNFo")
}

func TestParseLevelError(t *testing.T) {
	verifyLevelError := func(levels ...string) {
		for _, level := range levels {
			_, err := metadata.ParseLevel(level)
			require.Error(t, err, "not supposed to succeed while parsing level string [%s]", level)
		}
	}

	verifyLevelError("", "D", "DE BUG", ".")
}

func TestParseString(t *testing.T) {
	require.Equal(t, "CRITICAL", metadata.ParseString(metadata.CRITICAL))
	require.Equal(t, "ERROR", metadata.ParseString(metadata.ERROR))
	require.Equal(t, "WARNING", metadata.ParseString(metadata.WARNING))
	require.Equal(t, "DEBUG", metadata.ParseString(metadata.DEBUG))
	require.Equal(t, "INFO", metadata.ParseString(metadata.INFO))
}
