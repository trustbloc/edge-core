/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package metadata

import (
	"errors"
	"strings"
)

// Levels are the log levels supported.
var Levels = []string{ // nolint:gochecknoglobals // defines log levels
	"CRITICAL",
	"ERROR",
	"WARNING",
	"INFO",
	"DEBUG",
}

// ParseLevel returns the log level from a string representation.
func ParseLevel(level string) (Level, error) {
	for i, name := range Levels {
		if strings.EqualFold(name, level) {
			return Level(i), nil
		}
	}

	return ERROR, errors.New("logger: invalid log level")
}

// ParseString returns string representation of given log level.
func ParseString(level Level) string {
	return Levels[level]
}
