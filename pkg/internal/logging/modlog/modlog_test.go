/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package modlog_test

import (
	"testing"

	"github.com/trustbloc/edge-core/pkg/internal/logging/modlog"
)

func TestModLog(t *testing.T) {
	const module = "sample-module"
	modLogger := modlog.NewModLog(modlog.GetSampleCustomLogger(module), module)
	modlog.VerifyCustomLogger(t, modLogger, module)
}
