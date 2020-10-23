/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package cmd_test

import (
	"os"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/edge-core/pkg/utils/cmd"
)

const (
	flagName = "host-url"
	envKey   = "TEST_HOST_URL"
)

func TestGetUserSetVarFromStringNegative(t *testing.T) {
	os.Clearenv()

	command := &cobra.Command{
		Use:   "start",
		Short: "short usage",
		Long:  "long usage",
		RunE: func(cmd *cobra.Command, args []string) error {
			return nil
		},
	}

	// test missing both command line argument and environment vars
	env, err := cmd.GetUserSetVarFromString(command, flagName, envKey, false)
	require.Error(t, err)
	require.Empty(t, env)
	require.Contains(t, err.Error(), "TEST_HOST_URL (environment variable) have been set.")

	// test env var is empty
	err = os.Setenv(envKey, "")
	require.NoError(t, err)

	env, err = cmd.GetUserSetVarFromString(command, flagName, envKey, false)
	require.Error(t, err)
	require.Contains(t, err.Error(), "TEST_HOST_URL value is empty")
	require.Empty(t, env)

	// test arg is empty
	command.Flags().StringP(flagName, "", "initial", "")
	args := []string{"--" + flagName, ""}
	command.SetArgs(args)
	err = command.Execute()
	require.NoError(t, err)

	env, err = cmd.GetUserSetVarFromString(command, flagName, envKey, false)
	require.Error(t, err)
	require.Contains(t, err.Error(), "host-url value is empty")
	require.Empty(t, env)
}

func TestGetUserSetVarFromArrayStringNegative(t *testing.T) {
	os.Clearenv()

	command := &cobra.Command{
		Use:   "start",
		Short: "short usage",
		Long:  "long usage",
		RunE: func(cmd *cobra.Command, args []string) error {
			return nil
		},
	}

	// test missing both command line argument and environment vars
	env, err := cmd.GetUserSetVarFromArrayString(command, flagName, envKey, false)
	require.Error(t, err)
	require.Empty(t, env)
	require.Contains(t, err.Error(), "TEST_HOST_URL (environment variable) have been set.")

	// test env var is empty
	err = os.Setenv(envKey, "")
	require.NoError(t, err)

	env, err = cmd.GetUserSetVarFromArrayString(command, flagName, envKey, false)
	require.Error(t, err)
	require.Contains(t, err.Error(), "TEST_HOST_URL value is empty")
	require.Empty(t, env)

	// test arg is empty
	command.Flags().StringArrayP(flagName, "", []string{}, "")
	args := []string{"--" + flagName, ""}
	command.SetArgs(args)
	err = command.Execute()
	require.NoError(t, err)

	env, err = cmd.GetUserSetVarFromArrayString(command, flagName, envKey, false)
	require.Error(t, err)
	require.Contains(t, err.Error(), "host-url value is empty")
	require.Empty(t, env)
}

func TestGetUserSetVarFromString(t *testing.T) {
	os.Clearenv()

	command := &cobra.Command{
		Use:   "start",
		Short: "short usage",
		Long:  "long usage",
		RunE: func(cmd *cobra.Command, args []string) error {
			return nil
		},
	}

	// test env var is set
	hostURL := "localhost:8080"
	err := os.Setenv(envKey, hostURL)
	require.NoError(t, err)

	// test resolution via environment variable
	env, err := cmd.GetUserSetVarFromString(command, flagName, envKey, false)
	require.NoError(t, err)
	require.Equal(t, hostURL, env)

	// set command line arguments
	command.Flags().StringP(flagName, "", "initial", "")
	args := []string{"--" + flagName, "other"}
	command.SetArgs(args)
	err = command.Execute()
	require.NoError(t, err)

	// test resolution via command line argument - no environment variable set
	env, err = cmd.GetUserSetVarFromString(command, flagName, "", false)
	require.NoError(t, err)
	require.Equal(t, "other", env)
}

func TestGetUserSetVarFromArrayString(t *testing.T) {
	os.Clearenv()

	command := &cobra.Command{
		Use:   "start",
		Short: "short usage",
		Long:  "long usage",
		RunE: func(cmd *cobra.Command, args []string) error {
			return nil
		},
	}

	// test env var is set
	hostURL := "localhost:8080"
	err := os.Setenv(envKey, hostURL)
	require.NoError(t, err)

	// test resolution via environment variable
	env, err := cmd.GetUserSetVarFromArrayString(command, flagName, envKey, false)
	require.NoError(t, err)
	require.Equal(t, []string{hostURL}, env)

	// set command line arguments
	command.Flags().StringArrayP(flagName, "", []string{}, "")
	args := []string{"--" + flagName, "other", "--" + flagName, "other1"}
	command.SetArgs(args)
	err = command.Execute()
	require.NoError(t, err)

	// test resolution via command line argument - no environment variable set
	env, err = cmd.GetUserSetVarFromArrayString(command, flagName, "", false)
	require.NoError(t, err)
	require.Equal(t, []string{"other", "other1"}, env)
}
