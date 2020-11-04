/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package zcapld_test

import (
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/ed25519signature2018"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util/signature"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/fingerprint"
	"github.com/igor-pavlenko/httpsignatures-go"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/edge-core/pkg/zcapld"
)

func TestNewHTTPSigAuthorizationHandler(t *testing.T) {
	t.Run("using did:key -> executes next handler if request is valid", func(t *testing.T) {
		var logErr error
		executed := false
		next := func(w http.ResponseWriter, r *http.Request) {
			executed = true
		}
		logger := func(e error) {
			logErr = e
		}
		resource := fmt.Sprintf("http://www.example.org/foo/documents/%s", uuid.New().String())

		resourceOwner, ownerSecrets, ownerVerMethod := signerAndSecrets(t)
		ownerZCAP, err := zcapld.NewCapability(
			&zcapld.Signer{
				SignatureSuite:     ed25519signature2018.New(suite.WithSigner(resourceOwner)),
				SuiteType:          ed25519signature2018.SignatureType,
				VerificationMethod: ownerVerMethod,
			},
			zcapld.WithAllowedActions("read", "write"),
			zcapld.WithInvocationTarget(resource, "urn:edv:document"),
			zcapld.WithID(resource),
		)
		require.NoError(t, err)

		_, thirdPartySecrets, thirdPartyVerMethod := signerAndSecrets(t)
		thirdPartyZCAP, err := zcapld.NewCapability(
			&zcapld.Signer{
				SignatureSuite:     ed25519signature2018.New(suite.WithSigner(resourceOwner)),
				SuiteType:          ed25519signature2018.SignatureType,
				VerificationMethod: ownerVerMethod,
			},
			zcapld.WithParent(ownerZCAP.ID),
			zcapld.WithInvoker(thirdPartyVerMethod),
			zcapld.WithCapabilityChain(resource),
			zcapld.WithAllowedActions("read"), // attenuated
			zcapld.WithInvocationTarget(resource, "urn:edv:document"),
		)
		require.NoError(t, err)

		ownerSecrets = importDIDKeyIntoSecrets(t, thirdPartyVerMethod, ownerSecrets)

		thirdPartyRequest := httptest.NewRequest(http.MethodGet, resource, nil)
		thirdPartyRequest.Header.Set(
			zcapld.CapabilityInvocationHTTPHeader,
			fmt.Sprintf(`zcap capability="%s",action="%s"`, compressZCAP(t, thirdPartyZCAP), "read"),
		)

		err = httpsignatures.NewHTTPSignatures(thirdPartySecrets).Sign(thirdPartyVerMethod, thirdPartyRequest)
		require.NoError(t, err)

		zcapld.NewHTTPSigAuthHandler(
			&zcapld.HTTPSigAuthConfig{
				CapabilityResolver: zcapld.SimpleCapabilityResolver{ownerZCAP.ID: ownerZCAP},
				KeyResolver:        &zcapld.DIDKeyResolver{},
				VerifierOptions: []zcapld.VerificationOption{
					zcapld.WithSignatureSuites(
						ed25519signature2018.New(suite.WithVerifier(ed25519signature2018.NewPublicKeyVerifier())),
					),
					zcapld.WithLDDocumentLoaders(testLDDocumentLoader),
				},
				Secrets:     ownerSecrets,
				ErrConsumer: logger,
			},
			&zcapld.InvocationExpectations{
				Target:         resource,
				RootCapability: resource,
				Action:         "read",
			},
			next,
		).ServeHTTP(httptest.NewRecorder(), thirdPartyRequest)
		require.NoError(t, logErr)
		require.True(t, executed)
	})

	t.Run("does not authorize HTTP request signed with unrecognized key", func(t *testing.T) {
		var logErr error
		executed := false
		next := func(w http.ResponseWriter, r *http.Request) {
			executed = true
		}
		logger := func(e error) {
			logErr = e
		}
		resource := fmt.Sprintf("http://www.example.org/foo/documents/%s", uuid.New().String())

		resourceOwner, ownerSecrets, ownerVerMethod := signerAndSecrets(t)
		ownerZCAP, err := zcapld.NewCapability(
			&zcapld.Signer{
				SignatureSuite:     ed25519signature2018.New(suite.WithSigner(resourceOwner)),
				SuiteType:          ed25519signature2018.SignatureType,
				VerificationMethod: ownerVerMethod,
			},
			zcapld.WithAllowedActions("read", "write"),
			zcapld.WithInvocationTarget(resource, "urn:edv:document"),
			zcapld.WithID(resource),
		)
		require.NoError(t, err)

		_, _, thirdPartyVerMethod := signerAndSecrets(t)
		thirdPartyZCAP, err := zcapld.NewCapability(
			&zcapld.Signer{
				SignatureSuite:     ed25519signature2018.New(suite.WithSigner(resourceOwner)),
				SuiteType:          ed25519signature2018.SignatureType,
				VerificationMethod: ownerVerMethod,
			},
			zcapld.WithParent(ownerZCAP.ID),
			zcapld.WithInvoker(thirdPartyVerMethod),
			zcapld.WithCapabilityChain(resource),
			zcapld.WithAllowedActions("read"), // attenuated
			zcapld.WithInvocationTarget(resource, "urn:edv:document"),
		)
		require.NoError(t, err)

		ownerSecrets = importDIDKeyIntoSecrets(t, thirdPartyVerMethod, ownerSecrets)

		thirdPartyRequest := httptest.NewRequest(http.MethodGet, resource, nil)
		thirdPartyRequest.Header.Set(
			zcapld.CapabilityInvocationHTTPHeader,
			fmt.Sprintf(`zcap capability="%s",action="%s"`, compressZCAP(t, thirdPartyZCAP), "read"),
		)

		_, unrecognizedSecrets, unrecognizedVerMethod := signerAndSecrets(t)

		err = httpsignatures.NewHTTPSignatures(unrecognizedSecrets).Sign(unrecognizedVerMethod, thirdPartyRequest)
		require.NoError(t, err)

		zcapld.NewHTTPSigAuthHandler(
			&zcapld.HTTPSigAuthConfig{
				CapabilityResolver: zcapld.SimpleCapabilityResolver{ownerZCAP.ID: ownerZCAP},
				KeyResolver:        &zcapld.DIDKeyResolver{},
				VerifierOptions: []zcapld.VerificationOption{
					zcapld.WithSignatureSuites(
						ed25519signature2018.New(suite.WithVerifier(ed25519signature2018.NewPublicKeyVerifier())),
					),
					zcapld.WithLDDocumentLoaders(testLDDocumentLoader),
				},
				Secrets:     ownerSecrets,
				ErrConsumer: logger,
			},
			&zcapld.InvocationExpectations{
				Target:         resource,
				RootCapability: resource,
				Action:         "read",
			},
			next,
		).ServeHTTP(httptest.NewRecorder(), thirdPartyRequest)
		require.Error(t, logErr)
		require.Contains(t, logErr.Error(), "secret not found")
		require.False(t, executed)
	})

	t.Run("does not authorize HTTP request authn'ed with key different than zcap invoker", func(t *testing.T) {
		var logErr error
		executed := false
		next := func(w http.ResponseWriter, r *http.Request) {
			executed = true
		}
		logger := func(e error) {
			logErr = e
		}
		resource := fmt.Sprintf("http://www.example.org/foo/documents/%s", uuid.New().String())

		resourceOwner, ownerSecrets, ownerVerMethod := signerAndSecrets(t)
		ownerZCAP, err := zcapld.NewCapability(
			&zcapld.Signer{
				SignatureSuite:     ed25519signature2018.New(suite.WithSigner(resourceOwner)),
				SuiteType:          ed25519signature2018.SignatureType,
				VerificationMethod: ownerVerMethod,
			},
			zcapld.WithAllowedActions("read", "write"),
			zcapld.WithInvocationTarget(resource, "urn:edv:document"),
			zcapld.WithID(resource),
		)
		require.NoError(t, err)

		_, _, thirdPartyVerMethod := signerAndSecrets(t)
		thirdPartyZCAP, err := zcapld.NewCapability(
			&zcapld.Signer{
				SignatureSuite:     ed25519signature2018.New(suite.WithSigner(resourceOwner)),
				SuiteType:          ed25519signature2018.SignatureType,
				VerificationMethod: ownerVerMethod,
			},
			zcapld.WithParent(ownerZCAP.ID),
			zcapld.WithInvoker(thirdPartyVerMethod),
			zcapld.WithCapabilityChain(resource),
			zcapld.WithAllowedActions("read"), // attenuated
			zcapld.WithInvocationTarget(resource, "urn:edv:document"),
		)
		require.NoError(t, err)

		_, moreThirdPartySecrets, anotherThirdPartyVerMethod := signerAndSecrets(t)

		ownerSecrets = importDIDKeyIntoSecrets(t, thirdPartyVerMethod, ownerSecrets)
		ownerSecrets = importDIDKeyIntoSecrets(t, anotherThirdPartyVerMethod, ownerSecrets)

		thirdPartyRequest := httptest.NewRequest(http.MethodGet, resource, nil)
		thirdPartyRequest.Header.Set(
			zcapld.CapabilityInvocationHTTPHeader,
			fmt.Sprintf(`zcap capability="%s",action="%s"`, compressZCAP(t, thirdPartyZCAP), "read"),
		)

		err = httpsignatures.NewHTTPSignatures(moreThirdPartySecrets).Sign(anotherThirdPartyVerMethod, thirdPartyRequest)
		require.NoError(t, err)

		zcapld.NewHTTPSigAuthHandler(
			&zcapld.HTTPSigAuthConfig{
				CapabilityResolver: zcapld.SimpleCapabilityResolver{ownerZCAP.ID: ownerZCAP},
				KeyResolver:        &zcapld.DIDKeyResolver{},
				VerifierOptions: []zcapld.VerificationOption{
					zcapld.WithSignatureSuites(
						ed25519signature2018.New(suite.WithVerifier(ed25519signature2018.NewPublicKeyVerifier())),
					),
					zcapld.WithLDDocumentLoaders(testLDDocumentLoader),
				},
				Secrets:     ownerSecrets,
				ErrConsumer: logger,
			},
			&zcapld.InvocationExpectations{
				Target:         resource,
				RootCapability: resource,
				Action:         "read",
			},
			next,
		).ServeHTTP(httptest.NewRecorder(), thirdPartyRequest)
		require.Error(t, logErr)
		require.Contains(t, logErr.Error(), "the authorized invoker does not match the verification method or its controller")
		require.False(t, executed)
	})

	t.Run("does not authorize HTTP request if invoker is not allowed to perform an action", func(t *testing.T) {
		var logErr error
		executed := false
		next := func(w http.ResponseWriter, r *http.Request) {
			executed = true
		}
		logger := func(e error) {
			logErr = e
		}
		resource := fmt.Sprintf("http://www.example.org/foo/documents/%s", uuid.New().String())

		resourceOwner, ownerSecrets, ownerVerMethod := signerAndSecrets(t)
		ownerZCAP, err := zcapld.NewCapability(
			&zcapld.Signer{
				SignatureSuite:     ed25519signature2018.New(suite.WithSigner(resourceOwner)),
				SuiteType:          ed25519signature2018.SignatureType,
				VerificationMethod: ownerVerMethod,
			},
			zcapld.WithAllowedActions("read", "write"),
			zcapld.WithInvocationTarget(resource, "urn:edv:document"),
			zcapld.WithID(resource),
		)
		require.NoError(t, err)

		_, thirdPartySecrets, thirdPartyVerMethod := signerAndSecrets(t)
		thirdPartyZCAP, err := zcapld.NewCapability(
			&zcapld.Signer{
				SignatureSuite:     ed25519signature2018.New(suite.WithSigner(resourceOwner)),
				SuiteType:          ed25519signature2018.SignatureType,
				VerificationMethod: ownerVerMethod,
			},
			zcapld.WithParent(ownerZCAP.ID),
			zcapld.WithInvoker(thirdPartyVerMethod),
			zcapld.WithCapabilityChain(resource),
			zcapld.WithAllowedActions("read"),
			zcapld.WithInvocationTarget(resource, "urn:edv:document"),
		)
		require.NoError(t, err)

		ownerSecrets = importDIDKeyIntoSecrets(t, thirdPartyVerMethod, ownerSecrets)

		thirdPartyRequest := httptest.NewRequest(http.MethodGet, resource, nil)
		thirdPartyRequest.Header.Set(
			zcapld.CapabilityInvocationHTTPHeader,
			fmt.Sprintf(`zcap capability="%s",action="%s"`, compressZCAP(t, thirdPartyZCAP), "write"),
		)

		err = httpsignatures.NewHTTPSignatures(thirdPartySecrets).Sign(thirdPartyVerMethod, thirdPartyRequest)
		require.NoError(t, err)

		zcapld.NewHTTPSigAuthHandler(
			&zcapld.HTTPSigAuthConfig{
				CapabilityResolver: zcapld.SimpleCapabilityResolver{ownerZCAP.ID: ownerZCAP},
				KeyResolver:        &zcapld.DIDKeyResolver{},
				VerifierOptions: []zcapld.VerificationOption{
					zcapld.WithSignatureSuites(
						ed25519signature2018.New(suite.WithVerifier(ed25519signature2018.NewPublicKeyVerifier())),
					),
					zcapld.WithLDDocumentLoaders(testLDDocumentLoader),
				},
				Secrets:     ownerSecrets,
				ErrConsumer: logger,
			},
			&zcapld.InvocationExpectations{
				Target:         resource,
				RootCapability: resource,
				Action:         "write",
			},
			next,
		).ServeHTTP(httptest.NewRecorder(), thirdPartyRequest)
		require.Error(t, logErr)
		require.Contains(t, logErr.Error(), `capability action "write" is not allowed by the capability`)
		require.False(t, executed)
	})

	t.Run("fails if no signature suites are provided", func(t *testing.T) {
		var logErr error
		executed := false
		next := func(w http.ResponseWriter, r *http.Request) {
			executed = true
		}
		logger := func(e error) {
			logErr = e
		}
		resource := fmt.Sprintf("http://www.example.org/foo/documents/%s", uuid.New().String())

		resourceOwner, ownerSecrets, ownerVerMethod := signerAndSecrets(t)
		ownerZCAP, err := zcapld.NewCapability(
			&zcapld.Signer{
				SignatureSuite:     ed25519signature2018.New(suite.WithSigner(resourceOwner)),
				SuiteType:          ed25519signature2018.SignatureType,
				VerificationMethod: ownerVerMethod,
			},
			zcapld.WithAllowedActions("read", "write"),
			zcapld.WithInvocationTarget(resource, "urn:edv:document"),
			zcapld.WithID(resource),
		)
		require.NoError(t, err)

		_, thirdPartySecrets, thirdPartyVerMethod := signerAndSecrets(t)
		thirdPartyZCAP, err := zcapld.NewCapability(
			&zcapld.Signer{
				SignatureSuite:     ed25519signature2018.New(suite.WithSigner(resourceOwner)),
				SuiteType:          ed25519signature2018.SignatureType,
				VerificationMethod: ownerVerMethod,
			},
			zcapld.WithParent(ownerZCAP.ID),
			zcapld.WithInvoker(thirdPartyVerMethod),
			zcapld.WithCapabilityChain(resource),
			zcapld.WithAllowedActions("read"), // attenuated
			zcapld.WithInvocationTarget(resource, "urn:edv:document"),
		)
		require.NoError(t, err)

		ownerSecrets = importDIDKeyIntoSecrets(t, thirdPartyVerMethod, ownerSecrets)

		thirdPartyRequest := httptest.NewRequest(http.MethodGet, resource, nil)
		thirdPartyRequest.Header.Set(
			zcapld.CapabilityInvocationHTTPHeader,
			fmt.Sprintf(`zcap capability="%s",action="%s"`, compressZCAP(t, thirdPartyZCAP), "read"),
		)

		err = httpsignatures.NewHTTPSignatures(thirdPartySecrets).Sign(thirdPartyVerMethod, thirdPartyRequest)
		require.NoError(t, err)

		zcapld.NewHTTPSigAuthHandler(
			&zcapld.HTTPSigAuthConfig{
				CapabilityResolver: zcapld.SimpleCapabilityResolver{ownerZCAP.ID: ownerZCAP},
				KeyResolver:        &zcapld.DIDKeyResolver{},
				VerifierOptions: []zcapld.VerificationOption{
					zcapld.WithLDDocumentLoaders(testLDDocumentLoader),
				},
				Secrets:     ownerSecrets,
				ErrConsumer: logger,
			},
			&zcapld.InvocationExpectations{
				Target:         resource,
				RootCapability: resource,
				Action:         "read",
			},
			next,
		).ServeHTTP(httptest.NewRecorder(), thirdPartyRequest)
		require.Error(t, logErr)
		require.Contains(t, logErr.Error(), "failed to init document verifier: at least one suite must be provided")
		require.False(t, executed)
	})

	t.Run("does not authorize HTTP request if zcap is not provided", func(t *testing.T) {
		var logErr error
		executed := false
		next := func(w http.ResponseWriter, r *http.Request) {
			executed = true
		}
		logger := func(e error) {
			logErr = e
		}
		resource := fmt.Sprintf("http://www.example.org/foo/documents/%s", uuid.New().String())

		resourceOwner, ownerSecrets, ownerVerMethod := signerAndSecrets(t)
		ownerZCAP, err := zcapld.NewCapability(
			&zcapld.Signer{
				SignatureSuite:     ed25519signature2018.New(suite.WithSigner(resourceOwner)),
				SuiteType:          ed25519signature2018.SignatureType,
				VerificationMethod: ownerVerMethod,
			},
			zcapld.WithAllowedActions("read", "write"),
			zcapld.WithInvocationTarget(resource, "urn:edv:document"),
			zcapld.WithID(resource),
		)
		require.NoError(t, err)

		_, thirdPartySecrets, thirdPartyVerMethod := signerAndSecrets(t)
		ownerSecrets = importDIDKeyIntoSecrets(t, thirdPartyVerMethod, ownerSecrets)

		thirdPartyRequest := httptest.NewRequest(http.MethodGet, resource, nil)
		thirdPartyRequest.Header.Set(
			zcapld.CapabilityInvocationHTTPHeader,
			fmt.Sprintf(`zcap action="%s"`, "read"),
		)

		err = httpsignatures.NewHTTPSignatures(thirdPartySecrets).Sign(thirdPartyVerMethod, thirdPartyRequest)
		require.NoError(t, err)

		zcapld.NewHTTPSigAuthHandler(
			&zcapld.HTTPSigAuthConfig{
				CapabilityResolver: zcapld.SimpleCapabilityResolver{ownerZCAP.ID: ownerZCAP},
				KeyResolver:        &zcapld.DIDKeyResolver{},
				VerifierOptions: []zcapld.VerificationOption{
					zcapld.WithSignatureSuites(
						ed25519signature2018.New(suite.WithVerifier(ed25519signature2018.NewPublicKeyVerifier())),
					),
					zcapld.WithLDDocumentLoaders(testLDDocumentLoader),
				},
				Secrets:     ownerSecrets,
				ErrConsumer: logger,
			},
			&zcapld.InvocationExpectations{
				Target:         resource,
				RootCapability: resource,
				Action:         "read",
			},
			next,
		).ServeHTTP(httptest.NewRecorder(), thirdPartyRequest)
		require.Error(t, logErr)
		require.Contains(t, logErr.Error(), `"capability" was not found in the capability invocation proof`)
		require.False(t, executed)
	})

	t.Run("does not authorize HTTP request if capability-invocation header is not provided", func(t *testing.T) {
		var logErr error
		executed := false
		next := func(w http.ResponseWriter, r *http.Request) {
			executed = true
		}
		logger := func(e error) {
			logErr = e
		}
		resource := fmt.Sprintf("http://www.example.org/foo/documents/%s", uuid.New().String())

		resourceOwner, ownerSecrets, ownerVerMethod := signerAndSecrets(t)
		ownerZCAP, err := zcapld.NewCapability(
			&zcapld.Signer{
				SignatureSuite:     ed25519signature2018.New(suite.WithSigner(resourceOwner)),
				SuiteType:          ed25519signature2018.SignatureType,
				VerificationMethod: ownerVerMethod,
			},
			zcapld.WithAllowedActions("read", "write"),
			zcapld.WithInvocationTarget(resource, "urn:edv:document"),
			zcapld.WithID(resource),
		)
		require.NoError(t, err)

		_, thirdPartySecrets, thirdPartyVerMethod := signerAndSecrets(t)
		ownerSecrets = importDIDKeyIntoSecrets(t, thirdPartyVerMethod, ownerSecrets)

		thirdPartyRequest := httptest.NewRequest(http.MethodGet, resource, nil)

		err = httpsignatures.NewHTTPSignatures(thirdPartySecrets).Sign(thirdPartyVerMethod, thirdPartyRequest)
		require.NoError(t, err)

		zcapld.NewHTTPSigAuthHandler(
			&zcapld.HTTPSigAuthConfig{
				CapabilityResolver: zcapld.SimpleCapabilityResolver{ownerZCAP.ID: ownerZCAP},
				KeyResolver:        &zcapld.DIDKeyResolver{},
				VerifierOptions: []zcapld.VerificationOption{
					zcapld.WithSignatureSuites(
						ed25519signature2018.New(suite.WithVerifier(ed25519signature2018.NewPublicKeyVerifier())),
					),
					zcapld.WithLDDocumentLoaders(testLDDocumentLoader),
				},
				Secrets:     ownerSecrets,
				ErrConsumer: logger,
			},
			&zcapld.InvocationExpectations{
				Target:         resource,
				RootCapability: resource,
				Action:         "read",
			},
			next,
		).ServeHTTP(httptest.NewRecorder(), thirdPartyRequest)
		require.Error(t, logErr)
		require.Contains(t, logErr.Error(), `"capability-invocation" header is missing`)
		require.False(t, executed)
	})

	t.Run("does not authorize HTTP request if HTTP authorization scheme is not 'zcap'", func(t *testing.T) {
		var logErr error
		executed := false
		next := func(w http.ResponseWriter, r *http.Request) {
			executed = true
		}
		logger := func(e error) {
			logErr = e
		}
		resource := fmt.Sprintf("http://www.example.org/foo/documents/%s", uuid.New().String())

		resourceOwner, ownerSecrets, ownerVerMethod := signerAndSecrets(t)
		ownerZCAP, err := zcapld.NewCapability(
			&zcapld.Signer{
				SignatureSuite:     ed25519signature2018.New(suite.WithSigner(resourceOwner)),
				SuiteType:          ed25519signature2018.SignatureType,
				VerificationMethod: ownerVerMethod,
			},
			zcapld.WithAllowedActions("read", "write"),
			zcapld.WithInvocationTarget(resource, "urn:edv:document"),
			zcapld.WithID(resource),
		)
		require.NoError(t, err)

		_, thirdPartySecrets, thirdPartyVerMethod := signerAndSecrets(t)
		thirdPartyZCAP, err := zcapld.NewCapability(
			&zcapld.Signer{
				SignatureSuite:     ed25519signature2018.New(suite.WithSigner(resourceOwner)),
				SuiteType:          ed25519signature2018.SignatureType,
				VerificationMethod: ownerVerMethod,
			},
			zcapld.WithParent(ownerZCAP.ID),
			zcapld.WithInvoker(thirdPartyVerMethod),
			zcapld.WithCapabilityChain(resource),
			zcapld.WithAllowedActions("read"), // attenuated
			zcapld.WithInvocationTarget(resource, "urn:edv:document"),
		)
		require.NoError(t, err)

		ownerSecrets = importDIDKeyIntoSecrets(t, thirdPartyVerMethod, ownerSecrets)

		thirdPartyRequest := httptest.NewRequest(http.MethodGet, resource, nil)
		thirdPartyRequest.Header.Set(
			zcapld.CapabilityInvocationHTTPHeader,
			fmt.Sprintf(`INVALID capability="%s",action="%s"`, compressZCAP(t, thirdPartyZCAP), "read"),
		)

		err = httpsignatures.NewHTTPSignatures(thirdPartySecrets).Sign(thirdPartyVerMethod, thirdPartyRequest)
		require.NoError(t, err)

		zcapld.NewHTTPSigAuthHandler(
			&zcapld.HTTPSigAuthConfig{
				CapabilityResolver: zcapld.SimpleCapabilityResolver{ownerZCAP.ID: ownerZCAP},
				KeyResolver:        &zcapld.DIDKeyResolver{},
				VerifierOptions: []zcapld.VerificationOption{
					zcapld.WithSignatureSuites(
						ed25519signature2018.New(suite.WithVerifier(ed25519signature2018.NewPublicKeyVerifier())),
					),
					zcapld.WithLDDocumentLoaders(testLDDocumentLoader),
				},
				Secrets:     ownerSecrets,
				ErrConsumer: logger,
			},
			&zcapld.InvocationExpectations{
				Target:         resource,
				RootCapability: resource,
				Action:         "read",
			},
			next,
		).ServeHTTP(httptest.NewRecorder(), thirdPartyRequest)
		require.Error(t, logErr)
		require.Contains(t, logErr.Error(), "invalid invocation scheme")
		require.False(t, executed)
	})

	t.Run("does not authorize HTTP request if capability parameter is not a quoted-string", func(t *testing.T) {
		var logErr error
		executed := false
		next := func(w http.ResponseWriter, r *http.Request) {
			executed = true
		}
		logger := func(e error) {
			logErr = e
		}
		resource := fmt.Sprintf("http://www.example.org/foo/documents/%s", uuid.New().String())

		resourceOwner, ownerSecrets, ownerVerMethod := signerAndSecrets(t)
		ownerZCAP, err := zcapld.NewCapability(
			&zcapld.Signer{
				SignatureSuite:     ed25519signature2018.New(suite.WithSigner(resourceOwner)),
				SuiteType:          ed25519signature2018.SignatureType,
				VerificationMethod: ownerVerMethod,
			},
			zcapld.WithAllowedActions("read", "write"),
			zcapld.WithInvocationTarget(resource, "urn:edv:document"),
			zcapld.WithID(resource),
		)
		require.NoError(t, err)

		_, thirdPartySecrets, thirdPartyVerMethod := signerAndSecrets(t)
		thirdPartyZCAP, err := zcapld.NewCapability(
			&zcapld.Signer{
				SignatureSuite:     ed25519signature2018.New(suite.WithSigner(resourceOwner)),
				SuiteType:          ed25519signature2018.SignatureType,
				VerificationMethod: ownerVerMethod,
			},
			zcapld.WithParent(ownerZCAP.ID),
			zcapld.WithInvoker(thirdPartyVerMethod),
			zcapld.WithCapabilityChain(resource),
			zcapld.WithAllowedActions("read"), // attenuated
			zcapld.WithInvocationTarget(resource, "urn:edv:document"),
		)
		require.NoError(t, err)

		ownerSecrets = importDIDKeyIntoSecrets(t, thirdPartyVerMethod, ownerSecrets)

		thirdPartyRequest := httptest.NewRequest(http.MethodGet, resource, nil)
		thirdPartyRequest.Header.Set(
			zcapld.CapabilityInvocationHTTPHeader,
			fmt.Sprintf(`zcap capability=%s,action="%s"`, compressZCAP(t, thirdPartyZCAP), "read"),
		)

		err = httpsignatures.NewHTTPSignatures(thirdPartySecrets).Sign(thirdPartyVerMethod, thirdPartyRequest)
		require.NoError(t, err)

		zcapld.NewHTTPSigAuthHandler(
			&zcapld.HTTPSigAuthConfig{
				CapabilityResolver: zcapld.SimpleCapabilityResolver{ownerZCAP.ID: ownerZCAP},
				KeyResolver:        &zcapld.DIDKeyResolver{},
				VerifierOptions: []zcapld.VerificationOption{
					zcapld.WithSignatureSuites(
						ed25519signature2018.New(suite.WithVerifier(ed25519signature2018.NewPublicKeyVerifier())),
					),
					zcapld.WithLDDocumentLoaders(testLDDocumentLoader),
				},
				Secrets:     ownerSecrets,
				ErrConsumer: logger,
			},
			&zcapld.InvocationExpectations{
				Target:         resource,
				RootCapability: resource,
				Action:         "read",
			},
			next,
		).ServeHTTP(httptest.NewRecorder(), thirdPartyRequest)
		require.Error(t, logErr)
		require.Contains(t, logErr.Error(), "'capability' invocation header param value is not a quoted-string")
		require.False(t, executed)
	})

	t.Run("does not authorize HTTP request if capability parameter is malformed", func(t *testing.T) {
		var logErr error
		executed := false
		next := func(w http.ResponseWriter, r *http.Request) {
			executed = true
		}
		logger := func(e error) {
			logErr = e
		}
		resource := fmt.Sprintf("http://www.example.org/foo/documents/%s", uuid.New().String())

		resourceOwner, ownerSecrets, ownerVerMethod := signerAndSecrets(t)
		ownerZCAP, err := zcapld.NewCapability(
			&zcapld.Signer{
				SignatureSuite:     ed25519signature2018.New(suite.WithSigner(resourceOwner)),
				SuiteType:          ed25519signature2018.SignatureType,
				VerificationMethod: ownerVerMethod,
			},
			zcapld.WithAllowedActions("read", "write"),
			zcapld.WithInvocationTarget(resource, "urn:edv:document"),
			zcapld.WithID(resource),
		)
		require.NoError(t, err)

		_, thirdPartySecrets, thirdPartyVerMethod := signerAndSecrets(t)
		ownerSecrets = importDIDKeyIntoSecrets(t, thirdPartyVerMethod, ownerSecrets)

		thirdPartyRequest := httptest.NewRequest(http.MethodGet, resource, nil)
		thirdPartyRequest.Header.Set(
			zcapld.CapabilityInvocationHTTPHeader,
			fmt.Sprintf(`zcap capability="%s",action="%s"`, "MALFORMED", "read"),
		)

		err = httpsignatures.NewHTTPSignatures(thirdPartySecrets).Sign(thirdPartyVerMethod, thirdPartyRequest)
		require.NoError(t, err)

		zcapld.NewHTTPSigAuthHandler(
			&zcapld.HTTPSigAuthConfig{
				CapabilityResolver: zcapld.SimpleCapabilityResolver{ownerZCAP.ID: ownerZCAP},
				KeyResolver:        &zcapld.DIDKeyResolver{},
				VerifierOptions: []zcapld.VerificationOption{
					zcapld.WithSignatureSuites(
						ed25519signature2018.New(suite.WithVerifier(ed25519signature2018.NewPublicKeyVerifier())),
					),
					zcapld.WithLDDocumentLoaders(testLDDocumentLoader),
				},
				Secrets:     ownerSecrets,
				ErrConsumer: logger,
			},
			&zcapld.InvocationExpectations{
				Target:         resource,
				RootCapability: resource,
				Action:         "read",
			},
			next,
		).ServeHTTP(httptest.NewRecorder(), thirdPartyRequest)
		require.Error(t, logErr)
		require.Contains(t, logErr.Error(), "failed to base64URL-decode value MALFORMED")
		require.False(t, executed)
	})

	t.Run("does not authorize HTTP request if action parameter is not a quoted-string", func(t *testing.T) {
		var logErr error
		executed := false
		next := func(w http.ResponseWriter, r *http.Request) {
			executed = true
		}
		logger := func(e error) {
			logErr = e
		}
		resource := fmt.Sprintf("http://www.example.org/foo/documents/%s", uuid.New().String())

		resourceOwner, ownerSecrets, ownerVerMethod := signerAndSecrets(t)
		ownerZCAP, err := zcapld.NewCapability(
			&zcapld.Signer{
				SignatureSuite:     ed25519signature2018.New(suite.WithSigner(resourceOwner)),
				SuiteType:          ed25519signature2018.SignatureType,
				VerificationMethod: ownerVerMethod,
			},
			zcapld.WithAllowedActions("read", "write"),
			zcapld.WithInvocationTarget(resource, "urn:edv:document"),
			zcapld.WithID(resource),
		)
		require.NoError(t, err)

		_, thirdPartySecrets, thirdPartyVerMethod := signerAndSecrets(t)
		thirdPartyZCAP, err := zcapld.NewCapability(
			&zcapld.Signer{
				SignatureSuite:     ed25519signature2018.New(suite.WithSigner(resourceOwner)),
				SuiteType:          ed25519signature2018.SignatureType,
				VerificationMethod: ownerVerMethod,
			},
			zcapld.WithParent(ownerZCAP.ID),
			zcapld.WithInvoker(thirdPartyVerMethod),
			zcapld.WithCapabilityChain(resource),
			zcapld.WithAllowedActions("read"), // attenuated
			zcapld.WithInvocationTarget(resource, "urn:edv:document"),
		)
		require.NoError(t, err)

		ownerSecrets = importDIDKeyIntoSecrets(t, thirdPartyVerMethod, ownerSecrets)

		thirdPartyRequest := httptest.NewRequest(http.MethodGet, resource, nil)
		thirdPartyRequest.Header.Set(
			zcapld.CapabilityInvocationHTTPHeader,
			fmt.Sprintf(`zcap capability="%s",action=%s`, compressZCAP(t, thirdPartyZCAP), "read"),
		)

		err = httpsignatures.NewHTTPSignatures(thirdPartySecrets).Sign(thirdPartyVerMethod, thirdPartyRequest)
		require.NoError(t, err)

		zcapld.NewHTTPSigAuthHandler(
			&zcapld.HTTPSigAuthConfig{
				CapabilityResolver: zcapld.SimpleCapabilityResolver{ownerZCAP.ID: ownerZCAP},
				KeyResolver:        &zcapld.DIDKeyResolver{},
				VerifierOptions: []zcapld.VerificationOption{
					zcapld.WithSignatureSuites(
						ed25519signature2018.New(suite.WithVerifier(ed25519signature2018.NewPublicKeyVerifier())),
					),
					zcapld.WithLDDocumentLoaders(testLDDocumentLoader),
				},
				Secrets:     ownerSecrets,
				ErrConsumer: logger,
			},
			&zcapld.InvocationExpectations{
				Target:         resource,
				RootCapability: resource,
				Action:         "read",
			},
			next,
		).ServeHTTP(httptest.NewRecorder(), thirdPartyRequest)
		require.Error(t, logErr)
		require.Contains(t, logErr.Error(), "'action' invocation header param value is not a quoted-string")
		require.False(t, executed)
	})

	t.Run("does not authorize HTTP request if action parameter is missing", func(t *testing.T) {
		var logErr error
		executed := false
		next := func(w http.ResponseWriter, r *http.Request) {
			executed = true
		}
		logger := func(e error) {
			logErr = e
		}
		resource := fmt.Sprintf("http://www.example.org/foo/documents/%s", uuid.New().String())

		resourceOwner, ownerSecrets, ownerVerMethod := signerAndSecrets(t)
		ownerZCAP, err := zcapld.NewCapability(
			&zcapld.Signer{
				SignatureSuite:     ed25519signature2018.New(suite.WithSigner(resourceOwner)),
				SuiteType:          ed25519signature2018.SignatureType,
				VerificationMethod: ownerVerMethod,
			},
			zcapld.WithAllowedActions("read", "write"),
			zcapld.WithInvocationTarget(resource, "urn:edv:document"),
			zcapld.WithID(resource),
		)
		require.NoError(t, err)

		_, thirdPartySecrets, thirdPartyVerMethod := signerAndSecrets(t)
		thirdPartyZCAP, err := zcapld.NewCapability(
			&zcapld.Signer{
				SignatureSuite:     ed25519signature2018.New(suite.WithSigner(resourceOwner)),
				SuiteType:          ed25519signature2018.SignatureType,
				VerificationMethod: ownerVerMethod,
			},
			zcapld.WithParent(ownerZCAP.ID),
			zcapld.WithInvoker(thirdPartyVerMethod),
			zcapld.WithCapabilityChain(resource),
			zcapld.WithAllowedActions("read"), // attenuated
			zcapld.WithInvocationTarget(resource, "urn:edv:document"),
		)
		require.NoError(t, err)

		ownerSecrets = importDIDKeyIntoSecrets(t, thirdPartyVerMethod, ownerSecrets)

		thirdPartyRequest := httptest.NewRequest(http.MethodGet, resource, nil)
		thirdPartyRequest.Header.Set(
			zcapld.CapabilityInvocationHTTPHeader,
			fmt.Sprintf(`zcap capability="%s"`, compressZCAP(t, thirdPartyZCAP)),
		)

		err = httpsignatures.NewHTTPSignatures(thirdPartySecrets).Sign(thirdPartyVerMethod, thirdPartyRequest)
		require.NoError(t, err)

		zcapld.NewHTTPSigAuthHandler(
			&zcapld.HTTPSigAuthConfig{
				CapabilityResolver: zcapld.SimpleCapabilityResolver{ownerZCAP.ID: ownerZCAP},
				KeyResolver:        &zcapld.DIDKeyResolver{},
				VerifierOptions: []zcapld.VerificationOption{
					zcapld.WithSignatureSuites(
						ed25519signature2018.New(suite.WithVerifier(ed25519signature2018.NewPublicKeyVerifier())),
					),
					zcapld.WithLDDocumentLoaders(testLDDocumentLoader),
				},
				Secrets:     ownerSecrets,
				ErrConsumer: logger,
			},
			&zcapld.InvocationExpectations{
				Target:         resource,
				RootCapability: resource,
				Action:         "read",
			},
			next,
		).ServeHTTP(httptest.NewRecorder(), thirdPartyRequest)
		require.Error(t, logErr)
		require.Contains(t, logErr.Error(), `"action" header is missing`)
		require.False(t, executed)
	})

	t.Run("does not authorize HTTP request if an unrecognized capability-invocation parameter is present", func(t *testing.T) { // nolint:lll // excessive indentation otherwise
		var logErr error
		executed := false
		next := func(w http.ResponseWriter, r *http.Request) {
			executed = true
		}
		logger := func(e error) {
			logErr = e
		}
		resource := fmt.Sprintf("http://www.example.org/foo/documents/%s", uuid.New().String())

		resourceOwner, ownerSecrets, ownerVerMethod := signerAndSecrets(t)
		ownerZCAP, err := zcapld.NewCapability(
			&zcapld.Signer{
				SignatureSuite:     ed25519signature2018.New(suite.WithSigner(resourceOwner)),
				SuiteType:          ed25519signature2018.SignatureType,
				VerificationMethod: ownerVerMethod,
			},
			zcapld.WithAllowedActions("read", "write"),
			zcapld.WithInvocationTarget(resource, "urn:edv:document"),
			zcapld.WithID(resource),
		)
		require.NoError(t, err)

		_, thirdPartySecrets, thirdPartyVerMethod := signerAndSecrets(t)
		thirdPartyZCAP, err := zcapld.NewCapability(
			&zcapld.Signer{
				SignatureSuite:     ed25519signature2018.New(suite.WithSigner(resourceOwner)),
				SuiteType:          ed25519signature2018.SignatureType,
				VerificationMethod: ownerVerMethod,
			},
			zcapld.WithParent(ownerZCAP.ID),
			zcapld.WithInvoker(thirdPartyVerMethod),
			zcapld.WithCapabilityChain(resource),
			zcapld.WithAllowedActions("read"), // attenuated
			zcapld.WithInvocationTarget(resource, "urn:edv:document"),
		)
		require.NoError(t, err)

		ownerSecrets = importDIDKeyIntoSecrets(t, thirdPartyVerMethod, ownerSecrets)

		thirdPartyRequest := httptest.NewRequest(http.MethodGet, resource, nil)
		thirdPartyRequest.Header.Set(
			zcapld.CapabilityInvocationHTTPHeader,
			fmt.Sprintf(`zcap capability="%s",action="%s",unrecognized="foo"`, compressZCAP(t, thirdPartyZCAP), "read"),
		)

		err = httpsignatures.NewHTTPSignatures(thirdPartySecrets).Sign(thirdPartyVerMethod, thirdPartyRequest)
		require.NoError(t, err)

		zcapld.NewHTTPSigAuthHandler(
			&zcapld.HTTPSigAuthConfig{
				CapabilityResolver: zcapld.SimpleCapabilityResolver{ownerZCAP.ID: ownerZCAP},
				KeyResolver:        &zcapld.DIDKeyResolver{},
				VerifierOptions: []zcapld.VerificationOption{
					zcapld.WithSignatureSuites(
						ed25519signature2018.New(suite.WithVerifier(ed25519signature2018.NewPublicKeyVerifier())),
					),
					zcapld.WithLDDocumentLoaders(testLDDocumentLoader),
				},
				Secrets:     ownerSecrets,
				ErrConsumer: logger,
			},
			&zcapld.InvocationExpectations{
				Target:         resource,
				RootCapability: resource,
				Action:         "read",
			},
			next,
		).ServeHTTP(httptest.NewRecorder(), thirdPartyRequest)
		require.Error(t, logErr)
		require.Contains(t, logErr.Error(), `unrecognized invocation header param`)
		require.False(t, executed)
	})

	t.Run("does not authorize HTTP request if an capability-invocation parameter is not in key=value format", func(t *testing.T) { // nolint:lll // excessive indentation otherwise
		var logErr error
		executed := false
		next := func(w http.ResponseWriter, r *http.Request) {
			executed = true
		}
		logger := func(e error) {
			logErr = e
		}
		resource := fmt.Sprintf("http://www.example.org/foo/documents/%s", uuid.New().String())

		resourceOwner, ownerSecrets, ownerVerMethod := signerAndSecrets(t)
		ownerZCAP, err := zcapld.NewCapability(
			&zcapld.Signer{
				SignatureSuite:     ed25519signature2018.New(suite.WithSigner(resourceOwner)),
				SuiteType:          ed25519signature2018.SignatureType,
				VerificationMethod: ownerVerMethod,
			},
			zcapld.WithAllowedActions("read", "write"),
			zcapld.WithInvocationTarget(resource, "urn:edv:document"),
			zcapld.WithID(resource),
		)
		require.NoError(t, err)

		_, thirdPartySecrets, thirdPartyVerMethod := signerAndSecrets(t)
		ownerSecrets = importDIDKeyIntoSecrets(t, thirdPartyVerMethod, ownerSecrets)

		thirdPartyRequest := httptest.NewRequest(http.MethodGet, resource, nil)
		thirdPartyRequest.Header.Set(
			zcapld.CapabilityInvocationHTTPHeader,
			fmt.Sprintf(`zcap capability,action="%s"`, "read"),
		)

		err = httpsignatures.NewHTTPSignatures(thirdPartySecrets).Sign(thirdPartyVerMethod, thirdPartyRequest)
		require.NoError(t, err)

		zcapld.NewHTTPSigAuthHandler(
			&zcapld.HTTPSigAuthConfig{
				CapabilityResolver: zcapld.SimpleCapabilityResolver{ownerZCAP.ID: ownerZCAP},
				KeyResolver:        &zcapld.DIDKeyResolver{},
				VerifierOptions: []zcapld.VerificationOption{
					zcapld.WithSignatureSuites(
						ed25519signature2018.New(suite.WithVerifier(ed25519signature2018.NewPublicKeyVerifier())),
					),
					zcapld.WithLDDocumentLoaders(testLDDocumentLoader),
				},
				Secrets:     ownerSecrets,
				ErrConsumer: logger,
			},
			&zcapld.InvocationExpectations{
				Target:         resource,
				RootCapability: resource,
				Action:         "read",
			},
			next,
		).ServeHTTP(httptest.NewRecorder(), thirdPartyRequest)
		require.Error(t, logErr)
		require.Contains(t, logErr.Error(), `invalid key=value format`)
		require.False(t, executed)
	})
}

func compressZCAP(t *testing.T, zcap *zcapld.Capability) string {
	raw, err := json.Marshal(zcap)
	require.NoError(t, err)

	compressed := bytes.NewBuffer(nil)

	w := gzip.NewWriter(compressed)

	_, err = w.Write(raw)
	require.NoError(t, err)

	err = w.Close()
	require.NoError(t, err)

	return base64.URLEncoding.EncodeToString(compressed.Bytes())
}

func signerAndSecrets(t *testing.T) (signature.Signer, httpsignatures.Secrets, string) {
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	block := &pem.Block{Type: "PRIVATE KEY"}
	block.Bytes, err = x509.MarshalPKCS8PrivateKey(privKey)
	require.NoError(t, err)

	pemPrivKey := bytes.NewBuffer(nil)

	err = pem.Encode(pemPrivKey, block)
	require.NoError(t, err)

	block = &pem.Block{Type: "PUBLIC KEY"}
	block.Bytes, err = x509.MarshalPKIXPublicKey(pubKey)
	require.NoError(t, err)

	pemPubKey := bytes.NewBuffer(nil)

	err = pem.Encode(pemPubKey, block)
	require.NoError(t, err)

	signer := &ed25519Signer{
		pubKey:  pubKey,
		privKey: privKey,
	}

	_, didKeyURL := fingerprint.CreateDIDKey(pubKey)

	secrets := httpsignatures.NewSimpleSecretsStorage(map[string]httpsignatures.Secret{
		didKeyURL: {
			KeyID:      didKeyURL,
			PublicKey:  pemPubKey.String(),
			PrivateKey: pemPrivKey.String(),
			Algorithm:  kms.ED25519,
		},
	})

	return signer, secrets, didKeyURL
}

type ed25519Signer struct {
	pubKey  ed25519.PublicKey
	privKey ed25519.PrivateKey
}

func (e *ed25519Signer) Sign(msg []byte) ([]byte, error) {
	return ed25519.Sign(e.privKey, msg), nil
}

func (e *ed25519Signer) PublicKey() interface{} {
	return e.pubKey
}

func (e *ed25519Signer) PublicKeyBytes() []byte {
	return e.pubKey
}

// TODO should not have to import the sender's did:key verification key into the verifier's secrets store:
//  https://github.com/trustbloc/edge-core/issues/105.
func importDIDKeyIntoSecrets(t *testing.T, didKeyURL string, s httpsignatures.Secrets) httpsignatures.Secrets {
	key, err := (&zcapld.DIDKeyResolver{}).Resolve(didKeyURL)
	require.NoError(t, err)

	block := &pem.Block{Type: "PUBLIC KEY"}
	block.Bytes, err = x509.MarshalPKIXPublicKey(ed25519.PublicKey(key.Value))
	require.NoError(t, err)

	pemPubKey := bytes.NewBuffer(nil)

	err = pem.Encode(pemPubKey, block)
	require.NoError(t, err)

	first := httpsignatures.NewSimpleSecretsStorage(map[string]httpsignatures.Secret{
		didKeyURL: {
			KeyID:     didKeyURL,
			PublicKey: pemPubKey.String(),
			Algorithm: kms.ED25519,
		},
	})

	return &mockSecrets{
		first: first,
		next:  s,
	}
}

type mockSecrets struct {
	first httpsignatures.Secrets
	next  httpsignatures.Secrets
}

func (m *mockSecrets) Get(keyID string) (httpsignatures.Secret, error) {
	s, err := m.first.Get(keyID)
	if err == nil {
		return s, nil
	}

	return m.next.Get(keyID)
}
