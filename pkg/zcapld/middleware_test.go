/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package zcapld_test

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/ed25519signature2018"
	"github.com/hyperledger/aries-framework-go/pkg/mock/crypto"
	mockkms "github.com/hyperledger/aries-framework-go/pkg/mock/kms"
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
		resourceOwner := newAgent(t)
		resourceOwnerSigner := resourceOwner.signer()
		resourceOwnerVerMethod := didKeyURL(resourceOwnerSigner)
		resourceOwnerZCAP, err := zcapld.NewCapability(
			&zcapld.Signer{
				SignatureSuite:     ed25519signature2018.New(suite.WithSigner(resourceOwnerSigner)),
				SuiteType:          ed25519signature2018.SignatureType,
				VerificationMethod: resourceOwnerVerMethod,
			},
			zcapld.WithAllowedActions("read", "write"),
			zcapld.WithInvocationTarget(resource, "urn:edv:document"),
			zcapld.WithID(resource),
		)
		require.NoError(t, err)

		thirdParty := newAgent(t)
		thirdPartySigner := thirdParty.signer()
		thirdPartyVerMethod := didKeyURL(thirdPartySigner)
		thirdPartyZCAP, err := zcapld.NewCapability(
			&zcapld.Signer{
				SignatureSuite:     ed25519signature2018.New(suite.WithSigner(resourceOwnerSigner)),
				SuiteType:          ed25519signature2018.SignatureType,
				VerificationMethod: resourceOwnerVerMethod,
			},
			zcapld.WithParent(resourceOwnerZCAP.ID),
			zcapld.WithInvoker(thirdPartyVerMethod),
			zcapld.WithCapabilityChain(resource),
			zcapld.WithAllowedActions("read"), // attenuated
			zcapld.WithInvocationTarget(resource, "urn:edv:document"),
		)
		require.NoError(t, err)

		thirdPartyRequest := httptest.NewRequest(http.MethodGet, resource, nil)
		thirdPartyRequest.Header.Set(
			zcapld.CapabilityInvocationHTTPHeader,
			fmt.Sprintf(`zcap capability="%s",action="%s"`, compressZCAP(t, thirdPartyZCAP), "read"),
		)

		hs := httpsignatures.NewHTTPSignatures(&zcapld.AriesDIDKeySecrets{})
		hs.SetSignatureHashAlgorithm(&zcapld.AriesDIDKeySignatureHashAlgorithm{
			Crypto: thirdParty.Crypto(),
			KMS:    thirdParty.KMS(),
		})
		err = hs.Sign(thirdPartyVerMethod, thirdPartyRequest)
		require.NoError(t, err)

		zcapld.NewHTTPSigAuthHandler(
			&zcapld.HTTPSigAuthConfig{
				CapabilityResolver: zcapld.SimpleCapabilityResolver{resourceOwnerZCAP.ID: resourceOwnerZCAP},
				KeyResolver:        &zcapld.DIDKeyResolver{},
				VerifierOptions: []zcapld.VerificationOption{
					zcapld.WithSignatureSuites(
						ed25519signature2018.New(suite.WithVerifier(ed25519signature2018.NewPublicKeyVerifier())),
					),
					zcapld.WithLDDocumentLoaders(testLDDocumentLoader),
				},
				Secrets:     &zcapld.AriesDIDKeySecrets{},
				ErrConsumer: logger,
				KMS:         resourceOwner.KMS(),
				Crypto:      resourceOwner.Crypto(),
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

		resourceOwner := newAgent(t)
		resourceOwnerSigner := resourceOwner.signer()
		resourceOwnerVerMethod := didKeyURL(resourceOwnerSigner)
		ownerZCAP, err := zcapld.NewCapability(
			&zcapld.Signer{
				SignatureSuite:     ed25519signature2018.New(suite.WithSigner(resourceOwnerSigner)),
				SuiteType:          ed25519signature2018.SignatureType,
				VerificationMethod: resourceOwnerVerMethod,
			},
			zcapld.WithAllowedActions("read", "write"),
			zcapld.WithInvocationTarget(resource, "urn:edv:document"),
			zcapld.WithID(resource),
		)
		require.NoError(t, err)

		thirdParty := newAgent(t)
		thirdPartyVerMethod := didKeyURL(thirdParty.signer())
		thirdPartyZCAP, err := zcapld.NewCapability(
			&zcapld.Signer{
				SignatureSuite:     ed25519signature2018.New(suite.WithSigner(resourceOwnerSigner)),
				SuiteType:          ed25519signature2018.SignatureType,
				VerificationMethod: resourceOwnerVerMethod,
			},
			zcapld.WithParent(ownerZCAP.ID),
			zcapld.WithInvoker(thirdPartyVerMethod),
			zcapld.WithCapabilityChain(resource),
			zcapld.WithAllowedActions("read"), // attenuated
			zcapld.WithInvocationTarget(resource, "urn:edv:document"),
		)
		require.NoError(t, err)

		thirdPartyRequest := httptest.NewRequest(http.MethodGet, resource, nil)
		thirdPartyRequest.Header.Set(
			zcapld.CapabilityInvocationHTTPHeader,
			fmt.Sprintf(`zcap capability="%s",action="%s"`, compressZCAP(t, thirdPartyZCAP), "read"),
		)

		unknown := newAgent(t)
		unknownSigner := unknown.signer()
		unknownVerificationMethod := didKeyURL(unknownSigner)

		hs := httpsignatures.NewHTTPSignatures(&zcapld.AriesDIDKeySecrets{})
		hs.SetSignatureHashAlgorithm(&zcapld.AriesDIDKeySignatureHashAlgorithm{
			Crypto: unknown.Crypto(),
			KMS:    unknown.KMS(),
		})
		err = hs.Sign(unknownVerificationMethod, thirdPartyRequest)
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
				Secrets:     httpsignatures.NewSimpleSecretsStorage(nil),
				ErrConsumer: logger,
				KMS:         resourceOwner.KMS(),
				Crypto:      resourceOwner.Crypto(),
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

		resourceOwner := newAgent(t)
		resourceOwnerSigner := resourceOwner.signer()
		resourceOwnerVerMethod := didKeyURL(resourceOwnerSigner)
		ownerZCAP, err := zcapld.NewCapability(
			&zcapld.Signer{
				SignatureSuite:     ed25519signature2018.New(suite.WithSigner(resourceOwnerSigner)),
				SuiteType:          ed25519signature2018.SignatureType,
				VerificationMethod: resourceOwnerVerMethod,
			},
			zcapld.WithAllowedActions("read", "write"),
			zcapld.WithInvocationTarget(resource, "urn:edv:document"),
			zcapld.WithID(resource),
		)
		require.NoError(t, err)

		thirdPartyVerMethod := didKeyURL(newAgent(t).signer())
		thirdPartyZCAP, err := zcapld.NewCapability(
			&zcapld.Signer{
				SignatureSuite:     ed25519signature2018.New(suite.WithSigner(resourceOwnerSigner)),
				SuiteType:          ed25519signature2018.SignatureType,
				VerificationMethod: resourceOwnerVerMethod,
			},
			zcapld.WithParent(ownerZCAP.ID),
			zcapld.WithInvoker(thirdPartyVerMethod),
			zcapld.WithCapabilityChain(resource),
			zcapld.WithAllowedActions("read"), // attenuated
			zcapld.WithInvocationTarget(resource, "urn:edv:document"),
		)
		require.NoError(t, err)

		thirdPartyRequest := httptest.NewRequest(http.MethodGet, resource, nil)
		thirdPartyRequest.Header.Set(
			zcapld.CapabilityInvocationHTTPHeader,
			fmt.Sprintf(`zcap capability="%s",action="%s"`, compressZCAP(t, thirdPartyZCAP), "read"),
		)

		unknown := newAgent(t)
		unknownSigner := unknown.signer()
		unknownVerMethod := didKeyURL(unknownSigner)

		hs := httpsignatures.NewHTTPSignatures(&zcapld.AriesDIDKeySecrets{})
		hs.SetSignatureHashAlgorithm(&zcapld.AriesDIDKeySignatureHashAlgorithm{
			Crypto: unknown.Crypto(),
			KMS:    unknown.KMS(),
		})
		err = hs.Sign(unknownVerMethod, thirdPartyRequest)
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
				Secrets:     &zcapld.AriesDIDKeySecrets{},
				ErrConsumer: logger,
				KMS:         resourceOwner.KMS(),
				Crypto:      resourceOwner.Crypto(),
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

		resourceOwner := newAgent(t)
		resourceOwnerSigner := resourceOwner.signer()
		resourceOwnerVerMethod := didKeyURL(resourceOwnerSigner)
		ownerZCAP, err := zcapld.NewCapability(
			&zcapld.Signer{
				SignatureSuite:     ed25519signature2018.New(suite.WithSigner(resourceOwnerSigner)),
				SuiteType:          ed25519signature2018.SignatureType,
				VerificationMethod: resourceOwnerVerMethod,
			},
			zcapld.WithAllowedActions("read", "write"),
			zcapld.WithInvocationTarget(resource, "urn:edv:document"),
			zcapld.WithID(resource),
		)
		require.NoError(t, err)

		thirdParty := newAgent(t)
		thirdPartyVerMethod := didKeyURL(thirdParty.signer())
		thirdPartyZCAP, err := zcapld.NewCapability(
			&zcapld.Signer{
				SignatureSuite:     ed25519signature2018.New(suite.WithSigner(resourceOwnerSigner)),
				SuiteType:          ed25519signature2018.SignatureType,
				VerificationMethod: resourceOwnerVerMethod,
			},
			zcapld.WithParent(ownerZCAP.ID),
			zcapld.WithInvoker(thirdPartyVerMethod),
			zcapld.WithCapabilityChain(resource),
			zcapld.WithAllowedActions("read"),
			zcapld.WithInvocationTarget(resource, "urn:edv:document"),
		)
		require.NoError(t, err)

		thirdPartyRequest := httptest.NewRequest(http.MethodGet, resource, nil)
		thirdPartyRequest.Header.Set(
			zcapld.CapabilityInvocationHTTPHeader,
			fmt.Sprintf(`zcap capability="%s",action="%s"`, compressZCAP(t, thirdPartyZCAP), "write"),
		)

		hs := httpsignatures.NewHTTPSignatures(&zcapld.AriesDIDKeySecrets{})
		hs.SetSignatureHashAlgorithm(&zcapld.AriesDIDKeySignatureHashAlgorithm{
			Crypto: thirdParty.Crypto(),
			KMS:    thirdParty.KMS(),
		})
		err = hs.Sign(thirdPartyVerMethod, thirdPartyRequest)
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
				Secrets:     &zcapld.AriesDIDKeySecrets{},
				ErrConsumer: logger,
				KMS:         resourceOwner.KMS(),
				Crypto:      resourceOwner.Crypto(),
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

		resourceOwner := newAgent(t)
		resourceOwnerSigner := resourceOwner.signer()
		resourceOwnerVerMethod := didKeyURL(resourceOwnerSigner)
		ownerZCAP, err := zcapld.NewCapability(
			&zcapld.Signer{
				SignatureSuite:     ed25519signature2018.New(suite.WithSigner(resourceOwnerSigner)),
				SuiteType:          ed25519signature2018.SignatureType,
				VerificationMethod: resourceOwnerVerMethod,
			},
			zcapld.WithAllowedActions("read", "write"),
			zcapld.WithInvocationTarget(resource, "urn:edv:document"),
			zcapld.WithID(resource),
		)
		require.NoError(t, err)

		thirdParty := newAgent(t)
		thirdPartyVerMethod := didKeyURL(thirdParty.signer())
		thirdPartyZCAP, err := zcapld.NewCapability(
			&zcapld.Signer{
				SignatureSuite:     ed25519signature2018.New(suite.WithSigner(resourceOwnerSigner)),
				SuiteType:          ed25519signature2018.SignatureType,
				VerificationMethod: resourceOwnerVerMethod,
			},
			zcapld.WithParent(ownerZCAP.ID),
			zcapld.WithInvoker(thirdPartyVerMethod),
			zcapld.WithCapabilityChain(resource),
			zcapld.WithAllowedActions("read"), // attenuated
			zcapld.WithInvocationTarget(resource, "urn:edv:document"),
		)
		require.NoError(t, err)

		thirdPartyRequest := httptest.NewRequest(http.MethodGet, resource, nil)
		thirdPartyRequest.Header.Set(
			zcapld.CapabilityInvocationHTTPHeader,
			fmt.Sprintf(`zcap capability="%s",action="%s"`, compressZCAP(t, thirdPartyZCAP), "read"),
		)

		hs := httpsignatures.NewHTTPSignatures(&zcapld.AriesDIDKeySecrets{})
		hs.SetSignatureHashAlgorithm(&zcapld.AriesDIDKeySignatureHashAlgorithm{
			Crypto: thirdParty.Crypto(),
			KMS:    thirdParty.KMS(),
		})
		err = hs.Sign(thirdPartyVerMethod, thirdPartyRequest)
		require.NoError(t, err)

		zcapld.NewHTTPSigAuthHandler(
			&zcapld.HTTPSigAuthConfig{
				CapabilityResolver: zcapld.SimpleCapabilityResolver{ownerZCAP.ID: ownerZCAP},
				KeyResolver:        &zcapld.DIDKeyResolver{},
				VerifierOptions: []zcapld.VerificationOption{
					zcapld.WithLDDocumentLoaders(testLDDocumentLoader),
				},
				Secrets:     &zcapld.AriesDIDKeySecrets{},
				ErrConsumer: logger,
				KMS:         resourceOwner.KMS(),
				Crypto:      resourceOwner.Crypto(),
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

		resourceOwner := newAgent(t)
		resourceOwnerSigner := resourceOwner.signer()
		resourceOwnerVerMethod := didKeyURL(resourceOwnerSigner)
		ownerZCAP, err := zcapld.NewCapability(
			&zcapld.Signer{
				SignatureSuite:     ed25519signature2018.New(suite.WithSigner(resourceOwnerSigner)),
				SuiteType:          ed25519signature2018.SignatureType,
				VerificationMethod: resourceOwnerVerMethod,
			},
			zcapld.WithAllowedActions("read", "write"),
			zcapld.WithInvocationTarget(resource, "urn:edv:document"),
			zcapld.WithID(resource),
		)
		require.NoError(t, err)

		thirdParty := newAgent(t)
		thirdPartyVerMethod := didKeyURL(thirdParty.signer())

		thirdPartyRequest := httptest.NewRequest(http.MethodGet, resource, nil)
		thirdPartyRequest.Header.Set(
			zcapld.CapabilityInvocationHTTPHeader,
			fmt.Sprintf(`zcap action="%s"`, "read"),
		)

		hs := httpsignatures.NewHTTPSignatures(&zcapld.AriesDIDKeySecrets{})
		hs.SetSignatureHashAlgorithm(&zcapld.AriesDIDKeySignatureHashAlgorithm{
			Crypto: thirdParty.Crypto(),
			KMS:    thirdParty.KMS(),
		})
		err = hs.Sign(thirdPartyVerMethod, thirdPartyRequest)
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
				Secrets:     &zcapld.AriesDIDKeySecrets{},
				ErrConsumer: logger,
				KMS:         resourceOwner.KMS(),
				Crypto:      resourceOwner.Crypto(),
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

		resourceOwner := newAgent(t)
		resourceOwnerSigner := resourceOwner.signer()
		resourceOwnerVerMethod := didKeyURL(resourceOwnerSigner)
		ownerZCAP, err := zcapld.NewCapability(
			&zcapld.Signer{
				SignatureSuite:     ed25519signature2018.New(suite.WithSigner(resourceOwnerSigner)),
				SuiteType:          ed25519signature2018.SignatureType,
				VerificationMethod: resourceOwnerVerMethod,
			},
			zcapld.WithAllowedActions("read", "write"),
			zcapld.WithInvocationTarget(resource, "urn:edv:document"),
			zcapld.WithID(resource),
		)
		require.NoError(t, err)

		thirdParty := newAgent(t)
		thirdPartyVerMethod := didKeyURL(thirdParty.signer())

		thirdPartyRequest := httptest.NewRequest(http.MethodGet, resource, nil)

		hs := httpsignatures.NewHTTPSignatures(&zcapld.AriesDIDKeySecrets{})
		hs.SetSignatureHashAlgorithm(&zcapld.AriesDIDKeySignatureHashAlgorithm{
			Crypto: thirdParty.Crypto(),
			KMS:    thirdParty.KMS(),
		})
		err = hs.Sign(thirdPartyVerMethod, thirdPartyRequest)
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
				Secrets:     &zcapld.AriesDIDKeySecrets{},
				ErrConsumer: logger,
				KMS:         resourceOwner.KMS(),
				Crypto:      resourceOwner.Crypto(),
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

		resourceOwner := newAgent(t)
		resourceOwnerSigner := resourceOwner.signer()
		resourceOwnerVerMethod := didKeyURL(resourceOwnerSigner)
		ownerZCAP, err := zcapld.NewCapability(
			&zcapld.Signer{
				SignatureSuite:     ed25519signature2018.New(suite.WithSigner(resourceOwnerSigner)),
				SuiteType:          ed25519signature2018.SignatureType,
				VerificationMethod: resourceOwnerVerMethod,
			},
			zcapld.WithAllowedActions("read", "write"),
			zcapld.WithInvocationTarget(resource, "urn:edv:document"),
			zcapld.WithID(resource),
		)
		require.NoError(t, err)

		thirdParty := newAgent(t)
		thirdPartyVerMethod := didKeyURL(thirdParty.signer())
		thirdPartyZCAP, err := zcapld.NewCapability(
			&zcapld.Signer{
				SignatureSuite:     ed25519signature2018.New(suite.WithSigner(resourceOwnerSigner)),
				SuiteType:          ed25519signature2018.SignatureType,
				VerificationMethod: resourceOwnerVerMethod,
			},
			zcapld.WithParent(ownerZCAP.ID),
			zcapld.WithInvoker(thirdPartyVerMethod),
			zcapld.WithCapabilityChain(resource),
			zcapld.WithAllowedActions("read"), // attenuated
			zcapld.WithInvocationTarget(resource, "urn:edv:document"),
		)
		require.NoError(t, err)

		thirdPartyRequest := httptest.NewRequest(http.MethodGet, resource, nil)
		thirdPartyRequest.Header.Set(
			zcapld.CapabilityInvocationHTTPHeader,
			fmt.Sprintf(`INVALID capability="%s",action="%s"`, compressZCAP(t, thirdPartyZCAP), "read"),
		)

		hs := httpsignatures.NewHTTPSignatures(&zcapld.AriesDIDKeySecrets{})
		hs.SetSignatureHashAlgorithm(&zcapld.AriesDIDKeySignatureHashAlgorithm{
			Crypto: thirdParty.Crypto(),
			KMS:    thirdParty.KMS(),
		})
		err = hs.Sign(thirdPartyVerMethod, thirdPartyRequest)
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
				Secrets:     &zcapld.AriesDIDKeySecrets{},
				ErrConsumer: logger,
				KMS:         resourceOwner.KMS(),
				Crypto:      resourceOwner.Crypto(),
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

		resourceOwner := newAgent(t)
		resourceOwnerSigner := resourceOwner.signer()
		resourceOwnerVerMethod := didKeyURL(resourceOwnerSigner)
		ownerZCAP, err := zcapld.NewCapability(
			&zcapld.Signer{
				SignatureSuite:     ed25519signature2018.New(suite.WithSigner(resourceOwnerSigner)),
				SuiteType:          ed25519signature2018.SignatureType,
				VerificationMethod: resourceOwnerVerMethod,
			},
			zcapld.WithAllowedActions("read", "write"),
			zcapld.WithInvocationTarget(resource, "urn:edv:document"),
			zcapld.WithID(resource),
		)
		require.NoError(t, err)

		thirdParty := newAgent(t)
		thirdPartyVerMethod := didKeyURL(thirdParty.signer())
		thirdPartyZCAP, err := zcapld.NewCapability(
			&zcapld.Signer{
				SignatureSuite:     ed25519signature2018.New(suite.WithSigner(resourceOwnerSigner)),
				SuiteType:          ed25519signature2018.SignatureType,
				VerificationMethod: resourceOwnerVerMethod,
			},
			zcapld.WithParent(ownerZCAP.ID),
			zcapld.WithInvoker(thirdPartyVerMethod),
			zcapld.WithCapabilityChain(resource),
			zcapld.WithAllowedActions("read"), // attenuated
			zcapld.WithInvocationTarget(resource, "urn:edv:document"),
		)
		require.NoError(t, err)

		thirdPartyRequest := httptest.NewRequest(http.MethodGet, resource, nil)
		thirdPartyRequest.Header.Set(
			zcapld.CapabilityInvocationHTTPHeader,
			fmt.Sprintf(`zcap capability=%s,action="%s"`, compressZCAP(t, thirdPartyZCAP), "read"),
		)

		hs := httpsignatures.NewHTTPSignatures(&zcapld.AriesDIDKeySecrets{})
		hs.SetSignatureHashAlgorithm(&zcapld.AriesDIDKeySignatureHashAlgorithm{
			Crypto: thirdParty.Crypto(),
			KMS:    thirdParty.KMS(),
		})
		err = hs.Sign(thirdPartyVerMethod, thirdPartyRequest)
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
				Secrets:     &zcapld.AriesDIDKeySecrets{},
				ErrConsumer: logger,
				KMS:         resourceOwner.KMS(),
				Crypto:      resourceOwner.Crypto(),
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

		resourceOwner := newAgent(t)
		resourceOwnerSigner := resourceOwner.signer()
		resourceOwnerVerMethod := didKeyURL(resourceOwnerSigner)
		ownerZCAP, err := zcapld.NewCapability(
			&zcapld.Signer{
				SignatureSuite:     ed25519signature2018.New(suite.WithSigner(resourceOwnerSigner)),
				SuiteType:          ed25519signature2018.SignatureType,
				VerificationMethod: resourceOwnerVerMethod,
			},
			zcapld.WithAllowedActions("read", "write"),
			zcapld.WithInvocationTarget(resource, "urn:edv:document"),
			zcapld.WithID(resource),
		)
		require.NoError(t, err)

		thirdParty := newAgent(t)
		thirdPartyVerMethod := didKeyURL(thirdParty.signer())

		thirdPartyRequest := httptest.NewRequest(http.MethodGet, resource, nil)
		thirdPartyRequest.Header.Set(
			zcapld.CapabilityInvocationHTTPHeader,
			fmt.Sprintf(`zcap capability="%s",action="%s"`, "MALFORMED", "read"),
		)

		hs := httpsignatures.NewHTTPSignatures(&zcapld.AriesDIDKeySecrets{})
		hs.SetSignatureHashAlgorithm(&zcapld.AriesDIDKeySignatureHashAlgorithm{
			Crypto: thirdParty.Crypto(),
			KMS:    thirdParty.KMS(),
		})
		err = hs.Sign(thirdPartyVerMethod, thirdPartyRequest)
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
				Secrets:     &zcapld.AriesDIDKeySecrets{},
				ErrConsumer: logger,
				KMS:         resourceOwner.KMS(),
				Crypto:      resourceOwner.Crypto(),
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

		resourceOwner := newAgent(t)
		resourceOwnerSigner := resourceOwner.signer()
		resourceOwnerVerMethod := didKeyURL(resourceOwnerSigner)
		ownerZCAP, err := zcapld.NewCapability(
			&zcapld.Signer{
				SignatureSuite:     ed25519signature2018.New(suite.WithSigner(resourceOwnerSigner)),
				SuiteType:          ed25519signature2018.SignatureType,
				VerificationMethod: resourceOwnerVerMethod,
			},
			zcapld.WithAllowedActions("read", "write"),
			zcapld.WithInvocationTarget(resource, "urn:edv:document"),
			zcapld.WithID(resource),
		)
		require.NoError(t, err)

		thirdParty := newAgent(t)
		thirdPartyVerMethod := didKeyURL(thirdParty.signer())
		thirdPartyZCAP, err := zcapld.NewCapability(
			&zcapld.Signer{
				SignatureSuite:     ed25519signature2018.New(suite.WithSigner(resourceOwnerSigner)),
				SuiteType:          ed25519signature2018.SignatureType,
				VerificationMethod: resourceOwnerVerMethod,
			},
			zcapld.WithParent(ownerZCAP.ID),
			zcapld.WithInvoker(thirdPartyVerMethod),
			zcapld.WithCapabilityChain(resource),
			zcapld.WithAllowedActions("read"), // attenuated
			zcapld.WithInvocationTarget(resource, "urn:edv:document"),
		)
		require.NoError(t, err)

		thirdPartyRequest := httptest.NewRequest(http.MethodGet, resource, nil)
		thirdPartyRequest.Header.Set(
			zcapld.CapabilityInvocationHTTPHeader,
			fmt.Sprintf(`zcap capability="%s",action=%s`, compressZCAP(t, thirdPartyZCAP), "read"),
		)

		hs := httpsignatures.NewHTTPSignatures(&zcapld.AriesDIDKeySecrets{})
		hs.SetSignatureHashAlgorithm(&zcapld.AriesDIDKeySignatureHashAlgorithm{
			Crypto: thirdParty.Crypto(),
			KMS:    thirdParty.KMS(),
		})
		err = hs.Sign(thirdPartyVerMethod, thirdPartyRequest)
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
				Secrets:     &zcapld.AriesDIDKeySecrets{},
				ErrConsumer: logger,
				KMS:         resourceOwner.KMS(),
				Crypto:      resourceOwner.Crypto(),
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

		resourceOwner := newAgent(t)
		resourceOwnerSigner := resourceOwner.signer()
		resourceOwnerVerMethod := didKeyURL(resourceOwnerSigner)
		ownerZCAP, err := zcapld.NewCapability(
			&zcapld.Signer{
				SignatureSuite:     ed25519signature2018.New(suite.WithSigner(resourceOwnerSigner)),
				SuiteType:          ed25519signature2018.SignatureType,
				VerificationMethod: resourceOwnerVerMethod,
			},
			zcapld.WithAllowedActions("read", "write"),
			zcapld.WithInvocationTarget(resource, "urn:edv:document"),
			zcapld.WithID(resource),
		)
		require.NoError(t, err)

		thirdParty := newAgent(t)
		thirdPartyVerMethod := didKeyURL(thirdParty.signer())
		thirdPartyZCAP, err := zcapld.NewCapability(
			&zcapld.Signer{
				SignatureSuite:     ed25519signature2018.New(suite.WithSigner(resourceOwnerSigner)),
				SuiteType:          ed25519signature2018.SignatureType,
				VerificationMethod: resourceOwnerVerMethod,
			},
			zcapld.WithParent(ownerZCAP.ID),
			zcapld.WithInvoker(thirdPartyVerMethod),
			zcapld.WithCapabilityChain(resource),
			zcapld.WithAllowedActions("read"), // attenuated
			zcapld.WithInvocationTarget(resource, "urn:edv:document"),
		)
		require.NoError(t, err)

		thirdPartyRequest := httptest.NewRequest(http.MethodGet, resource, nil)
		thirdPartyRequest.Header.Set(
			zcapld.CapabilityInvocationHTTPHeader,
			fmt.Sprintf(`zcap capability="%s"`, compressZCAP(t, thirdPartyZCAP)),
		)

		hs := httpsignatures.NewHTTPSignatures(&zcapld.AriesDIDKeySecrets{})
		hs.SetSignatureHashAlgorithm(&zcapld.AriesDIDKeySignatureHashAlgorithm{
			Crypto: thirdParty.Crypto(),
			KMS:    thirdParty.KMS(),
		})
		err = hs.Sign(thirdPartyVerMethod, thirdPartyRequest)
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
				Secrets:     &zcapld.AriesDIDKeySecrets{},
				ErrConsumer: logger,
				KMS:         resourceOwner.KMS(),
				Crypto:      resourceOwner.Crypto(),
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

		resourceOwner := newAgent(t)
		resourceOwnerSigner := resourceOwner.signer()
		resourceOwnerVerMethod := didKeyURL(resourceOwnerSigner)
		ownerZCAP, err := zcapld.NewCapability(
			&zcapld.Signer{
				SignatureSuite:     ed25519signature2018.New(suite.WithSigner(resourceOwnerSigner)),
				SuiteType:          ed25519signature2018.SignatureType,
				VerificationMethod: resourceOwnerVerMethod,
			},
			zcapld.WithAllowedActions("read", "write"),
			zcapld.WithInvocationTarget(resource, "urn:edv:document"),
			zcapld.WithID(resource),
		)
		require.NoError(t, err)

		thirdParty := newAgent(t)
		thirdPartyVerMethod := didKeyURL(thirdParty.signer())
		thirdPartyZCAP, err := zcapld.NewCapability(
			&zcapld.Signer{
				SignatureSuite:     ed25519signature2018.New(suite.WithSigner(resourceOwnerSigner)),
				SuiteType:          ed25519signature2018.SignatureType,
				VerificationMethod: resourceOwnerVerMethod,
			},
			zcapld.WithParent(ownerZCAP.ID),
			zcapld.WithInvoker(thirdPartyVerMethod),
			zcapld.WithCapabilityChain(resource),
			zcapld.WithAllowedActions("read"), // attenuated
			zcapld.WithInvocationTarget(resource, "urn:edv:document"),
		)
		require.NoError(t, err)

		thirdPartyRequest := httptest.NewRequest(http.MethodGet, resource, nil)
		thirdPartyRequest.Header.Set(
			zcapld.CapabilityInvocationHTTPHeader,
			fmt.Sprintf(`zcap capability="%s",action="%s",unrecognized="foo"`, compressZCAP(t, thirdPartyZCAP), "read"),
		)

		hs := httpsignatures.NewHTTPSignatures(&zcapld.AriesDIDKeySecrets{})
		hs.SetSignatureHashAlgorithm(&zcapld.AriesDIDKeySignatureHashAlgorithm{
			Crypto: thirdParty.Crypto(),
			KMS:    thirdParty.KMS(),
		})
		err = hs.Sign(thirdPartyVerMethod, thirdPartyRequest)
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
				Secrets:     &zcapld.AriesDIDKeySecrets{},
				ErrConsumer: logger,
				KMS:         resourceOwner.KMS(),
				Crypto:      resourceOwner.Crypto(),
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

		resourceOwner := newAgent(t)
		resourceOwnerSigner := resourceOwner.signer()
		resourceOwnerVerMethod := didKeyURL(resourceOwnerSigner)
		ownerZCAP, err := zcapld.NewCapability(
			&zcapld.Signer{
				SignatureSuite:     ed25519signature2018.New(suite.WithSigner(resourceOwnerSigner)),
				SuiteType:          ed25519signature2018.SignatureType,
				VerificationMethod: resourceOwnerVerMethod,
			},
			zcapld.WithAllowedActions("read", "write"),
			zcapld.WithInvocationTarget(resource, "urn:edv:document"),
			zcapld.WithID(resource),
		)
		require.NoError(t, err)

		thirdParty := newAgent(t)
		thirdPartyVerMethod := didKeyURL(thirdParty.signer())

		thirdPartyRequest := httptest.NewRequest(http.MethodGet, resource, nil)
		thirdPartyRequest.Header.Set(
			zcapld.CapabilityInvocationHTTPHeader,
			fmt.Sprintf(`zcap capability,action="%s"`, "read"),
		)

		hs := httpsignatures.NewHTTPSignatures(&zcapld.AriesDIDKeySecrets{})
		hs.SetSignatureHashAlgorithm(&zcapld.AriesDIDKeySignatureHashAlgorithm{
			Crypto: thirdParty.Crypto(),
			KMS:    thirdParty.KMS(),
		})
		err = hs.Sign(thirdPartyVerMethod, thirdPartyRequest)
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
				Secrets:     &zcapld.AriesDIDKeySecrets{},
				ErrConsumer: logger,
				KMS:         resourceOwner.KMS(),
				Crypto:      resourceOwner.Crypto(),
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

func TestAriesDIDKeySignatureHashAlgorithm_Create(t *testing.T) {
	t.Run("fails if not a did:key url", func(t *testing.T) {
		a := &zcapld.AriesDIDKeySignatureHashAlgorithm{}
		_, err := a.Create(
			httpsignatures.Secret{KeyID: "NOT_A_DID_KEY_URL"},
			nil,
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to resolve did:key URL")
	})

	t.Run("fails if did:key is not registered in the aries KMS", func(t *testing.T) {
		agent := newAgent(t)
		a := &zcapld.AriesDIDKeySignatureHashAlgorithm{
			Crypto: agent.Crypto(),
			KMS:    agent.KMS(),
		}
		_, err := a.Create(
			httpsignatures.Secret{KeyID: didKeyURL(newAgent(t).signer())},
			nil,
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to get key handle for kid")
	})

	t.Run("fails if cannot sign the message", func(t *testing.T) {
		expected := errors.New("test")
		agent := newAgent(t)
		keyID := didKeyURL(agent.signer())
		a := &zcapld.AriesDIDKeySignatureHashAlgorithm{
			KMS:    agent.KMS(),
			Crypto: &crypto.Crypto{SignErr: expected},
		}
		_, err := a.Create(httpsignatures.Secret{KeyID: keyID}, nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to sign data")
		require.True(t, errors.Is(err, expected))
	})
}

func TestAriesDIDKeySignatureHashAlgorithm_Verify(t *testing.T) {
	t.Run("fails if not a did:key url", func(t *testing.T) {
		a := &zcapld.AriesDIDKeySignatureHashAlgorithm{}
		err := a.Verify(httpsignatures.Secret{KeyID: "NOT_DID_KEY"}, nil, nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to resolve did:key URL")
	})

	t.Run("fails if KMS cannot create key handle", func(t *testing.T) {
		expected := errors.New("test")
		a := &zcapld.AriesDIDKeySignatureHashAlgorithm{
			KMS: &mockkms.KeyManager{PubKeyBytesToHandleErr: expected},
		}
		err := a.Verify(httpsignatures.Secret{KeyID: didKeyURL(newAgent(t).signer())}, nil, nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to convert did:key pubkey to aries kms handle")
		require.True(t, errors.Is(err, expected))
	})

	t.Run("fails if framework Crypto cannot verify signature", func(t *testing.T) {
		expected := errors.New("test")
		agent := newAgent(t)
		a := &zcapld.AriesDIDKeySignatureHashAlgorithm{
			KMS:    agent.KMS(),
			Crypto: &crypto.Crypto{VerifyErr: expected},
		}
		err := a.Verify(httpsignatures.Secret{KeyID: didKeyURL(agent.signer())}, nil, nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to verify signature")
		require.True(t, errors.Is(err, expected))
	})
}
