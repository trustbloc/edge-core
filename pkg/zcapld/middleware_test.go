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
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/jsonld"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/ed25519signature2018"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/mock/crypto"
	mockkms "github.com/hyperledger/aries-framework-go/pkg/mock/kms"
	"github.com/igor-pavlenko/httpsignatures-go"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/edge-core/pkg/zcapld"
)

func TestNewHTTPSigAuthorizationHandler(t *testing.T) {
	loader := createTestJSONLDDocumentLoader(t)

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
				ProcessorOpts:      []jsonld.ProcessorOpts{jsonld.WithDocumentLoader(loader)},
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
				ProcessorOpts:      []jsonld.ProcessorOpts{jsonld.WithDocumentLoader(loader)},
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
				KeyResolver:        zcapld.NewDIDKeyResolver(nil),
				VerifierOptions: []zcapld.VerificationOption{
					zcapld.WithSignatureSuites(
						ed25519signature2018.New(suite.WithVerifier(ed25519signature2018.NewPublicKeyVerifier())),
					),
					zcapld.WithLDDocumentLoaders(loader),
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
				ProcessorOpts:      []jsonld.ProcessorOpts{jsonld.WithDocumentLoader(loader)},
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
				ProcessorOpts:      []jsonld.ProcessorOpts{jsonld.WithDocumentLoader(loader)},
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

		result := httptest.NewRecorder()
		zcapld.NewHTTPSigAuthHandler(
			&zcapld.HTTPSigAuthConfig{
				CapabilityResolver: zcapld.SimpleCapabilityResolver{ownerZCAP.ID: ownerZCAP},
				KeyResolver:        &zcapld.DIDKeyResolver{},
				VerifierOptions: []zcapld.VerificationOption{
					zcapld.WithSignatureSuites(
						ed25519signature2018.New(suite.WithVerifier(ed25519signature2018.NewPublicKeyVerifier())),
					),
					zcapld.WithLDDocumentLoaders(loader),
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
		).ServeHTTP(result, thirdPartyRequest)
		require.Error(t, logErr)
		require.Contains(t, logErr.Error(), "secret not found")
		require.False(t, executed)
		require.Equal(t, http.StatusUnauthorized, result.Code)
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
				ProcessorOpts:      []jsonld.ProcessorOpts{jsonld.WithDocumentLoader(loader)},
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
				ProcessorOpts:      []jsonld.ProcessorOpts{jsonld.WithDocumentLoader(loader)},
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

		result := httptest.NewRecorder()
		zcapld.NewHTTPSigAuthHandler(
			&zcapld.HTTPSigAuthConfig{
				CapabilityResolver: zcapld.SimpleCapabilityResolver{ownerZCAP.ID: ownerZCAP},
				KeyResolver:        &zcapld.DIDKeyResolver{},
				VerifierOptions: []zcapld.VerificationOption{
					zcapld.WithSignatureSuites(
						ed25519signature2018.New(suite.WithVerifier(ed25519signature2018.NewPublicKeyVerifier())),
					),
					zcapld.WithLDDocumentLoaders(loader),
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
		).ServeHTTP(result, thirdPartyRequest)
		require.Error(t, logErr)
		require.Contains(t, logErr.Error(), "the authorized invoker does not match the verification method or its controller")
		require.False(t, executed)
		require.Equal(t, http.StatusUnauthorized, result.Code)
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
				ProcessorOpts:      []jsonld.ProcessorOpts{jsonld.WithDocumentLoader(loader)},
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
				ProcessorOpts:      []jsonld.ProcessorOpts{jsonld.WithDocumentLoader(loader)},
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

		result := httptest.NewRecorder()
		zcapld.NewHTTPSigAuthHandler(
			&zcapld.HTTPSigAuthConfig{
				CapabilityResolver: zcapld.SimpleCapabilityResolver{ownerZCAP.ID: ownerZCAP},
				KeyResolver:        &zcapld.DIDKeyResolver{},
				VerifierOptions: []zcapld.VerificationOption{
					zcapld.WithSignatureSuites(
						ed25519signature2018.New(suite.WithVerifier(ed25519signature2018.NewPublicKeyVerifier())),
					),
					zcapld.WithLDDocumentLoaders(loader),
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
		).ServeHTTP(result, thirdPartyRequest)
		require.Error(t, logErr)
		require.Contains(t, logErr.Error(), `capability action "write" is not allowed by the capability`)
		require.False(t, executed)
		require.Equal(t, http.StatusUnauthorized, result.Code)
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
				ProcessorOpts:      []jsonld.ProcessorOpts{jsonld.WithDocumentLoader(loader)},
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
				ProcessorOpts:      []jsonld.ProcessorOpts{jsonld.WithDocumentLoader(loader)},
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

		result := httptest.NewRecorder()
		zcapld.NewHTTPSigAuthHandler(
			&zcapld.HTTPSigAuthConfig{
				CapabilityResolver: zcapld.SimpleCapabilityResolver{ownerZCAP.ID: ownerZCAP},
				KeyResolver:        &zcapld.DIDKeyResolver{},
				VerifierOptions: []zcapld.VerificationOption{
					zcapld.WithLDDocumentLoaders(loader),
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
		).ServeHTTP(result, thirdPartyRequest)
		require.Error(t, logErr)
		require.Contains(t, logErr.Error(), "failed to init document verifier: at least one suite must be provided")
		require.False(t, executed)
		require.Equal(t, http.StatusInternalServerError, result.Code)
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
				ProcessorOpts:      []jsonld.ProcessorOpts{jsonld.WithDocumentLoader(loader)},
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

		result := httptest.NewRecorder()
		zcapld.NewHTTPSigAuthHandler(
			&zcapld.HTTPSigAuthConfig{
				CapabilityResolver: zcapld.SimpleCapabilityResolver{ownerZCAP.ID: ownerZCAP},
				KeyResolver:        &zcapld.DIDKeyResolver{},
				VerifierOptions: []zcapld.VerificationOption{
					zcapld.WithSignatureSuites(
						ed25519signature2018.New(suite.WithVerifier(ed25519signature2018.NewPublicKeyVerifier())),
					),
					zcapld.WithLDDocumentLoaders(loader),
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
		).ServeHTTP(result, thirdPartyRequest)
		require.Error(t, logErr)
		require.Contains(t, logErr.Error(), `"capability" was not found in the capability invocation proof`)
		require.False(t, executed)
		require.Equal(t, http.StatusUnauthorized, result.Code)
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
				ProcessorOpts:      []jsonld.ProcessorOpts{jsonld.WithDocumentLoader(loader)},
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

		result := httptest.NewRecorder()
		zcapld.NewHTTPSigAuthHandler(
			&zcapld.HTTPSigAuthConfig{
				CapabilityResolver: zcapld.SimpleCapabilityResolver{ownerZCAP.ID: ownerZCAP},
				KeyResolver:        &zcapld.DIDKeyResolver{},
				VerifierOptions: []zcapld.VerificationOption{
					zcapld.WithSignatureSuites(
						ed25519signature2018.New(suite.WithVerifier(ed25519signature2018.NewPublicKeyVerifier())),
					),
					zcapld.WithLDDocumentLoaders(loader),
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
		).ServeHTTP(result, thirdPartyRequest)
		require.Error(t, logErr)
		require.Contains(t, logErr.Error(), `"capability-invocation" header is missing`)
		require.False(t, executed)
		require.Equal(t, http.StatusBadRequest, result.Code)
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
				ProcessorOpts:      []jsonld.ProcessorOpts{jsonld.WithDocumentLoader(loader)},
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
				ProcessorOpts:      []jsonld.ProcessorOpts{jsonld.WithDocumentLoader(loader)},
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

		result := httptest.NewRecorder()
		zcapld.NewHTTPSigAuthHandler(
			&zcapld.HTTPSigAuthConfig{
				CapabilityResolver: zcapld.SimpleCapabilityResolver{ownerZCAP.ID: ownerZCAP},
				KeyResolver:        &zcapld.DIDKeyResolver{},
				VerifierOptions: []zcapld.VerificationOption{
					zcapld.WithSignatureSuites(
						ed25519signature2018.New(suite.WithVerifier(ed25519signature2018.NewPublicKeyVerifier())),
					),
					zcapld.WithLDDocumentLoaders(loader),
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
		).ServeHTTP(result, thirdPartyRequest)
		require.Error(t, logErr)
		require.Contains(t, logErr.Error(), "invalid invocation scheme")
		require.False(t, executed)
		require.Equal(t, http.StatusBadRequest, result.Code)
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
				ProcessorOpts:      []jsonld.ProcessorOpts{jsonld.WithDocumentLoader(loader)},
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
				ProcessorOpts:      []jsonld.ProcessorOpts{jsonld.WithDocumentLoader(loader)},
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

		result := httptest.NewRecorder()
		zcapld.NewHTTPSigAuthHandler(
			&zcapld.HTTPSigAuthConfig{
				CapabilityResolver: zcapld.SimpleCapabilityResolver{ownerZCAP.ID: ownerZCAP},
				KeyResolver:        &zcapld.DIDKeyResolver{},
				VerifierOptions: []zcapld.VerificationOption{
					zcapld.WithSignatureSuites(
						ed25519signature2018.New(suite.WithVerifier(ed25519signature2018.NewPublicKeyVerifier())),
					),
					zcapld.WithLDDocumentLoaders(loader),
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
		).ServeHTTP(result, thirdPartyRequest)
		require.Error(t, logErr)
		require.Contains(t, logErr.Error(), "'capability' invocation header param value is not a quoted-string")
		require.False(t, executed)
		require.Equal(t, http.StatusBadRequest, result.Code)
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
				ProcessorOpts:      []jsonld.ProcessorOpts{jsonld.WithDocumentLoader(loader)},
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

		result := httptest.NewRecorder()
		zcapld.NewHTTPSigAuthHandler(
			&zcapld.HTTPSigAuthConfig{
				CapabilityResolver: zcapld.SimpleCapabilityResolver{ownerZCAP.ID: ownerZCAP},
				KeyResolver:        &zcapld.DIDKeyResolver{},
				VerifierOptions: []zcapld.VerificationOption{
					zcapld.WithSignatureSuites(
						ed25519signature2018.New(suite.WithVerifier(ed25519signature2018.NewPublicKeyVerifier())),
					),
					zcapld.WithLDDocumentLoaders(loader),
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
		).ServeHTTP(result, thirdPartyRequest)
		require.Error(t, logErr)
		require.Contains(t, logErr.Error(), "failed to base64URL-decode value MALFORMED")
		require.False(t, executed)
		require.Equal(t, http.StatusBadRequest, result.Code)
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
				ProcessorOpts:      []jsonld.ProcessorOpts{jsonld.WithDocumentLoader(loader)},
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
				ProcessorOpts:      []jsonld.ProcessorOpts{jsonld.WithDocumentLoader(loader)},
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

		result := httptest.NewRecorder()
		zcapld.NewHTTPSigAuthHandler(
			&zcapld.HTTPSigAuthConfig{
				CapabilityResolver: zcapld.SimpleCapabilityResolver{ownerZCAP.ID: ownerZCAP},
				KeyResolver:        &zcapld.DIDKeyResolver{},
				VerifierOptions: []zcapld.VerificationOption{
					zcapld.WithSignatureSuites(
						ed25519signature2018.New(suite.WithVerifier(ed25519signature2018.NewPublicKeyVerifier())),
					),
					zcapld.WithLDDocumentLoaders(loader),
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
		).ServeHTTP(result, thirdPartyRequest)
		require.Error(t, logErr)
		require.Contains(t, logErr.Error(), "'action' invocation header param value is not a quoted-string")
		require.False(t, executed)
		require.Equal(t, http.StatusBadRequest, result.Code)
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
				ProcessorOpts:      []jsonld.ProcessorOpts{jsonld.WithDocumentLoader(loader)},
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
				ProcessorOpts:      []jsonld.ProcessorOpts{jsonld.WithDocumentLoader(loader)},
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

		result := httptest.NewRecorder()
		zcapld.NewHTTPSigAuthHandler(
			&zcapld.HTTPSigAuthConfig{
				CapabilityResolver: zcapld.SimpleCapabilityResolver{ownerZCAP.ID: ownerZCAP},
				KeyResolver:        &zcapld.DIDKeyResolver{},
				VerifierOptions: []zcapld.VerificationOption{
					zcapld.WithSignatureSuites(
						ed25519signature2018.New(suite.WithVerifier(ed25519signature2018.NewPublicKeyVerifier())),
					),
					zcapld.WithLDDocumentLoaders(loader),
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
		).ServeHTTP(result, thirdPartyRequest)
		require.Error(t, logErr)
		require.Contains(t, logErr.Error(), `"action" header is missing`)
		require.False(t, executed)
		require.Equal(t, http.StatusBadRequest, result.Code)
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
				ProcessorOpts:      []jsonld.ProcessorOpts{jsonld.WithDocumentLoader(loader)},
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
				ProcessorOpts:      []jsonld.ProcessorOpts{jsonld.WithDocumentLoader(loader)},
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

		result := httptest.NewRecorder()
		zcapld.NewHTTPSigAuthHandler(
			&zcapld.HTTPSigAuthConfig{
				CapabilityResolver: zcapld.SimpleCapabilityResolver{ownerZCAP.ID: ownerZCAP},
				KeyResolver:        &zcapld.DIDKeyResolver{},
				VerifierOptions: []zcapld.VerificationOption{
					zcapld.WithSignatureSuites(
						ed25519signature2018.New(suite.WithVerifier(ed25519signature2018.NewPublicKeyVerifier())),
					),
					zcapld.WithLDDocumentLoaders(loader),
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
		).ServeHTTP(result, thirdPartyRequest)
		require.Error(t, logErr)
		require.Contains(t, logErr.Error(), `unrecognized invocation header param`)
		require.False(t, executed)
		require.Equal(t, http.StatusBadRequest, result.Code)
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
				ProcessorOpts:      []jsonld.ProcessorOpts{jsonld.WithDocumentLoader(loader)},
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

		result := httptest.NewRecorder()
		zcapld.NewHTTPSigAuthHandler(
			&zcapld.HTTPSigAuthConfig{
				CapabilityResolver: zcapld.SimpleCapabilityResolver{ownerZCAP.ID: ownerZCAP},
				KeyResolver:        &zcapld.DIDKeyResolver{},
				VerifierOptions: []zcapld.VerificationOption{
					zcapld.WithSignatureSuites(
						ed25519signature2018.New(suite.WithVerifier(ed25519signature2018.NewPublicKeyVerifier())),
					),
					zcapld.WithLDDocumentLoaders(loader),
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
		).ServeHTTP(result, thirdPartyRequest)
		require.Error(t, logErr)
		require.Contains(t, logErr.Error(), `invalid key=value format`)
		require.False(t, executed)
		require.Equal(t, http.StatusBadRequest, result.Code)
	})

	t.Run("multi-level delegation", func(t *testing.T) {
		t.Run("2-level: authorizes valid request", func(t *testing.T) {
			var logErr error
			executed := false
			next := func(w http.ResponseWriter, r *http.Request) {
				executed = true
			}
			logger := func(e error) {
				logErr = e
			}
			// server creates a resource and a ZCAP for its own resource
			resource := fmt.Sprintf("http://www.example.org/foo/documents/%s", uuid.New().String())
			server := newAgent(t)
			serverSigner := server.signer()
			serverVerMethod := didKeyURL(serverSigner)
			serverZCAP, err := zcapld.NewCapability(
				&zcapld.Signer{
					SignatureSuite:     ed25519signature2018.New(suite.WithSigner(serverSigner)),
					SuiteType:          ed25519signature2018.SignatureType,
					VerificationMethod: serverVerMethod,
					ProcessorOpts:      []jsonld.ProcessorOpts{jsonld.WithDocumentLoader(loader)},
				},
				zcapld.WithAllowedActions("read", "write", "archive"),
				zcapld.WithInvocationTarget(resource, "urn:edv:document"),
				zcapld.WithID(resource),
			)
			require.NoError(t, err)

			client := newAgent(t)
			clientSigner := client.signer()
			clientVerMethod := didKeyURL(clientSigner)

			// server creates a ZCAP for the client that owns this resource
			// notice the allowed actions have been attenuated - the client cannot "archive" the resource
			clientZCAP, err := zcapld.NewCapability(
				&zcapld.Signer{
					SignatureSuite:     ed25519signature2018.New(suite.WithSigner(serverSigner)),
					SuiteType:          ed25519signature2018.SignatureType,
					VerificationMethod: serverVerMethod,
					ProcessorOpts:      []jsonld.ProcessorOpts{jsonld.WithDocumentLoader(loader)},
				},
				zcapld.WithParent(serverZCAP.ID),
				zcapld.WithInvoker(clientVerMethod),
				zcapld.WithCapabilityChain(serverZCAP.ID),
				zcapld.WithAllowedActions("read", "write"), // attenuated
				zcapld.WithInvocationTarget(resource, "urn:edv:document"),
			)
			require.NoError(t, err)

			thirdParty := newAgent(t)
			thirdPartySigner := thirdParty.signer()
			thirdPartyVerMethod := didKeyURL(thirdPartySigner)

			// the client then creates a zcap for a third party
			// notice this zcap is further attenuated - it can only "read"
			thirdPartyZCAP, err := zcapld.NewCapability(
				&zcapld.Signer{
					SignatureSuite:     ed25519signature2018.New(suite.WithSigner(clientSigner)),
					SuiteType:          ed25519signature2018.SignatureType,
					VerificationMethod: clientVerMethod,
					ProcessorOpts:      []jsonld.ProcessorOpts{jsonld.WithDocumentLoader(loader)},
				},
				zcapld.WithParent(clientZCAP.ID),
				zcapld.WithInvoker(thirdPartyVerMethod),
				zcapld.WithCapabilityChain(serverZCAP.ID, clientZCAP.ID),
				zcapld.WithAllowedActions("read"),
				zcapld.WithInvocationTarget(resource, "urn:edv:document"),
			)
			require.NoError(t, err)

			// third party makes an authenticated request w/zcap to perform a "read" action on the resource
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

			// server's middleware authenticates this request
			zcapld.NewHTTPSigAuthHandler(
				&zcapld.HTTPSigAuthConfig{
					CapabilityResolver: zcapld.SimpleCapabilityResolver{
						serverZCAP.ID: serverZCAP,
						clientZCAP.ID: clientZCAP,
					},
					KeyResolver: zcapld.NewDIDKeyResolver(nil),
					VerifierOptions: []zcapld.VerificationOption{
						zcapld.WithSignatureSuites(
							ed25519signature2018.New(suite.WithVerifier(ed25519signature2018.NewPublicKeyVerifier())),
						),
						zcapld.WithLDDocumentLoaders(loader),
					},
					Secrets:     &zcapld.AriesDIDKeySecrets{},
					ErrConsumer: logger,
					KMS:         server.KMS(),
					Crypto:      server.Crypto(),
				},
				&zcapld.InvocationExpectations{
					Target:         resource,
					RootCapability: serverZCAP.ID,
					Action:         "read",
				},
				next,
			).ServeHTTP(httptest.NewRecorder(), thirdPartyRequest)
			require.NoError(t, logErr)
			require.True(t, executed)
		})

		t.Run("2-level: rejects request with invalid attenuation on the 1st delegated zcap", func(t *testing.T) {
			var logErr error
			executed := false
			next := func(w http.ResponseWriter, r *http.Request) {
				executed = true
			}
			logger := func(e error) {
				logErr = e
			}
			// server creates a resource and a ZCAP for its own resource
			resource := fmt.Sprintf("http://www.example.org/foo/documents/%s", uuid.New().String())
			server := newAgent(t)
			serverSigner := server.signer()
			serverVerMethod := didKeyURL(serverSigner)
			serverZCAP, err := zcapld.NewCapability(
				&zcapld.Signer{
					SignatureSuite:     ed25519signature2018.New(suite.WithSigner(serverSigner)),
					SuiteType:          ed25519signature2018.SignatureType,
					VerificationMethod: serverVerMethod,
					ProcessorOpts:      []jsonld.ProcessorOpts{jsonld.WithDocumentLoader(loader)},
				},
				zcapld.WithAllowedActions("read", "write", "archive"),
				zcapld.WithInvocationTarget(resource, "urn:edv:document"),
				zcapld.WithID(resource),
			)
			require.NoError(t, err)

			client := newAgent(t)
			clientSigner := client.signer()
			clientVerMethod := didKeyURL(clientSigner)

			// server creates a ZCAP for the client that owns this resource
			// notice the allowed actions have been attenuated - the client cannot "archive" the resource
			clientZCAP, err := zcapld.NewCapability(
				&zcapld.Signer{
					SignatureSuite:     ed25519signature2018.New(suite.WithSigner(serverSigner)),
					SuiteType:          ed25519signature2018.SignatureType,
					VerificationMethod: serverVerMethod,
					ProcessorOpts:      []jsonld.ProcessorOpts{jsonld.WithDocumentLoader(loader)},
				},
				zcapld.WithParent(serverZCAP.ID),
				zcapld.WithInvoker(clientVerMethod),
				zcapld.WithCapabilityChain(serverZCAP.ID),
				zcapld.WithAllowedActions("read", "write", "fly"), // fly is not included in parent's allowed actions
				zcapld.WithInvocationTarget(resource, "urn:edv:document"),
			)
			require.NoError(t, err)

			thirdParty := newAgent(t)
			thirdPartySigner := thirdParty.signer()
			thirdPartyVerMethod := didKeyURL(thirdPartySigner)

			// the client then creates a zcap for a third party
			// notice this zcap is further attenuated - it can only "read"
			thirdPartyZCAP, err := zcapld.NewCapability(
				&zcapld.Signer{
					SignatureSuite:     ed25519signature2018.New(suite.WithSigner(clientSigner)),
					SuiteType:          ed25519signature2018.SignatureType,
					VerificationMethod: clientVerMethod,
					ProcessorOpts:      []jsonld.ProcessorOpts{jsonld.WithDocumentLoader(loader)},
				},
				zcapld.WithParent(clientZCAP.ID),
				zcapld.WithInvoker(thirdPartyVerMethod),
				zcapld.WithCapabilityChain(serverZCAP.ID, clientZCAP.ID),
				zcapld.WithAllowedActions("read"),
				zcapld.WithInvocationTarget(resource, "urn:edv:document"),
			)
			require.NoError(t, err)

			// third party makes an authenticated request w/zcap to perform a "read" action on the resource
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

			// server's middleware authenticates this request
			zcapld.NewHTTPSigAuthHandler(
				&zcapld.HTTPSigAuthConfig{
					CapabilityResolver: zcapld.SimpleCapabilityResolver{
						serverZCAP.ID: serverZCAP,
						clientZCAP.ID: clientZCAP,
					},
					KeyResolver: zcapld.NewDIDKeyResolver(nil),
					VerifierOptions: []zcapld.VerificationOption{
						zcapld.WithSignatureSuites(
							ed25519signature2018.New(suite.WithVerifier(ed25519signature2018.NewPublicKeyVerifier())),
						),
						zcapld.WithLDDocumentLoaders(loader),
					},
					Secrets:     &zcapld.AriesDIDKeySecrets{},
					ErrConsumer: logger,
					KMS:         server.KMS(),
					Crypto:      server.Crypto(),
				},
				&zcapld.InvocationExpectations{
					Target:         resource,
					RootCapability: serverZCAP.ID,
					Action:         "read",
				},
				next,
			).ServeHTTP(httptest.NewRecorder(), thirdPartyRequest)
			require.Error(t, logErr)
			require.Contains(t, logErr.Error(), "failed to verify attenuation of zcap")
			require.False(t, executed)
		})

		t.Run("2-level: rejects request with invalid attenuation on leaf zcap", func(t *testing.T) {
			var logErr error
			executed := false
			next := func(w http.ResponseWriter, r *http.Request) {
				executed = true
			}
			logger := func(e error) {
				logErr = e
			}
			// server creates a resource and a ZCAP for its own resource
			resource := fmt.Sprintf("http://www.example.org/foo/documents/%s", uuid.New().String())
			server := newAgent(t)
			serverSigner := server.signer()
			serverVerMethod := didKeyURL(serverSigner)
			serverZCAP, err := zcapld.NewCapability(
				&zcapld.Signer{
					SignatureSuite:     ed25519signature2018.New(suite.WithSigner(serverSigner)),
					SuiteType:          ed25519signature2018.SignatureType,
					VerificationMethod: serverVerMethod,
					ProcessorOpts:      []jsonld.ProcessorOpts{jsonld.WithDocumentLoader(loader)},
				},
				zcapld.WithAllowedActions("read", "write", "archive"),
				zcapld.WithInvocationTarget(resource, "urn:edv:document"),
				zcapld.WithID(resource),
			)
			require.NoError(t, err)

			client := newAgent(t)
			clientSigner := client.signer()
			clientVerMethod := didKeyURL(clientSigner)

			// server creates a ZCAP for the client that owns this resource
			// notice the allowed actions have been attenuated - the client cannot "archive" the resource
			clientZCAP, err := zcapld.NewCapability(
				&zcapld.Signer{
					SignatureSuite:     ed25519signature2018.New(suite.WithSigner(serverSigner)),
					SuiteType:          ed25519signature2018.SignatureType,
					VerificationMethod: serverVerMethod,
					ProcessorOpts:      []jsonld.ProcessorOpts{jsonld.WithDocumentLoader(loader)},
				},
				zcapld.WithParent(serverZCAP.ID),
				zcapld.WithInvoker(clientVerMethod),
				zcapld.WithCapabilityChain(serverZCAP.ID),
				zcapld.WithAllowedActions("read", "write"), // attenuated
				zcapld.WithInvocationTarget(resource, "urn:edv:document"),
			)
			require.NoError(t, err)

			thirdParty := newAgent(t)
			thirdPartySigner := thirdParty.signer()
			thirdPartyVerMethod := didKeyURL(thirdPartySigner)

			// the client then creates a zcap for a third party
			// notice this zcap is further attenuated - it can only "read"
			thirdPartyZCAP, err := zcapld.NewCapability(
				&zcapld.Signer{
					SignatureSuite:     ed25519signature2018.New(suite.WithSigner(clientSigner)),
					SuiteType:          ed25519signature2018.SignatureType,
					VerificationMethod: clientVerMethod,
					ProcessorOpts:      []jsonld.ProcessorOpts{jsonld.WithDocumentLoader(loader)},
				},
				zcapld.WithParent(clientZCAP.ID),
				zcapld.WithInvoker(thirdPartyVerMethod),
				zcapld.WithCapabilityChain(serverZCAP.ID, clientZCAP.ID),
				zcapld.WithAllowedActions("read", "archive"), // archive not included in parent capability
				zcapld.WithInvocationTarget(resource, "urn:edv:document"),
			)
			require.NoError(t, err)

			// third party makes an authenticated request w/zcap to perform a "read" action on the resource
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

			// server's middleware authenticates this request
			zcapld.NewHTTPSigAuthHandler(
				&zcapld.HTTPSigAuthConfig{
					CapabilityResolver: zcapld.SimpleCapabilityResolver{
						serverZCAP.ID: serverZCAP,
						clientZCAP.ID: clientZCAP,
					},
					KeyResolver: zcapld.NewDIDKeyResolver(nil),
					VerifierOptions: []zcapld.VerificationOption{
						zcapld.WithSignatureSuites(
							ed25519signature2018.New(suite.WithVerifier(ed25519signature2018.NewPublicKeyVerifier())),
						),
						zcapld.WithLDDocumentLoaders(loader),
					},
					Secrets:     &zcapld.AriesDIDKeySecrets{},
					ErrConsumer: logger,
					KMS:         server.KMS(),
					Crypto:      server.Crypto(),
				},
				&zcapld.InvocationExpectations{
					Target:         resource,
					RootCapability: serverZCAP.ID,
					Action:         "read",
				},
				next,
			).ServeHTTP(httptest.NewRecorder(), thirdPartyRequest)
			require.Error(t, logErr)
			require.Contains(t, logErr.Error(), "failed to verify attenuation of zcap")
			require.False(t, executed)
		})

		// TODO the implementation supports delegation chains of arbitrary length, but requires all but the last
		//  zcap to be resolvable. Therefore, this implementation is a poor fit for use cases where there is no
		//  central registry of zcaps and needs to be improved such that the server does not require pre-loading
		//  all those descendent zcaps in order to verify the chain.
		t.Run("4-level: authorizes valid request", func(t *testing.T) {
			var logErr error
			executed := false
			next := func(w http.ResponseWriter, r *http.Request) {
				executed = true
			}
			logger := func(e error) {
				logErr = e
			}
			resource := fmt.Sprintf("http://www.example.org/foo/documents/%s", uuid.New().String())
			server := newAgent(t)
			serverSigner := server.signer()
			serverVerMethod := didKeyURL(serverSigner)
			serverZCAP, err := zcapld.NewCapability(
				&zcapld.Signer{
					SignatureSuite:     ed25519signature2018.New(suite.WithSigner(serverSigner)),
					SuiteType:          ed25519signature2018.SignatureType,
					VerificationMethod: serverVerMethod,
					ProcessorOpts:      []jsonld.ProcessorOpts{jsonld.WithDocumentLoader(loader)},
				},
				zcapld.WithAllowedActions("create", "read", "write", "delete", "archive"),
				zcapld.WithInvocationTarget(resource, "urn:edv:document"),
				zcapld.WithID(resource),
			)
			require.NoError(t, err)

			client := newAgent(t)
			clientSigner := client.signer()
			clientVerMethod := didKeyURL(clientSigner)

			clientZCAP, err := zcapld.NewCapability(
				&zcapld.Signer{
					SignatureSuite:     ed25519signature2018.New(suite.WithSigner(serverSigner)),
					SuiteType:          ed25519signature2018.SignatureType,
					VerificationMethod: serverVerMethod,
					ProcessorOpts:      []jsonld.ProcessorOpts{jsonld.WithDocumentLoader(loader)},
				},
				zcapld.WithParent(serverZCAP.ID),
				zcapld.WithInvoker(clientVerMethod),
				zcapld.WithCapabilityChain(serverZCAP.ID),
				zcapld.WithAllowedActions("create", "read", "write", "delete"), // attenuated
				zcapld.WithInvocationTarget(resource, "urn:edv:document"),
			)
			require.NoError(t, err)

			thirdParty := newAgent(t)
			thirdPartySigner := thirdParty.signer()
			thirdPartyVerMethod := didKeyURL(thirdPartySigner)

			thirdPartyZCAP, err := zcapld.NewCapability(
				&zcapld.Signer{
					SignatureSuite:     ed25519signature2018.New(suite.WithSigner(clientSigner)),
					SuiteType:          ed25519signature2018.SignatureType,
					VerificationMethod: clientVerMethod,
					ProcessorOpts:      []jsonld.ProcessorOpts{jsonld.WithDocumentLoader(loader)},
				},
				zcapld.WithParent(clientZCAP.ID),
				zcapld.WithInvoker(thirdPartyVerMethod),
				zcapld.WithCapabilityChain(serverZCAP.ID, clientZCAP.ID),
				zcapld.WithAllowedActions("read", "write", "delete"),
				zcapld.WithInvocationTarget(resource, "urn:edv:document"),
			)
			require.NoError(t, err)

			fourthParty := newAgent(t)
			fourthPartySigner := fourthParty.signer()
			fourthPartyVerMethod := didKeyURL(fourthPartySigner)

			fourthPartyZCAP, err := zcapld.NewCapability(
				&zcapld.Signer{
					SignatureSuite:     ed25519signature2018.New(suite.WithSigner(thirdPartySigner)),
					SuiteType:          ed25519signature2018.SignatureType,
					VerificationMethod: thirdPartyVerMethod,
					ProcessorOpts:      []jsonld.ProcessorOpts{jsonld.WithDocumentLoader(loader)},
				},
				zcapld.WithParent(thirdPartyZCAP.ID),
				zcapld.WithInvoker(fourthPartyVerMethod),
				zcapld.WithCapabilityChain(serverZCAP.ID, clientZCAP.ID, thirdPartyZCAP.ID),
				zcapld.WithAllowedActions("read", "write"),
				zcapld.WithInvocationTarget(resource, "urn:edv:document"),
			)
			require.NoError(t, err)

			fifthParty := newAgent(t)
			fifthPartySigner := fifthParty.signer()
			fifthPartyVerMethod := didKeyURL(fifthPartySigner)

			fifthPartyZCAP, err := zcapld.NewCapability(
				&zcapld.Signer{
					SignatureSuite:     ed25519signature2018.New(suite.WithSigner(fourthPartySigner)),
					SuiteType:          ed25519signature2018.SignatureType,
					VerificationMethod: fourthPartyVerMethod,
					ProcessorOpts:      []jsonld.ProcessorOpts{jsonld.WithDocumentLoader(loader)},
				},
				zcapld.WithParent(fourthPartyZCAP.ID),
				zcapld.WithInvoker(fifthPartyVerMethod),
				zcapld.WithCapabilityChain(serverZCAP.ID, clientZCAP.ID, thirdPartyZCAP.ID, fourthPartyZCAP.ID),
				zcapld.WithAllowedActions("read"),
				zcapld.WithInvocationTarget(resource, "urn:edv:document"),
			)
			require.NoError(t, err)

			// fifth party makes an authenticated request w/zcap to perform a "read" action on the resource
			fifthPartyRequest := httptest.NewRequest(http.MethodGet, resource, nil)
			fifthPartyRequest.Header.Set(
				zcapld.CapabilityInvocationHTTPHeader,
				fmt.Sprintf(`zcap capability="%s",action="%s"`, compressZCAP(t, fifthPartyZCAP), "read"),
			)

			hs := httpsignatures.NewHTTPSignatures(&zcapld.AriesDIDKeySecrets{})
			hs.SetSignatureHashAlgorithm(&zcapld.AriesDIDKeySignatureHashAlgorithm{
				Crypto: fifthParty.Crypto(),
				KMS:    fifthParty.KMS(),
			})
			err = hs.Sign(fifthPartyVerMethod, fifthPartyRequest)
			require.NoError(t, err)

			// server's middleware authenticates this request
			zcapld.NewHTTPSigAuthHandler(
				&zcapld.HTTPSigAuthConfig{
					CapabilityResolver: zcapld.SimpleCapabilityResolver{
						serverZCAP.ID:      serverZCAP,
						clientZCAP.ID:      clientZCAP,
						thirdPartyZCAP.ID:  thirdPartyZCAP,
						fourthPartyZCAP.ID: fourthPartyZCAP,
					},
					KeyResolver: zcapld.NewDIDKeyResolver(nil),
					VerifierOptions: []zcapld.VerificationOption{
						zcapld.WithSignatureSuites(
							ed25519signature2018.New(suite.WithVerifier(ed25519signature2018.NewPublicKeyVerifier())),
						),
						zcapld.WithLDDocumentLoaders(loader),
					},
					Secrets:     &zcapld.AriesDIDKeySecrets{},
					ErrConsumer: logger,
					KMS:         server.KMS(),
					Crypto:      server.Crypto(),
				},
				&zcapld.InvocationExpectations{
					Target:         resource,
					RootCapability: serverZCAP.ID,
					Action:         "read",
				},
				next,
			).ServeHTTP(httptest.NewRecorder(), fifthPartyRequest)
			require.NoError(t, logErr)
			require.True(t, executed)
		})
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

func TestCompressZCAP(t *testing.T) {
	t.Run("Marshal error", func(t *testing.T) {
		_, err := zcapld.CompressZCAP(&zcapld.Capability{
			Proof: []verifiable.Proof{{"key": make(chan int64)}},
		})
		require.EqualError(t, err, "json: unsupported type: chan int64")
	})

	t.Run("Success", func(t *testing.T) {
		res, err := zcapld.CompressZCAP(&zcapld.Capability{})
		require.NoError(t, err)
		require.NotEmpty(t, res)
	})
}
