{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE TypeApplications #-}
{-# OPTIONS_GHC -Wno-orphans #-}

-- |
-- Module      : Servant.OAuth2.IDP.GoldenSpec
-- Description : Golden tests for RFC 7591 ClientRegistration types
-- Copyright   : (C) 2025 PakSCADA LLC
-- License     : MIT
-- Maintainer  : mpg@mpg.is, alberto.valverde@pakenergy.com
-- Stability   : experimental
-- Portability : GHC
--
-- Golden tests for JSON serialization of OAuth 2.1 client registration types
-- per RFC 7591 compliance. Tests verify that:
--
-- 1. JSON field names use snake_case (RFC 7591 requirement)
-- 2. Serialization round-trips correctly
-- 3. Generated JSON matches canonical golden files
--
-- = Traceability
--
-- * FR-021: RFC 7591 compliance for ClientRegistrationRequest
-- * FR-022: RFC 7591 compliance for ClientRegistrationResponse
-- * SC-008: JSON serialization produces RFC 7591 compliant field names
module Servant.OAuth2.IDP.GoldenSpec (spec) where

import Data.List.NonEmpty (NonEmpty (..))
import Data.Maybe (fromJust)
import Data.Proxy (Proxy (..))
import Data.Text (Text)
import Data.Time.Clock.POSIX (POSIXTime)
import Test.Aeson.GenericSpecs (roundtripAndGoldenSpecs)
import Test.Hspec (Spec, describe)
import Test.QuickCheck (Arbitrary (..), Gen, elements, listOf1)

import Servant.OAuth2.IDP.API qualified as API
import Servant.OAuth2.IDP.Types
  ( ClientAuthMethod (..),
    ClientSecret,
    GrantType (..),
    mkClientSecret,
  )

-- | Arbitrary instance for Text (needed for ClientSecret)
instance Arbitrary Text where
  arbitrary = arbitrary
  shrink = shrink

-- | Arbitrary instance for ClientSecret using smart constructor
instance Arbitrary ClientSecret where
  arbitrary = fromJust . mkClientSecret <$> (arbitrary :: Gen Text)
  shrink _ = []


-- | Arbitrary instance for ClientRegistrationRequest
--
-- Generates valid RFC 7591 compliant requests with required fields.
instance Arbitrary API.ClientRegistrationRequest where
  arbitrary = do
    client_name <- arbitrary
    uri1 <- arbitrary
    uris <- listOf1 arbitrary
    let redirect_uris = uri1 :| uris
    grant1 <- elements [GrantAuthorizationCode, GrantRefreshToken]
    grants <- listOf1 (elements [GrantAuthorizationCode, GrantRefreshToken])
    let grant_types = grant1 :| grants
    resp1 <- arbitrary
    resps <- listOf1 arbitrary
    let response_types = resp1 :| resps
    token_endpoint_auth_method <- elements [AuthClientSecretBasic, AuthClientSecretPost, AuthNone]
    pure $ API.ClientRegistrationRequest {..}

-- | Arbitrary instance for ClientRegistrationResponse
--
-- Generates valid RFC 7591 compliant responses with all required fields.
instance Arbitrary API.ClientRegistrationResponse where
  arbitrary = do
    client_id <- arbitrary
    client_secret <- arbitrary
    client_name <- arbitrary
    uri1 <- arbitrary
    uris <- listOf1 arbitrary
    let redirect_uris = uri1 :| uris
    grant1 <- elements [GrantAuthorizationCode, GrantRefreshToken]
    grants <- listOf1 (elements [GrantAuthorizationCode, GrantRefreshToken])
    let grant_types = grant1 :| grants
    resp1 <- arbitrary
    resps <- listOf1 arbitrary
    let response_types = resp1 :| resps
    token_endpoint_auth_method <- elements [AuthClientSecretBasic, AuthClientSecretPost, AuthNone]
    -- Generate a reasonable Unix timestamp (2024-01-01 onwards)
    posixTime <- (fromIntegral :: Int -> POSIXTime) <$> arbitrary
    let client_id_issued_at = 1704067200.0 + fromIntegral (abs (floor posixTime :: Integer) `mod` 31536000)
    pure $ API.ClientRegistrationResponse {..}

-- | Golden tests for RFC 7591 ClientRegistration types
--
-- These tests verify:
--
-- 1. Round-trip: @fromJSON . toJSON = id@
-- 2. Golden files: JSON matches canonical RFC 7591 compliant format
spec :: Spec
spec = describe "ClientRegistration Golden Tests (RFC 7591)" $ do
  -- FR-021: ClientRegistrationRequest roundtrip and golden tests
  -- Verifies snake_case field names per RFC 7591 Section 2.1
  clientRegistrationRequestTests

  -- FR-022: ClientRegistrationResponse roundtrip and golden tests
  -- Verifies snake_case field names per RFC 7591 Section 3.2.1
  clientRegistrationResponseTests

-- | ClientRegistrationRequest golden tests (RFC 7591 Section 2.1)
--
-- SC-008: Validates that field names use snake_case:
-- * @client_name@ ✓
-- * @redirect_uris@ ✓
-- * @grant_types@ ✓
-- * @response_types@ ✓
-- * @token_endpoint_auth_method@ ✓
clientRegistrationRequestTests :: Spec
clientRegistrationRequestTests = do
  describe "ClientRegistrationRequest" $ do
    roundtripAndGoldenSpecs (Proxy @API.ClientRegistrationRequest)

-- | ClientRegistrationResponse golden tests (RFC 7591 Section 3.2.1)
--
-- SC-008: Validates that field names use snake_case:
-- * @client_id@ ✓
-- * @client_secret@ ✓
-- * @client_id_issued_at@ ✓
-- * @client_name@ ✓
-- * @redirect_uris@ ✓
-- * @grant_types@ ✓
-- * @response_types@ ✓
-- * @token_endpoint_auth_method@ ✓
clientRegistrationResponseTests :: Spec
clientRegistrationResponseTests = do
  describe "ClientRegistrationResponse" $ do
    roundtripAndGoldenSpecs (Proxy @API.ClientRegistrationResponse)
