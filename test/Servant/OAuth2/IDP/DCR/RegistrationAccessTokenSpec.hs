{-# LANGUAGE OverloadedStrings #-}
{-# OPTIONS_GHC -Wno-incomplete-uni-patterns #-}

{- HLINT ignore "Avoid partial function" -}

{- |
Module      : Servant.OAuth2.IDP.DCR.RegistrationAccessTokenSpec
Description : Tests for RegistrationAccessToken per RFC 7592
Copyright   : (C) 2025 PakSCADA LLC
License     : MIT
Maintainer  : mpg@mpg.is, alberto.valverde@pakenergy.com
Stability   : experimental
Portability : GHC

Tests for the RegistrationAccessToken smart constructor, generator, hashing,
and JSON serialisation per RFC 7592.

Note: RegistrationAccessToken has no Show instance (sensitive credential),
so tests use structural pattern matching and Bool assertions instead of
shouldBe / shouldNotBe where Show is required.
-}
module Servant.OAuth2.IDP.DCR.RegistrationAccessTokenSpec (spec) where

import Data.Aeson (decode, encode)
import Data.Text qualified as T
import Servant.OAuth2.IDP.DCR.RegistrationAccessToken
import Test.Hspec
import Test.Hspec.QuickCheck (prop)
import Test.QuickCheck ((===))

spec :: Spec
spec = do
  describe "mkRegistrationAccessToken" $ do
    -- | OAUTH2_CLIENT_ENTITY-FR-001, SC-001: dcr_-prefixed token accepted
    it "accepts dcr_-prefixed token" $ do
      let result = mkRegistrationAccessToken "dcr_a1b2c3d4e5f6"
      case result of
        Nothing -> expectationFailure "Expected Just, got Nothing"
        Just _  -> pure ()

    -- | OAUTH2_CLIENT_ENTITY-SC-002: JWT-like token rejected
    it "rejects non-dcr_ prefix (JWT)" $ do
      let result = mkRegistrationAccessToken "eyJhbGciOi..."
      case result of
        Just _  -> expectationFailure "Expected Nothing, got Just"
        Nothing -> pure ()

    -- | OAUTH2_CLIENT_ENTITY-SC-003: empty token rejected
    it "rejects empty token" $ do
      let result = mkRegistrationAccessToken ""
      case result of
        Just _  -> expectationFailure "Expected Nothing, got Just"
        Nothing -> pure ()

  describe "generateRegistrationAccessToken" $ do
    -- | OAUTH2_CLIENT_ENTITY-FR-003, SC-006: generated token has dcr_ prefix and 64+ hex suffix
    it "generateRegistrationAccessToken produces dcr_<64hexchars>" $ do
      token <- generateRegistrationAccessToken
      let t = unRegistrationAccessToken token
      T.isPrefixOf "dcr_" t `shouldBe` True
      T.length t `shouldBe` 68  -- 4 (dcr_) + 64 (hex)

    -- | OAUTH2_CLIENT_ENTITY-SC-007: two generated tokens are distinct
    it "generateRegistrationAccessToken produces unique tokens" $ do
      t1 <- generateRegistrationAccessToken
      t2 <- generateRegistrationAccessToken
      -- Compare via unRegistrationAccessToken to avoid Show constraint
      unRegistrationAccessToken t1 `shouldNotBe` unRegistrationAccessToken t2

  describe "isRegistrationAccessToken" $ do
    -- | OAUTH2_CLIENT_ENTITY-FR-004, SC-008: isRegistrationAccessToken true for dcr_ prefix
    it "isRegistrationAccessToken returns True for dcr_ prefix" $ do
      isRegistrationAccessToken "dcr_abc123" `shouldBe` True

    -- | OAUTH2_CLIENT_ENTITY-SC-009: isRegistrationAccessToken false for JWT
    it "isRegistrationAccessToken returns False for JWT" $ do
      isRegistrationAccessToken "eyJhbGciOiJSUzI1NiIs..." `shouldBe` False

  describe "hashRegistrationAccessToken / verifyRegistrationAccessToken" $ do
    -- | OAUTH2_CLIENT_ENTITY-FR-002, SC-004: hash then verify with same token
    it "hash and verify round-trip succeeds" $ do
      let Just tok = mkRegistrationAccessToken "dcr_abc123"
      mHash <- hashRegistrationAccessToken tok
      case mHash of
        Nothing -> expectationFailure "hashRegistrationAccessToken returned Nothing"
        Just h  -> verifyRegistrationAccessToken tok h `shouldBe` True

    -- | OAUTH2_CLIENT_ENTITY-SC-005: verify with different token fails
    it "verify with different token fails" $ do
      let Just tok1 = mkRegistrationAccessToken "dcr_abc123"
          Just tok2 = mkRegistrationAccessToken "dcr_different"
      mHash <- hashRegistrationAccessToken tok1
      case mHash of
        Nothing -> expectationFailure "hashRegistrationAccessToken returned Nothing"
        Just h  -> verifyRegistrationAccessToken tok2 h `shouldBe` False

  describe "JSON instances" $ do
    -- | JSON round-trip (uses Eq, not Show)
    prop "ToJSON/FromJSON round-trip" $ \(tok :: RegistrationAccessToken) ->
      (decode . encode $ tok) === Just tok
