{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE OverloadedStrings #-}

-- |
-- Module      : Servant.OAuth2.IDP.JWKS
-- Description : RFC 7517 JSON Web Key Set types and serialization
-- Copyright   : (C) 2025 PakSCADA LLC
-- License     : MIT
-- Maintainer  : alberto.valverde@pakenergy.com
-- Stability   : experimental
-- Portability : GHC
--
-- This module provides types for RFC 7517 JSON Web Key Sets with proper JSON serialization.
--
-- The jose library's JWK type serializes a single key; these types wrap it to provide
-- the RFC 7517 required structure: @{"keys": [...]}@
--
-- RFC 7517 requires certain fields in the JSON representation:
-- - @use@: Key usage (e.g., "sig" for signing)
-- - @alg@: Algorithm (derived from key type)
-- - @kid@: Key ID (derived from key thumbprint or existing kid)
module Servant.OAuth2.IDP.JWKS
  ( -- * JWKS Types
    JWKSet (..),
    RFC7517JWK (..),
  ) where

import Control.Lens ((^.))
import Crypto.Hash (Digest, SHA256)
import Crypto.JOSE.JWK (thumbprint)
import Crypto.JWT (JWK)
import Data.Aeson
import Data.Aeson.Key qualified as Key
import Data.Aeson.KeyMap qualified as KM
import Data.ByteArray (convert)
import Data.ByteArray.Encoding (Base (Base64URLUnpadded), convertToBase)
import Data.ByteString (ByteString)
import Data.Text.Encoding (decodeUtf8')

-- | JWKS wrapper for RFC 7517 compliance
--
-- The jose library's JWK type serializes a single key; we need @{"keys": [...]}@
-- per RFC 7517.
newtype JWKSet = JWKSet {jwksKeys :: [RFC7517JWK]}
  deriving stock (Eq, Show)

instance ToJSON JWKSet where
  toJSON (JWKSet ks) = object ["keys" .= ks]

-- | JWK wrapper that ensures RFC 7517 required fields are present in JSON
--
-- Delegates to jose library's ToJSON/FromJSON but extends with:
-- - @use@: "sig" (signing key)
-- - @alg@: derived from key type (ES256 for P-256, RS256 for RSA)
-- - @kid@: derived from key thumbprint (RFC 7638) or existing kid if present
newtype RFC7517JWK = RFC7517JWK {unRFC7517JWK :: JWK}
  deriving stock (Eq, Show)

instance ToJSON RFC7517JWK where
  toJSON (RFC7517JWK jwk) =
    -- Start with jose library's toJSON output
    case toJSON jwk of
      Object baseObj ->
        -- Extend with RFC 7517 required fields (use, alg, kid)
        let
          -- Always use "sig" for signing
          useVal = String "sig"

          -- Derive algorithm from key type
          algVal =
            let kty = KM.lookup "kty" baseObj
                crv = KM.lookup "crv" baseObj
             in case (kty, crv) of
                  (Just (String "EC"), Just (String "P-256")) -> String "ES256"
                  (Just (String "EC"), Just (String "P-384")) -> String "ES384"
                  (Just (String "EC"), Just (String "P-521")) -> String "ES512"
                  (Just (String "RSA"), _) -> String "RS256"
                  (Just (String "OKP"), _) -> String "EdDSA"
                  _ -> String "RS256" -- fallback

          -- Derive kid from thumbprint if not present
          kidVal =
            case KM.lookup "kid" baseObj of
              Just existing -> existing
              Nothing ->
                -- RFC 7638: Generate kid from SHA-256 thumbprint
                let digest = jwk ^. thumbprint :: Digest SHA256
                    -- Use memory package's convertToBase for proper base64url unpadded encoding
                    -- base64url only uses ASCII characters, so decoding always succeeds
                    kidBytes = convertToBase Base64URLUnpadded (convert digest :: ByteString) :: ByteString
                 in case decodeUtf8' kidBytes of
                      Right kidText -> String kidText
                      -- This should never happen as base64url is always valid UTF-8
                      Left _ -> String "invalid-encoding"

          -- Build updated object by extending base with required fields
          updatedObj =
            KM.insert
              (Key.fromString "use")
              useVal
              ( KM.insert
                  (Key.fromString "alg")
                  algVal
                  (KM.insert (Key.fromString "kid") kidVal baseObj)
              )
         in
          Object updatedObj
      -- If not an object, return as-is (shouldn't happen with valid JWK)
      other -> other

instance FromJSON RFC7517JWK where
  parseJSON v = do
    jwk <- parseJSON v
    pure (RFC7517JWK jwk)
