{-# LANGUAGE OverloadedStrings #-}

-- |
-- Module      : Servant.OAuth2.IDP.JWT
-- Description : JWT signing utilities for access tokens
-- Copyright   : (C) 2025 PakSCADA LLC
-- License     : MIT
-- Maintainer  : alberto.valverde@pakenergy.com
-- Stability   : experimental
-- Portability : GHC
--
-- This module provides reusable JWT signing functions for access tokens, abstracting
-- the signing logic needed by OAuth 2.1 servers. Uses jose library's 'HasClaimsSet'
-- typeclass for payload conversion.
--
-- == Key Features
--
-- - Generic over payload types via jose's 'HasClaimsSet' constraint
-- - RFC 7638 thumbprint-based @kid@ header (deterministic, matches signing key)
-- - RFC 9068 @typ@ header (\"at+jwt\" for access tokens)
-- - MonadRandom constraint enables deterministic testing
-- - Type-safe error handling via jose's 'AsError' constraint
module Servant.OAuth2.IDP.JWT
  ( -- * Signing Functions
    signAccessToken,
  ) where

import Control.Monad.Error.Class (MonadError)
import Data.Aeson (ToJSON)
import Crypto.Hash (Digest, SHA256)
import Crypto.JOSE.Error (AsError)
import Crypto.JOSE.Header (HeaderParam (..), kid, typ)
import Crypto.JOSE.JWK (thumbprint)
import Crypto.JWT
  ( JWK
  , SignedJWT
  , encodeCompact
  , getProtected
  , makeJWSHeader
  , signJWT
  )
import Crypto.Random (MonadRandom)
import Data.ByteArray (convert)
import Data.ByteArray.Encoding (Base (Base64URLUnpadded), convertToBase)
import Data.ByteString (ByteString)
import Data.ByteString.Lazy qualified as LBS
import Data.Functor ((<&>))
import Data.Text.Encoding (decodeUtf8)
import Lens.Micro ((?~), (^.))
import Servant.OAuth2.IDP.Types (AccessToken (..))

-- | Sign a payload as an access token JWT
--
-- Creates a JWT with:
--
-- - @typ@ header set to \"at+jwt\" per RFC 9068 section 2
-- - @kid@ header set to SHA-256 thumbprint of signing key per RFC 7638
-- - Payload converted via jose's 'HasClaimsSet' constraint
--
-- == Parameters
--
-- - @signingKey@: JWK with private key material (must be suitable for signing)
-- - @payload@: Any type with jose's 'HasClaimsSet' instance
--
-- == Returns
--
-- Signed JWT in compact serialization format (3 base64url parts separated by dots),
-- wrapped in 'AccessToken' newtype for type safety.
--
-- == Error Handling
--
-- Uses jose library's error types via 'AsError' constraint. Errors include:
--
-- - Key unsuitable for signing (no private key material)
-- - Algorithm not supported by key
-- - Encoding failures
--
-- == RFC Compliance
--
-- - RFC 7638 (JSON Web Key (JWK) Thumbprint): kid header derived from key thumbprint
-- - RFC 9068 (JSON Web Token (JWT) Profile for OAuth 2.0 Access Tokens): typ=\"at+jwt\"
--
-- == Example
--
-- @
-- -- With AccessTokenData (has HasClaimsSet instance from jose)
-- token <- signAccessToken signingKey tokenData
--
-- -- With raw ClaimsSet
-- token <- signAccessToken signingKey claimsSet
-- @
signAccessToken
  :: (MonadRandom m, MonadError e m, AsError e, ToJSON payload)
  => JWK           -- ^ Signing key (must have private key material)
  -> payload       -- ^ Any type with jose's HasClaimsSet instance (ToJSON suffices for signJWT)
  -> m AccessToken -- ^ Signed JWT wrapped in AccessToken newtype
signAccessToken signingKey payload = do
  -- Build JWS header with RFC 9068 typ and RFC 7638 kid (both protected)
  hdr <-
    makeJWSHeader signingKey
      <&> (typ ?~ HeaderParam getProtected "at+jwt")  -- RFC 9068: Access Token JWT
      <&> (kid ?~ HeaderParam getProtected kidText)   -- RFC 7638: Thumbprint-based kid

  -- Sign the JWT using jose library
  signed <- signJWT signingKey hdr payload

  -- Compact serialize and wrap in AccessToken
  pure $ signedJWTToAccessToken signed
  where
    -- RFC 7638: Generate kid from SHA-256 thumbprint
    kidText =
      let digest = signingKey ^. thumbprint :: Digest SHA256
          kidBytes = convertToBase Base64URLUnpadded (convert digest :: ByteString) :: ByteString
       in decodeUtf8 kidBytes

    -- Convert SignedJWT to AccessToken via compact serialization
    signedJWTToAccessToken :: SignedJWT -> AccessToken
    signedJWTToAccessToken jwt =
      AccessToken $ decodeUtf8 $ LBS.toStrict $ encodeCompact jwt
