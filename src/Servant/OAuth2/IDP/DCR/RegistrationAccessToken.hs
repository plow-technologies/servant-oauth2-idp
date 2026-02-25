{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE OverloadedStrings #-}

{- |
Module      : Servant.OAuth2.IDP.DCR.RegistrationAccessToken
Description : Registration Access Token for Dynamic Client Registration (RFC 7592)
Copyright   : (C) 2025 PakSCADA LLC
License     : MIT
Maintainer  : mpg@mpg.is, alberto.valverde@pakenergy.com
Stability   : experimental
Portability : GHC

Opaque 'RegistrationAccessToken' and 'HashedRegistrationAccessToken' types
for Dynamic Client Registration management endpoints per RFC 7592.

Tokens use a @dcr_@ prefix with 32 bytes of cryptographically secure random
data encoded as hex (256 bits of entropy). Hashing uses bcrypt for secure
server-side storage.
-}
module Servant.OAuth2.IDP.DCR.RegistrationAccessToken
  ( -- * Opaque types
    RegistrationAccessToken
  , HashedRegistrationAccessToken
    -- * Smart constructors
  , mkRegistrationAccessToken
  , generateRegistrationAccessToken
  , unRegistrationAccessToken
    -- * Predicates
  , isRegistrationAccessToken
    -- * Hashing
  , hashRegistrationAccessToken
  , verifyRegistrationAccessToken
  ) where

import Crypto.BCrypt qualified as BCrypt
import Crypto.Random (getRandomBytes)
import Data.Aeson (FromJSON (..), ToJSON (..), withText)
import Data.ByteArray.Encoding (Base (Base16), convertToBase)
import Data.ByteString (ByteString)
import Data.Text (Text)
import Data.Text qualified as T
import Data.Text.Encoding qualified as TE
import GHC.Generics (Generic)
import Test.QuickCheck (Arbitrary (..), elements, oneof)

-- | An opaque registration access token, always prefixed with @dcr_@.
--
-- Used to authenticate management requests to the Dynamic Client Registration
-- endpoint per RFC 7592. Tokens carry 256 bits of entropy.
--
-- The 'Show' instance is redacting — it never leaks the token value.
-- See 'unRegistrationAccessToken' if the value must be inspected (with care).
newtype RegistrationAccessToken = RegistrationAccessToken Text
  deriving stock (Generic)
  deriving (Eq, Ord)

-- | Redacting 'Show' instance — never leaks the token value.
instance Show RegistrationAccessToken where
  show _ = "RegistrationAccessToken <redacted>"

-- | A bcrypt hash of a 'RegistrationAccessToken', suitable for server-side storage.
--
-- Never store the plaintext token server-side; store only the hash.
newtype HashedRegistrationAccessToken = HashedRegistrationAccessToken ByteString
  deriving stock (Generic)
  deriving (Eq, Ord)

-- | Redacting 'Show' instance — never leaks the hash value.
instance Show HashedRegistrationAccessToken where
  show _ = "HashedRegistrationAccessToken <redacted>"

-- | Smart constructor: accepts only tokens with the @dcr_@ prefix.
--
-- Returns 'Nothing' if the token does not start with @dcr_@.
mkRegistrationAccessToken :: Text -> Maybe RegistrationAccessToken
mkRegistrationAccessToken t
  | "dcr_" `T.isPrefixOf` t = Just (RegistrationAccessToken t)
  | otherwise = Nothing

-- | Unwrap the underlying 'Text' from a 'RegistrationAccessToken'.
unRegistrationAccessToken :: RegistrationAccessToken -> Text
unRegistrationAccessToken (RegistrationAccessToken t) = t

-- | Predicate: returns 'True' if the given 'Text' starts with @dcr_@.
--
-- Useful for distinguishing registration access tokens from JWT bearer tokens
-- at API boundaries without full construction.
isRegistrationAccessToken :: Text -> Bool
isRegistrationAccessToken = T.isPrefixOf "dcr_"

-- | Generate a cryptographically secure 'RegistrationAccessToken'.
--
-- Produces @dcr_@ followed by 64 lowercase hex characters (32 random bytes,
-- giving 256 bits of entropy).
generateRegistrationAccessToken :: IO RegistrationAccessToken
generateRegistrationAccessToken = do
  bytes <- getRandomBytes 32 :: IO ByteString
  -- Base16 encoding always produces valid ASCII; decodeUtf8' is total here
  let hexBytes = convertToBase Base16 bytes :: ByteString
      hex = TE.decodeUtf8 hexBytes  -- safe: Base16 output is ASCII subset of UTF-8
  pure (RegistrationAccessToken ("dcr_" <> hex))

-- | Hash a 'RegistrationAccessToken' using bcrypt for secure storage.
--
-- Returns 'Nothing' if bcrypt hashing fails (extremely unlikely in practice).
-- Always store the hash, never the plaintext token.
hashRegistrationAccessToken :: RegistrationAccessToken -> IO (Maybe HashedRegistrationAccessToken)
hashRegistrationAccessToken (RegistrationAccessToken t) = do
  result <- BCrypt.hashPasswordUsingPolicy BCrypt.slowerBcryptHashingPolicy (TE.encodeUtf8 t)
  pure (HashedRegistrationAccessToken <$> result)

-- | Verify a plaintext 'RegistrationAccessToken' against a stored bcrypt hash.
--
-- Uses constant-time comparison internally (via bcrypt).
verifyRegistrationAccessToken :: RegistrationAccessToken -> HashedRegistrationAccessToken -> Bool
verifyRegistrationAccessToken (RegistrationAccessToken t) (HashedRegistrationAccessToken h) =
  BCrypt.validatePassword h (TE.encodeUtf8 t)

-- | JSON serialisation: emits the token as a plain JSON string.
--
-- Used in DCR registration responses per RFC 7591 Section 3.2.1.
instance ToJSON RegistrationAccessToken where
  toJSON (RegistrationAccessToken t) = toJSON t

-- | JSON deserialisation: validates the @dcr_@ prefix.
instance FromJSON RegistrationAccessToken where
  parseJSON = withText "RegistrationAccessToken" $ \t ->
    case mkRegistrationAccessToken t of
      Nothing -> fail "RegistrationAccessToken must start with 'dcr_'"
      Just rat -> pure rat

-- | 'Arbitrary' instance for property testing.
--
-- Generates @dcr_@ followed by a non-empty sequence of hex characters.
instance Arbitrary RegistrationAccessToken where
  arbitrary = do
    suffix <- listOf1 (elements (['0' .. '9'] ++ ['a' .. 'f']))
    pure (RegistrationAccessToken ("dcr_" <> T.pack suffix))
    where
      listOf1 gen = (:) <$> gen <*> listOf gen
      listOf gen = oneof [pure [], (:) <$> gen <*> listOf gen]
