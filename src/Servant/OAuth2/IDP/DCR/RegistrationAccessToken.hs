{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE OverloadedStrings #-}

-- |
-- Module      : Servant.OAuth2.IDP.DCR.RegistrationAccessToken
-- Description : Registration Access Token for Dynamic Client Registration (RFC 7592)
-- Copyright   : (C) 2025 PakSCADA LLC
-- License     : MIT
-- Maintainer  : mpg@mpg.is, alberto.valverde@pakenergy.com
-- Stability   : experimental
-- Portability : GHC
--
-- Opaque 'RegistrationAccessToken' and 'HashedRegistrationAccessToken' types
-- for Dynamic Client Registration management endpoints per RFC 7592.
--
-- Tokens use a @dcr_@ prefix with 32 bytes of cryptographically secure random
-- data encoded as hex (256 bits of entropy). Hashing uses bcrypt for secure
-- server-side storage.
module Servant.OAuth2.IDP.DCR.RegistrationAccessToken
  ( -- * Opaque types
    RegistrationAccessToken,
    HashedRegistrationAccessToken,

    -- * Smart constructors
    mkRegistrationAccessToken,
    generateRegistrationAccessToken,
    unRegistrationAccessToken,
    mkHashedRegistrationAccessToken,
    unHashedRegistrationAccessToken,

    -- * Predicates
    isRegistrationAccessToken,

    -- * Hashing
    hashRegistrationAccessToken,
    verifyRegistrationAccessToken,
  ) where

import Control.Monad.IO.Class (MonadIO, liftIO)
import Crypto.BCrypt qualified as BCrypt
import Crypto.Random (MonadRandom (getRandomBytes))
import Data.Aeson (FromJSON (..), ToJSON (..), withText)
import Data.ByteArray.Encoding (Base (Base16), convertToBase)
import Data.ByteString (ByteString)
import Data.ByteString qualified as BS
import Data.Text (Text)
import Data.Text qualified as T
import Data.Text.Encoding qualified as TE
import GHC.Generics (Generic)
import Test.QuickCheck (Arbitrary (..), elements, oneof, vectorOf)

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

-- | Smart constructor for 'HashedRegistrationAccessToken' from raw 'ByteString'.
--
-- Only accepts valid bcrypt hashes (starting with @$2a$@, @$2b$@, or @$2y$@).
-- Use 'hashRegistrationAccessToken' to create from a plaintext token;
-- use this only to reconstruct an existing stored hash.
mkHashedRegistrationAccessToken :: ByteString -> Maybe HashedRegistrationAccessToken
mkHashedRegistrationAccessToken bs
  | any (`BS.isPrefixOf` bs) prefixes = Just (HashedRegistrationAccessToken bs)
  | otherwise = Nothing
  where
    prefixes = map (TE.encodeUtf8 . T.pack) ["$2a$", "$2b$", "$2y$"]

-- | Unwrap the underlying 'ByteString' from a 'HashedRegistrationAccessToken'.
--
-- Use with care — this exposes the raw bcrypt hash for storage purposes only.
unHashedRegistrationAccessToken :: HashedRegistrationAccessToken -> ByteString
unHashedRegistrationAccessToken (HashedRegistrationAccessToken bs) = bs

-- | Generate a cryptographically secure 'RegistrationAccessToken'.
--
-- Produces @dcr_@ followed by 64 lowercase hex characters (32 random bytes,
-- giving 256 bits of entropy).
generateRegistrationAccessToken :: (MonadRandom m) => m RegistrationAccessToken
generateRegistrationAccessToken = do
  (bytes :: ByteString) <- getRandomBytes 32
  -- Base16 encoding always produces valid ASCII; decodeUtf8' is total here
  let hexBytes = convertToBase Base16 bytes :: ByteString
      hex = TE.decodeUtf8 hexBytes -- safe: Base16 output is ASCII subset of UTF-8
  pure (RegistrationAccessToken ("dcr_" <> hex))

-- | Hash a 'RegistrationAccessToken' using bcrypt for secure storage.
--
-- Returns 'Nothing' if bcrypt hashing fails (extremely unlikely in practice).
-- Always store the hash, never the plaintext token.
hashRegistrationAccessToken :: (MonadIO m) => RegistrationAccessToken -> m (Maybe HashedRegistrationAccessToken)
hashRegistrationAccessToken (RegistrationAccessToken t) = liftIO $ do
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

-- | JSON serialisation for 'HashedRegistrationAccessToken'.
--
-- Serialises the bcrypt hash bytes as a UTF-8 text string.
-- bcrypt output is always ASCII-safe, so UTF-8 encoding is lossless.
-- IMPORTANT: This exposes the bcrypt hash — only use for server-side persistence,
-- never in API responses to clients.
instance ToJSON HashedRegistrationAccessToken where
  toJSON (HashedRegistrationAccessToken bs) = toJSON (TE.decodeUtf8 bs)

-- | JSON deserialisation for 'HashedRegistrationAccessToken'.
--
-- Validates the bcrypt prefix (@$2a$@, @$2b$@, or @$2y$@) on deserialisation.
instance FromJSON HashedRegistrationAccessToken where
  parseJSON = withText "HashedRegistrationAccessToken" $ \t ->
    case mkHashedRegistrationAccessToken (TE.encodeUtf8 t) of
      Nothing -> fail "HashedRegistrationAccessToken must be a valid bcrypt hash"
      Just hrat -> pure hrat

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

-- | 'Arbitrary' instance for 'HashedRegistrationAccessToken' for property testing.
--
-- Generates a synthetic bcrypt-format hash (valid prefix, random alphanumeric content).
-- These are NOT real bcrypt hashes — they are test values that pass format validation.
instance Arbitrary HashedRegistrationAccessToken where
  arbitrary = do
    let bcryptBase64Chars = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    costFactor <- elements ["04", "05", "06", "07", "08", "09", "10", "11", "12"]
    saltChars <- vectorOf 22 (elements bcryptBase64Chars)
    hashChars <- vectorOf 31 (elements bcryptBase64Chars)
    let hashText = T.pack ("$2a$" <> costFactor <> "$" <> saltChars <> hashChars)
        hashBS = TE.encodeUtf8 hashText
    -- mkHashedRegistrationAccessToken always succeeds here since we generate valid prefix
    pure (HashedRegistrationAccessToken hashBS)
  shrink _ = []
