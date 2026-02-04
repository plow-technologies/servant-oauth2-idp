{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}

-- | DCR error types per RFC 7591 Section 3.2.2.
--
-- This module provides error types for Device Credential Resolution (DCR)
-- following the RFC 7591 standard for error responses.
module Servant.OAuth2.IDP.DCR.Error
  ( -- * Error Types
    DCRErrorCode (..),
    DCRError,
    mkDCRError,
    dcrErrorCode,
    dcrErrorDescription,
  )
where

import Data.Aeson
  ( FromJSON (parseJSON),
    KeyValue ((.=)),
    ToJSON (toJSON),
    object,
    withObject,
    withText,
    (.:),
    (.:?),
  )
import Data.Aeson.Types (parseFail)
import Data.Text (Text)
import qualified Data.Text as T
import GHC.Generics (Generic)
import Test.QuickCheck (Arbitrary (..), elements, oneof)

-- | DCR error codes per RFC 7591 Section 3.2.2.
data DCRErrorCode
  = -- | redirect_uri is invalid or not allowed
    InvalidRedirectUri
  | -- | Other metadata validation failure
    InvalidClientMetadata
  | -- | IP not in allowlist or other access control failure
    AccessDenied
  | -- | Server-side internal error (e.g., database write failure)
    ServerError
  deriving stock (Eq, Show, Generic, Ord, Enum, Bounded)

-- | JSON instances (RFC 7591 wire format):
-- ToJSON DCRErrorCode: InvalidRedirectUri -> "invalid_redirect_uri", etc.
-- FromJSON DCRErrorCode: "invalid_redirect_uri" -> InvalidRedirectUri, etc.
instance ToJSON DCRErrorCode where
  toJSON InvalidRedirectUri = toJSON ("invalid_redirect_uri" :: Text)
  toJSON InvalidClientMetadata = toJSON ("invalid_client_metadata" :: Text)
  toJSON AccessDenied = toJSON ("access_denied" :: Text)
  toJSON ServerError = toJSON ("server_error" :: Text)

instance FromJSON DCRErrorCode where
  parseJSON = withText "DCRErrorCode" $ \case
    "invalid_redirect_uri" -> pure InvalidRedirectUri
    "invalid_client_metadata" -> pure InvalidClientMetadata
    "access_denied" -> pure AccessDenied
    "server_error" -> pure ServerError
    other -> parseFail $ "Unknown DCRErrorCode: " <> T.unpack other

-- | DCR error response.
data DCRError = MkDCRError
  { dcrErrorCode :: DCRErrorCode
  , dcrErrorDescription :: Maybe Text
  }
  deriving stock (Eq, Show, Generic)

-- | Smart constructor for DCRError.
mkDCRError :: DCRErrorCode -> Maybe Text -> DCRError
mkDCRError = MkDCRError

-- | JSON instances (RFC 7591 wire format):
-- ToJSON DCRError: {"error": "<code>", "error_description": "<desc>"}
-- FromJSON DCRError: parse the above format
instance ToJSON DCRError where
  toJSON (MkDCRError code desc) =
    object $
      ("error" .= code) : ["error_description" .= d | Just d <- [desc]]

instance FromJSON DCRError where
  parseJSON = withObject "DCRError" $ \o ->
    MkDCRError <$> o .: "error" <*> o .:? "error_description"

-- | Arbitrary instance for property testing.
instance Arbitrary DCRErrorCode where
  arbitrary = elements [minBound .. maxBound]

-- | Arbitrary instance for property testing.
instance Arbitrary DCRError where
  arbitrary = MkDCRError <$> arbitrary <*> oneof [pure Nothing, Just <$> arbitraryText]
    where
      arbitraryText = T.pack <$> listOf1 (elements ['a' .. 'z'])
      listOf1 gen = (:) <$> gen <*> listOf gen
      listOf gen = oneof [pure [], (:) <$> gen <*> listOf gen]
