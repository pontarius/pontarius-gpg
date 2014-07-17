
module GpgMe
       ( Error(..)
       , ErrorSource(..)
       , ErrorCode(..)
       , checkVersion
       , ctxNew
       , setArmor
       , Key(..)
       , Attr(..)
       , keyName
       , keyID
       , keyFingerprint
       , getKeys
       , findKeyBy
       , keyGetStringAttr
       , ImportStatus(..)
       , importKeys
       , exportKeys
       , sign
       , SigMode(..)
       , SigStat(..)
       , SigSummary(..)
       , verifyDetach
       , verify
       , setPassphraseCallback
       , Engine(..)
       , getEngines
       , setEngine
       , PinentryMode(..)
       , setPinentryMode
       , GenKeyResult(..)
       , genKey
       , deleteKey
       , editKey
       , module Gpg.EditKey
       ) where

import           Control.Applicative
import qualified Control.Exception as Ex
import           Data.ByteString (ByteString)
import           Data.Maybe

import           Bindings
import           Gpg.EditKey

import Control.Monad


keyName :: Key -> IO (Maybe ByteString)
keyName k = keyGetStringAttr k AttrName 0

keyID :: Key -> IO (Maybe ByteString)
keyID k = keyGetStringAttr k AttrKeyid 0

keyFingerprint :: Key -> IO (Maybe ByteString)
keyFingerprint k = keyGetStringAttr k AttrFpr 0

findKeyBy :: Eq a => Ctx -> Bool -> (Key -> IO a) -> a -> IO [Key]
findKeyBy ctx secret f x = filterM (fmap (== x) . f) =<< getKeys ctx secret
