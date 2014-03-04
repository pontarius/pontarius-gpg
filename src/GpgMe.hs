module GpgMe
       ( Error(..)
       , checkVersion
       , ctxNew
       , setArmor
       , Key(..)
       , Attr(..)
       , keyName
       , keyID
       , keyFingerprint
       , getKeys
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
       ) where

import           Bindings
import           Control.Applicative
import           Data.ByteString (ByteString)

import qualified Control.Exception as Ex
import           Data.Maybe

keyName :: Key -> IO (Maybe ByteString)
keyName k = keyGetStringAttr k AttrName 0

keyID :: Key -> IO (Maybe ByteString)
keyID k = keyGetStringAttr k AttrKeyid 0

keyFingerprint :: Key -> IO (Maybe ByteString)
keyFingerprint k = keyGetStringAttr k AttrFpr 0
