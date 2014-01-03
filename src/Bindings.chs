-- | Bindings to GPGMe
--
-- partial bindings to gpgme

{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE NoMonomorphismRestriction #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE DeriveDataTypeable #-}

#include <gpgme.h>

module Bindings where

import           Control.Applicative ((<$>), (<*>))
import qualified Control.Exception as Ex
import           Data.Bits
import qualified Data.ByteString as BS
import qualified Data.Text as Text
import           Data.Typeable
import           Foreign.C
import           Foreign.C.String
import           Foreign.ForeignPtr
import           Foreign.Marshal.Alloc
import           Foreign.Marshal.Array
import           Foreign.Ptr
import           Foreign.Storable
import           System.IO.Unsafe (unsafePerformIO)

toFlags = foldr

{#context lib = "gpgme" prefix = "gpgme" #}

newtype Ctx = Ctx {fromCtx :: {#type gpgme_ctx_t#} }

instance Show Ctx where
    show _ = "<GpgMe.CTX>"

{#enum gpgme_err_code_t as ErrorCode {underscoreToCase}
       with prefix = "GPG"
       deriving (Show) #}

{#enum gpgme_err_source_t as ErrorSource {underscoreToCase}
       with prefix = "GPG"

       deriving (Show) #}

data Error = Error { errCode :: ErrorCode
                   , errSource :: ErrorSource
                   , errorString :: Text.Text
                   } deriving (Show, Typeable )

instance Ex.Exception Error

throwError e' = do
    mbe <- toError e'
    case mbe of
        Nothing -> return ()
        Just e -> Ex.throwIO e

#c
gpgme_err_code_t gpgme_err_code_uninlined (gpgme_error_t err);
gpgme_err_source_t gpgme_err_source_uninlined (gpgme_error_t err);
#endc

toError err = case err of
    0 -> return Nothing
    _ -> Just <$>
         (allocaBytes 256 $ \buff -> do -- We hope that any error message will
                                        -- be less than 256 bytes long
               {#call strerror_r#} err buff 256
               Error <$> (toEnum . fromIntegral
                          <$> {# call err_code_uninlined #} err)
                     <*> (toEnum . fromIntegral
                          <$> {# call err_source_uninlined #} err)
                     <*> (Text.pack <$> peekCString buff))

checkVersion Nothing = Just . Text.pack <$>
                         (peekCString =<< {#call check_version#} nullPtr)
checkVersion (Just txt) = withCString (Text.unpack txt) $ \buf -> do
    {#call check_version#} buf
    return Nothing

-- {#enum gpgme_protocol_t as Protocol {underscoreToCase} #}
-- gpgme_engine_check_version (gpgme_protocol_t protocol)

mkContext = fmap Ctx . peek
withCtx x f = f =<< return (fromCtx x)

{#fun new as ctxNew
   {alloca- `Ctx' mkContext*}
   -> `Maybe Error' toError* #}

{#fun release as ctxRelease
   {withCtx* `Ctx'}
   -> `()' #}

{#enum gpgme_validity_t as Validity {underscoreToCase} deriving (Show) #}
{#enum attr_t as Attr {underscoreToCase} deriving (Show) #}
fromAttr = fromIntegral . fromEnum


------------------------------------
-- Keys
------------------------------------

{#pointer gpgme_key_t as Key foreign newtype #}

withKeysArray :: [Key] -> (Ptr (Ptr Key) -> IO b) -> IO b
withKeysArray ks f = withKeys ks $ \ksPtrs -> withArray0 nullPtr ksPtrs f
  where
    withKeys []     g = g []
    withKeys (k:ks) g = withKey k $ \kPtr -> withKeys ks (g . (kPtr:))

foreign import ccall "gpgme.h &gpgme_key_unref"
    unrefPtr :: FunPtr (Ptr Key -> IO ())

getKeys (Ctx ctx) = do
    {#call gpgme_op_keylist_start #} ctx nullPtr 0
    alloca takeKeys
  where
    takeKeys (buf :: Ptr (Ptr Key)) = do
        e <- toError =<< {#call gpgme_op_keylist_next#} ctx buf
        case e of
            Nothing -> do
                keyPtr <- peek buf
                key <- newForeignPtr unrefPtr keyPtr
                (Key key :) <$> takeKeys buf
            Just e -> case errCode e of
                ErrEof -> return []
                _ -> error "takeKeys"

reserved f = f nullPtr

reserved0 f = f 0

{#fun pure key_get_string_attr as ^
   { withKey* `Key'
   , fromAttr `Attr'
   , reserved- `Ptr()'
   , `Int'
   } -> `Maybe Text.Text' toMaybeText* #}

-------------------------------
-- Data Buffers
-------------------------------

newtype DataBuffer = DataBuffer {fromDataBuffer :: Ptr ()}
mkDataBuffer = fmap DataBuffer . peek

toMaybeText ptr = if ptr == nullPtr
                then return Nothing
                else Just . Text.pack <$> peekCString ptr

withMaybeText Nothing = ($ nullPtr)
withMaybeText (Just txt) = withCString (Text.unpack txt)

{#fun data_new as ^
   { alloca- `DataBuffer' mkDataBuffer* }
   -> `Error' throwError- #}

peekInt = fmap fromIntegral . peek

{#fun data_release_and_get_mem as ^
   { fromDataBuffer `DataBuffer'
   , alloca- `Int' peekInt*
   } -> `Ptr ()' castPtr #}

getDataBufferBytes :: DataBuffer -> IO BS.ByteString
getDataBufferBytes db = do
    (dt, len) <- dataReleaseAndGetMem db
    res <- BS.packCStringLen (castPtr dt, len)
    {#call free#} dt
    return res

{# fun gpgme_op_export_keys as exportKey
   { withCtx* `Ctx'
   , withKeysArray* `[Key]'
   , reserved0- `CUInt'
   , fromDataBuffer `DataBuffer'
   } -> `Error' throwError- #}

getKeyBS :: Ctx -> Key -> IO BS.ByteString
getKeyBS ctx key = do
    db <- dataNew
    exp <- exportKey ctx [key] db
    getDataBufferBytes db

--     exportKey
