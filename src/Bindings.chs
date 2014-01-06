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
import           Control.Monad
import           Data.Bits
import qualified Data.ByteString as BS
import qualified Data.ByteString.Unsafe as BS
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
import           System.Posix.Types
import           System.Posix.IO

fromEnum' :: (Enum a, Num b) => a -> b
fromEnum' = fromIntegral . fromEnum

toEnum' :: (Enum c, Integral a) => a -> c
toEnum' = toEnum . fromIntegral

toFlags :: (Enum a, Num b, Data.Bits.Bits b) => [a] -> b
toFlags = foldr (.|.) 0 . map fromEnum'

-- fromFlags x = filter (\y -> let y' = fromEnum' y in x .|. y' == y')
--                      [minBound..maxBound]

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
withCtx x f = f $ fromCtx x

{#fun new as ctxNew
   {alloca- `Ctx' mkContext*}
   -> `()' throwError*- #}

{#fun release as ctxRelease
   {withCtx* `Ctx'}
   -> `()' #}

{#enum gpgme_validity_t as Validity {underscoreToCase} deriving (Show) #}
{#enum attr_t as Attr {underscoreToCase} deriving (Show) #}



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

getKeys :: Ctx -> Bool -> IO [Key]
getKeys (Ctx ctx) secretOnly= do
    {#call gpgme_op_keylist_start #} ctx nullPtr (fromEnum' secretOnly)
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
   , fromEnum' `Attr'
   , reserved- `Ptr()'
   , `Int'
   } -> `Maybe Text.Text' toMaybeText* #}

-------------------------------
-- Data Buffers
-------------------------------

newtype DataBuffer = DataBuffer {fromDataBuffer :: Ptr ()}
mkDataBuffer = fmap DataBuffer . peek
withDataBuffer (DataBuffer buf) f = f buf

toMaybeText ptr = if ptr == nullPtr
                then return Nothing
                else Just . Text.pack <$> peekCString ptr

withMaybeText Nothing = ($ nullPtr)
withMaybeText (Just txt) = withCString (Text.unpack txt)

{#fun data_new as ^
   { alloca- `DataBuffer' mkDataBuffer* }
   -> `()' throwError*- #}

peekInt = fmap fromIntegral . peek

{#fun data_release_and_get_mem as ^
   { fromDataBuffer `DataBuffer'
   , alloca- `Int' peekInt*
   } -> `Ptr ()' castPtr #}

getDataBufferBytes :: DataBuffer -> IO BS.ByteString
getDataBufferBytes db = do
    (dt, len) <- dataReleaseAndGetMem db
    res <- if dt == nullPtr then return BS.empty
                            else do
               bs <- BS.packCStringLen (castPtr dt, len)
               {#call free#} dt
               return bs
    return res

{# fun gpgme_op_export_keys as exportKey
   { withCtx* `Ctx'
   , withKeysArray* `[Key]'
   , reserved0- `CUInt'
   , fromDataBuffer `DataBuffer'
   } -> `Error' throwError*- #}

getKeyBS :: Ctx -> Key -> IO BS.ByteString
getKeyBS ctx key = do
    db <- dataNew
    exp <- exportKey ctx [key] db
    getDataBufferBytes db

unsafeUseAsCStringLen' bs f =
    BS.unsafeUseAsCStringLen bs $ \(bs, l) -> f (bs, fromIntegral l)

{# fun data_new_from_mem as ^
   { alloca- `DataBuffer' mkDataBuffer*
   , unsafeUseAsCStringLen' * `BS.ByteString'&
   , fromEnum' `Bool'
   } -> `Error' throwError*- #}

{# fun data_release as ^
   { withDataBuffer* `DataBuffer'} -> `()' #}

{# fun set_armor as ^
     { withCtx* `Ctx'
     , fromEnum' `Bool'
     } -> `()' #}

withBSData bs =
    Ex.bracket (dataNewFromMem bs True)
               dataRelease

withBSBuffer f =
    Ex.bracketOnError dataNew
                      dataRelease
                      $ \db -> do
                          f db
                          getDataBufferBytes db


-----------------------------------
-- Signing
-----------------------------------

{#fun signers_clear as ^
    {withCtx* `Ctx'} -> `()'#}

{#fun signers_add as ^
    { withCtx* `Ctx'
    , withKey* `Key'
    } -> `()' throwError* #}

{# enum sig_mode_t as SigMode {underscoreToCase}
       with prefix = "GPGME"
       deriving (Show) #}

{#fun op_sign as ^
    { withCtx* `Ctx'
    , withDataBuffer* `DataBuffer'
    , withDataBuffer* `DataBuffer'
    , fromEnum' `SigMode'
    } -> `()' throwError*- #}
--     exportKey

-- | Sign a text using a private signing key from the GPG keychain
sign :: Ctx
     -> BS.ByteString -- ^ Text to sign
     -> Key -- ^ Signing key to use
     -> SigMode -- ^ Signing mode
     -> IO BS.ByteString
sign ctx plain key mode = withBSData plain $ \plainData ->
                          withBSBuffer $ \outData -> (do
    signersClear ctx
    signersAdd ctx key
    opSign ctx plainData outData mode)
       `Ex.finally` signersClear ctx

{# enum sigsum_t as SigSummary {underscoreToCase} deriving (Bounded, Show)#}
{# enum sig_stat_t as SigStat {underscoreToCase} deriving (Bounded, Show)#}

{#fun op_verify as ^
   { withCtx* `Ctx'
   , withDataBuffer* `DataBuffer' -- sig
   , withDataBuffer* `DataBuffer' -- signed-text
   , withDataBuffer* `DataBuffer' -- plain
   } -> `()' throwError*- #}

checkVerifyResult :: Ctx -> IO SigStat
checkVerifyResult ctx = withCtx ctx $ \ctx' -> do
    alloca $ \sigStatPtr -> do
        res <- {#call get_sig_status#} ctx' 0 sigStatPtr nullPtr
        if (res == nullPtr)
            then return SigStatNosig
            else do
                sigStat <- peek sigStatPtr
                return $! (toEnum' sigStat :: SigStat)


-- | Verify a signature created in 'SigModeDetach' mode
verifyDetach :: Ctx
             -> BS.ByteString -- ^ The source text that the signature pertains to
             -> BS.ByteString -- ^ The signature
             -> IO SigStat
verifyDetach ctx signedText sig = withBSData signedText $ \stData ->
                                  withBSData sig $ \sigData -> do
    opVerify ctx sigData stData (DataBuffer nullPtr)
    checkVerifyResult ctx

-- | Verify a signature created in 'SigModeNormal' or 'SigModeClear' mode
verify :: Ctx
        -> BS.ByteString -- ^ Text and attached Signature
        -> IO (SigStat, BS.ByteString) -- ^ result and extracted plain text
verify ctx sig = withBSData sig $ \sigData -> do
    plain <- withBSBuffer $ \plainData ->
        opVerify ctx sigData (DataBuffer nullPtr) plainData
    res <- checkVerifyResult ctx
    return (res, plain)

--------------------------------
-- Passphrases
--------------------------------

-- gpgme_error_t (*gpgme_passphrase_cb_t)(void *hook, const char *uid_hint, const char *passphrase_info, int prev_was_bad, int fd)

type PassphraseCallback = Ptr () -- ^ Hook
                        -> Ptr CChar -- ^ Uid Hint
                        -> Ptr CChar -- ^ passphrase info
                        -> CInt -- ^ Was Bad?
                        -> CInt -- ^ fd
                        -> IO CUInt

foreign import ccall "wrapper"
  mkPasswordCallback  :: PassphraseCallback -> IO (FunPtr PassphraseCallback)

setPassphraseCallback :: Ctx
                      -> (String -> String -> Bool -> IO String)
                      -> IO ()
setPassphraseCallback ctx f = do
    let cbFun _ uidHint pInfo bad fd = do
               uidHintString <- peekCString uidHint
               pInfoString <- peekCString pInfo
               out <- f uidHintString pInfoString (bad == 0)
               fdWrite (Fd fd) (filter (/= '\n') out ++ "\n" )
               return 0
    cb <- mkPasswordCallback cbFun
    withCtx ctx $ \ctxPtr -> {# call set_passphrase_cb #} ctxPtr cb nullPtr
