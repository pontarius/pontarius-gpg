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
import qualified Data.ByteString.Unsafe as BS
import           Data.Text (Text)
import qualified Data.Text as Text
import           Data.Typeable
import           Foreign.C
import           Foreign.ForeignPtr
import           Foreign.Marshal.Alloc
import           Foreign.Marshal.Array
import           Foreign.Marshal.Utils
import           Foreign.Ptr
import           Foreign.Storable
import           System.IO.Unsafe (unsafePerformIO)
import           System.Posix.IO
import           System.Posix.Types

fromEnum' :: (Enum a, Num b) => a -> b
fromEnum' = fromIntegral . fromEnum

toEnum' :: (Enum c, Integral a) => a -> c
toEnum' = toEnum . fromIntegral

toFlags :: (Enum a, Num b, Data.Bits.Bits b) => [a] -> b
toFlags = foldr (.|.) 0 . map fromEnum'

-- fromFlags x = filter (\y -> let y' = fromEnum' y in x .|. y' == y')
--                      [minBound..maxBound]

{#context lib = "gpgme" prefix = "gpgme" #}

{#pointer gpgme_ctx_t as Ctx foreign newtype#}

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

throwError :: CUInt -> IO ()
throwError e' = do
    mbe <- toError e'
    case mbe of
        Nothing -> return ()
        Just e -> Ex.throwIO e

#c
gpgme_err_code_t gpgme_err_code_uninlined (gpgme_error_t err);
gpgme_err_source_t gpgme_err_source_uninlined (gpgme_error_t err);
#endc

toError :: CUInt -> IO (Maybe Error)
toError err = case err of
    0 -> return Nothing
    _ -> Just <$>
         (allocaBytes 256 $ \buff -> do -- We hope that any error message will
                                        -- be less than 256 bytes long
               _ <- {#call strerror_r#} err buff 256
               Error <$> (toEnum . fromIntegral
                          <$> {# call err_code_uninlined #} err)
                     <*> (toEnum . fromIntegral
                          <$> {# call err_source_uninlined #} err)
                     <*> (Text.pack <$> peekCString buff))

checkVersion :: Maybe Text -> IO (Maybe Text)
checkVersion Nothing = Just . Text.pack <$>
                         (peekCString =<< {#call check_version#} nullPtr)
checkVersion (Just txt) = withCString (Text.unpack txt) $ \buf -> do
    _ <- {#call check_version#} buf
    return Nothing


{#enum gpgme_protocol_t as Protocol {underscoreToCase} deriving (Show, Eq)#}
-- gpgme_engine_check_version (gpgme_protocol_t protocol)

foreign import ccall unsafe "&gpgme_release"
    releaseCtx :: FunPtr (Ptr Ctx -> IO ())

mkContext :: Ptr (Ptr Ctx) -> IO Ctx
mkContext p = do
    if p == nullPtr
        then Ex.throw (Ex.AssertionFailed "nullPtr")
        else fmap Ctx $ newForeignPtr releaseCtx  . castPtr =<< peek p


-- withCtx :: Ctx -> (Ptr Ctx -> IO t) -> IO t
-- withCtx x f = withForeignPtr (fromCtx x) f

{#fun new as ctxNew'
   {alloca- `Ctx' mkContext*}
   -> `()' throwError*- #}

-- | Check that version constraint is satisfied and create a new context
ctxNew :: Maybe Text -> IO Ctx
ctxNew minVersion = do
    _ <- checkVersion minVersion
    ctxNew'

{#enum gpgme_validity_t as Validity {underscoreToCase} deriving (Show) #}
{#enum attr_t as Attr {underscoreToCase} deriving (Show) #}

------------------------------------
-- Keys
------------------------------------

{#pointer gpgme_key_t as Key foreign newtype #}

withKeysArray :: [Key] -> (Ptr (Ptr Key) -> IO b) -> IO b
withKeysArray ks' f = withKeys ks' $ \ksPtrs -> withArray0 nullPtr ksPtrs f
  where
    withKeys []     g = g []
    withKeys (k:ks) g = withKey k $ \kPtr -> withKeys ks (g . (kPtr:))

foreign import ccall "gpgme.h &gpgme_key_unref"
    unrefPtr :: FunPtr (Ptr Key -> IO ())

getKeys :: Ctx
        -> Bool -- ^ Only keys with secret
        -> IO [Key]
getKeys ctx secretOnly = withCtx ctx $ \ctxPtr -> do
    _ <- {#call gpgme_op_keylist_start #} ctxPtr nullPtr (fromEnum' secretOnly)
    alloca $ takeKeys ctxPtr
  where
    takeKeys ctxPtr (buf :: Ptr (Ptr Key)) = do
        e <- toError =<< {#call gpgme_op_keylist_next#} ctxPtr buf
        case e of
            Nothing -> do
                keyPtr <- peek buf
                key <- newForeignPtr unrefPtr keyPtr
                (Key key :) <$> takeKeys ctxPtr buf
            Just e -> case errCode e of
                ErrEof -> return []
                _ -> error "takeKeys"

reserved :: (Ptr a -> t) -> t
reserved f = f nullPtr

reserved0 :: Num a => (a -> t) -> t
reserved0 f = f 0

{#fun key_get_string_attr as ^
   { withKey* `Key'
   , fromEnum' `Attr'
   , reserved- `Ptr()'
   , `Int'
   } -> `Maybe BS.ByteString' toMaybeText* #}

-------------------------------
-- Data Buffers
-------------------------------

newtype DataBuffer = DataBuffer {fromDataBuffer :: Ptr ()}
mkDataBuffer :: Ptr (Ptr ()) -> IO DataBuffer
mkDataBuffer = fmap DataBuffer . peek

withDataBuffer :: DataBuffer -> (Ptr () -> t) -> t
withDataBuffer (DataBuffer buf) f = f buf

toMaybeText :: Ptr CChar -> IO (Maybe BS.ByteString)
toMaybeText ptr = maybePeek BS.packCString ptr

withMaybeText :: Maybe Text -> (Ptr CChar -> IO a) -> IO a
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

data ImportStatus = ImportStatus { isFprint :: String
                                 , isResult :: Maybe Error
                                 , isStatus :: Int -- TODO: convert to flags
                                 }

importKey :: Ctx -> DataBuffer -> IO [ImportStatus]
importKey ctx keyBuffer = withCtx ctx $ \ctxPtr ->
                          withDataBuffer keyBuffer $ \keyPtr -> do
    throwError =<< {#call op_import#} ctxPtr keyPtr
    result <- {#call op_import_result #} ctxPtr
    walkImports =<< {#get import_result_t.imports#} result
  where
    walkImports ptr = if ptr == nullPtr
                      then return []
                      else do
        is <- ImportStatus <$> (peekCString =<< {#get import_status_t.fpr #} ptr)
                           <*> (toError =<< {#get import_status_t.result #} ptr)
                           <*> (fromIntegral <$> {#get import_status_t.status #} ptr)
        (is:) <$> (walkImports =<< {#get import_status_t.next #} ptr)


importKeyBS ctx bs = withBSData bs $ importKey ctx

getKeyBS :: Ctx -> Key -> IO BS.ByteString
getKeyBS ctx key = do
    db <- dataNew
    exp <- exportKey ctx [key] db
    getDataBufferBytes db

unsafeUseAsCStringLen' :: Num t =>
                          BS.ByteString
                       -> ((Ptr CChar, t) -> IO a)
                       -> IO a
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

withBSData :: BS.ByteString -> (DataBuffer -> IO c) -> IO c
withBSData bs =
    Ex.bracket (dataNewFromMem bs True)
               dataRelease

withBSBuffer :: (DataBuffer -> IO a) -> IO BS.ByteString
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

data Engine = Engine { engineProtocol   :: Protocol
                     , engineFilename   :: Maybe String
                     , engineHomeDir    :: Maybe String
                     , engineVersion    :: Maybe String
                     , engineReqVersion :: Maybe String
                     } deriving (Show)

getEngines :: Ctx -> IO [Engine]
getEngines ctx = withCtx ctx $ \ctxPtr ->  do
    goEngines =<< {#call ctx_get_engine_info #} ctxPtr
  where
    goEngines this = if this == nullPtr
                     then return []
                     else do
        engine <- Engine <$> (toEnum' <$> {# get engine_info_t.protocol#} this)
                         <*> (peekCSM =<< {#get engine_info_t.file_name#}   this)
                         <*> (peekCSM =<< {#get engine_info_t.home_dir#}    this)
                         <*> (peekCSM =<< {#get engine_info_t.version#}     this)
                         <*> (peekCSM =<< {#get engine_info_t.req_version#} this)
        next <- {# get gpgme_engine_info_t.next #} this
        (engine:) <$> goEngines next
    peekCSM cString = if cString == nullPtr
                      then return Nothing
                      else Just <$> peekCString cString

setEngine :: Ctx -> Engine -> IO ()
setEngine ctx eng = withCtx ctx $ \ctxPtr->
                    withMBCString (engineFilename eng) $ \fNamePtr ->
                    withMBCString (engineHomeDir eng)  $ \hDirPtr ->
    throwError =<< {#call ctx_set_engine_info #} ctxPtr
                                                 (fromEnum' $ engineProtocol eng)
                                                 fNamePtr
                                                 hDirPtr
  where
    withMBCString Nothing f = f nullPtr
    withMBCString (Just str) f = withCString str f

{# enum pinentry_mode_t as PinentryMode {underscoreToCase} #}

{# fun set_pinentry_mode as ^
   { withCtx* `Ctx'
   , fromEnum' `PinentryMode'
   } -> `()' throwError*- #}

-------------------------------------------
-- Key Creation ---------------------------
-------------------------------------------
data GenKeyResult = GenKeyResult { genKeyhasPrimary :: Bool
                                 , genKeyhasSubKey :: Bool
                                 , genKeyFingerprint :: Maybe BS.ByteString
                                 } deriving (Show)

genKey :: Ctx -> String -> IO GenKeyResult
genKey ctx params = withCtx ctx $ \ctxPtr ->
                    withCString params $ \paramsPtr -> do
    putStrLn "starting key genearion"
    throwError =<< {#call gpgme_op_genkey#} ctxPtr paramsPtr nullPtr nullPtr
    putStrLn "retrieving result"
    res <- {#call gpgme_op_genkey_result#} ctxPtr
    putStrLn "Extracting result data"
    prim <- toEnum' <$> {#get gpgme_genkey_result_t.primary#} res
    sub <- toEnum' <$> {#get gpgme_genkey_result_t.sub#} res
    fprint <- maybePeek BS.packCString =<< {#get gpgme_genkey_result_t.fpr#} res
    return $ GenKeyResult prim sub fprint
