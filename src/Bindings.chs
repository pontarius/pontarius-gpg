-- | Bindings to GPGMe
--
-- partial bindings to gpgme

{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE NoMonomorphismRestriction #-}

#include <gpgme.h>

module Bindings where

import           Control.Applicative ((<$>), (<*>))
import qualified Data.Text as Text
import           Foreign.C
import           Foreign.C.String
import           Foreign.ForeignPtr
import           Foreign.Marshal.Alloc
import           Foreign.Ptr
import           Foreign.Storable

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
                   } deriving (Show)


#c
gpgme_err_code_t gpgme_err_code_uninlined (gpgme_error_t err);
gpgme_err_source_t gpgme_err_source_uninlined (gpgme_error_t err);
#endc

toError err = case err of
    0 -> return Nothing
    _ -> Just <$>
         (allocaBytes 256 $ \buff -> do
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
withCtx = fromCtx

{#fun new as ctxNew
   {alloca- `Ctx' mkContext*}
   -> `Maybe Error' toError* #}
