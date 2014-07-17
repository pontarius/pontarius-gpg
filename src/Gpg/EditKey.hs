{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE DeriveFunctor #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}

-- Module: Gpg.EditKey
--
-- Edit keys with Gpg's interactive mode

module Gpg.EditKey where
import           Control.Monad
import qualified Control.Exception as Ex
import           Control.Applicative
import qualified Data.Text.Encoding as Text
import           Control.Monad.Trans.Free
import           Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import           Data.IORef
import           Data.Monoid
import           Data.Text (Text)
import qualified Data.Text as Text
import qualified Data.Text.IO as Text
import           System.Posix
import           Foreign.Ptr
import           Control.Monad.Trans
import           System.IO

import           Bindings
import           Gpg.Basic

fdWrite' :: Fd -> ByteString -> IO ByteCount
fdWrite' fd bs = BS.useAsCStringLen bs $ \(ptr, len) ->
    fdWriteBuf fd (castPtr ptr) (fromIntegral len)

runEditAction :: Ctx -> Key -> GpgM () -> IO ByteString
runEditAction ctx key action = do
    ref <- newIORef action
    editKey ctx key $ cb ref
  where
    cb :: IORef (GpgM ()) -> EditCallback
    cb _ StatusGotIt "" fd = fdWrite' fd "\n" >> return noError
    cb ref sc ln fd@(Fd fdInt) = do
        GpgM st <- readIORef ref
        go =<< runFreeT st
      where
        go (Pure ()) = return $ Error ErrUser1 ErrSourceUser1 ""
        go (Free (GpgError e)) = Ex.throwIO (MethodError e)
        go (Free (Send txt cont)) = do
            writeIORef ref (GpgM cont)
            case (fdInt, txt) of
                (-1, "") -> return noError
                (-1, _) -> return $ Error ErrUser2 ErrSourceUser1 ""
                _ -> fdWrite' fd (Text.encodeUtf8 txt <> "\n")
                     >> return noError
        go (Free (GetState f)) = go =<< runFreeT (f sc ln)

data RevocationReason = NoReason
                      | Compromised
                      | Superseeded
                      | NoLongerUsed
                      deriving (Eq, Show, Enum)

-- | Revoke a key
revoke :: Ctx -> Key -> RevocationReason -> Text -> IO ByteString
revoke ctx key reason reasonText = runEditAction ctx key $ do
    expectAndSend (StatusGetLine, "keyedit.prompt") "revkey"
    expectAndSend (StatusGetBool, "keyedit.revoke.subkey.okay") "y"
    let reasonCode = Text.pack . show $ fromEnum reason
    expectAndSend (StatusGetLine, "ask_revocation_reason.code") reasonCode
    forM_ (Text.lines reasonText) $ \line -> do
        expect StatusGetLine "ask_revocation_reason.text"
        send line
    expectAndSend (StatusGetLine, "ask_revocation_reason.text") ""
    expectAndSend (StatusGetBool, "ask_revocation_reason.okay") "y"
    getPassphrase
    quit
    liftIO . print =<< getState
    return ()
