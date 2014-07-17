{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE DeriveFunctor #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}

module Gpg.Basic where

import           Control.Applicative
import qualified Control.Exception as Ex
import           Control.Monad
import           Control.Monad.Trans
import           Control.Monad.Trans.Free
import           Data.Char
import           Data.Data
import qualified Data.List as List
import           Data.Map (Map)
import qualified Data.Map as Map
import           Data.Maybe (fromJust)
import           Data.Monoid
import           Data.Text (Text)
import qualified Data.Text as Text
import           Data.Typeable
import           System.IO

import           Bindings

data GpgError = EngineNotFound
              | MethodError Text
              | MethodEnd -- ^ Method ended before interaction was done
              | ParseError Text
                deriving (Typeable, Eq, Show)

instance Ex.Exception GpgError

data Gpg r = GpgError Text
           | Send Text r
           | GetState (StatusCode -> Text -> r)
           deriving Functor

newtype GpgM a = GpgM { unGpgM :: FreeT Gpg IO a}
               deriving (Monad, Applicative, Functor, MonadIO)

-- | Send a response to gpg and yield the computation
send :: Text -> GpgM ()
send txt = GpgM . FreeT . return . Free  $ Send txt (return())

-- | Error to return when and unexpected state is encountered
errState :: Text
errState = "Invalid State"

-- | Return an error message and abort the computation
editError :: Text -> GpgM a
editError = GpgM . FreeT . return . Free . GpgError

-- | Guard the computation: If the predicate doesn't match the error is returned
-- and the computation aborted
editGuard :: Text -> Bool -> GpgM ()
editGuard _ True = return ()
editGuard e False = editError e

-- | Get the current state and argument text
getState :: GpgM (StatusCode, Text)
getState = do
    st <- GpgM . FreeT . return . Free $ GetState (\sc ln -> return (sc, ln))
    return st

-- | Chck that the current status code and argument text match or return an
-- error to gpg
expect :: StatusCode -> Text -> GpgM ()
expect status line = do
    (sc, ln) <- getState
    unless (status == sc && ln == line) $ do
        liftIO $ hPutStr stderr ("State transition error: Expected "
                                 ++ show status ++ " " ++ show line
                                 ++ " but got "
                                 ++ show sc ++ " " ++ show ln)
        editError $ "Invalid state, expected  " <> (Text.pack $ show status)
                     <> " but got " <> (Text.pack $ show sc)

-- | Check that the status code matches but ignore the argument text or return
-- an error
expectState :: StatusCode -> GpgM ()
expectState status = do
    (sc, ln) <- getState
    let err = "Invalid state, expected  " <> (Text.pack $ show status)
              <> " but got " <> (Text.pack $ show sc)
    editGuard err (status == sc)

-- | Combination of expect and send.
expectAndSend :: (StatusCode, Text) -> Text -> GpgM ()
expectAndSend (sc, ln) out = do
    expect sc ln
    send out

-- | Handle state transitions that occur when the user is queried for a
-- passphrase during gpg interactions
getPassphrase :: GpgM ()
getPassphrase = do
    (st, ln) <- getState
    case st of
        StatusNeedPassphrase -> send "" >> getPassphrase
        StatusBadPassphrase -> send "" >> getPassphrase
        StatusMissingPassphrase -> send "" >> getPassphrase
        StatusUseridHint -> send "" >> getPassphrase
        StatusGoodPassphrase -> send "" >> return ()
        _ -> do
            liftIO  . hPutStrLn stderr
                $ "getPassphrase: Unhandled state " ++ show st
            editError errState

quit :: GpgM ()
quit = do
    expect StatusGetLine "keyedit.prompt"
    send "quit"
    expectAndSend (StatusGetBool, "keyedit.save.okay") "y"
    expectAndSend (StatusEof, "") ""
