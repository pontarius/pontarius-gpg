{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE DeriveDataTypeable #-}
module Gpg.Run
  ( module Gpg.Run
  , module Gpg.Basic
  , StatusCode(..)
  ) where

import           Bindings
import           Control.Applicative
import qualified Control.Exception as Ex
import           Control.Monad
import           Control.Monad.Trans
import           Control.Monad.Trans.Free
import qualified Data.Attoparsec.Text as AP
import           Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import           Data.Char
import           Data.Data
import qualified Data.List as List
import           Data.Map.Strict (Map)
import qualified Data.Map.Strict as Map
import           Data.Maybe (fromJust)
import           Data.Monoid
import           Data.Text (Text)
import qualified Data.Text as Text
import qualified Data.Text.IO as Text
import           Data.Typeable
import           System.IO
import           System.Process


import           Gpg.Basic

debug = False

runGPG args exec = do
    engines <- ctxNew Nothing >>= getEngines
    let gpgEngines = List.find (\e -> engineProtocol e == ProtocolOpenpgp) engines
    pgpEngine <- case gpgEngines of
        Just e -> return e
        Nothing -> Ex.throwIO EngineNotFound
    let Just gpgBin = engineFilename pgpEngine
        p' = proc' gpgBin $ ["--status-fd=2", "--command-fd=0"
                            , "--no-tty"] ++ args
        p = p'{ std_in = CreatePipe
              , std_out = CreatePipe
              , std_err = CreatePipe
              }
    (Just control, Just out, Just status, procID) <- createProcess p
    interactGpg control status out (unGpgM exec) (terminateProcess procID)
  where
    interactGpg ctrl stat out m killProc = do
        st <- getState stat
        when debug $ hPutStrLn stderr $ show st
        next <- case st of
            (StatusGotIt, "") -> return m
            _ -> do
                (out, next) <- go st =<< runFreeT m
                when debug $ hPutStrLn stderr $ show out
                Text.hPutStrLn ctrl out
                hFlush ctrl
                return next
        isEof <- hIsEOF stat
        if isEof
            then BS.hGetContents out
            else interactGpg ctrl stat out next killProc
      where
        go _ (Pure a) = do
            killProc
            Ex.throwIO MethodEnd
        go _ (Free (GpgError e)) = do
            killProc
            Ex.throwIO (MethodError e)
        go _ (Free (Send t m)) = do
             return (t,m)
        go (st, line) (Free (GetState f)) = go (st, line) =<< runFreeT (f st line)
    getState stat = do
       line <- Text.hGetLine stat
       case AP.parseOnly lineParser line of
           Left e -> Ex.throwIO $ ParseError (Text.pack e)
           Right r -> return r
    lineParser = do
        AP.string "[GNUPG:]"
        AP.skipSpace
        statusLine <- AP.takeWhile $ not . isSpace
        status <- case parseStatus statusLine of
            Nothing -> mzero
            Just st -> return st
        AP.skipSpace
        line <- AP.takeWhile $ not . isSpace
        AP.skipSpace
        return (status, line)

-- HACK: We reconstruct the status line from the Constructor name via show
-- (which in turn is derived from the enum field in gpgme) because gpgme doesn't
-- export the status parsing code
statusList :: Map Text StatusCode
statusList = Map.fromList [(printStatus st, st) | st <- [minBound .. ]]
  where
    printStatus :: StatusCode -> Text
    printStatus = Text.pack . tail . caseToUnderscore
                  . fromJust . List.stripPrefix "Status" . show
    caseToUnderscore [] = []
    caseToUnderscore (x:xs) | isLower x = toUpper x : caseToUnderscore xs
                            | isUpper x = '_' : x : caseToUnderscore xs

parseStatus :: Text -> Maybe StatusCode
parseStatus ln = Map.lookup ln statusList


proc' = proc
