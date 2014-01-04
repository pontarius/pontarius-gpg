{-# LANGUAGE OverloadedStrings #-}

module GpgMe where

import           Bindings
import           Control.Monad
import           Data.Binary
import qualified Data.ByteString.Lazy as BSL
import qualified Data.OpenPGP as OpenPGP

keyName k = keyGetStringAttr k AttrName 0
keyID k = keyGetStringAttr k AttrKeyid 0

unMessage (OpenPGP.Message ps) = ps

sign ctx plain key = do
    plainData <- dataNewFromMem plain True
    outData <- dataNew
    signersClear ctx
    signersAdd ctx key
    opSign ctx plainData outData SigModeClear
    signersClear ctx
    dataRelease plainData
    getDataBufferBytes outData

main = do
    checkVersion Nothing
    (_, ctx) <- ctxNew
    (key:keys) <- getKeys ctx True
    sign ctx "lorem ipsum dolor sit amet" key
