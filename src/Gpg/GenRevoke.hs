{-# LANGUAGE OverloadedStrings #-}
module Gpg.GenRevoke where

import           Control.Monad
import           Data.Text (Text)
import qualified Data.Text as Text
import           Gpg.Run

data RevocationReason = NoReason
                      | Compromised
                      | Superseeded
                      | NoLongerUsed
                      deriving (Eq, Show, Enum)

genRevoke reason reasonText key = do
    runGPG ["--gen-revoke", "foobar"] $ do
        expectAndSend (StatusGetBool, "gen_revoke.okay") "y"
        let reasonCode = Text.pack . show $ fromEnum reason
        expectAndSend (StatusGetLine, "ask_revocation_reason.code") reasonCode
        forM_ (Text.lines reasonText) $ \line -> do
            expect StatusGetLine "ask_revocation_reason.text"
            send line
        expectAndSend (StatusGetLine, "ask_revocation_reason.text") ""
        expectAndSend (StatusGetBool, "ask_revocation_reason.okay") "y"
        getPassphrase
        getPassphrase
