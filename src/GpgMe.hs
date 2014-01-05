{-# LANGUAGE OverloadedStrings #-}

module GpgMe where

import           Bindings
import           Control.Monad
import           Data.Binary
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as BSL
import qualified Data.OpenPGP as OpenPGP

keyName k = keyGetStringAttr k AttrName 0
keyID k = keyGetStringAttr k AttrKeyid 0

unMessage (OpenPGP.Message ps) = ps

sgnGood = "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\nlorem ipsum dolor sit amet\n-----BEGIN PGP SIGNATURE-----\nVersion: GnuPG v2.0.22 (GNU/Linux)\n\niF4EAREIAAYFAlLIMucACgkQBcfk+3ZQIFLvzQEAtQ1Mmm3GuQ9qUpM3Wxi1xtFC\nl/qwvDMT0lZijdO8O4AA/RTCc9ZpKtRhEd8TiNEA0zLgx93YQ7suwq8X335E3xrs\n=CgkI\n-----END PGP SIGNATURE-----\n"

sgnBad = "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\nlorem ipsum dolor sit amet\n-----BEGIN PGP SIGNATURE-----\nVersion: GnuPG v2.0.22 (GNU/Linux)\n\niF4EAREIAAYFAlLIMucACgkQBcfk+3ZQIFLvzQEAtQ1Mmm3GuQ9qUpM3Wxi1xtFC\nl/qwvDMT0lZijdO8O4AA/RTCc9ZpKtRhEd8TiNEA0zLgx93YQ7suwq8X334E3xrs\n=CgkI\n-----END PGP SIGNATURE-----\n"

main = do
    checkVersion Nothing
    ctx <- ctxNew
    (key:keys) <- getKeys ctx True
    sgn <- sign ctx "Das Pferd frisst keinen Gurkensalat" (head keys) SigModeClear
    print =<< verifyDetach ctx "Das Pferd frisst keinen Gurkensalat" sgn
    print =<< verify ctx sgnGood
    print =<< verify ctx sgnBad

--    print =<< verifyDetach ctx "Das Pferd frisst keinen Gurkensalat" sgn
