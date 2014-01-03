module GpgMe where

import           Bindings
import           Data.Binary
import qualified Data.OpenPGP as OpenPGP
import qualified Data.ByteString.Lazy as BSL

keyName k = keyGetStringAttr k AttrName 0

unMessage (OpenPGP.Message ps) = ps

main = do
    checkVersion Nothing
    (_, ctx) <- ctxNew
    keys <- getKeys ctx
    bs <- getKeyBS ctx (keys !! 1)
    mapM print . unMessage $ decode ( BSL.fromChunks [bs])

-- >>> main
-- ["Felix von Leitner","Philipp Balzarek","Jon Kristensen","vrijn"]
