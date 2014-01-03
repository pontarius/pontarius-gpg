module GpgMe where

import Bindings

keyName k = keyGetStringAttr k AttrName 0

main = do
    checkVersion Nothing
    (_, ctx) <- ctxNew
    keys <- getKeys ctx
    print $ map keyName keys

-- >>> main
-- ["Felix von Leitner","Philipp Balzarek","Jon Kristensen","vrijn"]
