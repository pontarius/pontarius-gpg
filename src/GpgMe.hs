module GpgMe where

import Bindings

main = do
    print =<< checkVersion Nothing
    print =<< ctxNew
