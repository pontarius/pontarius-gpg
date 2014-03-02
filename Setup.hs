import Distribution.Simple
import Distribution.PackageDescription
import Distribution.Version

import Distribution.Simple.LocalBuildInfo
import Distribution.Simple.Program
import Distribution.Verbosity

import Control.Applicative
import Control.Monad
import Data.List
import Data.Maybe

main = defaultMainWithHooks simpleUserHooks {
  hookedPrograms = [gpgmeConfigProgram],

  confHook = \pkg flags -> do
    lbi <- confHook simpleUserHooks pkg flags
    bi <- psqlBuildInfo lbi
    return lbi {
      localPkgDescr = updatePackageDescription
                        (Just bi, []) (localPkgDescr lbi)
    }
}

gpgmeConfigProgram = simpleProgram "gpgme-config"


psqlBuildInfo :: LocalBuildInfo -> IO BuildInfo
psqlBuildInfo lbi = do
  (pgconfigProg, _) <- requireProgram verbosity
                         gpgmeConfigProgram (withPrograms lbi)
  let gpgmeConfig = rawSystemProgramStdout verbosity pgconfigProg

  incDirs <- hasPrefix "-I" <$> gpgmeConfig ["--cflags"]
  libInfo <- gpgmeConfig ["--libs"]
  let libDirs =  hasPrefix "-L"  libInfo
      extraLibs = hasPrefix "-l" libInfo
  return emptyBuildInfo
      { includeDirs  = incDirs
      , extraLibs = extraLibs
      , extraLibDirs = libDirs

  }
  where
    verbosity = normal -- honestly, this is a hack
    hasPrefix pre = catMaybes . map (stripPrefix pre) . words
