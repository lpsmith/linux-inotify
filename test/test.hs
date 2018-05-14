import System.Environment
import Prelude hiding (reverse, log)
import qualified System.Linux.Inotify as IN
import Data.Monoid(mconcat)
import Control.Monad(forever)
import Control.Exception(bracket)
import GHC.Conc.Sync(ThreadId)

log :: String -> IO()
log x = putStrLn $ "[linux-inotify]: " ++ x

events :: IN.Mask a
events = mconcat [IN.in_DELETE, IN.in_MODIFY, IN.in_MOVE, IN.in_CREATE]

initFileReload :: String -> IO ThreadId
initFileReload dir = do
  bracket IN.init IN.close $ \ind -> do
    _ <- IN.addWatch ind dir events
    forever $ do
      e <- IN.getEvent ind
      print e

main:: IO()
main = do
  [x] <- getArgs
  initFileReload x >> log "CLOSE"
