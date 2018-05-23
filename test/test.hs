module Main where

import System.Environment
import System.Exit
import Prelude hiding (reverse, log)
import qualified System.Linux.Inotify as IN
import Data.Monoid(mconcat)
import Control.Monad(forever)
import Control.Exception(bracket)
import GHC.Conc.Sync(ThreadId)
import Data.IORef (IORef, newIORef, atomicModifyIORef', readIORef)
import System.Posix.Signals(installHandler, Handler(Catch), sigINT, sigTERM, raiseSignal)
import Control.Concurrent(forkIO, threadDelay)
import Control.Concurrent.MVar(newEmptyMVar, takeMVar, putMVar, MVar)

log :: String -> IO()
log x = putStrLn $ "[linux-inotify]: " ++ x

events :: IN.Mask a
events = mconcat [IN.in_MODIFY]

initFileReload :: IORef Int -> String -> IO ThreadId
initFileReload counter dir = do
  forkIO.bracket IN.init IN.close $ \ind -> do
    _ <- IN.addWatch ind dir events
    forever $ do
      e <- IN.getEvent ind
      log $ show e
      atomicModifyIORef' counter (\n -> (n + 1, ()))

testFileWrite :: String -> IO ()
testFileWrite path = do
  writeFile path "test"
  log "Test writing to file"
  threadDelay $ 1
  raiseSignal sigINT
  -- sigTERM will not be caught :/

handler :: MVar () -> IO ()
handler s_interrupted =
  putMVar s_interrupted ()

recvFunction :: IORef Int -> MVar () -> IO ()
recvFunction counter signal = do
  output <- takeMVar signal
  n <- readIORef counter
  log $ "Interrupt Received. Stopping watcher" ++ show n
  if n == 1
     then exitSuccess
     else exitFailure

main:: IO()
main = do
    -- [file] <- getArgs
    -- https://github.com/haskell/cabal/issues/4643
    let file = "test/test.json"
    counter <- newIORef 0
    log $ "watching file: " ++ file
    _ <- initFileReload counter file
    testFileWrite file
    s_interrupted <- newEmptyMVar
    installHandler sigTERM (Catch $ handler s_interrupted) Nothing
    installHandler sigINT (Catch $ handler s_interrupted) Nothing
    recvFunction counter s_interrupted
