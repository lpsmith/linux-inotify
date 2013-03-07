{-# LANGUAGE ForeignFunctionInterface        #-}
{-# LANGUAGE RecordWildCards, NamedFieldPuns #-}
{-# LANGUAGE BangPatterns, DoAndIfThenElse   #-}

module System.Linux.Inotify
     ( Inotify
     , Watch(..)
     , EventMask(..)
     , Cookie
     , Event(..)
     , init
     , addWatch
     , addWatch_
     , rmWatch
     , getEvent
     , getEventNonBlocking
     , getEventFromBuffer
     , close
     , in_ACCESS
     , in_ATTRIB
     , in_CLOSE_WRITE
     , in_CLOSE_NOWRITE
     , in_CREATE
     , in_DELETE
     , in_DELETE_SELF
     , in_MODIFY
     , in_MOVE_SELF
     , in_MOVED_FROM
     , in_MOVED_TO
     , in_OPEN
     ) where

#include "unistd.h"
#include "sys/inotify.h"

import Prelude hiding (init)

import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as B8
import Control.Applicative
import Data.Monoid
import Control.Concurrent ( threadWaitRead )
import GHC.Conc ( closeFdWith )
#if __GLASGOW_HASKELL__ < 706
import Control.Concurrent.MVar
#endif
import Control.Monad
import System.Posix
import Data.IORef
#if __GLASGOW_HASKELL__ >= 702
import Foreign
import qualified Foreign.ForeignPtr.Unsafe as Unsafe
#else
import Foreign as Unsafe
#endif
import Foreign.C
import qualified Foreign.Concurrent as FC
import System.Posix.ByteString.FilePath (RawFilePath)

data Inotify = Inotify
    { fd       :: {-# UNPACK #-} !Fd
    , buffer   :: {-# UNPACK #-} !(ForeignPtr CChar)
    , startRef :: !(IORef Int)
    , endRef   :: !(IORef Int)
    } deriving (Eq)

bufferSize :: Int
bufferSize = 4096

{-
-- I'm tempted to define 'Watch' as

data Watch = Watch
    { fd :: {-# UNPACK #-} !Fd
    , wd :: {-# UNPACK #-} !CInt
    }

-- and then give rmWatch the type

rmWatch :: Watch -> IO ()

-- An advantage would be that it would make the API possibly
-- easier to use,  and harder to misuse.   A disadvantage is
-- that this is a slightly thicker wrapper around the system calls,
-- and that storing Watches in Maps would be less efficient, at least
-- somewhat.
-}

newtype Watch = Watch CInt deriving (Eq, Ord, Show)

newtype EventMask = EventMask CUInt deriving (Eq, Show)

instance Monoid EventMask where
   mempty = EventMask 0
   mappend (EventMask a) (EventMask b) = EventMask (a .|. b)

in_ACCESS :: EventMask
in_ACCESS = EventMask (#const IN_ACCESS)
in_ATTRIB :: EventMask
in_ATTRIB = EventMask (#const IN_ATTRIB)
in_CLOSE_WRITE :: EventMask
in_CLOSE_WRITE = EventMask (#const IN_CLOSE_WRITE)
in_CLOSE_NOWRITE :: EventMask
in_CLOSE_NOWRITE = EventMask (#const IN_CLOSE_NOWRITE)
in_CREATE :: EventMask
in_CREATE = EventMask (#const IN_CREATE)
in_DELETE :: EventMask
in_DELETE = EventMask (#const IN_DELETE)
in_DELETE_SELF :: EventMask
in_DELETE_SELF = EventMask (#const IN_DELETE_SELF)
in_MODIFY :: EventMask
in_MODIFY = EventMask (#const IN_MODIFY)
in_MOVE_SELF :: EventMask
in_MOVE_SELF = EventMask (#const IN_MOVE_SELF)
in_MOVED_FROM :: EventMask
in_MOVED_FROM = EventMask (#const IN_MOVED_FROM)
in_MOVED_TO :: EventMask
in_MOVED_TO = EventMask (#const IN_MOVED_TO)
in_OPEN :: EventMask
in_OPEN = EventMask (#const IN_OPEN)


type Cookie = CUInt

data Event = Event
   { wd     :: {-# UNPACK #-} !Watch
   , mask   :: {-# UNPACK #-} !EventMask
   , cookie :: {-# UNPACK #-} !Cookie
   , name   :: {-# UNPACK #-} !B.ByteString
   } deriving (Show)

#if __GLASGOW_HASKELL__ < 706
-- | Workaround for bug in 'FC.newForeignPtr' before base 4.6.  Ensure the
-- finalizer is only run once, to prevent a segfault.  See GHC ticket #7170
--
-- Note that 'getvalue' and 'maybeBsFromForeignPtr' do not need this
-- workaround, since their finalizers are just 'touchForeignPtr' calls.
addFinalizerOnce :: ForeignPtr a -> IO () -> IO ()
addFinalizerOnce ptr fin = do
    mv <- newMVar fin
    FC.addForeignPtrFinalizer ptr $ tryTakeMVar mv >>= maybe (return ()) id
#else
addFinalizerOnce :: ForeignPtr a -> IO () -> IO ()
addFinalizerOnce = FC.addForeignPtrFinalizer
#endif

-- | Creates an inotify socket descriptor that watches can be
-- added to and events can be read from.

init :: IO Inotify
init = do
    fd <- Fd <$> throwErrnoIfMinus1 "System.Linux.Inotify.init"
                   (c_inotify_init1 flags)
    buffer   <- mallocForeignPtrBytes bufferSize
    addFinalizerOnce buffer (closeFdWith closeFd fd)
    startRef <- newIORef 0
    endRef   <- newIORef 0
    return $! Inotify{..}
  where flags = (#const IN_NONBLOCK) .|. (#const IN_CLOEXEC)

-- | Adds a watch on the inotify descriptor,  returns a watch descriptor.
-- This function is thread safe.

addWatch :: Inotify -> FilePath -> EventMask -> IO Watch
addWatch Inotify{fd} path !mask =
    withCString path $ \cpath -> do
      Watch <$> throwErrnoPathIfMinus1 "System.Linux.Inotify.addWatch" path
                  (c_inotify_add_watch fd cpath mask)

-- | A variant of 'addWatch' that operates on a 'RawFilePath', which is
-- a file path represented as strict 'ByteString'.   One weakness of the
-- current implementation is that if 'addWatch_' throws an 'IOException',
-- then any unicode paths will be mangled in the error message.

addWatch_ :: Inotify -> RawFilePath -> EventMask -> IO Watch
addWatch_ Inotify{fd} path !mask =
    B.useAsCString path $ \cpath -> do
      Watch <$> throwErrnoPathIfMinus1 "System.Linux.Inotify.addWatch_"
                                         (B8.unpack path)
                  (c_inotify_add_watch fd cpath mask)


-- | Stops watching a path for changes.  This watch descriptor must be
--   associated with the particular inotify port,  otherwise undefined
--   behavior can happen.
--
--   This function is thread safe. This binding ignores @inotify_rm_watch@'s
--   errno when it is @EINVAL@, so it is ok to delete a previously
--   removed or non-existent watch descriptor.
--
--   However long lived applications that set and remove many watches
--   should still endeavor to avoid calling `rmWatch` on removed
--   watch descriptors,  due to possible wrap-around bugs.

--   The (small) downside to this behavior is that it also ignores the
--   case when,  for some slightly strange reason, 'rmWatch' is called
--   on a file descriptor that is not an inotify descriptor.
--   Unfortunately @inotify_rm_watch@ does not provide any way to
--   distinguish these cases.
--
--   Haskell's type system should prevent this from happening in almost
--   all cases,  but it could be possible in wrap-around situations
--   when you use an inotify descriptor after you have closed it.  But
--   then you deserve (at least some of) what you get anyway.

rmWatch :: Inotify -> Watch -> IO ()
rmWatch Inotify{fd} !wd = do
    res <- c_inotify_rm_watch fd wd
    when (res == -1) $ do
      err <- getErrno
      if err == eINVAL
      then resetErrno
      else throwErrno "System.Linux.Inotify.rmWatch"

{--
-- | Stops watching a path for changes.  This version throws an exception
--   on @EINVAL@,  so it is not ok to delete a non-existant watch
--   descriptor.   Therefore this function is not thread safe.
--
--   The problem is that in some cases the kernel will automatically
--   delete a watch descriptor.  Although the kernel generates an
--   @IN_IGNORED@ event whenever a descriptor is deleted,  it's
--   possible that multi-threaded use would delete the descriptor after
--   the kernel has deleted it but before your application has acted
--   on the message.
--
--   It may not even be safe to call this function from the thread
--   that is calling @getEvent@.  I need to investigate whether or
--   not the kernel would delete the descriptor before the @IN_IGNORED@
--   message has been delivered to your application.

rmWatch' :: Inotify -> Watch -> IO ()
rmWatch' (Inotify (Fd !fd)) (Watch !wd) = do
    throwErrnoIfMinus1_ "System.Linux.Inotify.rmWatch'" $
      c_inotify_rm_watch fd wd
--}

-- | Returns an inotify event,  blocking until one is available.
--
--   It is not safe to call this function from multiple threads at the same
--   time.  Though this could be fixed,  I do not see why it would be useful.

getEvent :: Inotify -> IO Event
getEvent inotify@Inotify{..} = do
    start <- readIORef startRef
    end   <- readIORef endRef
    if start >= end
    then do
      threadWaitRead fd
      let !ptr = Unsafe.unsafeForeignPtrToPtr buffer
      numBytes <- c_unsafe_read fd ptr (fromIntegral bufferSize)
      if numBytes == -1
      then do
        err <- getErrno
        if err == eINTR || err == eAGAIN || err == eWOULDBLOCK
        then getEvent inotify
        else throwErrno "System.Linux.Inotify.getEvent"
      else do
        writeIORef endRef (fromIntegral numBytes)
        readMessage 0 inotify
    else do
      readMessage start inotify

readMessage :: Int -> Inotify -> IO Event
readMessage start Inotify{..} = do
  let ptr = Unsafe.unsafeForeignPtrToPtr buffer `plusPtr` start
  wd     <- Watch     <$> ((#peek struct inotify_event, wd    ) ptr :: IO CInt)
  mask   <- EventMask <$> ((#peek struct inotify_event, mask  ) ptr :: IO CUInt)
  cookie <-               ((#peek struct inotify_event, cookie) ptr :: IO CUInt)
  len_   <-               ((#peek struct inotify_event, len   ) ptr :: IO CUInt)
  let len = fromIntegral len_
  name <- if len == 0
            then return B.empty
            else B.packCString ((#ptr struct inotify_event, name) ptr)
  writeIORef startRef $! (start + (#size struct inotify_event) + len)
  return $! Event{..}


-- | Returns an inotify event only if one is immediately available.
--
--   One possible downside of the current implementation is that
--   returning 'Nothing' necessarily results in a system call.

getEventNonBlocking :: Inotify -> IO (Maybe Event)
getEventNonBlocking inotify@Inotify{..} = do
    start <- readIORef startRef
    end   <- readIORef endRef
    if start >= end
    then do
      let !ptr = Unsafe.unsafeForeignPtrToPtr buffer
      numBytes <- c_unsafe_read fd ptr (fromIntegral bufferSize)
      if numBytes == -1
      then do
        err <- getErrno
        if err == eAGAIN || err == eWOULDBLOCK
        then return Nothing
        else if err == eINTR
             then getEventNonBlocking inotify
             else throwErrno "System.Linux.Inotify.getEventNonBlocking"
      else do
        writeIORef endRef (fromIntegral numBytes)
        Just <$> readMessage 0 inotify
    else do
      Just <$> readMessage start inotify


-- | Returns an inotify event only if one is available in 'Inotify's
--   buffer.  This won't ever make a system call.

getEventFromBuffer :: Inotify -> IO (Maybe Event)
getEventFromBuffer inotify@Inotify{..} = do
    start <- readIORef startRef
    end   <- readIORef endRef
    if start >= end
    then return Nothing
    else Just <$> readMessage start inotify


-- | Closes an inotify descriptor,  freeing the resources associated
-- with it.  This will also raise an 'IOException' in any threads that
-- are blocked on  'getEvent'.
--
-- Although using a descriptor after it is closed is likely to raise
-- an exception,  it is not safe to use the descriptor after it is closed.
-- However,  it is safe to call 'close' multiple times.
--
-- Descriptors will be closed after they are garbage collected, via
-- a finalizer,  although it is often preferable to call 'close' yourself.

close :: Inotify -> IO ()
close Inotify{buffer} = finalizeForeignPtr buffer

foreign import ccall unsafe "sys/inotify.h inotify_init1"
    c_inotify_init1 :: CInt -> IO CInt

foreign import ccall unsafe "sys/inotify.h inotify_add_watch"
    c_inotify_add_watch :: Fd -> CString -> EventMask -> IO CInt

foreign import ccall unsafe "sys/inotify.h inotify_rm_watch"
    c_inotify_rm_watch :: Fd -> Watch -> IO CInt

foreign import ccall unsafe "unistd.h read"
    c_unsafe_read :: Fd -> Ptr CChar -> CSize -> IO CSsize
