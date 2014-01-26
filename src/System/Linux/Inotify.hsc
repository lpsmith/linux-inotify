{-# LANGUAGE ForeignFunctionInterface        #-}
{-# LANGUAGE RecordWildCards, NamedFieldPuns #-}
{-# LANGUAGE BangPatterns, DoAndIfThenElse   #-}
{-# LANGUAGE EmptyDataDecls                  #-}
{-# LANGUAGE DeriveDataTypeable              #-}

module System.Linux.Inotify
     ( Inotify
     , Event(..)
     , Watch(..)
     , Mask(..)
     , isect
     , isSubset
     , hasOverlap
     , WatchFlag
     , EventFlag
     , Cookie(..)
     , init
     , initWith
     , InotifyOptions(..)
     , defaultInotifyOptions
     , addWatch
     , addWatch_
     , rmWatch
     , getEvent
     , getEventNonBlocking
     , getEventFromBuffer
     , peekEvent
     , peekEventNonBlocking
     , peekEventFromBuffer
     , close
     , in_ACCESS
     , in_ATTRIB
     , in_CLOSE
     , in_CLOSE_WRITE
     , in_CLOSE_NOWRITE
     , in_CREATE
     , in_DELETE
     , in_DELETE_SELF
     , in_MODIFY
     , in_MOVE_SELF
     , in_MOVE
     , in_MOVED_FROM
     , in_MOVED_TO
     , in_OPEN
     , in_ALL_EVENTS
     , in_DONT_FOLLOW
     , in_EXCL_UNLINK
     , in_MASK_ADD
     , in_ONESHOT
     , in_ONLYDIR
     , in_IGNORED
     , in_ISDIR
     , in_Q_OVERFLOW
     , in_UNMOUNT
     ) where

#include "unistd.h"
#include "sys/inotify.h"

import Prelude hiding (init)

import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as B8
import Control.Applicative
import Data.Monoid
import Data.Typeable
import Data.Function ( on )
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
    , bufSize  :: {-# UNPACK #-} !Int
    , startRef :: !(IORef Int)
    , endRef   :: !(IORef Int)
    } deriving (Eq, Typeable)

instance Show Inotify where
    show Inotify{fd} = "Inotify { fd = " ++ show fd ++ " }"

instance Ord  Inotify where
    compare = compare `on` fd

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

newtype Watch = Watch CInt deriving (Eq, Ord, Show, Typeable)

-- | Represents the mask,  which in inotify terminology is a union
--   of flags that are used when setting up watches and receiving
--   event notifications.
--
--   The type parameter is a phantom type that tracks whether
--   a particular flag is used to set up a watch ('WatchFlag') or
--   when receiving an event. ('EventFlag')   Polymorphic
--   parameters mean that the flag may appear in either context.

newtype Mask a = Mask CUInt deriving (Eq, Show, Typeable)

-- | Computes the union of two 'Mask's.
instance Monoid (Mask a) where
   mempty = Mask 0
   mappend (Mask a) (Mask b) = Mask (a .|. b)

-- | An empty type used to denote 'Mask' values that can be received
--   from the kernel in an inotify event message.
data EventFlag

-- | An empty type used to denote 'Mask' values that can be sent to
--   the kernel when setting up an inotify watch.
data WatchFlag

isect :: Mask a -> Mask a -> Mask a
isect (Mask a) (Mask b) = Mask (a .&. b)

hasOverlap :: Mask a -> Mask a -> Bool
hasOverlap a b = isect a b /= Mask 0

isSubset :: Mask a -> Mask a -> Bool
isSubset a b = isect a b == a


-- | File was accessed.  Includes the files of a watched directory.
in_ACCESS :: Mask a
in_ACCESS = Mask (#const IN_ACCESS)

-- | Metadata changed, e.g., permissions,  timestamps, extended  attributes,
--   link  count  (since  Linux 2.6.25), UID, GID, etc.  Includes the files of
--   a watched directory.
in_ATTRIB :: Mask a
in_ATTRIB = Mask (#const IN_ATTRIB)

-- | File was closed.  This is not a separate flag, but a convenience definition
--   such that  'in_CLOSE' '==' 'in_CLOSE_WRITE' '<>' 'in_CLOSE_NOWRITE'
in_CLOSE :: Mask a
in_CLOSE = Mask (#const IN_CLOSE)

-- | File opened for writing was closed.   Includes the files of a watched
--   directory.
in_CLOSE_WRITE :: Mask a
in_CLOSE_WRITE = Mask (#const IN_CLOSE_WRITE)

-- | File not opened for writing was closed.  Includes the files of a watched
--   directory.
in_CLOSE_NOWRITE :: Mask a
in_CLOSE_NOWRITE = Mask (#const IN_CLOSE_NOWRITE)

-- | File/directory created in watched directory.
in_CREATE :: Mask a
in_CREATE = Mask (#const IN_CREATE)

-- | File/directory  deleted  from  watched  directory.
in_DELETE :: Mask a
in_DELETE = Mask (#const IN_DELETE)

-- | Watched file/directory was itself deleted.
in_DELETE_SELF :: Mask a
in_DELETE_SELF = Mask (#const IN_DELETE_SELF)

-- | File was modified.  Includes the files of a watched
--   directory.
in_MODIFY :: Mask a
in_MODIFY = Mask (#const IN_MODIFY)

-- | Watched file/directory was itself moved.
in_MOVE_SELF :: Mask a
in_MOVE_SELF = Mask (#const IN_MOVE_SELF)

-- | File was moved.  This is not a separate flag, but a convenience definition
--   such that  'in_MOVE' '==' 'in_MOVED_FROM' '<>' 'in_MOVED_TO'.
in_MOVE :: Mask a
in_MOVE = Mask (#const IN_MOVE)

-- | File moved out of watched directory. Includes the files of a watched
--   directory.
in_MOVED_FROM :: Mask a
in_MOVED_FROM = Mask (#const IN_MOVED_FROM)

-- | File moved into watched directory. Includes the files of a watched
--   directory.
in_MOVED_TO :: Mask a
in_MOVED_TO = Mask (#const IN_MOVED_TO)

-- | File was opened.  Includes the files of a watched
--   directory.
in_OPEN :: Mask a
in_OPEN = Mask (#const IN_OPEN)

-- | A union of all flags above;  this is not a separate flag but a convenience
--   definition.
in_ALL_EVENTS :: Mask a
in_ALL_EVENTS = Mask (#const IN_OPEN)

-- | (since Linux 2.6.15) Don't  dereference  pathname  if it is a symbolic link.
in_DONT_FOLLOW :: Mask WatchFlag
in_DONT_FOLLOW = Mask (#const IN_DONT_FOLLOW)

-- | (since Linux 2.6.36)
--      By default, when watching events on the  children
--      of a directory, events are generated for children
--      even after  they  have  been  unlinked  from  the
--      directory.   This  can result in large numbers of
--      uninteresting events for some applications (e.g.,
--      if watching /tmp, in which many applications create
--      temporary files whose names  are  immediately
--      unlinked).  Specifying IN_EXCL_UNLINK changes the
--      default behavior, so that events are  not  generated
--      for  children after they have been unlinked
--      from the watched directory.
in_EXCL_UNLINK :: Mask WatchFlag
in_EXCL_UNLINK = Mask (#const IN_EXCL_UNLINK)

-- | Add (OR) events to watch mask for  this  pathname
--   if it already exists (instead of replacing mask).
in_MASK_ADD :: Mask WatchFlag
in_MASK_ADD = Mask (#const IN_MASK_ADD)

-- | Monitor pathname for one event, then remove from watch list.
in_ONESHOT :: Mask WatchFlag
in_ONESHOT = Mask (#const IN_ONESHOT)

-- | (since Linux 2.6.15) Only watch pathname if it is a directory.
in_ONLYDIR :: Mask WatchFlag
in_ONLYDIR = Mask (#const IN_ONLYDIR)

-- | Watch was removed explicitly ('rmWatch') or automatically
--   (file was deleted, or file system was unmounted).
in_IGNORED :: Mask EventFlag
in_IGNORED = Mask (#const IN_IGNORED)

-- | Subject of this event is a directory.
in_ISDIR :: Mask EventFlag
in_ISDIR = Mask (#const IN_ISDIR)

-- | Event queue overflowed (wd is -1 for this event).
in_Q_OVERFLOW :: Mask EventFlag
in_Q_OVERFLOW = Mask (#const IN_Q_OVERFLOW)

-- | File system containing watched object was unmounted.
in_UNMOUNT :: Mask EventFlag
in_UNMOUNT = Mask (#const IN_UNMOUNT)


newtype Cookie = Cookie CUInt deriving (Eq, Ord, Show, Typeable)

data Event = Event
   { wd     :: {-# UNPACK #-} !Watch
   , mask   :: {-# UNPACK #-} !(Mask EventFlag)
   , cookie :: {-# UNPACK #-} !Cookie
   , name   :: {-# UNPACK #-} !B.ByteString
      -- ^ The proper interpretation of this seems to be to use
      -- 'GHC.IO.getForeignEncoding' and then unpack it to a String
      -- or decode it using the text package.
   } deriving (Eq, Show, Typeable)

#if __GLASGOW_HASKELL__ < 706
-- | Workaround for bug in 'FC.newForeignPtr' before base 4.6.  Ensure the
-- finalizer is only run once.  See GHC ticket #7170
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
init = initWith defaultInotifyOptions

newtype InotifyOptions = InotifyOptions { bufferSize :: Int }

defaultInotifyOptions :: InotifyOptions
defaultInotifyOptions = InotifyOptions { bufferSize = 2048 }

initWith :: InotifyOptions -> IO Inotify
initWith InotifyOptions{..} = do
    fd <- Fd <$> throwErrnoIfMinus1 "System.Linux.Inotify.initWith"
                   (c_inotify_init1 flags)
    let bufSize = bufferSize
    buffer   <- mallocForeignPtrBytes bufSize
    addFinalizerOnce buffer (closeFdWith closeFd fd)
    startRef <- newIORef 0
    endRef   <- newIORef 0
    return $! Inotify{..}
  where flags = (#const IN_NONBLOCK) .|. (#const IN_CLOEXEC)

-- | Adds a watch on the inotify descriptor,  returns a watch descriptor.
-- This function is thread safe.

addWatch :: Inotify -> FilePath -> Mask WatchFlag -> IO Watch
addWatch Inotify{fd} path !mask =
    withCString path $ \cpath -> do
      Watch <$> throwErrnoPathIfMinus1 "System.Linux.Inotify.addWatch" path
                  (c_inotify_add_watch fd cpath mask)

-- | A variant of 'addWatch' that operates on a 'RawFilePath', which is
-- a file path represented as strict 'ByteString'.   One weakness of the
-- current implementation is that if 'addWatch_' throws an 'IOException',
-- then any unicode paths will be mangled in the error message.

addWatch_ :: Inotify -> RawFilePath -> Mask WatchFlag -> IO Watch
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
      then return ()
      else throwErrno "System.Linux.Inotify.rmWatch"

{--
-- | Stops watching a path for changes.  This version throws an exception
--   on @EINVAL@,  so it is not ok to delete a non-existant watch
--   descriptor.   Therefore this function is not thread safe,  even
--   if it's only ever called from a single thread.
--
--   The problem is that in some cases the kernel will automatically
--   delete a watch descriptor.  Although the kernel generates an
--   @IN_IGNORED@ event whenever a descriptor is deleted,  it's
--   possible that using @rmWatch'@ and @getEvent@ in different threads
--   would delete the descriptor after the kernel has delivered the
--   @IN_IGNORED@ event but before your application has acted on the
--   message.
--
--   It may not even be safe to call this function from the thread
--   that is calling @getEvent@.  I need to investigate whether or
--   not the kernel would return @EINVAL@ on a descriptor before
--   the @IN_IGNORED@ message has been delivered to your application.
--   This would make rmWatch' somewhat safer in the presence of threads,
--   but the application would still have to ensure that all delivered
--   events are processed before rmWatch' is called.

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
    fillBufferBlocking inotify "System.Linux.Inotify.getEvent"
    evt <- peekMessage inotify
    consumeMessage inotify
    return evt

-- | Returns an inotify event,  blocking until one is available.
--
--   If this returns an event, then the next read from the inotify
--   descriptor will return the same event and the second read will not
--   result in a system call.
--
--   It is not safe to call this function from multiple threads at the same
--   time.  Though this could be fixed,  I do not see why it would be useful.

peekEvent :: Inotify -> IO Event
peekEvent inotify@Inotify{..} = do
    fillBufferBlocking inotify "System.Linux.Inotify.peekEvent"
    peekMessage inotify

hasEmptyBuffer :: Inotify -> IO Bool
hasEmptyBuffer Inotify{..} = do
    start <- readIORef startRef
    end   <- readIORef endRef
    return $! (start >= end)
{-# INLINE hasEmptyBuffer #-}

fillBuffer :: Inotify -> a -> (Errno -> IO a) -> IO a
fillBuffer Inotify{..} val errorHandler = do
    let !ptr = Unsafe.unsafeForeignPtrToPtr buffer
    numBytes <- c_unsafe_read fd ptr (fromIntegral bufSize)
    if numBytes == -1
    then getErrno >>= errorHandler
    else do
        writeIORef startRef 0
        writeIORef endRef (fromIntegral numBytes)
        return val
{-# INLINE fillBuffer #-}

fillBufferBlocking :: Inotify -> String -> IO ()
fillBufferBlocking inotify@Inotify{..} funcName = do
    isEmpty <- hasEmptyBuffer inotify
    when isEmpty loop
  where
    loop = do
      threadWaitRead fd
      fillBuffer inotify () $ \err -> do
          if err == eINTR || err == eAGAIN || err == eWOULDBLOCK
          then loop
          else throwErrno funcName

fillBufferNonBlocking :: Inotify -> String -> IO Bool
fillBufferNonBlocking inotify@Inotify{..} funcName = do
    isEmpty <- hasEmptyBuffer inotify
    if isEmpty
    then loop
    else return False
  where
    loop = do
      fillBuffer inotify False $ \err -> do
          if err == eAGAIN || err == eWOULDBLOCK
          then return True
          else if err == eINTR
               then loop
               else throwErrno funcName

peekMessage :: Inotify -> IO Event
peekMessage Inotify{..} = do
  start  <- readIORef startRef
  let ptr = Unsafe.unsafeForeignPtrToPtr buffer `plusPtr` start
  wd     <- Watch  <$> ((#peek struct inotify_event, wd    ) ptr :: IO CInt)
  mask   <- Mask   <$> ((#peek struct inotify_event, mask  ) ptr :: IO CUInt)
  cookie <- Cookie <$> ((#peek struct inotify_event, cookie) ptr :: IO CUInt)
  len    <-            ((#peek struct inotify_event, len   ) ptr :: IO CUInt)
  name <- if len == 0
            then return B.empty
            else B.packCString ((#ptr struct inotify_event, name) ptr)
  return $! Event{..}
{-# INLINE peekMessage #-}

consumeMessage :: Inotify -> IO ()
consumeMessage Inotify{..} = do
  start <- readIORef startRef
  let ptr = Unsafe.unsafeForeignPtrToPtr buffer `plusPtr` start
  len   <- ((#peek struct inotify_event, len   ) ptr :: IO CUInt)
  writeIORef endRef $! start + (#size struct inotify_event) + fromIntegral len
{-# INLINE consumeMessage #-}

-- | Returns an inotify event only if one is immediately available.
--
--   One possible downside of the current implementation is that
--   returning 'Nothing' necessarily results in a system call.

getEventNonBlocking :: Inotify -> IO (Maybe Event)
getEventNonBlocking inotify@Inotify{..} = do
    isEmpty <- fillBufferNonBlocking inotify funcName
    if isEmpty
    then return Nothing
    else do
      evt <- peekMessage inotify
      consumeMessage inotify
      return $! Just evt
  where
    funcName = "System.Linux.Inotify.getEventNonBlocking"

-- | Returns an inotify event only if one is immediately available.
--
--   If this returns an event, then the next read from the inotify
--   descriptor will return the same event and the second read will
--   not result in a system call.
--
--   One possible downside of the current implementation is that
--   returning 'Nothing' necessarily results in a system call.

peekEventNonBlocking :: Inotify -> IO (Maybe Event)
peekEventNonBlocking inotify@Inotify{..} = do
    isEmpty <- fillBufferNonBlocking inotify funcName
    if isEmpty
    then return Nothing
    else do
      evt <- peekMessage inotify
      return $! Just evt
  where
    funcName = "System.Linux.Inotify.peekEventNonBlocking"

-- | Returns an inotify event only if one is available in 'Inotify's
--   buffer.  This won't ever make a system call.

getEventFromBuffer :: Inotify -> IO (Maybe Event)
getEventFromBuffer inotify = do
    isEmpty <- hasEmptyBuffer inotify
    if isEmpty
    then return Nothing
    else do
       evt <- peekMessage inotify
       consumeMessage inotify
       return $! Just evt

-- | Returns an inotify event only if one is available in 'Inotify's
--   buffer.  This won't ever make a system call.
--
--   If this returns an event, then the next read from the inotify
--   descriptor will return the same event and the second read will not
--   result in a system call.

peekEventFromBuffer :: Inotify -> IO (Maybe Event)
peekEventFromBuffer inotify@Inotify{..} = do
    isEmpty <- hasEmptyBuffer inotify
    if isEmpty
    then return Nothing
    else do
       evt <- peekMessage inotify
       return $! Just evt

-- | Closes an inotify descriptor,  freeing the resources associated
-- with it.  This will also raise an 'IOException' in any threads that
-- are blocked on  'getEvent'.
--
-- Although using a descriptor after it is closed is likely to raise
-- an exception,  it is not safe to use the descriptor after it is closed.
-- However,  it is safe to call 'close' multiple times;  this binding
-- ensures that only one system call will be made.
--
-- Descriptors will be closed after they are garbage collected, via
-- a finalizer,  although it is often preferable to call 'close' yourself.

close :: Inotify -> IO ()
close Inotify{buffer} = finalizeForeignPtr buffer

foreign import ccall unsafe "sys/inotify.h inotify_init1"
    c_inotify_init1 :: CInt -> IO CInt

foreign import ccall unsafe "sys/inotify.h inotify_add_watch"
    c_inotify_add_watch :: Fd -> CString -> Mask WatchFlag -> IO CInt

foreign import ccall unsafe "sys/inotify.h inotify_rm_watch"
    c_inotify_rm_watch :: Fd -> Watch -> IO CInt

foreign import ccall unsafe "unistd.h read"
    c_unsafe_read :: Fd -> Ptr CChar -> CSize -> IO CSsize
