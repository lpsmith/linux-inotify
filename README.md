This is a binding for GHC 7 to the Linux Kernel's inotify interface,
which provides notifications to applications regarding file system
events,  such as file creation,  modification, deletion,  etc.

`linux-inotify` was motivated by a recent examination of
[fsnotify](https://github.com/mdittmer/hfsnotify) and
[hinotify](https://github.com/kolmodin/hinotify),  and not being
satisfied with the API or implementation details of `hinotify` in
particular.

In contrast to `hinotify`,  which provides similar functionality,
`linux-inotify` is a much thinner binding to the system calls and
message format.   Some of the advantages are:

1.  `linux-notify` provides a plain `getEvent` operator that blocks,
instead of implementing a callback API.

2.  `linux-notify` avoids most of GHC's standard IO handling code,
relying on plain system calls with minimal overhead in Haskell-land.
(It does however,  make good use of GHC's IO manager via nonblocking
inotify sockets and `threadWaitRead`,  so `getEvent` is efficient.)

3.  `linux-notify` does not call `forkIO`, which means less context
switching and scheduling overhead, especially in some contexts.


Some of the downsides are:


1.   `linux-notify` currently requires linux 2.6.28,  even though
`inotify` support debuted in linux 2.6.13.    I would kind of like to
fix this at some point,  but it isn't a personal priority.

2.   `linux-notify` requires GHC 7.0.2 or later,  whereas `hinotify` 
works with many versions of GHC 6.   I have no plans on fixing this.

3.   `linux-notify` is currently just a quick proof of concept.
Documentation is missing.  The API is still in flux and needs
expanding.  I've only performed the most preliminary of smoke tests,
and I haven't done any performance testing.









