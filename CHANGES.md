Version 0.3.0.0:  (2015-11-20)
  * Use-after-close now result in exceptions rather than undefined behavior.

  * All functions are now (intended to be) thread-safe.

  * Masked async exceptions during a buffer fill,  which could otherwise
    have resulted in losing an entire buffer of events.   In particularly
    unlucky cases, it might have been possible that futher use of the buffer
    could have resulted in memory faults.

  * Masked async exceptions when closing a descriptor,  which could otherwise
    have resulted in leaking an inotify file descriptor.
