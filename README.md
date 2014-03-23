# waitforpid #

Wait for a (non-child) process' exit using Linux's ``PROC_EVENTS``.
Thanks to the ``CAP_NET_ADMIN`` POSIX capability permitted to the ``waitforpid`` binary, it does not need to be set suid root. 


### Installation ###

You need a Linux kernel having ``CONFIG_PROC_EVENTS`` enabled.
Clone the repository, compile, and install via
```sh
git clone https://github.com/stormc/waitforpid.git
cd waitforpid
make
make install
```
which installs the binary per default to ``/usr/local/sbin/waitforpid`` and sets the required POSIX capability ``CAP_NET_ADMIN`` to 'permitted'. ``DESTDIR`` and ``PREFIX`` parameters to ``make install`` are supported.


### Usage ###

``waitforpid`` requires exactly one command line parameter: the PID of the process whose exit is to be waited for. On its exit, ``waitforpid`` reports the PID, the exit code, and the signal received by the program it has waited for, in a shell-friendly manner:
```sh
> tail -f /dev/null &
  [1] 27080
> waitforpid $! &
  [2] 27082
> fg %1
  [1]  - 27080 running    tail -f /dev/null
> ^C
  PID=27080
  EXITCODE=2
  SIGNAL=17
  [2]  + 27082 done       waitforpid 27080
```
