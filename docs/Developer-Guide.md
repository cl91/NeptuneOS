# Neptune OS Developer Guide

## Architectural Overview of Neptune OS

The story is that allegedly Windows NT was originally intended to be a microkernel
operating system which comprises of a microkernel that implements basic process and
memory management as well as IPC, and on top of which a "NT Executive" is implemented.
The NT Executive is...

We hope to demonstrate that with modern progress in microkernel design it is possible
to realize the original NT design as an object oriented, message-passing based,
client-server style microkernel OS.

## Source Directory Organization

| Directory		 | Description			   |
| ---------------------  | ------------------------------- |
| public		 | Public headers                  |
| public/crt/inc	 | C Runtime Library headers	   |
| public/ndk/inc	 | NT Client public headers	   |
| public/ddk/inc	 | Device driver public headers	   |
| public/sdk/inc	 | Win32 public headers		   |
| private		 | seL4 root task and stub dlls	   |
| private/ntos		 | NT Executive (root task)  	   |
| private/ntdll		 | Native API stub dll		   |
| private/wdm		 | Device driver interface dll	   |
| base			 | Base native NT clients	   |
| base/smss		 | Session Manager Subsystem	   |
| base/ntcmd             | Native Command Prompt	   |
| drivers                | Device drivers                  |
| drivers/base           | Base device drivers             |
| drivers/base/pnp       | PNP root enumerator             |
| drivers/filesystems    | File system drivers		   |
| ^.../fatfs		 | FAT file system driver	   |
| drivers/input          | Input device drivers            |
| drivers/input/kbdclass | Keyboard class driver           |
| drivers/input/i8042prt | i8042 port driver               |
| drivers/storage        | Storage device drivers          |
| drivers/storage/fdc    | Floppy device driver            |
| win32			 | Win32 Subsystem (native exes)   |
| shell			 | Win32 applications (win32 exes) |

All code that makes seL4 calls and refers to seL4 headers should go under `private`. No code outside `private` can make any seL4 system calls or include any seL4 headers.

All executables and DLLs under `base` and `win32` are native NT clients. Projects under `base` cannot include Win32 headers. Projects under `win32` can (and typically do) include Win32 headers.

All executables and DLLs under `shell` are Win32 applications. Projects under `shell` should not make native NT api calls (although we don't explicitly forbid this).

## NT Executive Components

## Device Driver Interface

### Class, Port, Miniclass, Miniport

Minidrivers: miniclass and miniport drivers

### File System Drivers

Due to the fact that file system drivers run in their separate processes, significant
simplications can be achieved in terms of file system driver writing, especially in
terms of caching and synchronization.

Cache manager: in Windows/ReactOS architecture, file system drivers must work together
with the NT cache manager in the NT Executive in a complicated manner to implement
caching for the system. In Neptune OS the file system drivers act exclusively as
clients to the cache manager. Typically only when the file system driver accesses the
on disk metadata does it need to call the cache manager. It does not need to worry about
handling cached read/write IRPs because those are handled transparently by the Executive.

In particular, on Windows there is a set of so-called "fast-IO" routines that the file
system driver can choose to implement. These fast IO routines are called by the IO manager
to handle the cache-hit cases of IO without building an IRP in order to eliminate the
performance overhead of IRP constructions, and should be implemented as simple calls to the
cache manager to handle the IO (the Windows kernel provides a set of routines beginning
with FsRtl, which stands for file system runtime library, that the file system drivers
are supposed to simply invoke in their fast IO routines). On Neptune OS these fast IO
routines are eliminated completely. The equivalent functions of these fast IO routines
are implemented by the Executive server in a uniform fashion.

Additionally on Windows, the flow of IRPs often goes from the IO manager to the file
system driver, and then gets reflected back to the IO manager, which in turn redirects
the IRP to the file system driver for a second time, typically with some flags adjusted.
This recursive behavior is OK for Windows since drivers run in kernel mode. On a microkernel
operating system such as Neptune OS, this would incur unacceptable performance penalties
and is therefore disallowed. On Neptune OS the flow of IRPs is always uni-directional
and goes from the IO manager in the Executive, to the file system driver, and then to
the underlying secondary disk driver.

Synchronization: in Windows/ReactOS, most file system drivers will need to carefully
guard concurrent write operations in order to maintain consistency of data. Typically
they acquire Executive resources to prevent write operations from proceeding until the
read operations are done (concurrent read operations are allowed). In Neptune OS this
is unnecessary as the Executive ensures this on the server side --- for noncached IO
the server never sends write operations unless all the read operations on that file
are completed.

Similarly, features such as byte-range locks are implemented transparently on the server
side. Client drivers do not need any special code to implement them.

### Driver Porting Guide

Summary of issues mentioned above. Guide to porting drivers from ReactOS and Windows WDM.

#### Low-level Device Drivers

#### File System Drivers

Read IRP:

1. Remove the Executive resources needed to guard concurrent write operations. These are
usually called MainResource and PagingIOResource for user thread requests and paging IO
requests respectively.
2. Remove the code responsible for handling cached read. This is handled transparently
by the Executive.
3. Remove the byte-lock checks. This is handled transparently by the Executive.
4. In general you should simply translate the file offsets into (a series of) low-level
disk offsets, and forward them to the lower driver without, expecting a return. This
minimizes the number of context switches and improves performance.

Windows provides a thread-local variable in the Executive `ETHREAD` object to indicate
the component from which the top level IRP being processed originates. This is typically
used in the recursive IRP flows discussed above. We disallow such recursion of IRP
flows, and therefore do not provide such field and its related functions (`IoGetTopLevelIrp`
and `IoSetTopLevelIrp`).

Fast I/O

Fast I/O is now handled transparently by the Executive. Therefore the fast I/O related
fields in the common FSB header are removed.