# Neptune OS Developer Guide

## Architectural Overview of Neptune OS

The story is that allegedly Windows NT was originally intended to be a microkernel
operating system which comprises of a microkernel that implements basic process and
memory management as well as IPC, and on top of which a "NT Executive" is implemented.
The NT Executive is...

We hope to demonstrate that with modern progress in microkernel design it is possible
to realize the original NT design as a performant, general purpose, object oriented,
message-passing based, client-server style microkernel OS.

### Compatibility with Windows and ReactOS
In theory we should be able to achieve binary compatibility with native Windows
executables provided that our implementation of the NT Native API is sufficiently faithful.

The main obstacle of achieving binary compatibility of kernel drivers is
that many Windows kernel drivers do not follow the standard Windows driver communication
protocol (ie. passing IRPs when you need to call another driver) and instead just pass
pointers around and call into other drivers directly. In Neptune OS unless it's a
driver-minidriver pair we always run "kernel" drivers in their separate processes so it
is not possible to do that.

Explain why complete, line-for-line driver source code compatibility is a non-goal.

## Source Directory Organization

| Directory                 | Description                     |
|---------------------------|---------------------------------|
| public                    | Public headers                  |
| public/crt/inc            | C Runtime Library headers       |
| public/ndk/inc            | NT Client public headers        |
| public/ddk/inc            | Device driver public headers    |
| public/sdk/inc            | Win32 public headers            |
| private                   | seL4 root task and stub dlls    |
| private/ntos              | NT Executive (root task)        |
| private/ntdll             | Native API stub dll             |
| private/wdm               | Device driver interface dll     |
| base                      | Base native NT clients          |
| base/smss                 | Session Manager Subsystem       |
| base/ntcmd                | Native Command Prompt           |
| drivers                   | Device drivers                  |
| drivers/base              | Base device drivers             |
| drivers/base/pnp          | PNP root enumerator             |
| drivers/filesystems       | File system drivers             |
| drivers/filesystems/fatfs | FAT file system driver          |
| drivers/input             | Input device drivers            |
| drivers/input/kbdclass    | Keyboard class driver           |
| drivers/input/i8042prt    | i8042 port driver               |
| drivers/storage           | Storage device drivers          |
| drivers/storage/fdc       | Floppy device driver            |
| win32                     | Win32 Subsystem (native exes)   |
| shell                     | Win32 applications (win32 exes) |

All code that makes seL4 calls and refers to seL4 headers should go under `private`.
No code outside `private` can make any seL4 system calls or include any seL4 headers.

All executables and DLLs under `base` and `win32` are native NT clients. Projects under
`base` cannot include Win32 headers. Projects under `win32` can (and typically do) include
Win32 headers.

All executables and DLLs under `shell` are Win32 applications. Projects under `shell`
should not make native NT api calls (although we don't explicitly forbid this).

## NT Executive Components

## Device Driver Interface
The client-side device driver interface is implemented in `wdm.dll`. The name of the
DLL originally comes from "Windows driver model" which is what Microsoft calls the NT5-era
device driver interfaces. However, since we are not aiming for complete source
compatibility (and also since Windows is a Microsoft trademark) let's pretend that
WDM stands for "Well-organized Driver Model" (thank you ChatGPT for suggesting this
name).

### Class, Port, Miniclass, Miniport

Minidrivers: miniclass and miniport drivers

### File System Drivers

Due to the fact that file system drivers run in their separate processes, significant
simplications can be achieved in terms of file system driver writing, especially in
terms of caching and synchronization. On Windows, file system drivers must work together
with the NT cache manager in the Executive in a complicated dance to implement
caching for the system. The read and write IRP dispatch routines have to handle both
cached IO and uncached IO, with various subtleties that the driver author must take care
of. On Neptune OS this architecture is dramatically simplified: the file system drivers
act exclusively as clients to the cache manager, and do not need to worry about
handling cached read/write IRPs because those are handled transparently by the Executive.
The only role of the read/write IRP dispatch routines of a file system driver on Neptune
OS is to translate file offsets into disk offsets for the on-disk files, typically by
generating a series of associated IRPs in response to the read/write IRP directed to a
file object. When the file system driver needs to access the on-disk metadata, it can call
the cache manager to enable cached access for these in order to increase performance.

The Windows file system driver architecture implies that on Windows/ReactOS, IRPs often
flow from the IO manager to the file system driver, and then get reflected back to the
IO manager, which in turn redirects the IRPs to the file system driver for a second time,
typically with some flags adjusted. This recursive behavior is OK for Windows since drivers
run in kernel mode. On a microkernel operating system such as Neptune OS, this would incur
unacceptable performance penalties due to the number of context switches needed. The
aforementioned design decisions on Neptune OS are chosen precisely in order to minimize
said number of context switches. On Neptune OS, for IO operations initiated by a "userspace"
client, the flow of IRPs is always uni-directional and goes from the IO manager in the
Executive to the file system driver, and then to the underlying storage disk driver.
If the file object being read from or written to has caching enabled, these IRPs will be
examined by the Executive and intercepted and completed immediately if they can be fulfilled
directly from the cached data.

In particular, on Windows there is a set of so-called "fast-IO" routines that are implemented
by the file system runtume library FsRtl (although file system drivers can choose to implement
their own versions of the fast-IO routines, Microsoft recommends that they simply call the FsRtl
routines directly, and most file system drivers follow this recommendation). These fast IO
routines are called by the IO manager to handle the cache-hit cases of IO without calling into
file system-specific code. It should be apparent from above that on Neptune OS the interception
of the IRPs and their fulfillment from the cached data is functionally equivalent to what these
fast IO routines do. On Neptune OS, the boilerplate code for fast IO routines that file system
driver authors need to write on Windows are completely eliminated, and driver authors do not
need to worry about manually enabling fast IO and other fast-IO related businesses, as these
are handled by the system automatically and transparently.

In terms of synchronization, on Windows/ReactOS, most file system drivers will need to
carefully guard concurrent write operations in order to maintain consistency of data.
Typically they acquire Executive resources to prevent write operations from proceeding
until the read operations are done (concurrent read operations are allowed). On Neptune OS
this is unnecessary as the Executive handles this on the server side: the server never sends
write IRPs to a file system driver unless all the relevant read operations on that file have
been completed.

Similarly, features such as byte-range locks are implemented transparently on the server
side. Client drivers do not need any special code to implement them.

### Cache Manager
The cache manager of Neptune OS is designed to ensure consistency and guarantees
up-to-date access of the same on-disk data, even when the data are referenced in
different file objects mapped in different processes. The meaning of this guarantee
is two-fold: for the same file object mapped in different processes, the Neptune OS
cache manager guarantees that all the virtual pages corresponding to the same file
region map to the same physical page containing the file data. Secondly, if (parts
of) two file objects refer to the same on-disk data region, we ensure that the write
operations performed on one file object is seen immediately by all other file objects.
Most importantly, this includes handling the case of caching both an on-disk file
and its underlying volume device object. In this case we guarantee that the data
written to the volume file object is seen immediately by anyone caching the on-disk
file, and vice versa. Additionally, we also guarantee that there is always only one
single copy of the same on-disk data in physical memory, so if an application or driver
enables cached access for both a file (in a FS) and its underlying volume object,
we guarantee that only one single set of physical pages will contain the cached
file data. This guarantee is known as the "no-aliasing" guarantee of the Neptune OS
cache manager.

Note this non-aliasing guarantee applies to both the case where the cluster size of the
file system volume is an integer multiple of PAGE_SIZE (eg. 4K file system cluster size
on an x86 machine), and the case where the cluster size is smaller than one VM page. In
the latter case it is possible that some data belonging to one on-disk file with caching
enabled may be seen by another driver that enabled caching to a different on-disk file.
The Neptune OS cache manager will ensure that reading and writing will never spill over
to the region that does not belong to a file, as long as the driver uses the interfaces
provided by the cache manager to do the reading and writing. It is however, possible that
a malicious driver can access these data if it bypasses the cache manager interfaces.
In this case, the recommended solution is to completely disallow caching for this driver,
or reformat the file system volume with cluster size that is at least one page size.

### Driver Porting Guide

Summary of issues mentioned above. Guide to porting drivers from ReactOS and Windows WDM.

#### General Issues
Header file:
Include `ntddk.h` (under `public/ddk/inc`) as the master header file.

DEVICE_OBJECT.Characteristics has been merged with DEVICE_OBJECT.Flags to form a 64-bit
flag, so replace DEVICE_OBJECT.Characteristics with DEVICE_OBJECT.Flags.

IO Transfer Type:
Elaborate on how our architecture (running drivers in separate address spaces)
changes certain ways in which IO transfer types are implemented.

Unlike Windows and ReactOS, IO transfer types must be set when calling IoCreateDevice,
eg.
```
IoCreateDevice(DriverObject, sizeof(DEVICE_EXTENSION), &DeviceName,
	       FILE_DEVICE_BEEP, DO_BUFFERED_IO, FALSE, &DeviceObject);
```
Manually setting it in `DeviceObject->Flags |= DO_BUFFERED_IO` is incorrect.

You should always call `IoBuildSynchronousFsdRequest`, `IoBuildAsynchronousFsdRequest`,
and `IoBuildDeviceIoControlRequest` if you are generating an IRP within a driver
process and forwarding it to another driver (or yourself). Do NOT build IRPs yourself
as you may get the IO buffer settings wrong.

Sending IRP to itself:
Drivers should generally avoid sending IRPs to device objects created by itself and
should simply call the relevant function directly. This avoids the overhead of allocating
and freeing the IRP. In particular, for IRPs generated within the same driver address
space, the IO transfer type is ignored and NEITHER IO is always assumed. This is
especially important for driver-minidriver pairs since a driver-minidriver pair is
loaded in the same address space, so sending an IRP from the minidriver to the
library driver will always have NEITHER IO as the IO transfer type, regardless of
the flags in the device object or the IOCTL code.

#### Low-level Device Drivers

Synchronization:

KEVENT (only between different threads within the same driver process)
ERESOURCE (removed)

Queuing IRP:
A common pattern in Windows/ReactOS drivers is that the driver will queue an IRP to an
internal queue when IRPs come in faster than they can be processed by the driver. Common
mechanisms include the StartIo routine, device queues, interlocked queues, and cancel-safe
queues. These are generally speaking unnecessary on Neptune OS as the Executive limits
the rate of IRP flows to a driver by setting an upper limit to the incoming driver IRP
buffer. Low-level drivers should generally process IRPs synchronously. If the device is
busy processing the IRP, the device should simply wait till the device finishes. This does
NOT negatively impact system responsiveness since drivers run in their own separate process.
That being said, the StartIo mechanism is still present on Neptune OS in order to make
driver porting easier.

Work items:
In addition to queuing IRPs due to rate limits, it is a common pattern on Windows/ReactOS
for DPCs to queue a lengthy processing task to a system worker thread, which runs at
a lower IRQL. This is also generally speaking unnecessary since DPCs are processed in the
same thread as regular IRPs. That being said, Neptune OS drivers can use work items to run
long tasks that are of lower priority than regular IRP processing.

#### File System Drivers

Concurrency:
Since all IRPs are processed in a single thread unless they are moved to a work queue,
you can remove the KSPIN_LOCK, FAST_MUTEX, or similar locks that protect data structures
that are only accessed by the main IRP processing thread. If you have data structures
that are accessed by the interrupt service thread, or by the worker thread, you DO need
to keep the relevant locks. Otherwise synchronization issues will arise in SMP systems.
However, you should generally avoid queuing IRPs in a work queue as we explained above.

In particular DPCs are processed in the same thread as the IRPs (albeit with a higher
priority), so you do not need any special synchronization considerations for DPCs.

FCB and FILE_OBJECT:
1. For the common FCB header, remove SECTION_OBJECT_POINTERS as it is no longer needed.
   You only need the FsRtl common FCB header.
2. You don't need to initialize or modify FILE_OBJECT::PrivateCacheMap as it has been
   removed.
2. Remove FILE_LOCK and related objects.
3. Remove all ERESOURCE objects.

Read IRP:

1. Remove the Executive resources needed to guard concurrent write operations. These are
usually called MainResource and PagingIOResource for user thread requests and paging IO
requests respectively.
2. Remove the code responsible for handling cached read. This is handled transparently
by the Executive.
3. Remove the byte-lock checks. This is handled transparently by the Executive.
4. In general you should simply translate the file offsets into (a series of) low-level
disk offsets, and forward them to the lower driver without expecting a return. This
minimizes the number of context switches and improves performance.

Windows provides a thread-local variable in the Executive `ETHREAD` object to indicate
the component from which the top level IRP being processed originates. This is typically
used in the recursive IRP flows discussed above. We disallow such recursion of IRP
flows, and therefore do not provide such field and its related functions (`IoGetTopLevelIrp`
and `IoSetTopLevelIrp`).

Fast I/O

Fast I/O is now handled transparently by the Executive. Therefore the fast I/O related
fields in the common FSB header are removed.

Directory Control IRP

The IRP_MN_NOTIFY_CHANGE_DIRECTORY minor code is now handled automatically by the
server. You no longer have to handle this in the file system driver. In the future
this IRP minor code may be reused to report the user request for directory change
notification to the filesystem driver.

Lock User Buffer

User buffers are always locked for IO. You do not need to explicitly lock the user
buffers using MmProbeAndLockPages.

FsRtlEnterFileSystem and FsRtlExitFileSystem

These are no longer needed since drivers run in userspace.

Detecting and Responding to Media Changes in Removable Drives

When detecting media change (usually during processing of Read/Write/DeviceIoctl
IRPs) the driver should complete the IRP either with STATUS_MEDIA_CHANGED or
STATUS_NO_MEDIA_IN_DEVICE. Driver should then mark the relevant device object
with DO_VERIFY_REQUIRED so it knows to complete all future IRPs with STATUS_VERIFY_REQUIRED
(unless the IRP is marked with SL_OVERRIDE_VERIFY_VOLUME explicitly to disable this
logic), until such time that it receives a CHECK_VERIFY Ioctl or VERIFY_VOLUME Fsctl,
at which point it can clear the DO_VERIFY_REQUIRED and proceed with normal IO
proceeding.

Cache Manager API

IoCreateStreamFileObject:
This creates a purely client-side file object that does not have a server-side
counterpart. This is mainly used by the file system drivers so they can access the
on-disk file system metadata using the same cache manager API for ordinary file IO.
When porting, remove the FileObject parameter as it is never used in the ReactOS code
base so we have removed it entirely. On Windows, a non-NULL FileObject allows the
client driver to perform cached IO on file metadata such as the security descriptor
as if it were a file stream. This is not used by any driver in ReactOS so we won't
bother supporting it.

IRP_MJ_READ/IRP_MN_MDL:
The meaning of this combination of IRP major/minor code is largely unchanged from
ReactOS/Windows and indicates that when completing the IO request, the dispatch
routine needs to supply an MDL chain describing the mapped IO buffer. Each MDL in
the MDL chain describes virtually contiguous memory that may or may not be physically
contiguous. This is used mainly by the cache manager and is sent only to the file
system drivers and never to the underlying storage device driver. File system drivers
typically call CcMdlRead to satisfy an MDL READ.

IO transfer types for file system drivers:
Non-network file system drivers typically always use NEITHER IO as the IO transfer
type as these are almost always stacked on top of an underlying storage device. Network
file system drivers and purely in-memory file systems typically use DIRECT IO instead.
The main difference between DIRECT IO and NEITHER IO is that the server will always
allocate an IO buffer for DIRECT IO when initiating the IO, while for NEITHER IO the
allocation of IO buffers may be deferred.

Handling NEITHER IO:
The UserBuffer can be (and will typically always be) NULL. This indicates that the
IO buffer has not yet been allocated when the IO is initiated. What the file system
driver should do in this case is to simply translate the file offset to disk offset
and pass the IRP to the underlying storage driver (or to Cc if it is an MDL IO). The
initiator of the IO (typically the cache manager) will take care of properly mapping
the IO buffers later.

Associated IRPs and BUFFERED_IO:
The Irp::AssociatedIrp union has been dissolved and the IrpCount member has been removed.
Drivers do not need to set it. Counting the number of associated IRPs is done automatically
by the system when forwarding the master IRP. As a consequence, accessing the system
buffer for buffered IO is now done with `Irp->SystemBuffer` rather than
`Irp->AssociatedIrp.SystemBuffer`. Likewise, change `Irp->AssociatedIrp.MasterIrp` to
`Irp->MasterIrp`.

