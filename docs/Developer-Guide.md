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

### Memory manager (Mm)
### Microkernel IPC (Ke)

### Object manager (Ob)

In the Windows/ReactOS design, an object type can implement
the semantics of sub-objecting by defining a parse method,
which parses part of the object path to produce a sub-object.
The object manager recursively invokes the parse method when
when opening an object.

In our design a complication arises due to the fact that we
run the NT Executive in user space. Opening an object may
involve, for instance, queuing an IRP to a driver object and
suspending the Executive service processing for the current
thread. Therefore the "parse" procedure need to take an async
context. On the other hand, for objects that live inside the
NT Executive address space, or for objects that have already
been opened, we need a way to make sure that the "parse"
procedure will never suspend, so that it is safe to call it
when the server does not have an async context in that moment.

The solution we have here is to have two types of "parse"
procedures: one that does not take an async context, and one
that does. The "parse" procedure that does NOT take an async
state is called the parse procedure in our codebase and the
"parse" procedure that DOES take an async state is called the
open procedure. Both take the sub-path being parsed as an
argument and both implement the semantics of sub-objecting.

The parse procedure will typically examine the cached object
database to locate the sub-object given by the sub-path. These
can include the sub-objects that have already been opened (by
the open procedure) or sub-objects that always live locally
(in the address space of the NT Executive). The parse procedure
operates on a global context, meaning that it does not take
a PTHREAD parameter and cannot modify THREAD states.

On the other hand, the open procedure operates on a thread
context, meaning that it takes a PTHREAD parameter and can
modify the THREAD states. The open procedure will typically
queue an IRP or (asynchronously) query an out-of-process
database to find the specified sub-object. In particular,
if the sub-path being parsed is empty, an open procedure can
return a different object type to implement the semantics of
an opened instance of the original object. This is employed
by the IO manager extensively: opening a DEVICE object gives
a FILE object.

The object manager provides two public interfaces,
ObReferenceObjectByName and ObOpenObjectByName, to implement
the notion of looking up an object path and opening an object.
ObReferenceObjectByName only calls the parse procedure, and
always returns the pointer to the original object (such as
a DEVICE object), as opposed to the opened instance (such as
a FILE object). ObOpenObjectByName invokes both the parse
and the open procedures, and assigns a handle to the opened
instance. It therefore must be called with an async context,
whereas ObReferenceObjectByName does not need one. This also
means that an additional semantic difference between the
parse routine and the open routine is that the open routine
expects the opened instance to be assigned a handle after
a successful open (although the open routine itself does not
need to be concerned with handle assignment), while the parse
routine does not expect so. Generally speaking, parsing is
a non-invasive procedure where in case of error, one can simply
throw the parsed object away, while opening is an "invasive"
routine where one must take care of properly closing an opened
instance when one is done with the opened object (or in the
case of an error). This also means that the parse routine
should not increase the reference count of the returned subobject,
while the open routine should increase the reference count of the
returned object, except in the case of reparsing.

The IO subsystem uses the facilities of the object manager
extensively. Since opening a device or a file is inherently
an asynchronous process, the IO subsystem uses a two-step
scheme when opening or creating a file. First, the parse
procedures are invoked on the given path to locate the DEVICE
object to be opened. For a simple DEVICE such as \Device\Beep,
the parse prodecure will essentially be a no-op since the
device does not implement sub-objects. The object manager
then invokes the open procedure of the DEVICE object, which
will yield a FILE_OBJECT, representing an opened instance of
the DEVICE object. The open procedure will then queue the IRP
to the thread calling the NT system service and depending on
whether the open is synchronous or asynchronous, either wait
on the IO completion event or return STATUS_PENDING.

For a more complex device such as a volume object, its parse
procedure will take the remaining path after the device name
(ie. the src\main.c in \Device\Harddisk0\Partition0\src\main.c)
and first invoke the cache manager and see if the file has been
previously opened. If it was previously opened, the cached device
object is returned immediately. Otherwise, the open procedure
is invoked just like the simple case above.

On the other hand, closing an object is always a lazy process.
We simply flag the object for closing and queues the object
closure IRP to the driver process (if it's created by a driver).
The close routine does not wait for the driver's response and
is therefore synchronous. This simplifies the error paths,
especially in an asynchronous function.

All object methods operate with in-process pointers. Assigning
HANDLEs to opened objects is done by the object manager itself.
Open routines do not need to be concered with handle assignment.

#### Reference Counting

### Process manager (Ps)
### IO manager (Io)
#### Cache manager (Cc)
### Configuration manager (Cm)
### Executive objects (Ex)

#### LPC (Local Procedure Call) Port Objects

Built as a thin wrapper over the seL4 endpoint API. Differences from the NT LPC port object API in Windows NT (3.1 till 5.0):

- NtAcceptConnectPort is renamed to NtAcceptPort. NtRequestWaitReplyPort is renamed to NtRequestWaitReceivePort.
- Single threaded synchronous IPC: there is one server communication port for each connection port (rather than one per client), server communication port is created in NtCreatePort rather than NtAcceptPort. To increase throughput and prevent a long running request from blocking other clients, the server is encouraged to create an event object for each connected client, and return pending status for long running requests and signal the event when the request is completed. The client can wait on the event for the completion signal of the request. The result of the request can be delivered in the shared memory or via another call to the server.
- You don't need to call NtCompleteConnectPort as this is automatically done when NtAcceptPort returns success

### Security reference manager (Se)
### Hardware abstraction layer (Hal)
### System loader (Ldr)
### Runtime library (Rtl)

## Device Driver Interface
The client-side device driver interface is implemented in `wdm.dll`. The name of the
DLL originally comes from "Windows driver model" which is what Microsoft calls the NT5-era
device driver interfaces. However, since we are not aiming for complete source
compatibility (and also since Windows is a Microsoft trademark) let's pretend that
WDM stands for "Well-organized Driver Model" (thank you ChatGPT for suggesting this
name).

### Class, Port, Miniclass, Miniport

Minidrivers: miniclass and miniport drivers

Class and filter drivers are loaded in two places: once as a standalone driver in their
own address space, and for each port driver to which the class/filter driver is attached,
the `.sys` image file of the class/driver object is also loaded in the port driver's address
space. During driver initialization, the `DriverEntry` of the class/filter driver is called
once the port driver's `DriverEntry` returns `STATUS_SUCCESS`. The class/filter driver
running inside the port driver process will process IRPs directed at its device objects in
the same process as the port driver. This is done so that passing an IRP from, for instance,
the hard disk class driver to the underlying port driver does not incur any performance
penalties due to context switches. If the class/filter driver creates or manages global
resources, it should do so in the standalone, singleton driver process. The routine
`IoIsSingletonMode` returns `TRUE` if the driver image is loaded in their standalone
address space.

The `AddDevice` routine of the class or filter driver should use the `IoIsSingletonMode`
routine to indicate to the NT Executive whether it wishes to process the IO in its own
standalone process (ie. the singleton mode) or in the driver process of the function
driver. In the former case, the `AddDevice` routine should do nothing and return
`STATUS_SUCCESS` if `IoIsSingletonMode` returns `FALSE`. In the latter case, it should
do so when `IoIsSingletonMode` returns `TRUE`. Failure to do so will lead to two device
objects being registered for one physical device object, one in the standalone process,
one in the function driver process. Although the system does not explicitly forbid this,
it is generally considered an anti-pattern to do so.

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
The only role of the read IRP dispatch routines of a file system driver on Neptune OS is
to translate file offsets into disk offsets for the on-disk files, typically by generating
a series of associated IRPs in response to the read IRP directed to a file object. The role
of the WRITE IRP in a file system driver is even simpler: it only needs to handle appending
to a file, ie. extension of the file size. When the file system driver receives a WRITE IRP,
it simply needs to allocate the required amount of spaces in the file system and inform the
server of the translated offsets, again by generating a series of associated WRITE IRP to
the underlying disk device, which the Executive will intercept. When the file system driver
needs to access file system metadata on the disk, the cache manager will also enable cached
access for them in order to increase performance.

In the Windows/ReactOS file system driver architecture, IRPs often flow from the IO manager
to the file system driver, and then get reflected back to the IO manager, which in turn
redirects the IRPs to the file system driver for a second time, typically with some flags
adjusted. This recursive behavior is OK for Windows since drivers run in kernel mode. On a
microkernel operating system such as Neptune OS, this would incur unacceptable performance
penalties due to the number of context switches needed. The aforementioned design decisions
for Neptune OS file system drivers are chosen precisely in order to minimize said context
switches. On Neptune OS, the flow of IRPs is always uni-directional and goes from the IO
manager in the Executive to the file system driver, and then to the underlying storage disk
driver. If the file object being read from or written to has caching enabled, these IRPs
will be examined by the Executive and intercepted and completed immediately if they can be
fulfilled directly from the cached data.

Despite the architectural differences with Windows/ReactOS, the programming interfaces for
file system drivers on Neptune OS remain largely compatible with those on Windows/ReactOS.
It is our hope that by consulting the Driver Porting Guide below, a programmer familiar
with Windows file system driver writing can comfortably port an existing Windows/ReactOS
file system driver to Neptune OS without much difficulty. In fact, much of the driver porting
work involves deleting code, rather than writing new code, due to the above-mentioned
simplifications of the driver architecture. For instance, on Windows there is a set of
so-called "fast-IO" routines that are implemented by the file system runtume library FsRtl
(although file system drivers can choose to implement their own versions of the fast-IO
routines, Microsoft recommends that they simply call the FsRtl routines directly, and most
file system drivers follow this recommendation). These fast IO routines are called by the
IO manager to handle the cache-hit cases of IO without calling into file system-specific code.
It should be apparent from above that on Neptune OS the interception of the IRPs and their
fulfillment from the cached data is functionally equivalent to what these fast IO routines do.
On Neptune OS, the boilerplate code for fast IO routines that file system driver authors need
to write on Windows are completely eliminated, and driver authors do not need to worry about
manually enabling fast IO and other fast-IO related businesses, as these are handled by the
system automatically and transparently.

Likewise, in terms of synchronization, on Windows/ReactOS most file system drivers will need
to carefully guard concurrent write operations in order to maintain consistency of data.
Typically they acquire Executive resources (a type of read-write lock in the Windows kernel)
to prevent write operations from proceeding until the read operations are done (concurrent
read operations are allowed). On Neptune OS this is completely unnecessary as the WRITE IRPs
are used only for extending a file, and therefore no READ IRPs will be sent for the file
region before the WRITE IRP is completed. When porting from Windows/ReactOS, these Executive
resources and the relevant locking and unlocking calls should therefore be removed (we don't
provide them anyway).

Similarly, features such as byte-range locks are implemented transparently on the server
side. Client drivers do not need any special code to implement them and should remove the
relevant code when porting from Windows/ReactOS.

### Cache Manager
The cache manager of Neptune OS is designed to ensure consistent cached access for the
file system and block device data for both "userspace" NT clients and file system drivers.
This works across process boundary: for the same file object mapped in different processes,
the Neptune OS cache manager guarantees that all virtual pages corresponding to the same
file region map to the same physical page containing the file data. When the client driver
writes to a cached file region, it sends the server a notification about the dirty pages.
Server then updates the dirty status in the cache map, and flushes the caches appropriately.
For file sections mapped in a NT client process, the server will query the dirty bit in
the page directory to determine the dirty status when flushing the cache.

The NT system service `NtFlushBuffersFile` can be used to initiate a cache flush explicitly.
It is important to note that `NtFlushBuffersFile` only guarantees that the IO operations
that have been completed at the time when this service is called will be flushed once the
service routine returns. It makes no guarantee about the ongoing IO operations or future IO
operations that are initiated after the service is called. The `NtFlushBuffersFile` is
similar to the `fsync` system call in Unix and Unix-like systems.

#### Write-back caching and stable page write

Discuss the lack of stable page write and the problem for check-summing devices.

### Driver Porting Guide

Summary of issues mentioned above. Guide to porting drivers from ReactOS and Windows WDM.

#### General Issues

##### Header file
Include `ntddk.h` (under `public/ddk/inc`) as the master header file.

##### `DEVICE_OBJECT`

`DEVICE_OBJECT.Characteristics` has been merged with `DEVICE_OBJECT.Flags` to form a 64-bit
flag, so replace `DEVICE_OBJECT.Characteristics` with `DEVICE_OBJECT.Flags`.

##### Reference Counting

Objects that have `OBJECT_HEADER` as the first member of its structure are reference counted.
These include the device objects and file objects (see `ntddk.h` for the full list). In
particular, when you set the device object and file object of an IRP, you must increase
their reference counting. The system-provided helper routines such as
`IoBuildAsynchronousFsdRequest` already takes care of increasing the refcount of the
device object. If you set the file object pointer of the IO stack location, you must
increase the refcount of the file object manually.

If your driver increased the reference counting of the file object in the CREATE dispatch
routine (or any other IRP dispatch routine), you should dereference the file object in the
CLOSE dispatch routine. Otherwise, you should NOT dereference the file object, because
wdm.dll will dereference the file object as a response to the CloseFile server message.

##### IO Transfer Type

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

##### Sending IRP to self

Drivers should generally avoid sending IRPs to device objects created by itself and
should simply call the relevant function directly. This avoids the overhead of allocating
and freeing the IRP. In particular, for IRPs generated within the same driver address
space, the IO transfer type is ignored and NEITHER IO is always assumed. This is
especially important for driver-minidriver pairs since a driver-minidriver pair is
loaded in the same address space, so sending an IRP from the minidriver to the
library driver will always have NEITHER IO as the IO transfer type, regardless of
the flags in the device object or the IOCTL code.

##### Variable-length structs

We use the C99 flexible array member feature where the last array member of a variable
length struct will have zero dimension. This differs from the Window/ReactOS convention
where a variable-length struct is defined with the last array member having dimension one.
When computing the size of the full struct, use `sizeof(STRUCT_NAME) + NumElem * ELEM_SIZE`,
without subtracting one from `NumElem` as you would in Windows/ReactOS. An example is
the `IO_RESOURCE_REQUIREMENTS_LIST` structure used in the PnP driver interface.

#### Low-level Device Drivers

##### Synchronization

KEVENT (only between different threads within the same driver process)

If you allocate the `KEVENT` on the stack and call `KeWaitForSingleObject` to wait for
the completion of an IRP, you should in general initialize a synchronization event rather
than a notification event. If you initialize a notification event, you will need to manually
reset it to the unsignaled state before returning from the dispatch routine, since it does
not automatically get reset and will remain in the signaled object list. When the coroutine
stack gets released when control leaves the dispatch routine, the driver's list of signaled
object will be in a inconsistent state.

ERESOURCE (removed)

##### Queuing IRP
A common pattern in Windows/ReactOS drivers is that the driver will queue an IRP to an
internal queue when IRPs come in faster than they can be processed by the driver. Common
mechanisms include the StartIo routine, device queues, interlocked queues, and cancel-safe
queues. These are generally speaking unnecessary on Neptune OS as the Executive limits
the rate of IRP flows to a driver by setting an upper limit to the incoming driver IRP
buffer. Low-level drivers should generally process IRPs synchronously. If the device is
busy processing the IRP, the driver should simply wait till the device finishes. This does
not negatively impact system responsiveness since drivers run in their own separate process.
That being said, the StartIo mechanism is still present on Neptune OS in order to make
driver porting easier. For instance, you can use the StartIo routine or device queues in a
DPC routine in response to an interrupt to schedule the main thread to start processing the
relevant IRP. Alternatively, you can also use a KEVENT and have the IRP dispatch routine
wait on the KEVENT and the interrupt service routine signal the KEVENT.

Microsoft [discourages](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/startio-routines-in-higher-level-drivers)
higher-level drivers from having a StartIo routine. This recommendation applies to Neptune OS
drivers as well. For instance, class drivers should not have a StartIo routine and should not
use the `IoStartPacket` routine to queue and start IRP processing.

As opposed to Windows, you cannot call `IoStartPacket`, `IoStartNextPacket`, and related
routines in a DPC routine. To call the `StartIo` routine in a DPC routine, schedule an IO
work item to start IRP processing.

##### Work items
In addition to queuing IRPs due to rate limits, it is a common pattern on Windows/ReactOS
for DPCs to queue a lengthy processing task to a system worker thread, which runs at
a lower IRQL. Work items are scheduled to run at PASSIVE_LEVEL, ie. in the main event loop
thread. It is recommended that ISRs and DPCs queue IO work items to process IRPs. As opposed
to Windows, You cannot call `IoCompleteIrp` and related functions in a DPC routine. Also as
opposed to Windows, you can re-queue IO work items and you do not need to free the IO work
item at the end of its worker routine. On Neptune OS, IO work items are not one-shot objects
and can be safely reused.

#### File System Drivers

##### Concurrency:
Since all IRPs are processed in a single thread unless they are moved to a work queue,
you can remove the KSPIN_LOCK, FAST_MUTEX, or similar locks that protect data structures
that are only accessed by the main IRP processing thread. If you have data structures
that are accessed by the interrupt service thread, or by a DPC routine, or by a worker
thread that you have created yourself, you DO need to keep the relevant locks. Otherwise
synchronization issues will arise in SMP systems.

To protect concurrent access by an interrupt service thread, use `IoAcquireInterruptMutex`
and `IoReleaseInterruptMutex`. To protect concurrent access by a DPC routine, use
`IoAcquireDpcMutex` and `IoReleaseDpcMutex`.

##### FCB and FILE_OBJECT:
1. For the common FCB header, remove SECTION_OBJECT_POINTERS as it is no longer needed.
   You only need the FsRtl common FCB header.
2. You don't need to initialize or modify FILE_OBJECT::PrivateCacheMap as it has been
   removed.
2. Remove FILE_LOCK and related objects.
3. Remove all ERESOURCE objects.

##### Read IRP:

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

##### Fast I/O

Fast I/O is now handled transparently by the Executive. Therefore the fast I/O related
fields in the common FSB header are removed.

##### Directory Control IRP

The IRP_MN_NOTIFY_CHANGE_DIRECTORY minor code is now handled automatically by the
server. You no longer have to handle this in the file system driver. In the future
this IRP minor code may be reused to report the user request for directory change
notification to the filesystem driver.

##### Lock User Buffer

User buffers are always locked for IO. You do not need to explicitly lock the user
buffers using MmProbeAndLockPages.

##### FsRtlEnterFileSystem and FsRtlExitFileSystem

These are no longer needed since drivers run in userspace.

##### Detecting and Responding to Media Changes in Removable Drives

When detecting media change (usually during processing of Read/Write/DeviceIoctl
IRPs) the driver should complete the IRP either with STATUS_MEDIA_CHANGED or
STATUS_NO_MEDIA_IN_DEVICE. Driver should then mark the relevant device object
with DO_VERIFY_REQUIRED so it knows to complete all future IRPs with STATUS_VERIFY_REQUIRED
(unless the IRP is marked with SL_OVERRIDE_VERIFY_VOLUME explicitly to disable this
logic), until such time that it receives a CHECK_VERIFY Ioctl or VERIFY_VOLUME Fsctl,
at which point it can clear the DO_VERIFY_REQUIRED and proceed with normal IO
proceeding.

#### Cache Manager API

##### IoCreateStreamFileObject:

This creates a purely client-side file object that does not have a server-side
counterpart. This is mainly used by the file system drivers so they can access the
on-disk file system metadata using the same cache manager API for ordinary file IO.
When porting, remove the FileObject parameter as it is never used in the ReactOS code
base so we have removed it entirely. On Windows, a non-NULL FileObject allows the
client driver to perform cached IO on file metadata such as the security descriptor
as if it were a file stream. This is not used by any driver in ReactOS so we won't
bother supporting it.

##### IRP_MJ_READ/IRP_MN_MDL:

The meaning of this combination of IRP major/minor code is largely unchanged from
ReactOS/Windows and indicates that when completing the IO request, the dispatch
routine needs to supply an MDL chain describing the mapped IO buffer. Each MDL in
the MDL chain describes virtually contiguous memory that may or may not be physically
contiguous. This is used mainly by the cache manager and is sent only to the file
system drivers and never to the underlying storage device driver. File system drivers
typically call CcMdlRead to satisfy an MDL READ.

##### IO transfer types for file system drivers:

Non-network file system drivers typically always use NEITHER IO as the IO transfer
type as these are almost always stacked on top of an underlying storage device. Network
file system drivers and purely in-memory file systems typically use DIRECT IO instead.
The main difference between DIRECT IO and NEITHER IO is that the server will always
allocate an IO buffer for DIRECT IO when initiating the IO, while for NEITHER IO the
allocation of IO buffers may be deferred.

##### Handling NEITHER IO:

The `UserBuffer` can be (and will typically always be) NULL. This indicates that the
IO buffer has not yet been allocated when the IO is initiated. What the file system
driver should do in this case is to simply translate the file offset to disk offset
and pass the IRP to the underlying storage driver (or to Cc if it is an MDL IO). The
initiator of the IO (typically the cache manager) will take care of properly mapping
the IO buffers later.

##### Associated IRPs and BUFFERED_IO:

The `Irp::AssociatedIrp` union has been dissolved and its `IrpCount` member has been removed.
Drivers do not need to set it. Counting the number of associated IRPs is done automatically
by the system when forwarding the master IRP. Drivers must call `IoCallDriver` on all
associated IRPs before calling `IoCallDriver` on the master IRP, so that all associated IRPs
are correctly accounted for.

As a consequence, accessing the system buffer for buffered IO is now done with
`Irp->SystemBuffer` rather than `Irp->AssociatedIrp.SystemBuffer`. Likewise, change
`Irp->AssociatedIrp.MasterIrp` to `Irp->MasterIrp`.

##### `CcFlushCache`

`CcFlushCache` sends the server a message to flush the relevant cache buffers and waits
for the server to reply. Therefore for performance reasons, `CcFlushCache` should only be
called as a response to the `IRP_MJ_FLUSH_BUFFERS` IRP and during a volume dismount sequence.
Driver authors should remove the calls to `CcFlushCache` and only call the function as the
last step before completing the `IRP_MJ_FLUSH_BUFFERS` IRP and the dismount FSCTLs.
