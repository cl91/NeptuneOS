#pragma once

#include "ke.h"
#include "mm.h"
#include "ex.h"
#include <wdmsvc.h>

/*
 * Private flags for object creation. See public/ndk/inc/ntobapi.h
 * for public flags. See ntos/src/ob/create.c for details.
 */
#define OBJ_NO_PARSE	0x1000L

C_ASSERT((OBJ_VALID_ATTRIBUTES & OBJ_NO_PARSE) == 0);

/* Unlike in Windows, the ObjectType itself is not a type.
 *
 * Windows has ObpTypeObjectType which denotes the type of all
 * object types. This leads to a classic instance of Russell's
 * paradox, namely that the proposition
 *
 *    S \el S where S = { x | x \not\el x }
 *
 * is neither true nor false. Here x \el y means that object x is
 * of type y, and S = { x | \phi(x) } is the type of all objects x
 * that satisfy the proposition \phi(x).
 *
 * When referencing an object the caller can specify a bit mask
 * indicating the desired type(s). Specify OBJECT_TYPE_ALL to bypass
 * type checking.
 */
typedef enum _OBJECT_TYPE_ENUM {
    OBJECT_TYPE_DIRECTORY,
    OBJECT_TYPE_THREAD,
    OBJECT_TYPE_PROCESS,
    OBJECT_TYPE_SECTION,
    OBJECT_TYPE_FILE,
    OBJECT_TYPE_DEVICE,
    OBJECT_TYPE_DRIVER,
    OBJECT_TYPE_TIMER,
    OBJECT_TYPE_KEY,
    OBJECT_TYPE_EVENT,
    OBJECT_TYPE_SYSTEM_ADAPTER,	/* System DMA adapter object */
    MAX_NUM_OBJECT_TYPES,
    OBJECT_TYPE_ANY = MAX_NUM_OBJECT_TYPES
} OBJECT_TYPE_ENUM;

/* Object format:
 *
 *    |-------------|
 *    |OBJECT_HEADER|
 *    |-------------|    <- (POBJECT) Self
 *    | OBJECT_BODY |
 *    |-------------|
 *
 * Note: (POBJECT) Self always points to the beginning of the
 * object body, not the object header. To avoid confusion we
 * always pass OBJECT pointers across function boundary, and
 * never pass OBJECT_HEADER pointers.
 *
 * In the Windows/ReactOS design, an object type can implement
 * the semantics of sub-objecting by defining a parse method,
 * which parses part of the object path to produce a sub-object.
 * The object manager recursively invokes the parse method when
 * when opening an object.
 *
 * In our design a complication arises due to the fact that we
 * run the NT Executive in user space. Opening an object may
 * involve, for instance, queuing an IRP to a driver object and
 * suspending the Executive service processing for the current
 * thread. Therefore the "parse" procedure need to take an async
 * context. On the other hand, for objects that live inside the
 * NT Executive address space, or for objects that have already
 * been opened, we need a way to make sure that the "parse"
 * procedure will never suspend, so that it is safe to call it
 * when the server does not have an async context in that moment.
 *
 * The solution we have here is to have two types of "parse"
 * procedures: one that does not take an async context, and one
 * that does. The "parse" procedure that does NOT take an async
 * state is called the parse procedure in our codebase and the
 * "parse" procedure that DOES take an async state is called the
 * open procedure. Both take the sub-path being parsed as an
 * argument and both implement the semantics of sub-objecting.
 *
 * The parse procedure will typically examine the cached object
 * database to locate the sub-object given by the sub-path. These
 * can include the sub-objects that have already been opened (by
 * the open procedure) or sub-objects that always live locally
 * (in the address space of the NT Executive). The parse procedure
 * operates on a global context, meaning that it does not take
 * a PTHREAD parameter and cannot modify THREAD states.
 *
 * On the other hand, the open procedure operates on a thread
 * context, meaning that it takes a PTHREAD parameter and can
 * modify the THREAD states. The open procedure will typically
 * queue an IRP or (asynchronously) query an out-of-process
 * database to find the specified sub-object. In particular,
 * if the sub-path being parsed is empty, an open procedure can
 * return a different object type to implement the semantics of
 * an opened instance of the original object. This is employed
 * by the IO manager extensively: opening a DEVICE object gives
 * a FILE object.
 *
 * The object manager provides two public interfaces,
 * ObReferenceObjectByName and ObOpenObjectByName, to implement
 * the notion of looking up an object path and opening an object.
 * ObReferenceObjectByName only calls the parse procedure, and
 * always returns the pointer to the original object (such as
 * a DEVICE object), as opposed to the opened instance (such as
 * a FILE object). ObOpenObjectByName invokes both the parse
 * and the open procedures, and assigns a handle to the opened
 * instance. It therefore must be called with an async context,
 * whereas ObReferenceObjectByName does not need one.
 *
 * The IO subsystem uses the facilities of the object manager
 * extensively. Since opening a device or a file is inherently
 * an asynchronous process, the IO subsystem uses a two-step
 * scheme when opening or creating a file. First, the parse
 * procedures are invoked on the given path to locate the DEVICE
 * object to be opened. For a simple DEVICE such as \Device\Beep,
 * the parse prodecure will essentially be a no-op since the
 * device does not implement sub-objects. The object manager
 * then invokes the open procedure of the DEVICE object, which
 * will yield a FILE_OBJECT, representing an opened instance of
 * the DEVICE object. The open procedure will then queue the IRP
 * to the thread calling the NT system service and depending on
 * whether the open is synchronous or asynchronous, either wait
 * on the IO completion event or return STATUS_PENDING.
 *
 * For a more complex device such as a partition device, its parse
 * procedure will take the remaining path after the device name
 * (ie. the src\main.c in \Device\Harddisk0\Partition0\src\main.c)
 * and first invoke the cache manager and see if the file has been
 * previously opened. If it was previously opened, the cached device
 * object is returned immediately. Otherwise, the open procedure
 * is invoked just like the simple case above.
 *
 * On the other hand, closing an object is always a lazy process.
 * We simply flag the object for closing and queues the object
 * closure IRP to the driver process (if it's created by a driver).
 * The close routine does not wait for the driver's response and
 * is therefore synchronous. This simplifies the error paths,
 * especially in an asynchronous function.
 *
 * All object methods operate with in-process pointers. Assigning
 * HANDLEs to opened objects is done by the object manager itself.
 */
typedef PVOID POBJECT;
typedef struct _OBJECT_HEADER {
    struct _OBJECT_TYPE *Type;
    LIST_ENTRY ObjectLink;
    LIST_ENTRY HandleEntryList;	/* List of all handle entries of this object. */
    POBJECT ParentObject; /* Parent object under which this object is inserted */
    PCSTR ObjectName; /* Sub-path of this object under the parent object.
		       * This is always allocated on the ExPool by the object
		       * manager and owned by this object. */
    LONG RefCount;
} OBJECT_HEADER, *POBJECT_HEADER;

#define OBJECT_HEADER_TO_OBJECT(Ptr)			\
    ((Ptr) == NULL ? NULL : (POBJECT)(((MWORD)(Ptr)) + sizeof(OBJECT_HEADER)))

#define OBJECT_TO_OBJECT_HEADER(Ptr)			\
    ((Ptr) == NULL ? NULL : (POBJECT_HEADER)(((MWORD)(Ptr)) - sizeof(OBJECT_HEADER)))

static inline PCSTR ObGetObjectName(IN POBJECT Object)
{
    return OBJECT_TO_OBJECT_HEADER(Object)->ObjectName;
}

/*
 * We use the offset of an object header pointer from the start of the
 * Executive pool as the global handle of an object. Since the
 * lowest EX_POOL_BLOCK_SHIFT (== 3 on x86 and 4 on amd64) bits are
 * always zero for any memory allocated on the ExPool we use the lowest
 * bits to indicate the nature of the handle.
 *
 * We cannot just use the server-side pointer as the global handle.
 * The reason is that on i386, the highest bits of the badge are ignored
 * by seL4, due to the way that seL4 implements IPC on i386. On amd64
 * there is presumably no such limitation, but we need to be portable.
 *
 * For the NTOS executive services we use the global handle of the
 * thread as the badge of the IPC endpoint to distinguish the sender
 * of the service messages. Since the lowest three bits of the global
 * handle are guaranteed to be zero, we are free to use the three bits
 * to indicate the service type, since there are more than one types
 * of executive services for a client thread.
 *
 * Note: the type GLOBAL_HANDLE is defined in rtl/inc/wdmsvc.h
 *
 * As should be obvious from above, values of SERVICE_TYPE enum cannot
 * be larger than 1 << EX_POOL_BLOCK_SHIFT. Also, you can only assign
 * global handles for objects allocated on the ExPool. Objects allocated
 * statically cannot have global handles, because their address lies
 * below the start of ExPool.
 */
typedef enum _SERVICE_TYPE {
    SERVICE_TYPE_SYSTEM_SERVICE,
    SERVICE_TYPE_WDM_SERVICE,
    SERVICE_TYPE_FAULT_HANDLER,
    SERVICE_TYPE_SYSTEM_THREAD_FAULT_HANDLER,
    SERVICE_TYPE_NOTIFICATION,
    NUM_SERVICE_TYPES
} SERVICE_TYPE;

compile_assert(TOO_MANY_SERVICE_TYPES, NUM_SERVICE_TYPES <= (1 << EX_POOL_BLOCK_SHIFT));

/* For structures that are not managed by the Object Manager (for
 * instance IO_PACKET and IO_DEVICE_OBJECT) we simply take the offset
 * of the pointer from EX_POOL_START */
#define POINTER_TO_GLOBAL_HANDLE(Ptr)		\
    ObpPtrToGlobalHandle((MWORD)(Ptr))

/* For objects managed by the Object Manager, use the offset of the
 * object header from the ExPool start address */
#define OBJECT_TO_GLOBAL_HANDLE(Ptr)				\
    POINTER_TO_GLOBAL_HANDLE(OBJECT_TO_OBJECT_HEADER(Ptr))

/*
 * We convert the global handle into an object header pointer by masking
 * off the lowest EX_POOL_BLOCK_SHIFT bits and the bits higher than
 * EX_POOL_MAX_SIZE
 */
#define GLOBAL_HANDLE_TO_POINTER(Handle)				\
    ((Handle) == 0 ? NULL :						\
	((PVOID)((((((MWORD)(Handle) >> EX_POOL_BLOCK_SHIFT)		\
		    << EX_POOL_BLOCK_SHIFT)				\
		   & (EX_POOL_MAX_SIZE - 1)) + EX_POOL_START))))

#define GLOBAL_HANDLE_TO_OBJECT(Handle)					\
    OBJECT_HEADER_TO_OBJECT(GLOBAL_HANDLE_TO_POINTER(Handle))

#define GLOBAL_HANDLE_GET_FLAG(Handle)			\
    ((MWORD)Handle & ((1 << EX_POOL_BLOCK_SHIFT) - 1))

static inline MWORD ObpPtrToGlobalHandle(IN MWORD Ptr)
{
    if (Ptr < EX_POOL_START) {
	return 0;
    }
    MWORD Handle = Ptr - EX_POOL_START;
    if (GLOBAL_HANDLE_GET_FLAG(Handle)) {
	return 0;
    }
    return Handle;
}

/*
 * Equivalent of NT's OBJECT_ATTRIBUTES, except we make it easier to
 * pass around, ie. we replace the PUNICODE_STRING ObjectName member
 * with a pointer to the UTF-8 string buffer as well as its size, so
 * that we don't need to allocate a UNICODE_STRING struct when creating
 * this struct. This makes it easier to allocate it on the stack which
 * simplifies the system service argument marshaling.
 */
typedef struct _OB_OBJECT_ATTRIBUTES {
    HANDLE RootDirectory;
    ULONG Attributes;
    PCSTR ObjectNameBuffer;
    ULONG ObjectNameBufferLength; /* including the terminating '\0' */
} OB_OBJECT_ATTRIBUTES, *POB_OBJECT_ATTRIBUTES;

/*
 * The create routine initializes the object given the create context.
 * Self points to the beginning of the object body.
 *
 * If the create routine returned an error status, the object's deletion
 * routine will be invoked. The object is then freed from the ExPool.
 * It is the create routine and the deletion routine's responsibilities
 * to make sure that when create routine returns error, the object is
 * in a well-defined state and the deletion routine can correctly delete
 * the object.
 *
 * The create routine cannot be NULL. The object manager will reject
 * such object types during object type registration.
 *
 * If the object body stores pointers to other objects, the create routine
 * should increase the reference count of those objects. Likewise, the
 * delete routine should decrease the reference count of these objects.
 */
typedef NTSTATUS (*OBJECT_CREATE_METHOD)(IN POBJECT Self,
					 IN PVOID CreationContext);

/*
 * The parse procedure is used by the object manager when other
 * Executive components request an object by a path. It implements
 * the semantics of a subobject identified by a subpath, given by
 * the argument Path. The parse procedure will consume as many
 * characters in Path as needed, and will return the subobject
 * (if found) and the remaining path that is yet to be parsed.
 * The object manager will recursively invoke the parse routine
 * of the sub-object with the remaining path until the remaining
 * path is empty, or until the object fails to parse a path,
 * whichever occurs earlier.
 *
 * The parse procedure can be NULL, in which case the object does
 * not implement the semantics of sub-objecting.
 *
 * The parse procedure is not allowed to modify the Path string.
 * RemainingPath must point to a sub-string within Path (unless
 * the REPARSE status is returned, in which case RemainingPath
 * points to the new path to be parsed), and does NOT include the
 * leading OBJ_NAME_PATH_SEPARATOR.
 *
 * The parse procedure should not increase the reference count of
 * the object. All reference counting is done by the object manager.
 */
typedef NTSTATUS (*OBJECT_PARSE_METHOD)(IN POBJECT Self,
					IN PCSTR Path,
					IN BOOLEAN CaseInsensitive,
					OUT POBJECT *pSubobject,
					OUT PCSTR *pRemainingPath);

/*
 * The open procedure is similar to the parse procedure in that
 * it implements the notion of a sub-object given by the sub-path.
 * The difference from a parse procedure is that an open procedure
 * takes an async context and can modify the thread object of the
 * async context. In particular, it can suspend the current thread
 * and wait for the completion of IO. The open procedure can also
 * produce an opened instance of the object that has a different
 * object type from the original object. For instance, opening a
 * DEVICE object produces a FILE object.
 *
 * Assigning the object handle is not the open procedure's concern.
 * The object manager will assign the handle.
 *
 * The open procedure can be NULL, in which case the object does not
 * support being opened (for instance, FILE object cannot be opened.
 * since it represents an opened instance of a DEVICE. Only DEVICE
 * object can be opened). For object types where the opened instance
 * of an object is simply itself, the object type should supply a
 * trivial open procedure (but not NULL).
 *
 * Like the parse procedure, the open procedure is not allowed to
 * modify the Path string. RemainingPath must point to a sub-string
 * within Path (unless the REPARSE status is returned, in which case
 * RemainingPath points to the new path to be parsed), and does NOT
 * include the leading OBJ_NAME_PATH_SEPARATOR.
 *
 * Like the parse procedure, the open procedure should not increase the
 * reference count of the object being opened or the opened instance.
 * All reference counting is done by the object manager.
 */
typedef enum _OPEN_CONTEXT_TYPE {
    OPEN_CONTEXT_DEVICE_OPEN,	/* IO_OPEN_CONTEXT */
    OPEN_CONTEXT_KEY_OPEN,	/* CM_OPEN_CONTEXT */
} OPEN_CONTEXT_TYPE;
typedef struct _OB_OPEN_CONTEXT {
    OPEN_CONTEXT_TYPE Type; /* Type of the parse context following the header */
} OB_OPEN_CONTEXT, *POB_OPEN_CONTEXT;	 /* Header of the object parse context */
typedef NTSTATUS (*OBJECT_OPEN_METHOD)(IN ASYNC_STATE State,
				       IN struct _THREAD *Thread,
				       IN POBJECT Self,
				       IN PCSTR SubPath,
				       IN ULONG Attributes,
				       IN POB_OPEN_CONTEXT OpenContext,
				       OUT POBJECT *pOpenedInstance,
				       OUT PCSTR *pRemainingPath);

/*
 * The insert procedure inserts the given object (Subobject) as the
 * sub-object into the parent object (Parent), with Subpath as the
 * identifier name of the sub-object. The insert procedure is called
 * during object creation, where user can specify the parent object
 * and name of the object as part of the object attributes. The insert
 * procedure should not increase the reference count as it is done
 * by the object manager.
 */
typedef NTSTATUS (*OBJECT_INSERT_METHOD)(IN POBJECT Parent,
					 IN POBJECT Subobject,
					 IN PCSTR Subpath);

/*
 * The remove procedure is the opposite of the insert procedure and
 * removes the subobject from the parent object. It is called during
 * object deletion and likewise should not decrease the reference count
 * of the object as it is done by the object manager.
 *
 * The remove procedure cannot be NULL if the insert procedure is
 * supplied.
 */
typedef VOID (*OBJECT_REMOVE_METHOD)(IN POBJECT Parent,
				     IN POBJECT Subobject,
				     IN PCSTR Subpath);

/*
 * The delete procedure releases the resources of an object. It is
 * called when the user deletes an object, or when object creation
 * fails. Therefore the delete procedure must be able to clean up
 * partially created objects. The delete procedure should not free
 * the pool memory of the object itself. This is done by the object
 * manager. The delete procedure can be NULL.
 *
 * If the object body stores pointers to other objects, the delete
 * routine should decrease the reference count of those objects.
 */
typedef VOID (*OBJECT_DELETE_METHOD)(IN POBJECT Self);

typedef struct _OBJECT_TYPE_INITIALIZER {
    OBJECT_CREATE_METHOD CreateProc;
    OBJECT_PARSE_METHOD ParseProc;
    OBJECT_OPEN_METHOD OpenProc;
    OBJECT_INSERT_METHOD InsertProc;
    OBJECT_REMOVE_METHOD RemoveProc;
    OBJECT_DELETE_METHOD DeleteProc;
} OBJECT_TYPE_INITIALIZER, *POBJECT_TYPE_INITIALIZER;

typedef struct _OBJECT_TYPE {
    PCSTR Name;
    OBJECT_TYPE_ENUM Index;
    ULONG ObjectBodySize;
    OBJECT_TYPE_INITIALIZER TypeInfo;
} OBJECT_TYPE, *POBJECT_TYPE;

static inline OBJECT_TYPE_ENUM ObObjectGetType(IN POBJECT Object)
{
    return OBJECT_TO_OBJECT_HEADER(Object)->Type->Index;
}

static inline BOOLEAN ObObjectIsType(IN POBJECT Object,
				     IN OBJECT_TYPE_ENUM Type)
{
    return ObObjectGetType(Object) == Type;
}

/* This overrides the definition in public/ndk/inc/ntobapi.h */
#define OBJ_NAME_PATH_SEPARATOR ('\\')

typedef struct _OBJECT_DIRECTORY *POBJECT_DIRECTORY;

/*
 * A process's object handle table. All handles are inserted into
 * an AVL tree, organized by the handle values.
 */
typedef struct _HANDLE_TABLE {
    MM_AVL_TREE Tree;
} HANDLE_TABLE, *PHANDLE_TABLE;

static inline VOID ObInitializeHandleTable(IN PHANDLE_TABLE Table)
{
    MmAvlInitializeTree(&Table->Tree);
}

/*
 * An entry in the process's object handle table. Each handle is
 * represented by an AVL node where the node key is the handle value.
 */
typedef struct _HANDLE_TABLE_ENTRY {
    MM_AVL_NODE AvlNode;	/* Node key is handle */
    POBJECT Object;
    LIST_ENTRY HandleEntryLink; /* Link for the object header's HandleEntryList */
} HANDLE_TABLE_ENTRY, *PHANDLE_TABLE_ENTRY;

/*
 * In Windows/ReactOS the lowest two bits of a HANDLE (called EXHANDLE
 * therein) are available for application use. Therefore all HANDLE
 * values we return to client processes are aligned by 4. We also skip
 * the NULL handle value. System services can use NULL as a special
 * handle value for specific semantics.
 */
#define HANDLE_VALUE_INC 4

/*
 * Helper function to locate the first path separator.
 *
 * This should only be called within the object type's parse/open routines
 */
static inline ULONG ObpLocateFirstPathSeparator(IN PCSTR Path)
{
    /* Extract the name of the sub-object, which will be whatever is before
     * the first OBJ_NAME_PATH_SEPARATOR. The remaining path will be whatever
     * is left after the first OBJ_NAME_PATH_SEPARATOR (possibly empty). */
    ULONG NameLength = 0;
    for (PCSTR Ptr = Path; (*Ptr != '\0') && (*Ptr != OBJ_NAME_PATH_SEPARATOR); Ptr++) {
	NameLength++;
    }
    return NameLength;
}

/*
 * Helper function to determine if the given path has a path separator.
 *
 * This should only be called within the object type's parse/open routines
 */
static inline BOOLEAN ObpPathHasSeparator(IN PCSTR Path)
{
    while (*Path != '\0') {
	if (*Path == OBJ_NAME_PATH_SEPARATOR) {
	    return TRUE;
	}
	Path++;
    }
    return FALSE;
}

/* This should only be called by the object manager */
static inline void ObpReferenceObjectHeader(POBJECT_HEADER ObjectHeader)
{
    ObjectHeader->RefCount++;
}

/* This should only be called in the create routine of an object */
static inline void ObpReferenceObject(POBJECT Object)
{
    ObpReferenceObjectHeader(OBJECT_TO_OBJECT_HEADER(Object));
}

/* init.c */
NTSTATUS ObInitSystemPhase0();

/* create.c */
NTSTATUS ObCreateObjectType(IN OBJECT_TYPE_ENUM Type,
			    IN PCSTR TypeName,
			    IN ULONG ObjectBodySize,
			    IN OBJECT_TYPE_INITIALIZER Init);
NTSTATUS ObCreateObject(IN OBJECT_TYPE_ENUM Type,
			OUT POBJECT *Object,
			IN POBJECT DirectoryObject,
			IN PCSTR Subpath,
			IN ULONG Flags,
			IN PVOID CreationContext);

/* dirobj.c */
NTSTATUS ObCreateDirectory(IN PCSTR DirectoryPath);

/* obref.c */
struct _PROCESS;
NTSTATUS ObReferenceObjectByName(IN PCSTR Path,
				 IN OBJECT_TYPE_ENUM Type,
				 IN POBJECT RootDirectory,
				 IN BOOLEAN CaseInsensitive,
				 OUT POBJECT *Object);
NTSTATUS ObReferenceObjectByHandle(IN struct _PROCESS *Process,
				   IN HANDLE Handle,
				   IN OBJECT_TYPE_ENUM Type,
				   OUT POBJECT *pObject);
NTSTATUS ObCreateHandle(IN struct _PROCESS *Process,
			IN POBJECT Object,
			OUT HANDLE *pHandle);
VOID ObDereferenceObject(IN POBJECT Object);

/* open.c */
NTSTATUS ObOpenObjectByName(IN ASYNC_STATE State,
			    IN struct _THREAD *Thread,
			    IN OB_OBJECT_ATTRIBUTES ObjectAttributes,
			    IN OBJECT_TYPE_ENUM Type,
			    IN POB_OPEN_CONTEXT OpenContext,
			    OUT HANDLE *pHandle);
