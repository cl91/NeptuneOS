#pragma once

#include "ke.h"
#include "mm.h"
#include "ex.h"
#include <wdmsvc.h>

#ifdef OBDBG
#define ObDbg(...)	DbgTrace(__VA_ARGS__)
#else
#define ObDbg(...)
#endif

/*
 * Private flags for object creation. See public/ndk/inc/ntobapi.h
 * for public flags. See ntos/src/ob/create.c for details.
 */
#define OBJ_NO_PARSE		0x1000UL

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
    OBJECT_TYPE_SYMBOLIC_LINK,
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

/*
 *Object format:
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
 */
typedef PVOID POBJECT;
typedef struct _OBJECT_HEADER {
    struct _OBJECT_TYPE *Type;
    LIST_ENTRY ObjectLink;
    LIST_ENTRY HandleEntryList;	/* List of all handle entries of this object. */
    POBJECT ParentObject; /* Parent object under which this object is inserted */
    PVOID ParentLink;	  /* Pointer that the parent object can freely use to
			   * point to bookkeeping information. */
    LONG RefCount;
} OBJECT_HEADER, *POBJECT_HEADER;

#define OBJECT_HEADER_TO_OBJECT(Ptr)			\
    ((Ptr) == NULL ? NULL : (POBJECT)(((MWORD)(Ptr)) + sizeof(OBJECT_HEADER)))

#define OBJECT_TO_OBJECT_HEADER(Ptr)			\
    ((Ptr) == NULL ? NULL : (POBJECT_HEADER)(((MWORD)(Ptr)) - sizeof(OBJECT_HEADER)))

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
 * points to the new path to be parsed).
 *
 * When returning REPARSE, the parse routine must allocate the
 * RemainingPath string from the pool with tag OB_PARSE_TAG. When
 * returning an error status, the parse routine must set the
 * RemainingPath to the original Path passed into the parse routine.
 *
 * The parse procedure should not increase the reference count of
 * the object.
 */
#define OB_PARSE_TAG	(EX_POOL_TAG('P', 'A', 'R', 'S'))
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
 * RemainingPath points to the new path to be parsed)
 *
 * Unlike the parse procedure, the open procedure SHOULD increase the
 * reference count of returned *pOpenedInstance object, except in the
 * case of reparsing. The semantics here is that opening an object
 * creates an "opened instance" of the original object. In the case
 * of a DEVICE object, opening it creates a FILE object. If the opened
 * instance of an object is simply itself, the open routine can return
 * the original object as the opened instance after increasing the
 * original object's reference count.
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
				       IN ACCESS_MASK DesiredAccess,
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
 * procedure should not increase the reference count of either the
 * parent or the subobject. Increasing the refcount of the appropriate
 * object is done by the object manager.
 *
 * Note you cannot call ObInsertObject to insert the subobject into
 * another object inside an insert procedure. Doing so will corrupt
 * the object header of the subobjects.
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
 * Note when the object manager removes an object, it calls the RemoveProc
 * of its parent object type, rather than the object type itself. If
 * a type has an insert procedure, its remove procedure cannot be NULL.
 */
typedef VOID (*OBJECT_REMOVE_METHOD)(IN POBJECT Subobject);

/*
 * The close procedure of an object is called when the object manager
 * closes a client handle (Windows NT would call these handles "userspace
 * handles", but since we are a microkernel OS and the Neptune OS
 * Executive also runs in userspace, we refer to handles that we
 * give out to client processes as "client handles"). The close procedure
 * is semantically the opposite of the open procedure and should basically
 * "undo" what is done by the open procedure, which usually involves
 * sending an IRP with the IRP_MJ_CLEANUP code to notify the driver
 * of the handle closure. The close procedure should NOT dereference
 * the object as this is done by the object manager automatically when
 * releasing the handle. The close procedure can wait, and therefore
 * carries an ASYNC_STACK. The close procedure can be NULL. The close
 * procedure does not return a value, and therefore must be able to
 * clean up the opened instance despite any potential errors. If an
 * object type has the open procedure defined, it must have a close
 * procedure.
 */
typedef NTSTATUS (*OBJECT_CLOSE_METHOD)(IN ASYNC_STATE State,
					IN struct _THREAD *Thread,
					IN POBJECT Self);

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
    OBJECT_CLOSE_METHOD CloseProc;
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
#ifdef OBJ_NAME_PATH_SEPARATOR
#undef OBJ_NAME_PATH_SEPARATOR
#endif
#define OBJ_NAME_PATH_SEPARATOR ('\\')

typedef struct _OBJECT_DIRECTORY *POBJECT_DIRECTORY;
typedef struct _OBJECT_SYMBOLIC_LINK *POBJECT_SYMBOLIC_LINK;

/*
 * A process's object handle table. All handles are inserted into
 * an AVL tree, organized by the handle values.
 */
typedef struct _HANDLE_TABLE {
    AVL_TREE Tree;
} HANDLE_TABLE, *PHANDLE_TABLE;

static inline VOID ObInitializeHandleTable(IN PHANDLE_TABLE Table)
{
    AvlInitializeTree(&Table->Tree);
}

/*
 * An entry in the process's object handle table. Each handle is
 * represented by an AVL node where the node key is the handle value.
 */
typedef struct _HANDLE_TABLE_ENTRY {
    AVL_NODE AvlNode;	/* Node key is handle */
    POBJECT Object;
    LIST_ENTRY HandleEntryLink; /* Link for the object header's HandleEntryList */
    BOOLEAN InvokeClose; /* TRUE if the handle was created as part of an open and
			  * we should invoke the close routine when closing it. */
} HANDLE_TABLE_ENTRY, *PHANDLE_TABLE_ENTRY;

/*
 * In Windows/ReactOS the lowest two bits of a HANDLE (called EXHANDLE
 * therein) are available for application use. Therefore all HANDLE
 * values we return to client processes are aligned by 4. We also skip
 * the NULL handle value. System services can use NULL as a special
 * handle value for specific semantics.
 */
#define HANDLE_VALUE_INC 4

/* Helper function to locate the first path separator. */
static inline ULONG ObLocateFirstPathSeparator(IN PCSTR Path)
{
    /* Extract the name of the sub-object, which will be whatever is before
     * the first OBJ_NAME_PATH_SEPARATOR. The remaining path will be whatever
     * is left after the first OBJ_NAME_PATH_SEPARATOR (possibly empty). */
    ULONG Idx = 0;
    for (PCSTR Ptr = Path; *Ptr && *Ptr != OBJ_NAME_PATH_SEPARATOR; Ptr++) {
	Idx++;
    }
    return Idx;
}

/* Helper function to locate the last path separator. */
static inline LONG ObLocateLastPathSeparator(IN PCSTR Path)
{
    LONG Idx = strlen(Path);
    while (Idx >= 0 && Path[Idx] != OBJ_NAME_PATH_SEPARATOR) {
	Idx--;
    }
    return Idx;
}

/* Helper function to determine if the given path has a path separator. */
static inline BOOLEAN ObPathHasSeparator(IN PCSTR Path)
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
			IN PVOID CreationContext);
NTSTATUS ObInsertObject(IN OPTIONAL POBJECT DirectoryObject,
			IN POBJECT Object,
			IN PCSTR Path,
			IN ULONG Flags);

/* dirobj.c */
NTSTATUS ObCreateDirectoryEx(IN OPTIONAL POBJECT Parent,
			     IN PCSTR DirectoryPath,
                             OUT OPTIONAL POBJECT_DIRECTORY *DirObj);
NTSTATUS ObDirectoryObjectSearchObject(IN POBJECT_DIRECTORY Directory,
				       IN PCSTR Name,
				       IN ULONG Length, /* Excluding trailing '\0' */
				       IN BOOLEAN CaseInsensitive,
				       OUT POBJECT *FoundObject);
NTSTATUS ObDirectoryObjectInsertObject(IN POBJECT_DIRECTORY Directory,
                                       IN POBJECT Object,
				       IN PCSTR Name);
VOID ObDirectoryObjectRemoveObject(IN POBJECT Subobject);
SIZE_T ObDirectoryGetObjectCount(IN POBJECT_DIRECTORY DirObj);
NTSTATUS ObCreateParentDirectory(IN OPTIONAL POBJECT RootDirectory,
                                 IN PCSTR ObjectPath,
                                 OUT OPTIONAL POBJECT_DIRECTORY *ParentDir);
POBJECT_DIRECTORY ObGetParentDirectory(IN POBJECT Object);
FORCEINLINE NTSTATUS ObCreateDirectory(IN PCSTR DirectoryPath)
{
    return ObCreateDirectoryEx(NULL, DirectoryPath, NULL);
}

/* obref.c */
struct _PROCESS;
NTSTATUS ObReferenceObjectByName(IN PCSTR Path,
				 IN OBJECT_TYPE_ENUM Type,
				 IN POBJECT RootDirectory,
				 IN BOOLEAN CaseInsensitive,
				 OUT POBJECT *Object);
NTSTATUS ObReferenceObjectByHandle(IN struct _THREAD *Thread,
				   IN HANDLE Handle,
				   IN OBJECT_TYPE_ENUM Type,
				   OUT POBJECT *pObject);
NTSTATUS ObCreateHandle(IN struct _PROCESS *Process,
			IN POBJECT Object,
			IN BOOLEAN ObjectOpened,
			OUT HANDLE *pHandle);
VOID ObRemoveObject(IN POBJECT Object);
VOID ObDereferenceObject(IN POBJECT Object);

/* open.c */
NTSTATUS ObParseObjectByName(IN POBJECT DirectoryObject,
			     IN PCSTR Path,
			     IN BOOLEAN CaseInsensitive,
			     OUT POBJECT *FoundObject);
NTSTATUS ObOpenObjectByNameEx(IN ASYNC_STATE State,
			      IN struct _THREAD *Thread,
			      IN OB_OBJECT_ATTRIBUTES ObjectAttributes,
			      IN OBJECT_TYPE_ENUM Type,
			      IN ACCESS_MASK DesiredAccess,
			      IN POB_OPEN_CONTEXT OpenContext,
			      IN BOOLEAN AssignHandle,
			      OUT PVOID *pHandle);

FORCEINLINE NTSTATUS ObOpenObjectByName(IN ASYNC_STATE State,
					IN struct _THREAD *Thread,
					IN OB_OBJECT_ATTRIBUTES ObjectAttributes,
					IN OBJECT_TYPE_ENUM Type,
					IN ACCESS_MASK DesiredAccess,
					IN POB_OPEN_CONTEXT OpenContext,
					OUT PVOID *pHandle) {
    return ObOpenObjectByNameEx(State, Thread, ObjectAttributes, Type,
				DesiredAccess, OpenContext, TRUE, pHandle);
}

/* symlink.c */
NTSTATUS ObCreateSymbolicLink(IN PCSTR LinkTarget,
			      IN OPTIONAL POBJECT LinkTargetObject,
			      OUT POBJECT_SYMBOLIC_LINK *Symlink);
