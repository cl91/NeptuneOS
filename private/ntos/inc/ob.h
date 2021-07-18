#pragma once

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
 */
typedef enum _OBJECT_TYPE_ENUM {
    OBJECT_TYPE_DIRECTORY,
    OBJECT_TYPE_THREAD,
    OBJECT_TYPE_PROCESS,
    OBJECT_TYPE_SECTION,
    NUM_OBJECT_TYPES
} OBJECT_TYPE_ENUM;

/* Object format:
 *
 *    |-------------|
 *    |OBJECT_HEADER|
 *    |-------------|    <- (PVOID) Self
 *    | OBJECT_BODY |
 *    |-------------|
 *
 * Note: (PVOID) Self always points to the beginning of the
 * object body, not the object header.
 *
 * TODO: We need to figure out the supported API of object types,
 * especially since the object namespace needs to have
 * objects that are represented across process boundary. For
 * instance, the IO manager uses the object namespace to manage
 * device objects and their driver objects, and their functions
 * are implemented in a different process.
 *
 * The preliminary design is that opening an object can yield
 * a different object (such as a FILE object, or an IO request)
 * which represents an opened instance of said object.
 * For instance, opening a Device object yields a FILE object.
 *
 * The parse procedure allows the object type to implement the
 * idea of a sub-object. Calling the parse procedure produces
 * a sub-object of the object being called.
 *
 * We of course also need to figure out the delete procedure,
 * closing an object, and object life-times.
 *
 * All of these methods operate with in-process pointers. The
 * APIs for handles to objects are yet to be determined.
 */
typedef struct _OBJECT_HEADER {
    struct _OBJECT_TYPE *Type;
    LONG RefCount;
    LIST_ENTRY ObjectLink;
} OBJECT_HEADER, *POBJECT_HEADER;

#define OBJECT_HEADER_TO_OBJECT(Ptr)			\
    ((PVOID)(((MWORD) Ptr) + sizeof(OBJECT_HEADER)))

#define OBJECT_TO_OBJECT_HEADER(Ptr)			\
    ((POBJECT_HEADER)(((MWORD) Ptr) - sizeof(OBJECT_HEADER)))

/*
 * The create routine creates an empty object and initializes
 * the object body to sane, default values. Self points to the
 * beginning of the object body.
 *
 * The create routine cannot be NULL. The object manager will
 * reject such object types during object type registration.
 */
typedef NTSTATUS (*OBJECT_CREATE_METHOD)(IN PVOID Self);

/*
 * The open routine produces an opened instance of the object,
 * which can be an object of a different object type. For instance,
 * opening a DEVICE object produces a FILE object.
 */
typedef NTSTATUS (*OBJECT_OPEN_METHOD)(IN PVOID Self);

/*
 * The parse routine is used by the object manager when other
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
 * The parse routine can be NULL, in which case the object does
 * not implement the semantics of sub-object.
 *
 * The parse routine is not allowed to modify the Path string.
 * RemainingPath must point to a sub-string within Path, and does
 * NOT include the leading OBJ_NAME_PATH_SEPARATOR.
 */
typedef NTSTATUS (*OBJECT_PARSE_METHOD)(IN PVOID Self,
					IN PCSTR Path,
					OUT POBJECT_HEADER *Subobject,
					OUT PCSTR *RemainingPath);

/* Insert the given object as the sub-object of Self, with Subpath
 * as the name identifier of said sub-object.
 */
typedef NTSTATUS (*OBJECT_INSERT_METHOD)(IN PVOID Self,
					 IN POBJECT_HEADER Subobject,
					 IN PCSTR Subpath);

typedef struct _OBJECT_TYPE_INITIALIZER {
    OBJECT_CREATE_METHOD CreateProc;
    OBJECT_OPEN_METHOD OpenProc;
    OBJECT_PARSE_METHOD ParseProc;
    OBJECT_INSERT_METHOD InsertProc;
} OBJECT_TYPE_INITIALIZER, *POBJECT_TYPE_INITIALIZER;

typedef struct _OBJECT_TYPE {
    PCSTR Name;
    OBJECT_TYPE_ENUM Index;
    ULONG ObjectBodySize;
    OBJECT_TYPE_INITIALIZER TypeInfo;
} OBJECT_TYPE, *POBJECT_TYPE;

#define OBJ_NAME_PATH_SEPARATOR ('\\')

#define NUMBER_HASH_BUCKETS 37
typedef struct _OBJECT_DIRECTORY {
    LIST_ENTRY HashBuckets[NUMBER_HASH_BUCKETS];
} OBJECT_DIRECTORY, *POBJECT_DIRECTORY;

/* init.c */
NTSTATUS ObInitSystem();

/* create.c */
NTSTATUS ObCreateObjectType(IN OBJECT_TYPE_ENUM Type,
			    IN PCSTR TypeName,
			    IN ULONG ObjectBodySize,
			    IN OBJECT_TYPE_INITIALIZER Init);
NTSTATUS ObCreateObject(IN OBJECT_TYPE_ENUM Type,
			OUT PVOID *Object);

/* obref.c */
NTSTATUS ObReferenceObjectByName(IN PCSTR Path,
				 OUT PVOID *Object);
NTSTATUS ObDereferenceObject(IN PVOID Object);
