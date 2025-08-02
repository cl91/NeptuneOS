#pragma once

#include <ntdef.h>
#include <ntstatus.h>
#include <ntseapi.h>

/*
 * Definitions for Object Creation
 */
#define OBJ_INHERIT                             0x00000002L
#define OBJ_PERMANENT                           0x00000010L
#define OBJ_EXCLUSIVE                           0x00000020L
#define OBJ_CASE_INSENSITIVE                    0x00000040L
#define OBJ_OPENIF                              0x00000080L
#define OBJ_OPENLINK                            0x00000100L
#define OBJ_KERNEL_HANDLE                       0x00000200L
#define OBJ_FORCE_ACCESS_CHECK                  0x00000400L
#define OBJ_VALID_ATTRIBUTES                    0x000007F2L

#define InitializeObjectAttributes(p,n,a,r,s) {		\
	(p)->Length = sizeof(OBJECT_ATTRIBUTES);	\
	(p)->RootDirectory = (r);			\
	(p)->Attributes = (a);				\
	(p)->ObjectName = (n);				\
	(p)->SecurityDescriptor = (s);			\
	(p)->SecurityQualityOfService = NULL;		\
    }

/* You can use InitializeObjectAttributes for OBJECT_ATTRIBUTES_ANSI */
C_ASSERT(sizeof(OBJECT_ATTRIBUTES) == sizeof(OBJECT_ATTRIBUTES_ANSI));

#define OBJECT_TYPE_CREATE                0x0001
#define OBJECT_TYPE_ALL_ACCESS            (STANDARD_RIGHTS_REQUIRED | 0x1)

#define SYMBOLIC_LINK_QUERY               0x0001
#define SYMBOLIC_LINK_ALL_ACCESS          (STANDARD_RIGHTS_REQUIRED | 0x1)

#define DUPLICATE_CLOSE_SOURCE            0x00000001
#define DUPLICATE_SAME_ACCESS             0x00000002
#define DUPLICATE_SAME_ATTRIBUTES         0x00000004

/*
 * Number of custom-defined bits that can be attached to a handle
 */
#define OBJ_HANDLE_TAGBITS                      0x3

/*
 * In the NTOS Executive this is defined as the ASCII '\\'
 */
#ifndef _NTOSKRNL_
#define OBJ_NAME_PATH_SEPARATOR                 L'\\'
#endif

/*
 * Directory Object Access Rights
 */
#define DIRECTORY_QUERY                         0x0001
#define DIRECTORY_TRAVERSE                      0x0002
#define DIRECTORY_CREATE_OBJECT                 0x0004
#define DIRECTORY_CREATE_SUBDIRECTORY           0x0008
#define DIRECTORY_ALL_ACCESS                    (STANDARD_RIGHTS_REQUIRED | 0xF)

/*
 * Object Information Types for NtQueryInformationObject
 */
typedef struct _OBJECT_NAME_INFORMATION {
    UNICODE_STRING Name;
} OBJECT_NAME_INFORMATION, *POBJECT_NAME_INFORMATION;

typedef struct _OBJECT_HANDLE_ATTRIBUTE_INFORMATION {
    BOOLEAN Inherit;
    BOOLEAN ProtectFromClose;
} OBJECT_HANDLE_ATTRIBUTE_INFORMATION, *POBJECT_HANDLE_ATTRIBUTE_INFORMATION;

typedef struct _OBJECT_DIRECTORY_INFORMATION {
    UNICODE_STRING Name;
    UNICODE_STRING TypeName;
} OBJECT_DIRECTORY_INFORMATION, *POBJECT_DIRECTORY_INFORMATION;

/*
 * Native Calls. These are only available for client threads.
 * The NTOS root task has different function signatures for these.
 */
#ifndef _NTOSKRNL_

NTAPI NTSYSAPI NTSTATUS NtClose(IN HANDLE Handle);
#define ZwClose NtClose

NTAPI NTSYSAPI NTSTATUS NtWaitForSingleObject(IN HANDLE WaitObject,
                                              IN BOOLEAN Alertable,
                                              IN PLARGE_INTEGER Time);

NTAPI NTSYSAPI NTSTATUS NtCreateDirectoryObject(OUT PHANDLE DirectoryHandle,
						IN ACCESS_MASK DesiredAccess,
						IN POBJECT_ATTRIBUTES ObjectAttributes);

NTAPI NTSYSAPI NTSTATUS NtCreateSymbolicLinkObject(OUT PHANDLE SymbolicLinkHandle,
						   IN ACCESS_MASK DesiredAccess,
						   IN POBJECT_ATTRIBUTES ObjectAttributes,
						   IN PUNICODE_STRING Name);

NTAPI NTSYSAPI NTSTATUS NtOpenSymbolicLinkObject(OUT PHANDLE SymbolicLinkHandle,
						 IN ACCESS_MASK DesiredAccess,
						 IN POBJECT_ATTRIBUTES ObjectAttributes);

NTAPI NTSYSAPI NTSTATUS NtMakePermanentObject(IN HANDLE Object);

NTAPI NTSYSAPI NTSTATUS NtMakeTemporaryObject(IN HANDLE Handle);

#endif
