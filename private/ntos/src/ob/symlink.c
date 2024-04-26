#include "obp.h"
#include "ex.h"
#include "ntrtl.h"
#include "ntstatus.h"
#include "ob.h"
#include "util.h"

typedef struct _OBJECT_SYMBOLIC_LINK {
    PCSTR LinkTarget;		/* String to be reparsed. Owned by this object. */
    POBJECT LinkTargetObject;	/* Object against which the LinkTarget string should be
				 * reparsed. */
} OBJECT_SYMBOLIC_LINK;

typedef struct _OBP_SYMLINK_CREATION_CONTEXT {
    PCSTR LinkTarget;
    POBJECT LinkTargetObject;
} SYMLINK_CREATION_CONTEXT, *PSYMLINK_CREATION_CONTEXT;

static NTSTATUS ObpSymlinkObjectCreateProc(IN POBJECT Self,
					   IN PVOID CreaCtx)
{
    assert(Self);
    assert(CreaCtx);
    POBJECT_SYMBOLIC_LINK Link = Self;
    PSYMLINK_CREATION_CONTEXT Context = CreaCtx;
    PCSTR LinkTarget = Context->LinkTarget;
    assert(LinkTarget);
    if (LinkTarget[0] == OBJ_NAME_PATH_SEPARATOR) {
	LinkTarget++;
    }
    if (!LinkTarget[0]) {
	return STATUS_OBJECT_NAME_INVALID;
    }
    Link->LinkTarget = RtlDuplicateString(LinkTarget, NTOS_OB_TAG);
    if (!Link->LinkTarget) {
	return STATUS_NO_MEMORY;
    }
    if (Context->LinkTargetObject) {
	ObpReferenceObject(Context->LinkTargetObject);
	Link->LinkTargetObject = Context->LinkTargetObject;
    } else {
	ObpReferenceObject(ObpRootObjectDirectory);
	Link->LinkTargetObject = ObpRootObjectDirectory;
    }
    return STATUS_SUCCESS;
}

static NTSTATUS ObpSymlinkObjectParseProc(IN POBJECT Self,
					  IN PCSTR Path,
					  IN BOOLEAN CaseInsensitive,
					  OUT POBJECT *FoundObject,
					  OUT PCSTR *RemainingPath)
{
    assert(Self);
    assert(Path);
    assert(Path[0] != OBJ_NAME_PATH_SEPARATOR);
    POBJECT_SYMBOLIC_LINK Link = Self;
    assert(Link->LinkTarget);
    assert(Link->LinkTargetObject);
    ULONG PathLen = strlen(Path);
    ULONG LinkTargetLen = strlen(Link->LinkTarget);
    ULONG StringSize = LinkTargetLen + 1;
    if (PathLen) {
	StringSize += PathLen + 1;
    }
    PCHAR NewPath = ExAllocatePoolWithTag(StringSize, OB_PARSE_TAG);
    if (!NewPath) {
	*RemainingPath = Path;
	*FoundObject = NULL;
	return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlCopyMemory(NewPath, Link->LinkTarget, LinkTargetLen);
    if (PathLen) {
	NewPath[LinkTargetLen] = OBJ_NAME_PATH_SEPARATOR;
	RtlCopyMemory(NewPath + LinkTargetLen + 1, Path, PathLen);
    }
    NewPath[StringSize-1] = '\0';
    *FoundObject = Link->LinkTargetObject;
    *RemainingPath = NewPath;
    return STATUS_REPARSE_OBJECT;
}

static VOID ObpSymlinkObjectDeleteProc(IN POBJECT Self)
{
    POBJECT_SYMBOLIC_LINK Link = Self;
    assert(Link);
    assert(Link->LinkTarget);
    assert(Link->LinkTargetObject);
    ObpFreePool(Link->LinkTarget);
    ObDereferenceObject(Link->LinkTargetObject);
}

NTSTATUS ObpInitSymlinkObjectType()
{
    OBJECT_TYPE_INITIALIZER TypeInfo = {
	.CreateProc = ObpSymlinkObjectCreateProc,
	.ParseProc = ObpSymlinkObjectParseProc,
	.DeleteProc = ObpSymlinkObjectDeleteProc,
    };
    return ObCreateObjectType(OBJECT_TYPE_SYMBOLIC_LINK,
			      "Symlink",
			      sizeof(OBJECT_SYMBOLIC_LINK),
			      TypeInfo);
}

NTSTATUS ObCreateSymbolicLink(IN PCSTR LinkTarget,
			      IN OPTIONAL POBJECT LinkTargetObject,
			      OUT POBJECT_SYMBOLIC_LINK *Symlink)
{
    SYMLINK_CREATION_CONTEXT CreaCtx = {
	.LinkTarget = LinkTarget,
	.LinkTargetObject = LinkTargetObject
    };
    return ObCreateObject(OBJECT_TYPE_SYMBOLIC_LINK, (PVOID *)Symlink, &CreaCtx);
}

NTSTATUS NtCreateSymbolicLinkObject(IN ASYNC_STATE AsyncState,
                                    IN PTHREAD Thread,
                                    OUT HANDLE *SymbolicLinkHandle,
                                    IN ACCESS_MASK DesiredAccess,
                                    IN OB_OBJECT_ATTRIBUTES ObjectAttributes,
                                    IN PCSTR LinkTarget)
{
    POBJECT_SYMBOLIC_LINK Symlink = NULL;
    POBJECT RootDirectory = NULL;
    NTSTATUS Status = STATUS_NTOS_BUG;
    BOOLEAN Inserted = FALSE;
    /* The reparse path in the symbolic link object created by this routine is
     * always absolute, ie. with respect to the global root directory. */
    RET_ERR(ObCreateSymbolicLink(LinkTarget, NULL, &Symlink));
    if (ObjectAttributes.RootDirectory) {
	IF_ERR_GOTO(out, Status,
		    ObReferenceObjectByHandle(Thread, ObjectAttributes.RootDirectory,
					      OBJECT_TYPE_ANY, RootDirectory));
    }
    if (ObjectAttributes.ObjectNameBuffer && ObjectAttributes.ObjectNameBuffer[0]) {
	IF_ERR_GOTO(out, Status, ObInsertObject(RootDirectory, Symlink,
						ObjectAttributes.ObjectNameBuffer, 0));
	Inserted = TRUE;
    }
    IF_ERR_GOTO(out, Status, ObCreateHandle(Thread->Process, Symlink, SymbolicLinkHandle));

    Status = STATUS_SUCCESS;

out:
    if (RootDirectory) {
	ObDereferenceObject(RootDirectory);
    }
    if (!NT_SUCCESS(Status)) {
	if (Inserted) {
	    ObRemoveObject(Symlink);
	}
	if (Symlink) {
	    ObDereferenceObject(Symlink);
	}
    }
    return Status;
}
