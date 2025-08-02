#include "obp.h"

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
    POBJECT_SYMBOLIC_LINK Link = Self;
    assert(Link->LinkTarget);
    assert(Link->LinkTargetObject);
    /* If the Path is non-empty but does not start with a '\\', we need to add one. */
    BOOLEAN AddSep = Path[0] && Path[0] != OBJ_NAME_PATH_SEPARATOR;
    ULONG PathLen = strlen(Path);
    ULONG LinkTargetLen = strlen(Link->LinkTarget);
    ULONG StringLen = LinkTargetLen + PathLen;
    if (AddSep) {
	StringLen++;
    }
    PCHAR NewPath = ExAllocatePoolWithTag(StringLen + 1, OB_PARSE_TAG);
    if (!NewPath) {
	*RemainingPath = Path;
	*FoundObject = NULL;
	return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlCopyMemory(NewPath, Link->LinkTarget, LinkTargetLen);
    if (AddSep) {
	NewPath[LinkTargetLen] = OBJ_NAME_PATH_SEPARATOR;
	RtlCopyMemory(NewPath + LinkTargetLen + 1, Path, PathLen);
    } else {
	RtlCopyMemory(NewPath + LinkTargetLen, Path, PathLen);
    }
    NewPath[StringLen] = '\0';
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
	.OpenProc = NULL,
	.CloseProc = NULL,
	.InsertProc = NULL,
	.RemoveProc = NULL,
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
    if (!(ObjectAttributes.ObjectNameBuffer && ObjectAttributes.ObjectNameBuffer[0])) {
	return STATUS_OBJECT_NAME_INVALID;
    }
    if (ObjectAttributes.RootDirectory) {
	RET_ERR(ObReferenceObjectByHandle(Thread, ObjectAttributes.RootDirectory,
					  OBJECT_TYPE_ANY, &RootDirectory));
    }
    /* The reparse path in the symbolic link object created by this routine is
     * always absolute, ie. with respect to the global root directory. */
    IF_ERR_GOTO(out, Status,
		ObCreateSymbolicLink(LinkTarget, NULL, &Symlink));
    IF_ERR_GOTO(out, Status, ObInsertObject(RootDirectory, Symlink,
					    ObjectAttributes.ObjectNameBuffer, 0));
    /* Note here ObCreateHandle increases the refcount to two (ObInsertObject does
     * NOT increase refcount of the object), making the object permanent as per
     * NT API semantics. */
    IF_ERR_GOTO(out, Status, ObCreateHandle(Thread->Process, Symlink,
					    FALSE, SymbolicLinkHandle));

    Status = STATUS_SUCCESS;

out:
    if (RootDirectory) {
	ObDereferenceObject(RootDirectory);
    }
    if (!NT_SUCCESS(Status) && Symlink) {
	/* ObRemoveObject is a no-op if Symlink is not inserted. */
	ObRemoveObject(Symlink);
	ObDereferenceObject(Symlink);
    }
    return Status;
}

NTSTATUS NtOpenSymbolicLinkObject(IN ASYNC_STATE AsyncState,
                                  IN PTHREAD Thread,
                                  OUT HANDLE *SymbolicLinkHandle,
                                  IN ACCESS_MASK DesiredAccess,
                                  IN OB_OBJECT_ATTRIBUTES ObjectAttributes)
{
    UNIMPLEMENTED;
}
