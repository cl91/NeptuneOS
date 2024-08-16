/*
 * Ldr Resource support code
 *
 * Copyright 1995 Thomas Sandford
 * Copyright 1996 Martin von Loewis
 * Copyright 2003 Alexandre Julliard
 * Copyright 1993 Robert J. Amstadt
 * Copyright 1997 Marcus Meissner
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

/* INCLUDES *****************************************************************/

#include <nt.h>

/* FUNCTIONS ****************************************************************/

FORCEINLINE ULONG ExecuteHandlerIfPageFault(ULONG ExceptionCode)
{
    if (ExceptionCode == EXCEPTION_ACCESS_VIOLATION ||
	ExceptionCode == EXCEPTION_PRIV_INSTRUCTION)
	return EXCEPTION_EXECUTE_HANDLER;
    return EXCEPTION_CONTINUE_SEARCH;
}

/**********************************************************************
 * ModuleIsLoadedAsData
 *
 * Check if a module handle is for a LOAD_LIBRARY_AS_DATAFILE module.
 */
FORCEINLINE BOOLEAN ModuleIsLoadedAsData(PVOID BaseAddress)
{
    return (ULONG_PTR)BaseAddress & 1;
}

/**********************************************************************
 * RtlpPushLanguageToList
 *
 * Push a language in the list of languages to try
 */
static ULONG RtlpPushLanguageToList(USHORT *List, ULONG Pos, WORD Lang)
{
    for (ULONG i = 0; i < Pos; i++)
	if (List[i] == Lang)
	    return Pos;
    List[Pos++] = Lang;
    return Pos;
}

/**********************************************************************
 * RtlpFindFirstResourceEntry
 *
 * Find the first suitable entry in a resource directory
 */
static IMAGE_RESOURCE_DIRECTORY *RtlpFindFirstResourceEntry(IMAGE_RESOURCE_DIRECTORY *Dir,
							    void *Root,
							    BOOLEAN WantDir)
{
    const IMAGE_RESOURCE_DIRECTORY_ENTRY *Entry =
	(const IMAGE_RESOURCE_DIRECTORY_ENTRY *)(Dir + 1);

    for (ULONG Pos = 0; Pos < Dir->NumberOfNamedEntries + Dir->NumberOfIdEntries; Pos++) {
	if (!Entry[Pos].DataIsDirectory == !WantDir)
	    return (IMAGE_RESOURCE_DIRECTORY *)((char *)Root +
						Entry[Pos].OffsetToDirectory);
    }
    return NULL;
}

/**********************************************************************
 * RtlpFindResourceEntryById
 *
 * Find an entry by id in a resource directory
 */
static IMAGE_RESOURCE_DIRECTORY *RtlpFindResourceEntryById(IMAGE_RESOURCE_DIRECTORY *Dir,
							   WORD Id,
							   PVOID Root,
							   BOOLEAN WantDir)
{
    const IMAGE_RESOURCE_DIRECTORY_ENTRY *Entry;
    LONG Min, Max, Pos;

    Entry = (const IMAGE_RESOURCE_DIRECTORY_ENTRY *)(Dir + 1);
    Min = Dir->NumberOfNamedEntries;
    Max = Min + Dir->NumberOfIdEntries - 1;
    while (Min <= Max) {
	Pos = (Min + Max) / 2;
	if (!Entry[Pos].Id) {
	    break;
	}
	if (Entry[Pos].Id == Id) {
	    if (!Entry[Pos].DataIsDirectory == !WantDir) {
		DPRINT("root %p dir %p id %04x ret %p\n", Root, Dir, Id,
		       (const char *)Root + Entry[Pos].OffsetToDirectory);
		return (IMAGE_RESOURCE_DIRECTORY *)((char *)Root +
						    Entry[Pos].OffsetToDirectory);
	    }
	    break;
	}
	if (Entry[Pos].Id > Id)
	    Max = Pos - 1;
	else
	    Min = Pos + 1;
    }
    DPRINT("root %p dir %p id %04x not found\n", Root, Dir, Id);
    return NULL;
}

/**********************************************************************
 * RtlpFindResourceEntryByName
 *
 * Find an entry by name in a resource directory
 */
static IMAGE_RESOURCE_DIRECTORY *RtlpFindResourceEntryByName(IMAGE_RESOURCE_DIRECTORY *Dir,
							     LPCWSTR Name,
							     void *Root,
							     BOOLEAN WantDir)
{
    const IMAGE_RESOURCE_DIRECTORY_ENTRY *Entry;
    const IMAGE_RESOURCE_DIR_STRING_U *Str;
    ULONG Min, Max, Res, Pos;
    size_t NameLen;

    if (!((ULONG_PTR)Name & 0xFFFF0000))
	return RtlpFindResourceEntryById(Dir, (ULONG_PTR)Name & 0xFFFF, Root, WantDir);
    Entry = (const IMAGE_RESOURCE_DIRECTORY_ENTRY *)(Dir + 1);
    NameLen = wcslen(Name);
    Min = 0;
    Max = Dir->NumberOfNamedEntries - 1;
    while (Min <= Max) {
	Pos = (Min + Max) / 2;
	Str = (const IMAGE_RESOURCE_DIR_STRING_U *)((const char *)Root +
						    Entry[Pos].NameOffset);
	Res = _wcsnicmp(Name, Str->NameString, Str->Length);
	if (!Res && NameLen == Str->Length) {
	    if (!Entry[Pos].DataIsDirectory == !WantDir) {
		DPRINT("root %p dir %p name %ws ret %p\n", Root, Dir, Name,
		       (const char *)Root + Entry[Pos].OffsetToDirectory);
		return (IMAGE_RESOURCE_DIRECTORY *)((char *)Root +
						    Entry[Pos].OffsetToDirectory);
	    }
	    break;
	}
	if (Res < 0)
	    Max = Pos - 1;
	else
	    Min = Pos + 1;
    }
    DPRINT("root %p dir %p name %ws not found\n", Root, Dir, Name);
    return NULL;
}

/**********************************************************************
 * RtlpFindResourceEntry
 *
 * Find a resource entry
 */
static NTSTATUS RtlpFindResourceEntry(PVOID BaseAddress,
				      LDR_RESOURCE_INFO *Info,
				      ULONG Level,
				      PPVOID Ret,
				      BOOLEAN WantDir)
{
    ULONG Size;
    void *Root;
    IMAGE_RESOURCE_DIRECTORY *ResDirPtr;
    USHORT List[9]; /* list of languages to try */
    ULONG Pos = 0;
    LCID UserLcid, SystemLcid;

    Root = RtlImageDirectoryEntryToData(BaseAddress, TRUE, IMAGE_DIRECTORY_ENTRY_RESOURCE,
					&Size);
    if (!Root)
	return STATUS_RESOURCE_DATA_NOT_FOUND;
    if (Size < sizeof(*ResDirPtr))
	return STATUS_RESOURCE_DATA_NOT_FOUND;
    ResDirPtr = Root;

    if (!Level--)
	goto done;
    if (!(*Ret = RtlpFindResourceEntryByName(ResDirPtr, (LPCWSTR)Info->Type, Root,
					     WantDir || Level)))
	return STATUS_RESOURCE_TYPE_NOT_FOUND;
    if (!Level--)
	return STATUS_SUCCESS;

    ResDirPtr = *Ret;
    if (!(*Ret = RtlpFindResourceEntryByName(ResDirPtr, (LPCWSTR)Info->Name, Root,
					     WantDir || Level)))
	return STATUS_RESOURCE_NAME_NOT_FOUND;
    if (!Level--)
	return STATUS_SUCCESS;
    if (Level)
	return STATUS_INVALID_PARAMETER; /* level > 3 */

    /* 1. specified language */
    Pos = RtlpPushLanguageToList(List, Pos, Info->Language);

    /* 2. specified language with neutral sublanguage */
    Pos = RtlpPushLanguageToList(List, Pos,
			MAKELANGID(PRIMARYLANGID(Info->Language), SUBLANG_NEUTRAL));

    /* 3. neutral language with neutral sublanguage */
    Pos = RtlpPushLanguageToList(List, Pos, MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL));

    /* if no explicitly specified language, try some defaults */
    if (PRIMARYLANGID(Info->Language) == LANG_NEUTRAL) {
	/* user defaults, unless SYS_DEFAULT sublanguage specified  */
	if (SUBLANGID(Info->Language) != SUBLANG_SYS_DEFAULT) {
	    /* 4. current thread locale language */
	    Pos = RtlpPushLanguageToList(List, Pos, LANGIDFROMLCID(NtCurrentTeb()->CurrentLocale));

	    if (NT_SUCCESS(NtQueryDefaultLocale(TRUE, &UserLcid))) {
		/* 5. user locale language */
		Pos = RtlpPushLanguageToList(List, Pos, LANGIDFROMLCID(UserLcid));

		/* 6. user locale language with neutral sublanguage  */
		Pos = RtlpPushLanguageToList(List, Pos,
				    MAKELANGID(PRIMARYLANGID(UserLcid),
					       SUBLANG_NEUTRAL));
	    }
	}

	/* now system defaults */

	if (NT_SUCCESS(NtQueryDefaultLocale(FALSE, &SystemLcid))) {
	    /* 7. system locale language */
	    Pos = RtlpPushLanguageToList(List, Pos, LANGIDFROMLCID(SystemLcid));

	    /* 8. system locale language with neutral sublanguage */
	    Pos = RtlpPushLanguageToList(List, Pos,
				MAKELANGID(PRIMARYLANGID(SystemLcid), SUBLANG_NEUTRAL));
	}

	/* 9. English */
	Pos = RtlpPushLanguageToList(List, Pos, MAKELANGID(LANG_ENGLISH, SUBLANG_DEFAULT));
    }

    ResDirPtr = *Ret;
    for (ULONG i = 0; i < Pos; i++)
	if ((*Ret = RtlpFindResourceEntryById(ResDirPtr, List[i], Root, WantDir)))
	    return STATUS_SUCCESS;

    /* if no explicitly specified language, return the first entry */
    if (PRIMARYLANGID(Info->Language) == LANG_NEUTRAL) {
	if ((*Ret = RtlpFindFirstResourceEntry(ResDirPtr, Root, WantDir)))
	    return STATUS_SUCCESS;
    }
    return STATUS_RESOURCE_LANG_NOT_FOUND;

done:
    *Ret = ResDirPtr;
    return STATUS_SUCCESS;
}

static NTSTATUS LdrpAccessResource(PVOID BaseAddress, IMAGE_RESOURCE_DATA_ENTRY *Entry,
				   PVOID *Ptr, ULONG *Size)
{
    NTSTATUS Status = STATUS_SUCCESS;

    __try {
	ULONG DirSize;

	if (!RtlImageDirectoryEntryToData(BaseAddress, TRUE,
					  IMAGE_DIRECTORY_ENTRY_RESOURCE, &DirSize)) {
	    Status = STATUS_RESOURCE_DATA_NOT_FOUND;
	} else {
	    if (Ptr) {
		if (ModuleIsLoadedAsData(BaseAddress)) {
		    PVOID Mod = (PVOID)((ULONG_PTR)BaseAddress & ~1);
		    *Ptr = RtlImageRvaToVa(RtlImageNtHeader(Mod), Mod,
					   Entry->OffsetToData, NULL);
		} else
		    *Ptr = (char *)BaseAddress + Entry->OffsetToData;
	    }
	    if (Size)
		*Size = Entry->Size;
	}
    } __except(ExecuteHandlerIfPageFault(GetExceptionCode())) {
	Status = GetExceptionCode();
    }
    return Status;
}

/*
 * @implemented
 */
NTAPI NTSTATUS LdrFindResource_U(PVOID BaseAddress,
				 PLDR_RESOURCE_INFO ResourceInfo,
				 ULONG Level,
				 PIMAGE_RESOURCE_DATA_ENTRY *ResourceDataEntry)
{
    void *Res;
    NTSTATUS Status = STATUS_SUCCESS;

    __try {
	if (ResourceInfo) {
	    DPRINT("module %p type %zx name %zx lang %04zx level %u\n", BaseAddress,
		   ResourceInfo->Type, Level > 1 ? ResourceInfo->Name : 0,
		   Level > 2 ? ResourceInfo->Language : 0, Level);
	}

	Status = RtlpFindResourceEntry(BaseAddress, ResourceInfo, Level, &Res, FALSE);
	if (NT_SUCCESS(Status))
	    *ResourceDataEntry = Res;
    } __except(ExecuteHandlerIfPageFault(GetExceptionCode())) {
	Status = GetExceptionCode();
    }
    return Status;
}

/*
 * @implemented
 */
NTAPI NTSTATUS LdrAccessResource(IN PVOID BaseAddress,
				 IN PIMAGE_RESOURCE_DATA_ENTRY ResourceDataEntry,
				 OUT PVOID *Resource OPTIONAL,
				 OUT PULONG Size OPTIONAL)
{
    return LdrpAccessResource(BaseAddress, ResourceDataEntry, Resource, Size);
}

/*
 * @implemented
 */
NTAPI NTSTATUS LdrFindResourceDirectory_U(IN PVOID BaseAddress,
					  IN PLDR_RESOURCE_INFO Info, IN ULONG Level,
					  OUT PIMAGE_RESOURCE_DIRECTORY *Addr)
{
    PVOID Res;
    NTSTATUS Status = STATUS_SUCCESS;

    __try {
	if (Info) {
	    DPRINT("module %p type %ws name %ws lang %04zx level %u\n", BaseAddress,
		   (LPCWSTR)Info->Type, Level > 1 ? (LPCWSTR)Info->Name : L"",
		   Level > 2 ? Info->Language : 0, Level);
	}

	Status = RtlpFindResourceEntry(BaseAddress, Info, Level, &Res, TRUE);
	if (NT_SUCCESS(Status))
	    *Addr = Res;
    } __except(ExecuteHandlerIfPageFault(GetExceptionCode())) {
	Status = GetExceptionCode();
    }
    return Status;
}

#define NAME_FROM_RESOURCE_ENTRY(RootDirectory, Entry)                          \
    ((Entry)->NameIsString ? (ULONG_PTR)(RootDirectory) + (Entry)->NameOffset : \
			     (Entry)->Id)

static LONG LdrpCompareResourceNames_U(IN PUCHAR ResourceData,
				       IN PIMAGE_RESOURCE_DIRECTORY_ENTRY Entry,
				       IN ULONG_PTR CompareName)
{
    PIMAGE_RESOURCE_DIR_STRING_U ResourceString;
    PWSTR String1, String2;
    USHORT ResourceStringLength;
    WCHAR Char1, Char2;

    /* Check if the resource name is an ID */
    if (CompareName <= USHRT_MAX) {
	/* Just compare the 2 IDs */
	return (CompareName - Entry->Id);
    } else {
	/* Get the resource string */
	ResourceString = (PIMAGE_RESOURCE_DIR_STRING_U)(ResourceData + Entry->NameOffset);

	/* Get the string length */
	ResourceStringLength = ResourceString->Length;

	String1 = ResourceString->NameString;
	String2 = (PWSTR)CompareName;

	/* Loop all characters of the resource string */
	while (ResourceStringLength--) {
	    /* Get the next characters */
	    Char1 = *String1++;
	    Char2 = *String2++;

	    /* Check if they don't match, or if the compare string ends */
	    if ((Char1 != Char2) || (Char2 == 0)) {
		/* They don't match, fail */
		return Char2 - Char1;
	    }
	}

	/* All characters match, check if the compare string ends here */
	return (*String2 == 0) ? 0 : 1;
    }
}

NTAPI NTSTATUS LdrEnumResources(IN PVOID ImageBase,
				IN PLDR_RESOURCE_INFO ResourceInfo,
				IN ULONG Level,
				IN OUT ULONG *ResourceCount,
				OUT LDR_ENUM_RESOURCE_INFO *Resources)
{
    PUCHAR ResourceData;
    NTSTATUS Status;
    ULONG NumberOfTypeEntries, NumberOfNameEntries, NumberOfLangEntries;
    ULONG Count, MaxResourceCount;
    PIMAGE_RESOURCE_DIRECTORY TypeDirectory, NameDirectory, LangDirectory;
    PIMAGE_RESOURCE_DIRECTORY_ENTRY TypeEntry, NameEntry, LangEntry;
    PIMAGE_RESOURCE_DATA_ENTRY DataEntry;
    ULONG Size;
    LONG Result;

    /* If the caller wants data, get the maximum count of entries */
    MaxResourceCount = (Resources != NULL) ? *ResourceCount : 0;

    /* Default to 0 */
    *ResourceCount = 0;

    /* Locate the resource directory */
    ResourceData = RtlImageDirectoryEntryToData(ImageBase, TRUE,
						IMAGE_DIRECTORY_ENTRY_RESOURCE, &Size);
    if (ResourceData == NULL)
	return STATUS_RESOURCE_DATA_NOT_FOUND;

    /* The type directory is at the root, followed by the entries */
    TypeDirectory = (PIMAGE_RESOURCE_DIRECTORY)ResourceData;
    TypeEntry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(TypeDirectory + 1);

    /* Get the number of entries in the type directory */
    NumberOfTypeEntries = TypeDirectory->NumberOfNamedEntries +
			  TypeDirectory->NumberOfIdEntries;

    /* Start with 0 resources and status success */
    Status = STATUS_SUCCESS;
    Count = 0;

    /* Loop all entries in the type directory */
    for (ULONG i = 0; i < NumberOfTypeEntries; ++i, ++TypeEntry) {
	/* Check if comparison of types is requested */
	if (Level > RESOURCE_TYPE_LEVEL) {
	    /* Compare the type with the requested Type */
	    Result = LdrpCompareResourceNames_U(ResourceData, TypeEntry,
						ResourceInfo->Type);

	    /* Not equal, continue with next entry */
	    if (Result != 0)
		continue;
	}

	/* The entry must point to the name directory */
	if (!TypeEntry->DataIsDirectory) {
	    return STATUS_INVALID_IMAGE_FORMAT;
	}

	/* Get a pointer to the name subdirectory and it's first entry */
	NameDirectory = (PIMAGE_RESOURCE_DIRECTORY)(ResourceData + TypeEntry->OffsetToDirectory);
	NameEntry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(NameDirectory + 1);

	/* Get the number of entries in the name directory */
	NumberOfNameEntries = NameDirectory->NumberOfNamedEntries +
			      NameDirectory->NumberOfIdEntries;

	/* Loop all entries in the name directory */
	for (ULONG j = 0; j < NumberOfNameEntries; ++j, ++NameEntry) {
	    /* Check if comparison of names is requested */
	    if (Level > RESOURCE_NAME_LEVEL) {
		/* Compare the name with the requested name */
		Result = LdrpCompareResourceNames_U(ResourceData, NameEntry,
						    ResourceInfo->Name);

		/* Not equal, continue with next entry */
		if (Result != 0)
		    continue;
	    }

	    /* The entry must point to the language directory */
	    if (!NameEntry->DataIsDirectory) {
		return STATUS_INVALID_IMAGE_FORMAT;
	    }

	    /* Get a pointer to the language subdirectory and it's first entry */
	    LangDirectory = (PIMAGE_RESOURCE_DIRECTORY)(ResourceData +
							NameEntry->OffsetToDirectory);
	    LangEntry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(LangDirectory + 1);

	    /* Get the number of entries in the language directory */
	    NumberOfLangEntries = LangDirectory->NumberOfNamedEntries +
				  LangDirectory->NumberOfIdEntries;

	    /* Loop all entries in the language directory */
	    for (ULONG k = 0; k < NumberOfLangEntries; ++k, ++LangEntry) {
		/* Check if comparison of languages is requested */
		if (Level > RESOURCE_LANGUAGE_LEVEL) {
		    /* Compare the language with the requested language */
		    Result = LdrpCompareResourceNames_U(ResourceData, LangEntry,
							ResourceInfo->Language);

		    /* Not equal, continue with next entry */
		    if (Result != 0)
			continue;
		}

		/* This entry must point to data */
		if (LangEntry->DataIsDirectory) {
		    return STATUS_INVALID_IMAGE_FORMAT;
		}

		/* Get a pointer to the data entry */
		DataEntry = (PIMAGE_RESOURCE_DATA_ENTRY)(ResourceData + LangEntry->OffsetToData);

		/* Check if there is still space to store the data */
		if (Count < MaxResourceCount) {
		    /* There is, fill the entry */
		    Resources[Count].Type = NAME_FROM_RESOURCE_ENTRY(ResourceData, TypeEntry);
		    Resources[Count].Name = NAME_FROM_RESOURCE_ENTRY(ResourceData, NameEntry);
		    Resources[Count].Language = NAME_FROM_RESOURCE_ENTRY(ResourceData, LangEntry);
		    Resources[Count].Data = (PUCHAR)ImageBase + DataEntry->OffsetToData;
		    Resources[Count].Reserved = 0;
		    Resources[Count].Size = DataEntry->Size;
		} else {
		    /* There is not enough space, save error status */
		    Status = STATUS_INFO_LENGTH_MISMATCH;
		}

		/* Count this resource */
		++Count;
	    }
	}
    }

    /* Return the number of matching resources */
    *ResourceCount = Count;
    return Status;
}
