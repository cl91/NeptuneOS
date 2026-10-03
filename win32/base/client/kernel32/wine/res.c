/*
 * Resources
 *
 * Copyright 1993 Robert J. Amstadt
 * Copyright 1995, 2003 Alexandre Julliard
 * Copyright 2006 Mike McCormack
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
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#include <k32.h>
DEBUG_CHANNEL(resource);

#define LIST_FOR_EACH_ENTRY(Entry, ListHead, Type, Member)		\
    for ((Entry) = CONTAINING_RECORD((ListHead)->Flink, Type, Member);		\
	 &(Entry)->Member != (ListHead);				\
	 (Entry) = CONTAINING_RECORD((Entry)->Member.Flink, Type, Member))

/* retrieve the resource name to pass to the ntdll functions */
static NTSTATUS BasepGetResNameA(LPCSTR Name, UNICODE_STRING *Str)
{
    if (IS_INTRESOURCE(Name)) {
	Str->Buffer = ULongToPtr(LOWORD(Name));
	return STATUS_SUCCESS;
    }
    if (Name[0] == '#') {
	ULONG Value;
	if (RtlCharToInteger(Name + 1, 10, &Value) != STATUS_SUCCESS || HIWORD(Value))
	    return STATUS_INVALID_PARAMETER;
	Str->Buffer = ULongToPtr(Value);
	return STATUS_SUCCESS;
    }
    RtlCreateUnicodeStringFromAsciiz(Str, Name);
    RtlUpcaseUnicodeString(Str, Str, FALSE);
    return STATUS_SUCCESS;
}

/* retrieve the resource name to pass to the ntdll functions */
static NTSTATUS BasepGetResNameW(LPCWSTR Name, UNICODE_STRING *Str)
{
    if (IS_INTRESOURCE(Name)) {
	Str->Buffer = ULongToPtr(LOWORD(Name));
	return STATUS_SUCCESS;
    }
    if (Name[0] == '#') {
	ULONG Value;
	RtlInitUnicodeString(Str, Name + 1);
	if (RtlUnicodeStringToInteger(Str, 10, &Value) != STATUS_SUCCESS || HIWORD(Value))
	    return STATUS_INVALID_PARAMETER;
	Str->Buffer = ULongToPtr(Value);
	return STATUS_SUCCESS;
    }
    RtlCreateUnicodeString(Str, Name);
    RtlUpcaseUnicodeString(Str, Str, FALSE);
    return STATUS_SUCCESS;
}

/* implementation of FindResourceExA */
static HRSRC BasepFindResourceA(HMODULE hModule, LPCSTR Type, LPCSTR Name, WORD Lang)
{
    NTSTATUS Status;
    UNICODE_STRING NameW, TypeW;
    LDR_RESOURCE_INFO Info;
    IMAGE_RESOURCE_DATA_ENTRY *Entry = NULL;

    NameW.Buffer = NULL;
    TypeW.Buffer = NULL;

    __TRY
    {
	if ((Status = BasepGetResNameA(Name, &NameW)) != STATUS_SUCCESS)
	    goto done;
	if ((Status = BasepGetResNameA(Type, &TypeW)) != STATUS_SUCCESS)
	    goto done;
	Info.Type = (ULONG_PTR)TypeW.Buffer;
	Info.Name = (ULONG_PTR)NameW.Buffer;
	Info.Language = Lang;
	Status = LdrFindResource_U(hModule, &Info, 3, &Entry);
    done:
	if (Status != STATUS_SUCCESS)
	    SetLastError(RtlNtStatusToDosError(Status));
    }
    __EXCEPT_PAGE_FAULT
    {
	SetLastError(ERROR_INVALID_PARAMETER);
    }
    __ENDTRY

    if (!IS_INTRESOURCE(NameW.Buffer))
	HeapFree(GetProcessHeap(), 0, NameW.Buffer);
    if (!IS_INTRESOURCE(TypeW.Buffer))
	HeapFree(GetProcessHeap(), 0, TypeW.Buffer);
    return (HRSRC)Entry;
}

/* implementation of FindResourceExW */
static HRSRC BasepFindResourceW(HMODULE hModule, LPCWSTR Type, LPCWSTR Name, WORD Lang)
{
    NTSTATUS Status;
    UNICODE_STRING NameW, TypeW;
    LDR_RESOURCE_INFO Info;
    IMAGE_RESOURCE_DATA_ENTRY *Entry = NULL;

    NameW.Buffer = TypeW.Buffer = NULL;

    __TRY
    {
	if ((Status = BasepGetResNameW(Name, &NameW)) != STATUS_SUCCESS)
	    goto done;
	if ((Status = BasepGetResNameW(Type, &TypeW)) != STATUS_SUCCESS)
	    goto done;
	Info.Type = (ULONG_PTR)TypeW.Buffer;
	Info.Name = (ULONG_PTR)NameW.Buffer;
	Info.Language = Lang;
	Status = LdrFindResource_U(hModule, &Info, 3, &Entry);
    done:
	if (Status != STATUS_SUCCESS)
	    SetLastError(RtlNtStatusToDosError(Status));
    }
    __EXCEPT_PAGE_FAULT
    {
	SetLastError(ERROR_INVALID_PARAMETER);
    }
    __ENDTRY

    if (!IS_INTRESOURCE(NameW.Buffer))
	HeapFree(GetProcessHeap(), 0, NameW.Buffer);
    if (!IS_INTRESOURCE(TypeW.Buffer))
	HeapFree(GetProcessHeap(), 0, TypeW.Buffer);
    return (HRSRC)Entry;
}

/**********************************************************************
 *	    FindResourceExA  (KERNEL32.@)
 */
WINAPI HRSRC FindResourceExA(HMODULE hModule, LPCSTR Type, LPCSTR Name, WORD Lang)
{
    TRACE("%p %s %s %04x\n", hModule, debugstr_a(type), debugstr_a(name), lang);

    if (!hModule)
	hModule = GetModuleHandleW(0);
    return BasepFindResourceA(hModule, Type, Name, Lang);
}

/**********************************************************************
 *	    FindResourceA    (KERNEL32.@)
 */
WINAPI HRSRC FindResourceA(HMODULE hModule, LPCSTR Name, LPCSTR Type)
{
    return FindResourceExA(hModule, Type, Name,
			   MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL));
}

/**********************************************************************
 *	    FindResourceExW  (KERNEL32.@)
 */
WINAPI HRSRC FindResourceExW(HMODULE hModule, LPCWSTR Type, LPCWSTR Name, WORD Lang)
{
    TRACE("%p %s %s %04x\n", hModule, debugstr_w(type), debugstr_w(name), lang);

    if (!hModule)
	hModule = GetModuleHandleW(0);
    return BasepFindResourceW(hModule, Type, Name, Lang);
}

/**********************************************************************
 *	    FindResourceW    (KERNEL32.@)
 */
WINAPI HRSRC FindResourceW(HINSTANCE hModule, LPCWSTR Name, LPCWSTR Type)
{
    return FindResourceExW(hModule, Type, Name,
			   MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL));
}

/**********************************************************************
 *	EnumResourceTypesA	(KERNEL32.@)
 */
WINAPI BOOL EnumResourceTypesA(HMODULE Hmod, ENUMRESTYPEPROCA Lpfun, LONG_PTR Lparam)
{
    int i;
    BOOL Ret = FALSE;
    LPSTR Type = NULL;
    DWORD Len = 0, Newlen;
    NTSTATUS Status;
    IMAGE_RESOURCE_DIRECTORY *Resdir;
    const IMAGE_RESOURCE_DIRECTORY_ENTRY *Et;
    const IMAGE_RESOURCE_DIR_STRING_U *Str;

    TRACE("%p %p %lx\n", hmod, lpfun, lparam);

    if (!Hmod)
	Hmod = GetModuleHandleA(NULL);

    if ((Status = LdrFindResourceDirectory_U(Hmod, NULL, 0, &Resdir)) != STATUS_SUCCESS) {
	SetLastError(RtlNtStatusToDosError(Status));
	return FALSE;
    }
    Et = (const IMAGE_RESOURCE_DIRECTORY_ENTRY *)(Resdir + 1);
    for (i = 0; i < Resdir->NumberOfNamedEntries + Resdir->NumberOfIdEntries; i++) {
	if (Et[i].NameIsString) {
	    Str = (const IMAGE_RESOURCE_DIR_STRING_U *)((const BYTE *)Resdir +
							Et[i].NameOffset);
	    Newlen = WideCharToMultiByte(CP_ACP, 0, Str->NameString, Str->Length, NULL, 0,
					 NULL, NULL);
	    if (Newlen + 1 > Len) {
		Len = Newlen + 1;
		HeapFree(GetProcessHeap(), 0, Type);
		if (!(Type = HeapAlloc(GetProcessHeap(), 0, Len)))
		    return FALSE;
	    }
	    WideCharToMultiByte(CP_ACP, 0, Str->NameString, Str->Length, Type, Len, NULL,
				NULL);
	    Type[Newlen] = 0;
	    Ret = Lpfun(Hmod, Type, Lparam);
	} else {
	    Ret = Lpfun(Hmod, UIntToPtr(Et[i].Id), Lparam);
	}
	if (!Ret)
	    break;
    }
    HeapFree(GetProcessHeap(), 0, Type);
    return Ret;
}

/**********************************************************************
 *	EnumResourceTypesW	(KERNEL32.@)
 */
WINAPI BOOL EnumResourceTypesW(HMODULE Hmod, ENUMRESTYPEPROCW Lpfun, LONG_PTR Lparam)
{
    int i, Len = 0;
    BOOL Ret = FALSE;
    LPWSTR Type = NULL;
    NTSTATUS Status;
    IMAGE_RESOURCE_DIRECTORY *Resdir;
    const IMAGE_RESOURCE_DIRECTORY_ENTRY *Et;
    const IMAGE_RESOURCE_DIR_STRING_U *Str;

    TRACE("%p %p %lx\n", hmod, lpfun, lparam);

    if (!Hmod)
	Hmod = GetModuleHandleW(NULL);

    if ((Status = LdrFindResourceDirectory_U(Hmod, NULL, 0, &Resdir)) != STATUS_SUCCESS) {
	SetLastError(RtlNtStatusToDosError(Status));
	return FALSE;
    }
    Et = (const IMAGE_RESOURCE_DIRECTORY_ENTRY *)(Resdir + 1);
    for (i = 0; i < Resdir->NumberOfNamedEntries + Resdir->NumberOfIdEntries; i++) {
	if (Et[i].NameIsString) {
	    Str = (const IMAGE_RESOURCE_DIR_STRING_U *)((const BYTE *)Resdir +
							Et[i].NameOffset);
	    if (Str->Length + 1 > Len) {
		Len = Str->Length + 1;
		HeapFree(GetProcessHeap(), 0, Type);
		if (!(Type = HeapAlloc(GetProcessHeap(), 0, Len * sizeof(WCHAR))))
		    return FALSE;
	    }
	    memcpy(Type, Str->NameString, Str->Length * sizeof(WCHAR));
	    Type[Str->Length] = 0;
	    Ret = Lpfun(Hmod, Type, Lparam);
	} else {
	    Ret = Lpfun(Hmod, UIntToPtr(Et[i].Id), Lparam);
	}
	if (!Ret)
	    break;
    }
    HeapFree(GetProcessHeap(), 0, Type);
    return Ret;
}

/**********************************************************************
 *	EnumResourceNamesA	(KERNEL32.@)
 */
WINAPI BOOL EnumResourceNamesA(HMODULE Hmod, LPCSTR Type, ENUMRESNAMEPROCA Lpfun,
			       LONG_PTR Lparam)
{
    int i;
    BOOL Ret = FALSE;
    DWORD Len = 0, Newlen;
    LPSTR Name = NULL;
    NTSTATUS Status;
    UNICODE_STRING TypeW;
    LDR_RESOURCE_INFO Info;
    IMAGE_RESOURCE_DIRECTORY *Basedir, *Resdir;
    const IMAGE_RESOURCE_DIRECTORY_ENTRY *Et;
    const IMAGE_RESOURCE_DIR_STRING_U *Str;

    TRACE("%p %s %p %lx\n", hmod, debugstr_a(type), lpfun, lparam);

    if (!Hmod)
	Hmod = GetModuleHandleA(NULL);
    TypeW.Buffer = NULL;
    if ((Status = LdrFindResourceDirectory_U(Hmod, NULL, 0, &Basedir)) != STATUS_SUCCESS)
	goto done;
    if ((Status = BasepGetResNameA(Type, &TypeW)) != STATUS_SUCCESS)
	goto done;
    Info.Type = (ULONG_PTR)TypeW.Buffer;
    if ((Status = LdrFindResourceDirectory_U(Hmod, &Info, 1, &Resdir)) != STATUS_SUCCESS)
	goto done;

    Et = (const IMAGE_RESOURCE_DIRECTORY_ENTRY *)(Resdir + 1);
    __TRY
    {
	for (i = 0; i < Resdir->NumberOfNamedEntries + Resdir->NumberOfIdEntries; i++) {
	    if (Et[i].NameIsString) {
		Str = (const IMAGE_RESOURCE_DIR_STRING_U *)((const BYTE *)Basedir +
							    Et[i].NameOffset);
		Newlen = WideCharToMultiByte(CP_ACP, 0, Str->NameString, Str->Length,
					     NULL, 0, NULL, NULL);
		if (Newlen + 1 > Len) {
		    Len = Newlen + 1;
		    HeapFree(GetProcessHeap(), 0, Name);
		    if (!(Name = HeapAlloc(GetProcessHeap(), 0, Len + 1))) {
			Ret = FALSE;
			break;
		    }
		}
		WideCharToMultiByte(CP_ACP, 0, Str->NameString, Str->Length, Name, Len,
				    NULL, NULL);
		Name[Newlen] = 0;
		Ret = Lpfun(Hmod, Type, Name, Lparam);
	    } else {
		Ret = Lpfun(Hmod, Type, UIntToPtr(Et[i].Id), Lparam);
	    }
	    if (!Ret)
		break;
	}
    }
    __EXCEPT_PAGE_FAULT
    {
	Ret = FALSE;
	Status = STATUS_ACCESS_VIOLATION;
    }
    __ENDTRY;

done:
    HeapFree(GetProcessHeap(), 0, Name);
    if (!IS_INTRESOURCE(TypeW.Buffer))
	HeapFree(GetProcessHeap(), 0, TypeW.Buffer);
    if (Status != STATUS_SUCCESS)
	SetLastError(RtlNtStatusToDosError(Status));
    return Ret;
}

/**********************************************************************
 *	EnumResourceNamesW	(KERNEL32.@)
 */
WINAPI BOOL EnumResourceNamesW(HMODULE Hmod, LPCWSTR Type, ENUMRESNAMEPROCW Lpfun,
			       LONG_PTR Lparam)
{
    int i, Len = 0;
    BOOL Ret = FALSE;
    LPWSTR Name = NULL;
    NTSTATUS Status;
    UNICODE_STRING TypeW;
    LDR_RESOURCE_INFO Info;
    IMAGE_RESOURCE_DIRECTORY *Basedir, *Resdir;
    const IMAGE_RESOURCE_DIRECTORY_ENTRY *Et;
    const IMAGE_RESOURCE_DIR_STRING_U *Str;

    TRACE("%p %s %p %lx\n", hmod, debugstr_w(type), lpfun, lparam);

    if (!Hmod)
	Hmod = GetModuleHandleW(NULL);
    TypeW.Buffer = NULL;
    if ((Status = LdrFindResourceDirectory_U(Hmod, NULL, 0, &Basedir)) != STATUS_SUCCESS)
	goto done;
    if ((Status = BasepGetResNameW(Type, &TypeW)) != STATUS_SUCCESS)
	goto done;
    Info.Type = (ULONG_PTR)TypeW.Buffer;
    if ((Status = LdrFindResourceDirectory_U(Hmod, &Info, 1, &Resdir)) != STATUS_SUCCESS)
	goto done;

    Et = (const IMAGE_RESOURCE_DIRECTORY_ENTRY *)(Resdir + 1);
    __TRY
    {
	for (i = 0; i < Resdir->NumberOfNamedEntries + Resdir->NumberOfIdEntries; i++) {
	    if (Et[i].NameIsString) {
		Str = (const IMAGE_RESOURCE_DIR_STRING_U *)((const BYTE *)Basedir +
							    Et[i].NameOffset);
		if (Str->Length + 1 > Len) {
		    Len = Str->Length + 1;
		    HeapFree(GetProcessHeap(), 0, Name);
		    if (!(Name = HeapAlloc(GetProcessHeap(), 0, Len * sizeof(WCHAR)))) {
			Ret = FALSE;
			break;
		    }
		}
		memcpy(Name, Str->NameString, Str->Length * sizeof(WCHAR));
		Name[Str->Length] = 0;
		Ret = Lpfun(Hmod, Type, Name, Lparam);
	    } else {
		Ret = Lpfun(Hmod, Type, UIntToPtr(Et[i].Id), Lparam);
	    }
	    if (!Ret)
		break;
	}
    }
    __EXCEPT_PAGE_FAULT
    {
	Ret = FALSE;
	Status = STATUS_ACCESS_VIOLATION;
    }
    __ENDTRY
done:
    HeapFree(GetProcessHeap(), 0, Name);
    if (!IS_INTRESOURCE(TypeW.Buffer))
	HeapFree(GetProcessHeap(), 0, TypeW.Buffer);
    if (Status != STATUS_SUCCESS)
	SetLastError(RtlNtStatusToDosError(Status));
    return Ret;
}

/**********************************************************************
 *	EnumResourceLanguagesA	(KERNEL32.@)
 */
WINAPI BOOL EnumResourceLanguagesA(HMODULE Hmod, LPCSTR Type, LPCSTR Name,
				   ENUMRESLANGPROCA Lpfun, LONG_PTR Lparam)
{
    int i;
    BOOL Ret = FALSE;
    NTSTATUS Status;
    UNICODE_STRING TypeW, NameW;
    LDR_RESOURCE_INFO Info;
    IMAGE_RESOURCE_DIRECTORY *Basedir, *Resdir;
    const IMAGE_RESOURCE_DIRECTORY_ENTRY *Et;

    TRACE("%p %s %s %p %lx\n", hmod, debugstr_a(type), debugstr_a(name), lpfun, lparam);

    if (!Hmod)
	Hmod = GetModuleHandleA(NULL);
    TypeW.Buffer = NameW.Buffer = NULL;
    if ((Status = LdrFindResourceDirectory_U(Hmod, NULL, 0, &Basedir)) != STATUS_SUCCESS)
	goto done;
    if ((Status = BasepGetResNameA(Type, &TypeW)) != STATUS_SUCCESS)
	goto done;
    if ((Status = BasepGetResNameA(Name, &NameW)) != STATUS_SUCCESS)
	goto done;
    Info.Type = (ULONG_PTR)TypeW.Buffer;
    Info.Name = (ULONG_PTR)NameW.Buffer;
    if ((Status = LdrFindResourceDirectory_U(Hmod, &Info, 2, &Resdir)) != STATUS_SUCCESS)
	goto done;

    Et = (const IMAGE_RESOURCE_DIRECTORY_ENTRY *)(Resdir + 1);
    __TRY
    {
	for (i = 0; i < Resdir->NumberOfNamedEntries + Resdir->NumberOfIdEntries; i++) {
	    Ret = Lpfun(Hmod, Type, Name, Et[i].Id, Lparam);
	    if (!Ret)
		break;
	}
    }
    __EXCEPT_PAGE_FAULT
    {
	Ret = FALSE;
	Status = STATUS_ACCESS_VIOLATION;
    }
    __ENDTRY
done:
    if (!IS_INTRESOURCE(TypeW.Buffer))
	HeapFree(GetProcessHeap(), 0, TypeW.Buffer);
    if (!IS_INTRESOURCE(NameW.Buffer))
	HeapFree(GetProcessHeap(), 0, NameW.Buffer);
    if (Status != STATUS_SUCCESS)
	SetLastError(RtlNtStatusToDosError(Status));
    return Ret;
}

/**********************************************************************
 *	EnumResourceLanguagesW	(KERNEL32.@)
 */
WINAPI BOOL EnumResourceLanguagesW(HMODULE Hmod, LPCWSTR Type, LPCWSTR Name,
				   ENUMRESLANGPROCW Lpfun, LONG_PTR Lparam)
{
    int i;
    BOOL Ret = FALSE;
    NTSTATUS Status;
    UNICODE_STRING TypeW, NameW;
    LDR_RESOURCE_INFO Info;
    IMAGE_RESOURCE_DIRECTORY *Basedir, *Resdir;
    const IMAGE_RESOURCE_DIRECTORY_ENTRY *Et;

    TRACE("%p %s %s %p %lx\n", hmod, debugstr_w(type), debugstr_w(name), lpfun, lparam);

    if (!Hmod)
	Hmod = GetModuleHandleW(NULL);
    TypeW.Buffer = NameW.Buffer = NULL;
    if ((Status = LdrFindResourceDirectory_U(Hmod, NULL, 0, &Basedir)) != STATUS_SUCCESS)
	goto done;
    if ((Status = BasepGetResNameW(Type, &TypeW)) != STATUS_SUCCESS)
	goto done;
    if ((Status = BasepGetResNameW(Name, &NameW)) != STATUS_SUCCESS)
	goto done;
    Info.Type = (ULONG_PTR)TypeW.Buffer;
    Info.Name = (ULONG_PTR)NameW.Buffer;
    if ((Status = LdrFindResourceDirectory_U(Hmod, &Info, 2, &Resdir)) != STATUS_SUCCESS)
	goto done;

    Et = (const IMAGE_RESOURCE_DIRECTORY_ENTRY *)(Resdir + 1);
    __TRY
    {
	for (i = 0; i < Resdir->NumberOfNamedEntries + Resdir->NumberOfIdEntries; i++) {
	    Ret = Lpfun(Hmod, Type, Name, Et[i].Id, Lparam);
	    if (!Ret)
		break;
	}
    }
    __EXCEPT_PAGE_FAULT
    {
	Ret = FALSE;
	Status = STATUS_ACCESS_VIOLATION;
    }
    __ENDTRY
done:
    if (!IS_INTRESOURCE(TypeW.Buffer))
	HeapFree(GetProcessHeap(), 0, TypeW.Buffer);
    if (!IS_INTRESOURCE(NameW.Buffer))
	HeapFree(GetProcessHeap(), 0, NameW.Buffer);
    if (Status != STATUS_SUCCESS)
	SetLastError(RtlNtStatusToDosError(Status));
    return Ret;
}

/**********************************************************************
 *	    LoadResource     (KERNEL32.@)
 */
WINAPI HGLOBAL LoadResource(HINSTANCE hModule, HRSRC hRsrc)
{
    NTSTATUS Status;
    void *Ret = NULL;

    TRACE("%p %p\n", hModule, hRsrc);

    if (!hRsrc)
	return 0;
    if (!hModule)
	hModule = GetModuleHandleA(NULL);
    Status = LdrAccessResource(hModule, (IMAGE_RESOURCE_DATA_ENTRY *)hRsrc, &Ret, NULL);
    if (Status != STATUS_SUCCESS)
	SetLastError(RtlNtStatusToDosError(Status));
    return Ret;
}

/**********************************************************************
 *	    LockResource     (KERNEL32.@)
 */
WINAPI LPVOID LockResource(HGLOBAL Handle)
{
    return Handle;
}

/**********************************************************************
 *	    FreeResource     (KERNEL32.@)
 */
WINAPI BOOL FreeResource(HGLOBAL Handle)
{
    return FALSE;
}

/**********************************************************************
 *	    SizeofResource   (KERNEL32.@)
 */
WINAPI DWORD SizeofResource(HINSTANCE hModule, HRSRC hRsrc)
{
    if (!hRsrc)
	return 0;
    return ((PIMAGE_RESOURCE_DATA_ENTRY)hRsrc)->Size;
}

/*
 *  Data structure for updating resources.
 *  Type/Name/Language is a keyset for accessing resource data.
 *
 *  QUEUEDUPDATES (root) ->
 *    list of struct resource_dir_entry    (Type) ->
 *      list of struct resource_dir_entry  (Name)   ->
 *         list of struct resource_data    Language + Data
 */

typedef struct {
    LPWSTR pFileName;
    BOOL bDeleteExistingResources;
    LIST_ENTRY Root;
} QUEUEDUPDATES;

/* this structure is shared for types and names */
typedef struct _RESOURCE_DIR_ENTRY {
    LIST_ENTRY Entry;
    LPWSTR Id;
    LIST_ENTRY Children;
} RESOURCE_DIR_ENTRY, *PRESOURCE_DIR_ENTRY;

/* this structure is the leaf */
typedef struct _RESOURCE_DATA {
    LIST_ENTRY Entry;
    LANGID Lang;
    DWORD Codepage;
    DWORD cbData;
    PVOID lpData;
} RESOURCE_DATA, *PRESOURCE_DATA;

static int ResourceStrcmp(LPCWSTR a, LPCWSTR b)
{
    if (a == b)
	return 0;
    if (!IS_INTRESOURCE(a) && !IS_INTRESOURCE(b))
	return lstrcmpW(a, b);
    /* strings come before ids */
    if (!IS_INTRESOURCE(a) && IS_INTRESOURCE(b))
	return -1;
    if (!IS_INTRESOURCE(b) && IS_INTRESOURCE(a))
	return 1;
    return (a < b) ? -1 : 1;
}

static PRESOURCE_DIR_ENTRY FindResourceDirEntry(PLIST_ENTRY Dir, LPCWSTR Id)
{
    PRESOURCE_DIR_ENTRY Ent;

    /* match either IDs or strings */
    LIST_FOR_EACH_ENTRY(Ent, Dir, RESOURCE_DIR_ENTRY, Entry) {
	if (!ResourceStrcmp(Id, Ent->Id))
	    return Ent;
    }

    return NULL;
}

static PRESOURCE_DATA FindResourceData(PLIST_ENTRY Dir, LANGID Lang)
{
    PRESOURCE_DATA ResData;

    /* match only languages here */
    LIST_FOR_EACH_ENTRY(ResData, Dir, RESOURCE_DATA, Entry) {
	if (Lang == ResData->Lang)
	    return ResData;
    }

    return NULL;
}

static void AddResourceDirEntry(PLIST_ENTRY Dir, PRESOURCE_DIR_ENTRY Resdir)
{
    PRESOURCE_DIR_ENTRY Ent;

    LIST_FOR_EACH_ENTRY(Ent, Dir, RESOURCE_DIR_ENTRY, Entry) {
	if (0 > ResourceStrcmp(Ent->Id, Resdir->Id))
	    continue;

	InsertTailList(&Resdir->Entry, &Ent->Entry);
	return;
    }
    InsertTailList(Dir, &Resdir->Entry);
}

static void AddResourceDataEntry(PLIST_ENTRY Dir, PRESOURCE_DATA Resdata)
{
    PRESOURCE_DATA Ent;

    LIST_FOR_EACH_ENTRY(Ent, Dir, RESOURCE_DATA, Entry) {
	if (Ent->Lang < Resdata->Lang)
	    continue;

	InsertTailList(&Resdata->Entry, &Ent->Entry);
	return;
    }
    InsertTailList(Dir, &Resdata->Entry);
}

static LPWSTR ResStrdupW(LPCWSTR Str)
{
    LPWSTR Ret;
    UINT Len;

    if (IS_INTRESOURCE(Str))
	return (LPWSTR)(UINT_PTR)LOWORD(Str);
    Len = (lstrlenW(Str) + 1) * sizeof(WCHAR);
    Ret = HeapAlloc(GetProcessHeap(), 0, Len);
    memcpy(Ret, Str, Len);
    return Ret;
}

static void ResFreeStr(LPWSTR Str)
{
    if (!IS_INTRESOURCE(Str))
	HeapFree(GetProcessHeap(), 0, Str);
}

static BOOL UpdateAddResource(QUEUEDUPDATES *Updates, LPCWSTR Type, LPCWSTR Name,
			      LANGID Lang, PRESOURCE_DATA Resdata,
			      BOOL OverwriteExisting)
{
    PRESOURCE_DIR_ENTRY Restype, Resname;
    PRESOURCE_DATA Existing;

    TRACE("%p %s %s %p %d\n", updates, debugstr_w(Type), debugstr_w(Name), resdata,
	  overwrite_existing);

    Restype = FindResourceDirEntry(&Updates->Root, Type);
    if (!Restype) {
	Restype = HeapAlloc(GetProcessHeap(), 0, sizeof *Restype);
	Restype->Id = ResStrdupW(Type);
	InitializeListHead(&Restype->Children);
	AddResourceDirEntry(&Updates->Root, Restype);
    }

    Resname = FindResourceDirEntry(&Restype->Children, Name);
    if (!Resname) {
	Resname = HeapAlloc(GetProcessHeap(), 0, sizeof *Resname);
	Resname->Id = ResStrdupW(Name);
	InitializeListHead(&Resname->Children);
	AddResourceDirEntry(&Restype->Children, Resname);
    }

    /*
     * If there's an existing resource entry with matching (Type,Name,Language)
     *  it needs to be removed before adding the new data.
     */
    Existing = FindResourceData(&Resname->Children, Lang);
    if (Existing) {
	if (!OverwriteExisting)
	    return FALSE;
	RemoveEntryList(&Existing->Entry);
	HeapFree(GetProcessHeap(), 0, Existing);
    }

    if (Resdata)
	AddResourceDataEntry(&Resname->Children, Resdata);

    return TRUE;
}

static PRESOURCE_DATA AllocateResourceData(WORD Language, DWORD Codepage,
						  LPVOID lpData, DWORD cbData,
						  BOOL CopyData)
{
    PRESOURCE_DATA Resdata;

    if (!lpData || !cbData)
	return NULL;

    Resdata = HeapAlloc(GetProcessHeap(), 0, sizeof *Resdata + (CopyData ? cbData : 0));
    if (Resdata) {
	Resdata->Lang = Language;
	Resdata->Codepage = Codepage;
	Resdata->cbData = cbData;
	if (CopyData) {
	    Resdata->lpData = &Resdata[1];
	    memcpy(Resdata->lpData, lpData, cbData);
	} else
	    Resdata->lpData = lpData;
    }

    return Resdata;
}

static void FreeResourceDirectory(PLIST_ENTRY Head, int Level)
{
    PLIST_ENTRY Ptr = NULL;

    while (!IsListEmpty(Head) && (Ptr = Head->Flink)) {
	RemoveEntryList(Ptr);
	if (Level) {
	    PRESOURCE_DIR_ENTRY Ent;

	    Ent = CONTAINING_RECORD(Ptr, RESOURCE_DIR_ENTRY, Entry);
	    ResFreeStr(Ent->Id);
	    FreeResourceDirectory(&Ent->Children, Level - 1);
	    HeapFree(GetProcessHeap(), 0, Ent);
	} else {
	    PRESOURCE_DATA Data;

	    Data = CONTAINING_RECORD(Ptr, RESOURCE_DATA, Entry);
	    HeapFree(GetProcessHeap(), 0, Data);
	}
    }
}

static IMAGE_NT_HEADERS *GetNtHeader(void *Base, DWORD MappingSize)
{
    IMAGE_NT_HEADERS *Nt;
    IMAGE_DOS_HEADER *Dos;

    if (MappingSize < sizeof(*Dos))
	return NULL;

    Dos = Base;
    if (Dos->e_magic != IMAGE_DOS_SIGNATURE)
	return NULL;

    if ((Dos->e_lfanew + sizeof(*Nt)) > MappingSize)
	return NULL;

    Nt = (void *)((BYTE *)Base + Dos->e_lfanew);

    if (Nt->Signature != IMAGE_NT_SIGNATURE)
	return NULL;

    return Nt;
}

static IMAGE_SECTION_HEADER *GetSectionHeader(void *Base, DWORD MappingSize,
					      DWORD *NumSections)
{
    IMAGE_NT_HEADERS *Nt;
    DWORD SectionOfs;

    Nt = GetNtHeader(Base, MappingSize);
    if (!Nt)
	return NULL;

    /* check that we don't go over the end of the file accessing the sections */
    SectionOfs = FIELD_OFFSET(IMAGE_NT_HEADERS, OptionalHeader) +
		  Nt->FileHeader.SizeOfOptionalHeader;
    if ((Nt->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER) + SectionOfs) >
	MappingSize)
	return NULL;

    if (NumSections)
	*NumSections = Nt->FileHeader.NumberOfSections;

    /* from here we have a valid PE exe to update */
    return (void *)((BYTE *)Nt + SectionOfs);
}

static BOOL CheckPeExe(HANDLE File, QUEUEDUPDATES *Updates)
{
    const IMAGE_NT_HEADERS32 *Nt;
    const IMAGE_SECTION_HEADER *Sec;
    BOOL Ret = FALSE;
    HANDLE Mapping;
    DWORD MappingSize, NumSections = 0;
    void *Base = NULL;

    MappingSize = GetFileSize(File, NULL);

    Mapping = CreateFileMappingW(File, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!Mapping)
	goto done;

    Base = MapViewOfFile(Mapping, FILE_MAP_READ, 0, 0, MappingSize);
    if (!Base)
	goto done;

    Nt = (IMAGE_NT_HEADERS32 *)GetNtHeader(Base, MappingSize);
    if (!Nt)
	goto done;

    TRACE("resources: %08x %08x\n", dd[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress,
	  dd[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size);

    Sec = GetSectionHeader(Base, MappingSize, &NumSections);
    if (!Sec)
	goto done;

    Ret = TRUE;

done:
    if (Base)
	UnmapViewOfFile(Base);
    if (Mapping)
	CloseHandle(Mapping);

    return Ret;
}

struct RESOURCE_SIZE_INFO {
    DWORD TypesOfs;
    DWORD NamesOfs;
    DWORD LangsOfs;
    DWORD DataEntryOfs;
    DWORD StringsOfs;
    DWORD DataOfs;
    DWORD TotalSize;
};

struct MAPPING_INFO {
    HANDLE File;
    void *Base;
    DWORD Size;
    BOOL ReadWrite;
};

static const IMAGE_SECTION_HEADER *SectionFromRva(void *Base, DWORD MappingSize,
						  DWORD Rva)
{
    const IMAGE_SECTION_HEADER *Sec;
    DWORD NumSections = 0;
    int i;

    Sec = GetSectionHeader(Base, MappingSize, &NumSections);
    if (!Sec)
	return NULL;

    for (i = NumSections - 1; i >= 0; i--) {
	if (Sec[i].VirtualAddress <= Rva &&
	    Rva <= (DWORD)Sec[i].VirtualAddress + Sec[i].SizeOfRawData) {
	    return &Sec[i];
	}
    }

    return NULL;
}

static void *AddressFromRva(void *Base, DWORD MappingSize, DWORD Rva, DWORD Len)
{
    const IMAGE_SECTION_HEADER *Sec;

    Sec = SectionFromRva(Base, MappingSize, Rva);
    if (!Sec)
	return NULL;

    if (Rva + Len <= (DWORD)Sec->VirtualAddress + Sec->SizeOfRawData)
	return (void *)((LPBYTE)Base +
			(Sec->PointerToRawData + Rva - Sec->VirtualAddress));

    return NULL;
}

static LPWSTR ResourceDupString(const IMAGE_RESOURCE_DIRECTORY *Root,
				const IMAGE_RESOURCE_DIRECTORY_ENTRY *Entry)
{
    const IMAGE_RESOURCE_DIR_STRING_U *String;
    LPWSTR s;

    if (!Entry->NameIsString)
	return UIntToPtr(Entry->Id);

    String = (const IMAGE_RESOURCE_DIR_STRING_U *)(((const char *)Root) +
						   Entry->NameOffset);
    s = HeapAlloc(GetProcessHeap(), 0, (String->Length + 1) * sizeof(WCHAR));
    memcpy(s, String->NameString, (String->Length + 1) * sizeof(WCHAR));
    s[String->Length] = 0;

    return s;
}

/* this function is based on the code in winedump's pe.c */
static BOOL EnumerateMappedResources(QUEUEDUPDATES *Updates, void *Base,
				     DWORD MappingSize,
				     const IMAGE_RESOURCE_DIRECTORY *Root)
{
    const IMAGE_RESOURCE_DIRECTORY *Namedir, *Langdir;
    const IMAGE_RESOURCE_DIRECTORY_ENTRY *E1, *E2, *E3;
    const IMAGE_RESOURCE_DATA_ENTRY *Data;
    DWORD i, j, k;

    TRACE("version (%d.%d) %d named %d id entries\n", root->MajorVersion,
	  root->MinorVersion, root->NumberOfNamedEntries, root->NumberOfIdEntries);

    for (i = 0; i < Root->NumberOfNamedEntries + Root->NumberOfIdEntries; i++) {
	LPWSTR Type;

	E1 = (const IMAGE_RESOURCE_DIRECTORY_ENTRY *)(Root + 1) + i;

	Type = ResourceDupString(Root, E1);

	Namedir = (const IMAGE_RESOURCE_DIRECTORY *)((const char *)Root +
						     E1->OffsetToDirectory);
	for (j = 0; j < Namedir->NumberOfNamedEntries + Namedir->NumberOfIdEntries; j++) {
	    LPWSTR Name;

	    E2 = (const IMAGE_RESOURCE_DIRECTORY_ENTRY *)(Namedir + 1) + j;

	    Name = ResourceDupString(Root, E2);

	    Langdir = (const IMAGE_RESOURCE_DIRECTORY *)((const char *)Root +
							 E2->OffsetToDirectory);
	    for (k = 0; k < Langdir->NumberOfNamedEntries + Langdir->NumberOfIdEntries;
		 k++) {
		LANGID Lang;
		void *p;
		PRESOURCE_DATA Resdata;

		E3 = (const IMAGE_RESOURCE_DIRECTORY_ENTRY *)(Langdir + 1) + k;

		Lang = E3->Id;

		Data = (const IMAGE_RESOURCE_DATA_ENTRY *)((const char *)Root +
							   E3->OffsetToData);

		p = AddressFromRva(Base, MappingSize, Data->OffsetToData, Data->Size);

		Resdata = AllocateResourceData(Lang, Data->CodePage, p, Data->Size,
						 FALSE);
		if (Resdata) {
		    if (!UpdateAddResource(Updates, Type, Name, Lang, Resdata, FALSE))
			HeapFree(GetProcessHeap(), 0, Resdata);
		}
	    }
	    ResFreeStr(Name);
	}
	ResFreeStr(Type);
    }

    return TRUE;
}

static BOOL ReadMappedResources(QUEUEDUPDATES *Updates, void *Base, DWORD MappingSize)
{
    const IMAGE_RESOURCE_DIRECTORY *Root;
    const IMAGE_NT_HEADERS *Nt;
    const IMAGE_SECTION_HEADER *Sec;
    DWORD NumSections = 0, i;

    Nt = GetNtHeader(Base, MappingSize);
    if (!Nt)
	return FALSE;

    Sec = GetSectionHeader(Base, MappingSize, &NumSections);
    if (!Sec)
	return FALSE;

    for (i = 0; i < NumSections; i++)
	if (!memcmp(Sec[i].Name, ".rsrc", 6))
	    break;

    if (i == NumSections)
	return TRUE;

    /* check the resource data is inside the mapping */
    if (Sec[i].PointerToRawData > MappingSize ||
	(Sec[i].PointerToRawData + Sec[i].SizeOfRawData) > MappingSize)
	return TRUE;

    TRACE("found .rsrc at %08x, size %08x\n", sec[i].PointerToRawData,
	  sec[i].SizeOfRawData);

    if (!Sec[i].PointerToRawData ||
	Sec[i].SizeOfRawData < sizeof(IMAGE_RESOURCE_DIRECTORY))
	return TRUE;

    Root = (void *)((BYTE *)Base + Sec[i].PointerToRawData);
    EnumerateMappedResources(Updates, Base, MappingSize, Root);

    return TRUE;
}

static BOOL MapFileIntoMemory(struct MAPPING_INFO *Mi)
{
    DWORD PageAttr, Perm;
    HANDLE Mapping;

    if (Mi->ReadWrite) {
	PageAttr = PAGE_READWRITE;
	Perm = FILE_MAP_WRITE | FILE_MAP_READ;
    } else {
	PageAttr = PAGE_READONLY;
	Perm = FILE_MAP_READ;
    }

    Mapping = CreateFileMappingW(Mi->File, NULL, PageAttr, 0, 0, NULL);
    if (!Mapping)
	return FALSE;

    Mi->Base = MapViewOfFile(Mapping, Perm, 0, 0, Mi->Size);
    CloseHandle(Mapping);

    return Mi->Base != NULL;
}

static BOOL UnmapFileFromMemory(struct MAPPING_INFO *Mi)
{
    if (Mi->Base)
	UnmapViewOfFile(Mi->Base);
    Mi->Base = NULL;
    return TRUE;
}

static void DestroyMapping(struct MAPPING_INFO *Mi)
{
    if (!Mi)
	return;
    UnmapFileFromMemory(Mi);
    if (Mi->File)
	CloseHandle(Mi->File);
    HeapFree(GetProcessHeap(), 0, Mi);
}

static struct MAPPING_INFO *CreateMapping(LPCWSTR Name, BOOL Rw)
{
    struct MAPPING_INFO *Mi;

    Mi = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof *Mi);
    if (!Mi)
	return NULL;

    Mi->ReadWrite = Rw;

    Mi->File = CreateFileW(Name, GENERIC_READ | (Rw ? GENERIC_WRITE : 0), 0, NULL,
			   OPEN_EXISTING, 0, 0);

    if (Mi->File != INVALID_HANDLE_VALUE) {
	Mi->Size = GetFileSize(Mi->File, NULL);

	if (MapFileIntoMemory(Mi))
	    return Mi;
    }
    DestroyMapping(Mi);
    return NULL;
}

static BOOL ResizeMapping(struct MAPPING_INFO *Mi, DWORD NewSize)
{
    if (!UnmapFileFromMemory(Mi))
	return FALSE;

    /* change the file size */
    SetFilePointer(Mi->File, NewSize, NULL, FILE_BEGIN);
    if (!SetEndOfFile(Mi->File)) {
	ERR("failed to set file size to %08x\n", new_size);
	return FALSE;
    }

    Mi->Size = NewSize;

    return MapFileIntoMemory(Mi);
}

static void GetResourceSizes(QUEUEDUPDATES *Updates, struct RESOURCE_SIZE_INFO *Si)
{
    PRESOURCE_DIR_ENTRY Types, Names;
    PRESOURCE_DATA Data;
    DWORD NumTypes = 0, NumNames = 0, NumLangs = 0, StringsSize = 0, DataSize = 0;

    memset(Si, 0, sizeof *Si);

    LIST_FOR_EACH_ENTRY(Types, &Updates->Root, RESOURCE_DIR_ENTRY, Entry) {
	NumTypes++;
	if (!IS_INTRESOURCE(Types->Id))
	    StringsSize += sizeof(WORD) + lstrlenW(Types->Id) * sizeof(WCHAR);

	LIST_FOR_EACH_ENTRY(Names, &Types->Children, RESOURCE_DIR_ENTRY, Entry) {
	    NumNames++;

	    if (!IS_INTRESOURCE(Names->Id))
		StringsSize += sizeof(WORD) + lstrlenW(Names->Id) * sizeof(WCHAR);

	    LIST_FOR_EACH_ENTRY(Data, &Names->Children, RESOURCE_DATA, Entry) {
		NumLangs++;
		DataSize += (Data->cbData + 3) & ~3;
	    }
	}
    }

    /* names are at the end of the types */
    Si->NamesOfs = sizeof(IMAGE_RESOURCE_DIRECTORY) +
		    NumTypes * sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY);

    /* language directories are at the end of the names */
    Si->LangsOfs = Si->NamesOfs + NumTypes * sizeof(IMAGE_RESOURCE_DIRECTORY) +
		    NumNames * sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY);

    Si->DataEntryOfs = Si->LangsOfs + NumNames * sizeof(IMAGE_RESOURCE_DIRECTORY) +
			 NumLangs * sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY);

    Si->StringsOfs = Si->DataEntryOfs + NumLangs * sizeof(IMAGE_RESOURCE_DATA_ENTRY);

    Si->DataOfs = Si->StringsOfs + ((StringsSize + 3) & ~3);

    Si->TotalSize = Si->DataOfs + DataSize;

    TRACE("names %08x langs %08x data entries %08x strings %08x data %08x total %08x\n",
	  si->names_ofs, si->langs_ofs, si->data_entry_ofs, si->strings_ofs, si->data_ofs,
	  si->total_size);
}

static void ResWritePadding(BYTE *ResBase, DWORD Size)
{
    static const BYTE Pad[] = { 'P', 'A', 'D', 'D', 'I', 'N', 'G', 'X',
				'X', 'P', 'A', 'D', 'D', 'I', 'N', 'G' };
    DWORD i;

    for (i = 0; i < Size / sizeof Pad; i++)
	memcpy(&ResBase[i * sizeof Pad], Pad, sizeof Pad);
    memcpy(&ResBase[i * sizeof Pad], Pad, Size % sizeof Pad);
}

static BOOL WriteResources(QUEUEDUPDATES *Updates, LPBYTE Base,
			   struct RESOURCE_SIZE_INFO *Si, DWORD Rva)
{
    PRESOURCE_DIR_ENTRY Types, Names;
    PRESOURCE_DATA Data;
    IMAGE_RESOURCE_DIRECTORY *Root;

    TRACE("%p %p %p %08x\n", updates, base, si, rva);

    memset(Base, 0, Si->TotalSize);

    /* the root entry always exists */
    Root = (IMAGE_RESOURCE_DIRECTORY *)Base;
    memset(Root, 0, sizeof *Root);
    Root->MajorVersion = 4;
    Si->TypesOfs = sizeof *Root;
    LIST_FOR_EACH_ENTRY(Types, &Updates->Root, RESOURCE_DIR_ENTRY, Entry) {
	IMAGE_RESOURCE_DIRECTORY_ENTRY *E1;
	IMAGE_RESOURCE_DIRECTORY *Namedir;

	E1 = (IMAGE_RESOURCE_DIRECTORY_ENTRY *)&Base[Si->TypesOfs];
	memset(E1, 0, sizeof *E1);
	if (!IS_INTRESOURCE(Types->Id)) {
	    WCHAR *Strings;
	    DWORD Len;

	    Root->NumberOfNamedEntries++;
	    E1->NameIsString = 1;
	    E1->NameOffset = Si->StringsOfs;

	    Strings = (WCHAR *)&Base[Si->StringsOfs];
	    Len = lstrlenW(Types->Id);
	    Strings[0] = Len;
	    memcpy(&Strings[1], Types->Id, Len * sizeof(WCHAR));
	    Si->StringsOfs += (Len + 1) * sizeof(WCHAR);
	} else {
	    Root->NumberOfIdEntries++;
	    E1->Id = LOWORD(Types->Id);
	}
	E1->OffsetToDirectory = Si->NamesOfs;
	E1->DataIsDirectory = TRUE;
	Si->TypesOfs += sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY);

	Namedir = (IMAGE_RESOURCE_DIRECTORY *)&Base[Si->NamesOfs];
	memset(Namedir, 0, sizeof *Namedir);
	Namedir->MajorVersion = 4;
	Si->NamesOfs += sizeof(IMAGE_RESOURCE_DIRECTORY);

	LIST_FOR_EACH_ENTRY(Names, &Types->Children, RESOURCE_DIR_ENTRY, Entry)	{
	    IMAGE_RESOURCE_DIRECTORY_ENTRY *E2;
	    IMAGE_RESOURCE_DIRECTORY *Langdir;

	    E2 = (IMAGE_RESOURCE_DIRECTORY_ENTRY *)&Base[Si->NamesOfs];
	    memset(E2, 0, sizeof *E2);
	    if (!IS_INTRESOURCE(Names->Id)) {
		WCHAR *Strings;
		DWORD Len;

		Namedir->NumberOfNamedEntries++;
		E2->NameIsString = 1;
		E2->NameOffset = Si->StringsOfs;

		Strings = (WCHAR *)&Base[Si->StringsOfs];
		Len = lstrlenW(Names->Id);
		Strings[0] = Len;
		memcpy(&Strings[1], Names->Id, Len * sizeof(WCHAR));
		Si->StringsOfs += (Len + 1) * sizeof(WCHAR);
	    } else {
		Namedir->NumberOfIdEntries++;
		E2->Id = LOWORD(Names->Id);
	    }
	    E2->OffsetToDirectory = Si->LangsOfs;
	    E2->DataIsDirectory = TRUE;
	    Si->NamesOfs += sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY);

	    Langdir = (IMAGE_RESOURCE_DIRECTORY *)&Base[Si->LangsOfs];
	    memset(Langdir, 0, sizeof *Langdir);
	    Langdir->MajorVersion = 4;
	    Si->LangsOfs += sizeof(IMAGE_RESOURCE_DIRECTORY);

	    LIST_FOR_EACH_ENTRY(Data, &Names->Children, RESOURCE_DATA, Entry) {
		IMAGE_RESOURCE_DIRECTORY_ENTRY *E3;
		IMAGE_RESOURCE_DATA_ENTRY *De;
		int PadSize;

		E3 = (IMAGE_RESOURCE_DIRECTORY_ENTRY *)&Base[Si->LangsOfs];
		memset(E3, 0, sizeof *E3);
		Langdir->NumberOfIdEntries++;
		E3->Id = LOWORD(Data->Lang);
		E3->OffsetToData = Si->DataEntryOfs;

		Si->LangsOfs += sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY);

		/* write out all the data entries */
		De = (IMAGE_RESOURCE_DATA_ENTRY *)&Base[Si->DataEntryOfs];
		memset(De, 0, sizeof *De);
		De->OffsetToData = Si->DataOfs + Rva;
		De->Size = Data->cbData;
		De->CodePage = Data->Codepage;
		Si->DataEntryOfs += sizeof(IMAGE_RESOURCE_DATA_ENTRY);

		/* write out the resource data */
		memcpy(&Base[Si->DataOfs], Data->lpData, Data->cbData);
		Si->DataOfs += Data->cbData;

		PadSize = (-Si->DataOfs) & 3;
		ResWritePadding(&Base[Si->DataOfs], PadSize);
		Si->DataOfs += PadSize;
	    }
	}
    }

    return TRUE;
}

/*
 *  FIXME:
 *  Assumes that the resources are in .rsrc
 *   and .rsrc is the last section in the file.
 *  Not sure whether updating resources will other cases on Windows.
 *  If the resources lie in a section containing other data,
 *   resizing that section could possibly cause trouble.
 *  If the section with the resources isn't last, the remaining
 *   sections need to be moved down in the file, and the section header
 *   would need to be adjusted.
 *  If we needed to add a section, what would we name it?
 *  If we needed to add a section and there wasn't space in the file
 *   header, how would that work?
 *  Seems that at least some of these cases can't be handled properly.
 */
static IMAGE_SECTION_HEADER *GetResourceSection(void *Base, DWORD MappingSize)
{
    IMAGE_SECTION_HEADER *Sec;
    IMAGE_NT_HEADERS *Nt;
    DWORD i, NumSections = 0;

    Nt = GetNtHeader(Base, MappingSize);
    if (!Nt)
	return NULL;

    Sec = GetSectionHeader(Base, MappingSize, &NumSections);
    if (!Sec)
	return NULL;

    /* find the resources section */
    for (i = 0; i < NumSections; i++)
	if (!memcmp(Sec[i].Name, ".rsrc", 6))
	    break;

    if (i == NumSections)
	return NULL;

    return &Sec[i];
}

static DWORD GetInitDataSize(void *Base, DWORD MappingSize)
{
    DWORD i, Sz = 0, NumSections = 0;
    IMAGE_SECTION_HEADER *s;

    s = GetSectionHeader(Base, MappingSize, &NumSections);

    for (i = 0; i < NumSections; i++)
	if (s[i].Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA)
	    Sz += s[i].SizeOfRawData;

    TRACE("size = %08x\n", sz);

    return Sz;
}

static BOOL WriteRawResources(QUEUEDUPDATES *Updates)
{
    static const WCHAR Prefix[] = { 'r', 'e', 's', 'u', 0 };
    WCHAR Tempdir[MAX_PATH], Tempfile[MAX_PATH];
    DWORD i, SectionSize;
    BOOL Ret = FALSE;
    IMAGE_SECTION_HEADER *Sec;
    IMAGE_NT_HEADERS32 *Nt;
    IMAGE_NT_HEADERS64 *Nt64;
    struct RESOURCE_SIZE_INFO ResSize;
    BYTE *ResBase;
    struct MAPPING_INFO *ReadMap = NULL, *WriteMap = NULL;
    DWORD PeSectionAlignment, PeFileAlignment, PeSizeOfImage;

    /* copy the exe to a temp file then update the temp file... */
    Tempdir[0] = 0;
    if (!GetTempPathW(MAX_PATH, Tempdir))
	return Ret;

    if (!GetTempFileNameW(Tempdir, Prefix, 0, Tempfile))
	return Ret;

    if (!CopyFileW(Updates->pFileName, Tempfile, FALSE))
	goto done;

    TRACE("tempfile %s\n", debugstr_w(tempfile));

    if (!Updates->bDeleteExistingResources) {
	ReadMap = CreateMapping(Updates->pFileName, FALSE);
	if (!ReadMap)
	    goto done;

	Ret = ReadMappedResources(Updates, ReadMap->Base, ReadMap->Size);
	if (!Ret) {
	    ERR("failed to read existing resources\n");
	    goto done;
	}
    }

    WriteMap = CreateMapping(Tempfile, TRUE);
    if (!WriteMap)
	goto done;

    Nt = (IMAGE_NT_HEADERS32 *)GetNtHeader(WriteMap->Base, WriteMap->Size);
    if (!Nt)
	goto done;

    Nt64 = (IMAGE_NT_HEADERS64 *)Nt;
    if (Nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
	PeSectionAlignment = Nt64->OptionalHeader.SectionAlignment;
	PeFileAlignment = Nt64->OptionalHeader.FileAlignment;
	PeSizeOfImage = Nt64->OptionalHeader.SizeOfImage;
    } else {
	PeSectionAlignment = Nt->OptionalHeader.SectionAlignment;
	PeFileAlignment = Nt->OptionalHeader.FileAlignment;
	PeSizeOfImage = Nt->OptionalHeader.SizeOfImage;
    }

    if ((LONG)PeSectionAlignment <= 0) {
	ERR("invalid section alignment %08x\n", PeSectionAlignment);
	goto done;
    }

    if ((LONG)PeFileAlignment <= 0) {
	ERR("invalid file alignment %08x\n", PeFileAlignment);
	goto done;
    }

    Sec = GetResourceSection(WriteMap->Base, WriteMap->Size);
    if (!Sec) /* no section, add one */
    {
	DWORD NumSections;

	Sec = GetSectionHeader(WriteMap->Base, WriteMap->Size, &NumSections);
	if (!Sec)
	    goto done;

	Sec += NumSections;
	Nt->FileHeader.NumberOfSections++;

	memset(Sec, 0, sizeof *Sec);
	memcpy(Sec->Name, ".rsrc", 5);
	Sec->Characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ;
	Sec->VirtualAddress = PeSizeOfImage;
    }

    if (!Sec->PointerToRawData) /* empty section */
    {
	Sec->PointerToRawData = WriteMap->Size + (-WriteMap->Size) % PeFileAlignment;
	Sec->SizeOfRawData = 0;
    }

    TRACE("before .rsrc at %08x, size %08x\n", sec->PointerToRawData, sec->SizeOfRawData);

    GetResourceSizes(Updates, &ResSize);

    /* round up the section size */
    SectionSize = ResSize.TotalSize;
    SectionSize += (-SectionSize) % PeFileAlignment;

    TRACE("requires %08x (%08x) bytes\n", res_size.total_size, section_size);

    /* check if the file size needs to be changed */
    if (SectionSize != Sec->SizeOfRawData) {
	DWORD OldSize = WriteMap->Size;
	DWORD VirtualSectionSize = ResSize.TotalSize +
				     (-ResSize.TotalSize) % PeSectionAlignment;
	int Delta = SectionSize -
		    (Sec->SizeOfRawData + (-Sec->SizeOfRawData) % PeFileAlignment);
	int RvaDelta = VirtualSectionSize -
			(Sec->Misc.VirtualSize +
			 (-Sec->Misc.VirtualSize) % PeSectionAlignment);
	/* when new section is added it could end past current mapping size */
	BOOL RsrcIsLast = Sec->PointerToRawData + Sec->SizeOfRawData >= OldSize;
	/* align .rsrc size when possible */
	DWORD MappingSize = RsrcIsLast ? Sec->PointerToRawData + SectionSize :
					    OldSize + Delta;

	/* postpone file truncation if there are some data to be moved down from file end
	 */
	BOOL ResizeAfter = MappingSize < OldSize && !RsrcIsLast;

	TRACE("file size %08x -> %08x\n", old_size, mapping_size);

	if (!ResizeAfter) {
	    /* unmap the file before changing the file size */
	    Ret = ResizeMapping(WriteMap, MappingSize);

	    /* get the pointers again - they might be different after remapping */
	    Nt = (IMAGE_NT_HEADERS32 *)GetNtHeader(WriteMap->Base, MappingSize);
	    if (!Nt) {
		ERR("couldn't get NT header\n");
		goto done;
	    }
	    Nt64 = (IMAGE_NT_HEADERS64 *)Nt;

	    Sec = GetResourceSection(WriteMap->Base, MappingSize);
	    if (!Sec)
		goto done;
	}

	if (!RsrcIsLast) /* not last section, relocate trailing sections */
	{
	    IMAGE_SECTION_HEADER *s;
	    DWORD TailStart = Sec->PointerToRawData + Sec->SizeOfRawData;
	    DWORD i, NumSections = 0;

	    memmove((char *)WriteMap->Base + TailStart + Delta,
		    (char *)WriteMap->Base + TailStart, OldSize - TailStart);

	    s = GetSectionHeader(WriteMap->Base, MappingSize, &NumSections);

	    for (i = 0; i < NumSections; i++) {
		if (s[i].PointerToRawData > Sec->PointerToRawData) {
		    s[i].PointerToRawData += Delta;
		    s[i].VirtualAddress += RvaDelta;
		}
	    }
	}

	if (ResizeAfter) {
	    Ret = ResizeMapping(WriteMap, MappingSize);

	    Nt = (IMAGE_NT_HEADERS32 *)GetNtHeader(WriteMap->Base, MappingSize);
	    if (!Nt) {
		ERR("couldn't get NT header\n");
		goto done;
	    }
	    Nt64 = (IMAGE_NT_HEADERS64 *)Nt;

	    Sec = GetResourceSection(WriteMap->Base, MappingSize);
	    if (!Sec)
		goto done;
	}

	/* adjust the PE header information */
	Sec->SizeOfRawData = SectionSize;
	Sec->Misc.VirtualSize = VirtualSectionSize;
	if (Nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
	    Nt64->OptionalHeader.SizeOfImage += RvaDelta;
	    Nt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE]
		.VirtualAddress = Sec->VirtualAddress;
	    Nt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size =
		ResSize.TotalSize;
	    Nt64->OptionalHeader.SizeOfInitializedData =
		GetInitDataSize(WriteMap->Base, MappingSize);

	    for (i = 0; i < Nt64->OptionalHeader.NumberOfRvaAndSizes; i++)
		if (Nt64->OptionalHeader.DataDirectory[i].VirtualAddress >
		    Sec->VirtualAddress)
		    Nt64->OptionalHeader.DataDirectory[i].VirtualAddress += RvaDelta;
	} else {
	    Nt->OptionalHeader.SizeOfImage += RvaDelta;
	    Nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE]
		.VirtualAddress = Sec->VirtualAddress;
	    Nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size =
		ResSize.TotalSize;
	    Nt->OptionalHeader.SizeOfInitializedData = GetInitDataSize(WriteMap->Base,
									  MappingSize);

	    for (i = 0; i < Nt->OptionalHeader.NumberOfRvaAndSizes; i++)
		if (Nt->OptionalHeader.DataDirectory[i].VirtualAddress >
		    Sec->VirtualAddress)
		    Nt->OptionalHeader.DataDirectory[i].VirtualAddress += RvaDelta;
	}
    }

    ResBase = (LPBYTE)WriteMap->Base + Sec->PointerToRawData;

    TRACE("base = %p offset = %08x\n", write_map->base, sec->PointerToRawData);

    Ret = WriteResources(Updates, ResBase, &ResSize, Sec->VirtualAddress);

    ResWritePadding(ResBase + ResSize.TotalSize, SectionSize - ResSize.TotalSize);

    TRACE("after  .rsrc at %08x, size %08x\n", sec->PointerToRawData, sec->SizeOfRawData);

done:
    DestroyMapping(ReadMap);
    DestroyMapping(WriteMap);

    if (Ret)
	Ret = CopyFileW(Tempfile, Updates->pFileName, FALSE);

    DeleteFileW(Tempfile);

    return Ret;
}

/***********************************************************************
 *          BeginUpdateResourceW                 (KERNEL32.@)
 */
WINAPI HANDLE BeginUpdateResourceW(LPCWSTR pFileName, BOOL bDeleteExistingResources)
{
    QUEUEDUPDATES *Updates = NULL;
    HANDLE hUpdate, File, Ret = NULL;

    TRACE("%s, %d\n", debugstr_w(pFileName), bDeleteExistingResources);

    hUpdate = GlobalAlloc(GHND, sizeof(QUEUEDUPDATES));
    if (!hUpdate)
	return Ret;

    Updates = GlobalLock(hUpdate);
    if (Updates) {
	InitializeListHead(&Updates->Root);
	Updates->bDeleteExistingResources = bDeleteExistingResources;
	Updates->pFileName = HeapAlloc(GetProcessHeap(), 0,
				       (lstrlenW(pFileName) + 1) * sizeof(WCHAR));
	if (Updates->pFileName) {
	    lstrcpyW(Updates->pFileName, pFileName);

	    File = CreateFileW(pFileName, GENERIC_READ | GENERIC_WRITE, 0, NULL,
			       OPEN_EXISTING, 0, 0);

	    /* if resources are deleted, only the file's presence is checked */
	    if (File != INVALID_HANDLE_VALUE &&
		(bDeleteExistingResources || CheckPeExe(File, Updates)))
		Ret = hUpdate;
	    else
		HeapFree(GetProcessHeap(), 0, Updates->pFileName);

	    CloseHandle(File);
	}
	GlobalUnlock(hUpdate);
    }

    if (!Ret)
	GlobalFree(hUpdate);

    return Ret;
}

/***********************************************************************
 *          BeginUpdateResourceA                 (KERNEL32.@)
 */
WINAPI HANDLE BeginUpdateResourceA(LPCSTR pFileName, BOOL bDeleteExistingResources)
{
    UNICODE_STRING FileNameW;
    HANDLE Ret;
    RtlCreateUnicodeStringFromAsciiz(&FileNameW, pFileName);
    Ret = BeginUpdateResourceW(FileNameW.Buffer, bDeleteExistingResources);
    RtlFreeUnicodeString(&FileNameW);
    return Ret;
}

/***********************************************************************
 *          EndUpdateResourceW                 (KERNEL32.@)
 */
WINAPI BOOL EndUpdateResourceW(HANDLE hUpdate, BOOL fDiscard)
{
    QUEUEDUPDATES *Updates;
    BOOL Ret;

    TRACE("%p %d\n", hUpdate, fDiscard);

    Updates = GlobalLock(hUpdate);
    if (!Updates)
	return FALSE;

    Ret = fDiscard || WriteRawResources(Updates);

    FreeResourceDirectory(&Updates->Root, 2);

    HeapFree(GetProcessHeap(), 0, Updates->pFileName);
    GlobalUnlock(hUpdate);
    GlobalFree(hUpdate);

    return Ret;
}

/***********************************************************************
 *          EndUpdateResourceA                 (KERNEL32.@)
 */
WINAPI BOOL EndUpdateResourceA(HANDLE hUpdate, BOOL fDiscard)
{
    return EndUpdateResourceW(hUpdate, fDiscard);
}

/***********************************************************************
 *           UpdateResourceW                 (KERNEL32.@)
 */
WINAPI BOOL UpdateResourceW(HANDLE hUpdate, LPCWSTR lpType, LPCWSTR lpName,
			    WORD wLanguage, LPVOID lpData, DWORD cbData)
{
    QUEUEDUPDATES *Updates;
    BOOL Ret = FALSE;

    TRACE("%p %s %s %08x %p %d\n", hUpdate, debugstr_w(lpType), debugstr_w(lpName),
	  wLanguage, lpData, cbData);

    Updates = GlobalLock(hUpdate);
    if (Updates) {
	if (lpData == NULL && cbData == 0) /* remove resource */
	{
	    Ret = UpdateAddResource(Updates, lpType, lpName, wLanguage, NULL, TRUE);
	} else {
	    PRESOURCE_DATA Data;
	    Data = AllocateResourceData(wLanguage, 0, lpData, cbData, TRUE);
	    if (Data)
		Ret = UpdateAddResource(Updates, lpType, lpName, wLanguage, Data, TRUE);
	}
	GlobalUnlock(hUpdate);
    }
    return Ret;
}

/***********************************************************************
 *           UpdateResourceA                 (KERNEL32.@)
 */
WINAPI BOOL UpdateResourceA(HANDLE hUpdate, LPCSTR lpType, LPCSTR lpName, WORD wLanguage,
			    LPVOID lpData, DWORD cbData)
{
    BOOL Ret;
    UNICODE_STRING TypeW;
    UNICODE_STRING NameW;
    if (IS_INTRESOURCE(lpType))
	TypeW.Buffer = ULongToPtr(LOWORD(lpType));
    else
	RtlCreateUnicodeStringFromAsciiz(&TypeW, lpType);
    if (IS_INTRESOURCE(lpName))
	NameW.Buffer = ULongToPtr(LOWORD(lpName));
    else
	RtlCreateUnicodeStringFromAsciiz(&NameW, lpName);
    Ret = UpdateResourceW(hUpdate, TypeW.Buffer, NameW.Buffer, wLanguage, lpData, cbData);
    if (!IS_INTRESOURCE(lpType))
	RtlFreeUnicodeString(&TypeW);
    if (!IS_INTRESOURCE(lpName))
	RtlFreeUnicodeString(&NameW);
    return Ret;
}
