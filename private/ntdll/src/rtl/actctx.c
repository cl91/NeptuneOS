/*
 * COPYRIGHT:       See COPYING in the top level directory
 * PROJECT:         ReactOS Runtime Library
 * PURPOSE:         Activation Context Support
 * FILE:            lib/rtl/actctx.c
 * PROGRAMERS:
 *                  Jon Griffiths
 *                  Eric Pouech
 *                  Jacek Caban for CodeWeavers
 *                  Alexandre Julliard
 *                  Stefan Ginsberg (stefan.ginsberg@reactos.org)
 *                  Samuel Serapión
 */

/* Based on Wine 3.2-37c98396 */
#include "rtlp.h"
#include <ntstrsafe.h>
#include <stdio.h>
#include <wchar.h>

#define CURRENT_ACTIVE_FRAME                                                          \
    (((PACTIVATION_CONTEXT_STACK)NtCurrentTeb()->ActivationContextStackPointer) \
	 ->ActiveFrame)

#define ACTCTX_FLAGS_ALL                                                      \
    (ACTCTX_FLAG_PROCESSOR_ARCHITECTURE_VALID | ACTCTX_FLAG_LANGID_VALID |    \
     ACTCTX_FLAG_ASSEMBLY_DIRECTORY_VALID | ACTCTX_FLAG_RESOURCE_NAME_VALID | \
     ACTCTX_FLAG_SET_PROCESS_DEFAULT | ACTCTX_FLAG_APPLICATION_NAME_VALID |   \
     ACTCTX_FLAG_SOURCE_IS_ASSEMBLYREF | ACTCTX_FLAG_HMODULE_VALID)

#define ACTCTX_MAGIC 0xC07E3E11
#define STRSECTION_MAGIC 0x64487353 /* dHsS */
#define GUIDSECTION_MAGIC 0x64487347 /* dHsG */

#define ACTCTX_FAKE_HANDLE ((HANDLE)0xf00baa)

/* We don't want to include winuser.h */
#define RT_MANIFEST ((ULONG_PTR)24)
#define CREATEPROCESS_MANIFEST_RESOURCE_ID ((ULONG_PTR)1)

#define MAX_NAMESPACES 64

typedef enum _LIBFLAGS {
    LIBFLAG_FRESTRICTED = 0x01,
    LIBFLAG_FCONTROL = 0x02,
    LIBFLAG_FHIDDEN = 0x04,
    LIBFLAG_FHASDISKIMAGE = 0x08
} LIBFLAGS;

typedef struct _XML_STRING {
    PCWSTR Ptr;
    ULONG Length;
} XML_STRING, *PXML_STRING;
typedef const XML_STRING *PCXML_STRING;

typedef struct _XML_ELEMENT {
    XML_STRING Name;
    XML_STRING Namespace;
    LONG NamespacePosition;
} XML_ELEMENT, *PXML_ELEMENT;
typedef const XML_ELEMENT *PCXML_ELEMENT;

typedef struct _XML_ATTRIBUTE {
    XML_STRING Name;
    XML_STRING Value;
} XML_ATTRIBUTE, *PXML_ATTRIBUTE;
typedef const XML_ATTRIBUTE *PCXML_ATTRIBUTE;

typedef struct _XML_BUFFER {
    PCWSTR Ptr;
    PCWSTR End;
    XML_ATTRIBUTE Namespaces[MAX_NAMESPACES];
    LONG NamespacePosition;
    BOOL Error;
} XML_BUFFER, *PXML_BUFFER;

typedef struct _FILE_INFO {
    ULONG Type;
    PWSTR Info;
} FILE_INFO;

typedef struct _ASSEMBLY_VERSION {
    USHORT Major;
    USHORT Minor;
    USHORT Build;
    USHORT Revision;
} ASSEMBLY_VERSION, *PASSEMBLY_VERSION;

typedef struct _ASSEMBLY_IDENTITY {
    PWSTR Name;
    PWSTR Architecture;
    PWSTR PublicKey;
    PWSTR Language;
    PWSTR Type;
    ASSEMBLY_VERSION Version;
    BOOL Optional;
    BOOL Delayed;
} ASSEMBLY_IDENTITY, *PASSEMBLY_IDENTITY;
typedef const ASSEMBLY_IDENTITY *PCASSEMBLY_IDENTITY;

typedef struct _STRSECTION_HEADER {
    DWORD Magic;
    ULONG Size;
    DWORD Unknown1[3];
    ULONG Count;
    ULONG IndexOffset;
    DWORD Unknown2[2];
    ULONG GlobalOffset;
    ULONG GlobalLength;
} STRSECTION_HEADER, *PSTRSECTION_HEADER;
typedef const STRSECTION_HEADER *PCSTRSECTION_HEADER;

typedef struct _STRING_INDEX {
    ULONG Hash; /* key string hash */
    ULONG NameOffset;
    ULONG NameLength;
    ULONG DataOffset; /* redirect data offset */
    ULONG DataLength;
    ULONG RosterIndex;
} STRING_INDEX, *PSTRING_INDEX;
typedef const STRING_INDEX *PCSTRING_INDEX;

typedef struct _GUIDSECTION_HEADER {
    DWORD Magic;
    ULONG Size;
    DWORD Unknown1[3];
    ULONG Count;
    ULONG IndexOffset;
    DWORD Unknown2;
    ULONG NamesOffset;
    ULONG NamesLength;
} GUIDSECTION_HEADER, *PGUIDSECTION_HEADER;
typedef const GUIDSECTION_HEADER *PCGUIDSECTION_HEADER;

typedef struct _GUID_INDEX {
    GUID Guid;
    ULONG DataOffset;
    ULONG DataLength;
    ULONG RosterIndex;
} GUID_INDEX, *PGUID_INDEX;
typedef GUID_INDEX *PCGUID_INDEX;

typedef struct _WNDCLASS_REDIRECT_DATA {
    ULONG Size;
    DWORD Resource;
    ULONG NameLength;
    ULONG NameOffset; /* versioned name offset */
    ULONG ModuleLength;
    ULONG ModuleOffset; /* container name offset */
} WNDCLASS_REDIRECT_DATA, *PWNDCLASS_REDIRECT_DATA;

typedef struct _TLIBREDIRECT_DATA {
    ULONG Size;
    DWORD Resource;
    ULONG NameLength;
    ULONG NameOffset;
    LANGID LangId;
    WORD Flags;
    ULONG HelpLength;
    ULONG HelpOffset;
    WORD MajorVersion;
    WORD MinorVersion;
} TLIBREDIRECT_DATA, *PTLIBREDIRECT_DATA;

typedef enum _COMCLASS_THREADINGMODEL {
    ThreadingModel_Apartment = 1,
    ThreadingModel_Free = 2,
    ThreadingModel_No = 3,
    ThreadingModel_Both = 4,
    ThreadingModel_Neutral = 5
} COMCLASS_THREADINGMODEL;

typedef enum _COMCLASS_MISCFIELDS {
    MiscStatus = 1,
    MiscStatusIcon = 2,
    MiscStatusContent = 4,
    MiscStatusThumbnail = 8,
    MiscStatusDocPrint = 16
} COMCLASS_MISCFIELDS;

typedef struct _COMCLASSREDIRECT_DATA {
    ULONG Size;
    ULONG Flags;
    DWORD Model;
    GUID ClassId1;
    GUID Alias;
    GUID ClassId2;
    GUID Tlbid;
    ULONG NameLength;
    ULONG NameOffset;
    ULONG ProgidLength;
    ULONG ProgidOffset;
    ULONG ClrdataLength;
    ULONG ClrdataOffset;
    DWORD MiscStatus;
    DWORD MiscStatusContent;
    DWORD MiscStatusThumbnail;
    DWORD MiscStatusIcon;
    DWORD MiscStatusDocPrint;
} COMCLASSREDIRECT_DATA, *PCOMCLASSREDIRECT_DATA;

enum _IFACEPS_MASK { NumMethods = 1, BaseIface = 2 };

typedef struct _IFACEPSREDIRECT_DATA {
    ULONG Size;
    DWORD Mask;
    GUID Iid;
    ULONG NumMethods;
    GUID Tlbid;
    GUID Base;
    ULONG NameLength;
    ULONG NameOffset;
} IFACEPSREDIRECT_DATA, *PIFACEPSREDIRECT_DATA;

typedef struct _CLRSURROGATE_DATA {
    ULONG Size;
    DWORD Resource;
    GUID Clsid;
    ULONG VersionOffset;
    ULONG VersionLength;
    ULONG NameOffset;
    ULONG NameLength;
} CLRSURROGATE_DATA, *PCLRSURROGATE_DATA;

typedef struct _CLRCLASS_DATA {
    ULONG Size;
    DWORD Resource[2];
    ULONG ModuleLength;
    ULONG ModuleOffset;
    ULONG NameLength;
    ULONG NameOffset;
    ULONG VersionLength;
    ULONG VersionOffset;
    DWORD Resource2[2];
} CLRCLASS_DATA, *PCLRCLASS_DATA;

typedef struct _PROGIDREDIRECT_DATA {
    ULONG Size;
    DWORD Reserved;
    ULONG ClsidOffset;
} PROGIDREDIRECT_DATA, *PPROGIDREDIRECT_DATA;

typedef struct _ACTIVATABLE_CLASS_DATA {
    ULONG Size;
    DWORD Unknown;
    DWORD ModuleLength;
    DWORD ModuleOffset;
    DWORD ThreadingModel;
} ACTIVATABLE_CLASS_DATA, *PACTIVATABLE_CLASS_DATA;

/*

   Sections structure.

   Sections are accessible by string or guid key, that defines two types of sections.
   All sections of each type have same magic value and header structure, index
   data could be of two possible types too. So every string based section uses
   the same index format, same applies to guid sections - they share same guid index
   format.

   - window class redirection section is a plain buffer with following format:

   <section header>
   <index[]>
   <data[]> --- <original name>
		<redirect data>
		<versioned name>
		<module name>

   Header is fixed length structure - STRSECTION_HEADER,
   contains redirected classes count;

   Index is an array of fixed length index records, each record is
   STRING_INDEX.

   All strings in data itself are WCHAR, null terminated, 4-bytes aligned.

   Versioned name offset is relative to redirect data structure (struct
   wndclass_redirect_data), others are relative to section itself.

   - dll redirect section format:

   <section header>
   <index[]>
   <data[]> --- <dll name>
		<data>

   This section doesn't seem to carry any payload data except dll names.

   - typelib section format:

   <section header>
   <module names[]>
   <index[]>
   <data[]> --- <data>
		<helpstring>

   Header is fixed length, index is an array of fixed length 'GUID_INDEX'.
   All strings are WCHAR, null terminated, 4-bytes aligned. Module names part is
   4-bytes aligned as a whole.

   Module name offsets are relative to section, helpstring offset is relative to data
   structure itself.

   - comclass section format:

   <section header>
   <module names[]>
   <index[]>
   <data[]> --- <data>   --- <data>
		<progid>     <clrdata>
			     <name>
			     <version>
			     <progid>

   This section uses two index records per comclass, one entry contains original guid
   as specified by context, another one has a generated guid. Index and strings handling
   is similar to typelib sections.

   For CLR classes additional data is stored after main COM class data, it contains
   class name and runtime version string, see 'CLRCLASS_DATA'.

   Module name offsets are relative to section, progid offset is relative to data
   structure itself.

   - COM interface section format:

   <section header>
   <index[]>
   <data[]> --- <data>
		<name>

   Interface section contains data for proxy/stubs and external proxy/stubs. External
   ones are defined at assembly level, so this section has no module information.
   All records are indexed with 'iid' value from manifest. There an exception for
   external variants - if 'proxyStubClsid32' is specified, it's stored as iid in
   redirect data, but index is still 'iid' from manifest.

   Interface name offset is relative to data structure itself.

   - CLR surrogates section format:

   <section header>
   <index[]>
   <data[]> --- <data>
		<name>
		<version>

    There's nothing special about this section, same way to store strings is used,
    no modules part as it belongs to assembly level, not a file.

   - ProgID section format:

   <section header>
   <guids[]>
   <index[]>
   <data[]> --- <progid>
		<data>

   This sections uses generated alias guids from COM server section. This way
   ProgID -> CLSID mapping returns generated guid, not the real one. ProgID string
   is stored too, aligned.

   - WinRT activatable class section is a plain buffer with following format:

   <section header>
   <module names[]>
   <index[]>
   <data[]> --- <class name>
		<data>

   Header is fixed length structure - STRSECTION_HEADER,
   contains classes count;

   Index is an array of fixed length index records, each record is
   STRING_INDEX.

   All strings in data itself are WCHAR, null terminated, 4-bytes aligned.

   All offsets are relative to section itself.

*/

typedef struct _PROGIDS {
    PWSTR *Progids;
    ULONG Count;
    ULONG Allocated;
} PROGIDS, *PPROGIDS;
typedef const PROGIDS *PCPROGIDS;

typedef struct _ENTITY {
    DWORD Kind;
    union {
	struct {
	    PWSTR Tlbid;
	    PWSTR HelpDir;
	    WORD Flags;
	    WORD Major;
	    WORD Minor;
	} TypeLib;
	struct {
	    PWSTR Clsid;
	    PWSTR Tlbid;
	    PWSTR Progid;
	    PWSTR Name; /* clrClass: class name */
	    PWSTR Version; /* clrClass: CLR runtime version */
	    DWORD Model;
	    DWORD MiscStatus;
	    DWORD MiscStatusContent;
	    DWORD MiscStatusThumbnail;
	    DWORD MiscStatusIcon;
	    DWORD MiscStatusDocPrint;
	    PROGIDS Progids;
	} ComClass;
	struct {
	    PWSTR Iid;
	    PWSTR Base;
	    PWSTR Tlib;
	    PWSTR Name;
	    PWSTR Ps32; /* only stored for 'comInterfaceExternalProxyStub' */
	    DWORD Mask;
	    ULONG NumMethods;
	} Ifaceps;
	struct {
	    PWSTR Name;
	    BOOL Versioned;
	} Class;
	struct {
	    PWSTR Name;
	    PWSTR Clsid;
	    PWSTR Version;
	} ClrSurrogate;
	struct {
	    PWSTR Name;
	    PWSTR Value;
	    PWSTR Namespace;
	} Settings;
	struct {
	    PWSTR Name;
	    DWORD ThreadingModel;
	} ActivatableClass;
    };
} ENTITY, *PENTITY;

typedef struct _ENTITY_ARRAY {
    PENTITY Base;
    unsigned int Count;
    unsigned int Allocated;
} ENTITY_ARRAY, *PENTITY_ARRAY;
typedef const ENTITY_ARRAY *PCENTITY_ARRAY;

typedef struct _DLL_REDIRECT {
    PWSTR Name;
    PWSTR LoadFrom;
    PWSTR Hash;
    ENTITY_ARRAY Entities;
} DLL_REDIRECT, *PDLL_REDIRECT;
typedef const DLL_REDIRECT *PCDLL_REDIRECT;

typedef enum _ASSEMBLY_TYPE {
    APPLICATION_MANIFEST,
    ASSEMBLY_MANIFEST,
    ASSEMBLY_SHARED_MANIFEST,
} ASSEMBLY_TYPE;

typedef struct _ASSEMBLY {
    ASSEMBLY_TYPE Type;
    ASSEMBLY_IDENTITY Id;
    FILE_INFO Manifest;
    PWSTR Directory;
    BOOL NoInherit;
    PDLL_REDIRECT Dlls;
    unsigned int NumDlls;
    unsigned int AllocatedDlls;
    ENTITY_ARRAY Entities;
    COMPATIBILITY_CONTEXT_ELEMENT *CompatContexts;
    ULONG NumCompatContexts;
    ACTCTX_REQUESTED_RUN_LEVEL RunLevel;
    ULONG UiAccess;
} ASSEMBLY, *PASSEMBLY;

enum _CONTEXT_SECTIONS {
    WINDOWCLASS_SECTION = 1,
    DLLREDIRECT_SECTION = 2,
    TLIBREDIRECT_SECTION = 4,
    SERVERREDIRECT_SECTION = 8,
    IFACEREDIRECT_SECTION = 16,
    CLRSURROGATES_SECTION = 32,
    PROGIDREDIRECT_SECTION = 64,
    ACTIVATABLE_CLASS_SECTION = 128,
};

typedef struct _ASSEMBLY_STORAGE_MAP_ENTRY {
    ULONG Flags;
    UNICODE_STRING DosPath;
    HANDLE Handle;
} ASSEMBLY_STORAGE_MAP_ENTRY, *PASSEMBLY_STORAGE_MAP_ENTRY;

typedef struct _ASSEMBLY_STORAGE_MAP {
    ULONG Flags;
    ULONG AssemblyCount;
    PASSEMBLY_STORAGE_MAP_ENTRY *AssemblyArray;
} ASSEMBLY_STORAGE_MAP, *PASSEMBLY_STORAGE_MAP;

typedef struct _ACTIVATION_CONTEXT {
    ULONG Magic;
    LONG RefCount;
    ULONG Flags;
    LIST_ENTRY Links;
    PACTIVATION_CONTEXT_DATA ActivationContextData;
    PVOID NotificationRoutine;
    PVOID NotificationContext;
    ULONG SentNotifications[8];
    ULONG DisabledNotifications[8];
    ASSEMBLY_STORAGE_MAP StorageMap;
    PASSEMBLY_STORAGE_MAP_ENTRY InlineStorageMapEntries;
    ULONG StackTraceIndex;
    PVOID StackTraces[4][4];
    FILE_INFO Config;
    FILE_INFO AppDir;
    PASSEMBLY Assemblies;
    unsigned int NumAssemblies;
    unsigned int AllocatedAssemblies;
    /* section data */
    DWORD Sections;
    PSTRSECTION_HEADER WndClassSection;
    PSTRSECTION_HEADER DllRedirectSection;
    PSTRSECTION_HEADER ProgidSection;
    PSTRSECTION_HEADER ActivatableClassSection;
    PGUIDSECTION_HEADER TlibSection;
    PGUIDSECTION_HEADER ComserverSection;
    PGUIDSECTION_HEADER IfacepsSection;
    PGUIDSECTION_HEADER ClrSurrogateSection;
} ACTIVATION_CONTEXT;

typedef struct _ACTCTX_LOADER {
    ACTIVATION_CONTEXT *ActCtx;
    PASSEMBLY_IDENTITY Dependencies;
    unsigned int NumDependencies;
    unsigned int AllocatedDependencies;
} ACTCTX_LOADER, *PACTCTX_LOADER;

static const XML_STRING EmptyXmlString;

#ifdef __i386__
static const WCHAR CurrentArchitecture[] = L"x86";
#elif defined __aarch64__ || defined __arm64ec__
static const WCHAR CurrentArchitecture[] = L"arm64";
#elif defined __x86_64__
static const WCHAR CurrentArchitecture[] = L"amd64";
#elif defined __arm__
static const WCHAR CurrentArchitecture[] = L"arm";
#else
static const WCHAR CurrentArchitecture[] = L"none";
#endif

static const WCHAR AssemblyV1[] = L"urn:schemas-microsoft-com:asm.v1";
static const WCHAR AssemblyV2[] = L"urn:schemas-microsoft-com:asm.v2";
static const WCHAR AssemblyV3[] = L"urn:schemas-microsoft-com:asm.v3";
static const WCHAR WinrtV1[] = L"urn:schemas-microsoft-com:winrt.v1";
static const WCHAR CompatibilityNS[] = L"urn:schemas-microsoft-com:compatibility.v1";
static const WCHAR WindowsSettings2005NS[] = L"http://schemas.microsoft.com/SMI/2005/"
					     L"WindowsSettings";
static const WCHAR WindowsSettings2011NS[] = L"http://schemas.microsoft.com/SMI/2011/"
					     L"WindowsSettings";
static const WCHAR WindowsSettings2016NS[] = L"http://schemas.microsoft.com/SMI/2016/"
					     L"WindowsSettings";
static const WCHAR WindowsSettings2017NS[] = L"http://schemas.microsoft.com/SMI/2017/"
					     L"WindowsSettings";
static const WCHAR WindowsSettings2019NS[] = L"http://schemas.microsoft.com/SMI/2019/"
					     L"WindowsSettings";
static const WCHAR WindowsSettings2020NS[] = L"http://schemas.microsoft.com/SMI/2020/"
					     L"WindowsSettings";

/* from oleidl.idl */
typedef enum _OLEMISC {
    OLEMISC_RECOMPOSEONRESIZE = 0x1,
    OLEMISC_ONLYICONIC = 0x2,
    OLEMISC_INSERTNOTREPLACE = 0x4,
    OLEMISC_STATIC = 0x8,
    OLEMISC_CANTLINKINSIDE = 0x10,
    OLEMISC_CANLINKBYOLE1 = 0x20,
    OLEMISC_ISLINKOBJECT = 0x40,
    OLEMISC_INSIDEOUT = 0x80,
    OLEMISC_ACTIVATEWHENVISIBLE = 0x100,
    OLEMISC_RENDERINGISDEVICEINDEPENDENT = 0x200,
    OLEMISC_INVISIBLEATRUNTIME = 0x400,
    OLEMISC_ALWAYSRUN = 0x800,
    OLEMISC_ACTSLIKEBUTTON = 0x1000,
    OLEMISC_ACTSLIKELABEL = 0x2000,
    OLEMISC_NOUIACTIVATE = 0x4000,
    OLEMISC_ALIGNABLE = 0x8000,
    OLEMISC_SIMPLEFRAME = 0x10000,
    OLEMISC_SETCLIENTSITEFIRST = 0x20000,
    OLEMISC_IMEMODE = 0x40000,
    OLEMISC_IGNOREACTIVATEWHENVISIBLE = 0x80000,
    OLEMISC_WANTSTOMENUMERGE = 0x100000,
    OLEMISC_SUPPORTSMULTILEVELUNDO = 0x200000
} OLEMISC;

typedef struct _OLEMISC_ENTRY {
    PCWSTR Name;
    OLEMISC Value;
} OLEMISC_ENTRY;

static const OLEMISC_ENTRY OlemiscValues[] = {
    { L"activatewhenvisible", OLEMISC_ACTIVATEWHENVISIBLE },
    { L"actslikebutton", OLEMISC_ACTSLIKEBUTTON },
    { L"actslikelabel", OLEMISC_ACTSLIKELABEL },
    { L"alignable", OLEMISC_ALIGNABLE },
    { L"alwaysrun", OLEMISC_ALWAYSRUN },
    { L"canlinkbyole1", OLEMISC_CANLINKBYOLE1 },
    { L"cantlinkinside", OLEMISC_CANTLINKINSIDE },
    { L"ignoreactivatewhenvisible", OLEMISC_IGNOREACTIVATEWHENVISIBLE },
    { L"imemode", OLEMISC_IMEMODE },
    { L"insertnotreplace", OLEMISC_INSERTNOTREPLACE },
    { L"insideout", OLEMISC_INSIDEOUT },
    { L"invisibleatruntime", OLEMISC_INVISIBLEATRUNTIME },
    { L"islinkobject", OLEMISC_ISLINKOBJECT },
    { L"nouiactivate", OLEMISC_NOUIACTIVATE },
    { L"onlyiconic", OLEMISC_ONLYICONIC },
    { L"recomposeonresize", OLEMISC_RECOMPOSEONRESIZE },
    { L"renderingisdeviceindependent", OLEMISC_RENDERINGISDEVICEINDEPENDENT },
    { L"setclientsitefirst", OLEMISC_SETCLIENTSITEFIRST },
    { L"simpleframe", OLEMISC_SIMPLEFRAME },
    { L"static", OLEMISC_STATIC },
    { L"supportsmultilevelundo", OLEMISC_SUPPORTSMULTILEVELUNDO },
    { L"wantstomenumerge", OLEMISC_WANTSTOMENUMERGE }
};

static ACTIVATION_CONTEXT SystemActCtx = { ACTCTX_MAGIC, 1 };
static ACTIVATION_CONTEXT *ProcessActCtx = &SystemActCtx;
static ACTIVATION_CONTEXT *ImplicitActCtx = &SystemActCtx;

static PWSTR RtlpDuplicateWideString(PCWSTR Str)
{
    ULONG NumChars = wcslen(Str) + 1;
    PWSTR Ptr;
    if (!(Ptr = RtlAllocateHeap(RtlGetProcessHeap(), 0, NumChars * sizeof(WCHAR))))
	return NULL;
    wcscpy_s(Ptr, NumChars, Str);
    return Ptr;
}

static PWSTR RtlpDuplicateXmlString(PCXML_STRING Str)
{
    PWSTR StrW;

    if ((StrW = RtlAllocateHeap(RtlGetProcessHeap(), 0, (Str->Length + 1) * sizeof(WCHAR)))) {
	memcpy(StrW, Str->Ptr, Str->Length * sizeof(WCHAR));
	StrW[Str->Length] = 0;
    }
    return StrW;
}

static inline BOOL RtlpCompareXmlString(PCXML_STRING Xmlstr, PCWSTR Str)
{
    return !wcsncmp(Xmlstr->Ptr, Str, Xmlstr->Length) && !Str[Xmlstr->Length];
}

static inline BOOL RtlpCompareXmlStringCaseInsensitive(PCXML_STRING Xmlstr, PCWSTR Str)
{
    return !_wcsnicmp(Xmlstr->Ptr, Str, Xmlstr->Length) && !Str[Xmlstr->Length];
}

static BOOL RtlpCompareXmlAttribute(PCXML_ATTRIBUTE Attr, PCWSTR Str)
{
    return RtlpCompareXmlString(&Attr->Name, Str);
}

static BOOL RtlpCompareXmlName(PCXML_ELEMENT Elem1, PCXML_ELEMENT Elem2)
{
    return (Elem1->Name.Length == Elem2->Name.Length &&
	    Elem1->Namespace.Length == Elem2->Namespace.Length &&
	    !wcsncmp(Elem1->Name.Ptr, Elem2->Name.Ptr, Elem1->Name.Length) &&
	    !wcsncmp(Elem1->Namespace.Ptr, Elem2->Namespace.Ptr, Elem1->Namespace.Length));
}

static inline BOOL RtlpCompareXmlElement(PCXML_ELEMENT Elem, PCWSTR Str,
					 PCWSTR Namespace)
{
    if (!RtlpCompareXmlString(&Elem->Name, Str))
	return FALSE;
    if (RtlpCompareXmlString(&Elem->Namespace, Namespace))
	return TRUE;
    if (!wcscmp(Namespace, AssemblyV1)) {
	if (RtlpCompareXmlString(&Elem->Namespace, AssemblyV2))
	    return TRUE;
	if (RtlpCompareXmlString(&Elem->Namespace, AssemblyV3))
	    return TRUE;
    } else if (!wcscmp(Namespace, AssemblyV2)) {
	if (RtlpCompareXmlString(&Elem->Namespace, AssemblyV3))
	    return TRUE;
    }
    return FALSE;
}

static inline BOOL RtlpIsXmlSpace(WCHAR Ch)
{
    return (Ch == ' ' || Ch == '\r' || Ch == '\n' || Ch == '\t');
}

#define DEBUGSTR_GUID_FMT "{%08lx-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x}"
#define DEBUGSTR_GUID(Id)						\
    (Id)->Data1, (Id)->Data2, (Id)->Data3,				\
	(Id)->Data4[0], (Id)->Data4[1], (Id)->Data4[2], (Id)->Data4[3],	\
	(Id)->Data4[4], (Id)->Data4[5], (Id)->Data4[6], (Id)->Data4[7]
#define DEBUGSTR_XML_ELEM_FMT "%ws ns %ws"
#define DEBUGSTR_XML_ELEM(Elem)	(Elem)->Name.Ptr, (Elem)->Namespace.Ptr
#define DEBUGSTR_XML_ATTR_FMT "%ws=%ws"
#define DEBUGSTR_XML_ATTR(Attr) (Attr)->Name.Ptr, (Attr)->Value.Ptr
#define DEBUGSTR_VERSION_FMT "%u.%u.%u.%u"
#define DEBUGSTR_VERSION(Ver) (Ver)->Major, (Ver)->Minor, (Ver)->Build, (Ver)->Revision
#define WARN_ATTR(Msg, Attr)						\
    WARN_(LDR, Msg DEBUGSTR_XML_ATTR_FMT "\n", DEBUGSTR_XML_ATTR(&Attr))
#define WARN_UNEXPECTED_ATTR(Attr) WARN_ATTR("unexpected attr", Attr)
#define WARN_ELEM(Msg, Elem)						\
    WARN_(LDR, Msg DEBUGSTR_XML_ELEM_FMT "\n", DEBUGSTR_XML_ELEM(&Elem));
#define WARN_UNEXPECTED_ELEM(Elem) WARN_ELEM("unexpected element", Elem)

static NTSTATUS GetModuleFilename(HMODULE Module, UNICODE_STRING *Str,
				  unsigned int ExtraLen)
{
    NTSTATUS Status;
    ULONG_PTR Magic;
    LDR_DATA_TABLE_ENTRY *Pldr;

    LdrLockLoaderLock(0, NULL, &Magic);
    Status = LdrFindEntryForAddress(Module, &Pldr);
    if (Status == STATUS_SUCCESS) {
	if ((Str->Buffer = RtlAllocateHeap(RtlGetProcessHeap(), 0,
					   Pldr->FullDllName.Length +
					   ExtraLen + sizeof(WCHAR)))) {
	    memcpy(Str->Buffer, Pldr->FullDllName.Buffer,
		   Pldr->FullDllName.Length + sizeof(WCHAR));
	    Str->Length = Pldr->FullDllName.Length;
	    Str->MaximumLength = Pldr->FullDllName.Length + ExtraLen + sizeof(WCHAR);
	} else
	    Status = STATUS_NO_MEMORY;
    }
    LdrUnlockLoaderLock(0, Magic);
    return Status;
}

static PASSEMBLY AddAssembly(ACTIVATION_CONTEXT *Ctx, ASSEMBLY_TYPE Type)
{
    PASSEMBLY Assembly;

    DPRINT("AddAssembly() actctx %p, activeframe ??\n", Ctx);

    if (Ctx->NumAssemblies == Ctx->AllocatedAssemblies) {
	void *Ptr;
	unsigned int NewCount;
	if (Ctx->Assemblies) {
	    NewCount = Ctx->AllocatedAssemblies * 2;
	    Ptr = RtlReAllocateHeap(RtlGetProcessHeap(), HEAP_ZERO_MEMORY,
				    Ctx->Assemblies, NewCount * sizeof(*Assembly));
	} else {
	    NewCount = 4;
	    Ptr = RtlAllocateHeap(RtlGetProcessHeap(), HEAP_ZERO_MEMORY,
				  NewCount * sizeof(*Assembly));
	}
	if (!Ptr)
	    return NULL;
	Ctx->Assemblies = Ptr;
	Ctx->AllocatedAssemblies = NewCount;
    }

    Assembly = &Ctx->Assemblies[Ctx->NumAssemblies++];
    Assembly->Type = Type;
    return Assembly;
}

static PDLL_REDIRECT AddDllRedirect(PASSEMBLY Assembly)
{
    DPRINT("AddDllRedirect() to assembly %p, num_dlls %d\n", Assembly,
	   Assembly->AllocatedDlls);

    if (Assembly->NumDlls == Assembly->AllocatedDlls) {
	void *Ptr;
	unsigned int NewCount;
	if (Assembly->Dlls) {
	    NewCount = Assembly->AllocatedDlls * 2;
	    Ptr = RtlReAllocateHeap(RtlGetProcessHeap(), HEAP_ZERO_MEMORY, Assembly->Dlls,
				    NewCount * sizeof(*Assembly->Dlls));
	} else {
	    NewCount = 4;
	    Ptr = RtlAllocateHeap(RtlGetProcessHeap(), HEAP_ZERO_MEMORY,
				  NewCount * sizeof(*Assembly->Dlls));
	}
	if (!Ptr)
	    return NULL;
	Assembly->Dlls = Ptr;
	Assembly->AllocatedDlls = NewCount;
    }
    return &Assembly->Dlls[Assembly->NumDlls++];
}

static PCOMPATIBILITY_CONTEXT_ELEMENT AddCompatContext(PASSEMBLY Assembly)
{
    void *Ptr;
    if (Assembly->NumCompatContexts) {
	unsigned int NewCount = Assembly->NumCompatContexts + 1;
	Ptr = RtlReAllocateHeap(RtlGetProcessHeap(), HEAP_ZERO_MEMORY,
				Assembly->CompatContexts,
				NewCount * sizeof(COMPATIBILITY_CONTEXT_ELEMENT));
    } else {
	Ptr = RtlAllocateHeap(RtlGetProcessHeap(), HEAP_ZERO_MEMORY,
			      sizeof(COMPATIBILITY_CONTEXT_ELEMENT));
    }
    if (!Ptr)
	return NULL;
    Assembly->CompatContexts = Ptr;
    return &Assembly->CompatContexts[Assembly->NumCompatContexts++];
}

static void FreeAssemblyIdentity(PASSEMBLY_IDENTITY Id)
{
    RtlFreeHeap(RtlGetProcessHeap(), 0, Id->Name);
    RtlFreeHeap(RtlGetProcessHeap(), 0, Id->Architecture);
    RtlFreeHeap(RtlGetProcessHeap(), 0, Id->PublicKey);
    RtlFreeHeap(RtlGetProcessHeap(), 0, Id->Language);
    RtlFreeHeap(RtlGetProcessHeap(), 0, Id->Type);
}

static PENTITY AddEntity(PENTITY_ARRAY Array, DWORD Kind)
{
    PENTITY Entity;

    if (Array->Count == Array->Allocated) {
	void *Ptr;
	unsigned int NewCount;
	if (Array->Base) {
	    NewCount = Array->Allocated * 2;
	    Ptr = RtlReAllocateHeap(RtlGetProcessHeap(), HEAP_ZERO_MEMORY, Array->Base,
				    NewCount * sizeof(*Array->Base));
	} else {
	    NewCount = 4;
	    Ptr = RtlAllocateHeap(RtlGetProcessHeap(), HEAP_ZERO_MEMORY,
				  NewCount * sizeof(*Array->Base));
	}
	if (!Ptr)
	    return NULL;
	Array->Base = Ptr;
	Array->Allocated = NewCount;
    }
    Entity = &Array->Base[Array->Count++];
    Entity->Kind = Kind;
    return Entity;
}

static void FreeEntityArray(PENTITY_ARRAY Array)
{
    for (ULONG i = 0; i < Array->Count; i++) {
	PENTITY Entity = &Array->Base[i];
	switch (Entity->Kind) {
	case ACTIVATION_CONTEXT_SECTION_COM_SERVER_REDIRECTION:
	    RtlFreeHeap(RtlGetProcessHeap(), 0, Entity->ComClass.Clsid);
	    RtlFreeHeap(RtlGetProcessHeap(), 0, Entity->ComClass.Tlbid);
	    RtlFreeHeap(RtlGetProcessHeap(), 0, Entity->ComClass.Progid);
	    RtlFreeHeap(RtlGetProcessHeap(), 0, Entity->ComClass.Name);
	    RtlFreeHeap(RtlGetProcessHeap(), 0, Entity->ComClass.Version);
	    for (ULONG j = 0; j < Entity->ComClass.Progids.Count; j++)
		RtlFreeHeap(RtlGetProcessHeap(), 0, Entity->ComClass.Progids.Progids[j]);
	    RtlFreeHeap(RtlGetProcessHeap(), 0, Entity->ComClass.Progids.Progids);
	    break;
	case ACTIVATION_CONTEXT_SECTION_COM_INTERFACE_REDIRECTION:
	    RtlFreeHeap(RtlGetProcessHeap(), 0, Entity->Ifaceps.Iid);
	    RtlFreeHeap(RtlGetProcessHeap(), 0, Entity->Ifaceps.Base);
	    RtlFreeHeap(RtlGetProcessHeap(), 0, Entity->Ifaceps.Ps32);
	    RtlFreeHeap(RtlGetProcessHeap(), 0, Entity->Ifaceps.Name);
	    RtlFreeHeap(RtlGetProcessHeap(), 0, Entity->Ifaceps.Tlib);
	    break;
	case ACTIVATION_CONTEXT_SECTION_COM_TYPE_LIBRARY_REDIRECTION:
	    RtlFreeHeap(RtlGetProcessHeap(), 0, Entity->TypeLib.Tlbid);
	    RtlFreeHeap(RtlGetProcessHeap(), 0, Entity->TypeLib.HelpDir);
	    break;
	case ACTIVATION_CONTEXT_SECTION_WINDOW_CLASS_REDIRECTION:
	    RtlFreeHeap(RtlGetProcessHeap(), 0, Entity->Class.Name);
	    break;
	case ACTIVATION_CONTEXT_SECTION_CLR_SURROGATES:
	    RtlFreeHeap(RtlGetProcessHeap(), 0, Entity->ClrSurrogate.Name);
	    RtlFreeHeap(RtlGetProcessHeap(), 0, Entity->ClrSurrogate.Clsid);
	    RtlFreeHeap(RtlGetProcessHeap(), 0, Entity->ClrSurrogate.Version);
	    break;
	case ACTIVATION_CONTEXT_SECTION_APPLICATION_SETTINGS:
	    RtlFreeHeap(RtlGetProcessHeap(), 0, Entity->Settings.Name);
	    RtlFreeHeap(RtlGetProcessHeap(), 0, Entity->Settings.Value);
	    RtlFreeHeap(RtlGetProcessHeap(), 0, Entity->Settings.Namespace);
	    break;
	case ACTIVATION_CONTEXT_SECTION_WINRT_ACTIVATABLE_CLASSES:
	    RtlFreeHeap(RtlGetProcessHeap(), 0, Entity->ActivatableClass.Name);
	    break;
	default:
	    INFO_(LDR, "Unknown entity kind %d\n", Entity->Kind);
	}
    }
    RtlFreeHeap(RtlGetProcessHeap(), 0, Array->Base);
}

static BOOL IsMatchingString(PCWSTR Str1, PCWSTR Str2)
{
    if (!Str1)
	return !Str2;
    return Str2 &&
	   !RtlCompareUnicodeStrings(Str1, wcslen(Str1), Str2, wcslen(Str2), TRUE);
}

static BOOL IsMatchingIdentity(PCASSEMBLY_IDENTITY Id1,
			       PCASSEMBLY_IDENTITY Id2)
{
    if (!IsMatchingString(Id1->Name, Id2->Name))
	return FALSE;
    if (!IsMatchingString(Id1->Architecture, Id2->Architecture))
	return FALSE;
    if (!IsMatchingString(Id1->PublicKey, Id2->PublicKey))
	return FALSE;

    if (Id1->Language && Id2->Language &&
	!IsMatchingString(Id1->Language, Id2->Language)) {
	if (wcscmp(L"*", Id1->Language) && wcscmp(L"*", Id2->Language))
	    return FALSE;
    }
    if (Id1->Version.Major != Id2->Version.Major)
	return FALSE;
    if (Id1->Version.Minor != Id2->Version.Minor)
	return FALSE;
    if (Id1->Version.Build > Id2->Version.Build)
	return FALSE;
    if (Id1->Version.Build == Id2->Version.Build &&
	Id1->Version.Revision > Id2->Version.Revision)
	return FALSE;
    return TRUE;
}

static BOOL AddDependentAssemblyId(PACTCTX_LOADER Acl,
				   PASSEMBLY_IDENTITY Ai)
{
    unsigned int i;

    /* check if we already have that assembly */

    for (i = 0; i < Acl->ActCtx->NumAssemblies; i++)
	if (IsMatchingIdentity(Ai, &Acl->ActCtx->Assemblies[i].Id)) {
	    TRACE_(LDR, "reusing existing assembly for %ws arch %ws version %u.%u.%u.%u\n",
		   Ai->Name, Ai->Architecture, Ai->Version.Major,
		   Ai->Version.Minor, Ai->Version.Build, Ai->Version.Revision);
	    return TRUE;
	}

    for (i = 0; i < Acl->NumDependencies; i++)
	if (IsMatchingIdentity(Ai, &Acl->Dependencies[i])) {
	    TRACE_(LDR,
		   "reusing existing dependency for %ws arch %ws version %u.%u.%u.%u\n",
		   Ai->Name, Ai->Architecture, Ai->Version.Major,
		   Ai->Version.Minor, Ai->Version.Build, Ai->Version.Revision);
	    return TRUE;
	}

    if (Acl->NumDependencies == Acl->AllocatedDependencies) {
	void *Ptr;
	unsigned int NewCount;
	if (Acl->Dependencies) {
	    NewCount = Acl->AllocatedDependencies * 2;
	    Ptr = RtlReAllocateHeap(RtlGetProcessHeap(), 0, Acl->Dependencies,
				    NewCount * sizeof(Acl->Dependencies[0]));
	} else {
	    NewCount = 4;
	    Ptr = RtlAllocateHeap(RtlGetProcessHeap(), 0,
				  NewCount * sizeof(Acl->Dependencies[0]));
	}
	if (!Ptr)
	    return FALSE;
	Acl->Dependencies = Ptr;
	Acl->AllocatedDependencies = NewCount;
    }
    Acl->Dependencies[Acl->NumDependencies++] = *Ai;

    return TRUE;
}

static void FreeDependManifests(PACTCTX_LOADER Acl)
{
    unsigned int i;
    for (i = 0; i < Acl->NumDependencies; i++)
	FreeAssemblyIdentity(&Acl->Dependencies[i]);
    RtlFreeHeap(RtlGetProcessHeap(), 0, Acl->Dependencies);
}

static PWSTR BuildAssemblyDir(PASSEMBLY_IDENTITY Id)
{
    static const WCHAR Mskey[] = L"deadbeef";
    PCWSTR Arch = Id->Architecture ? Id->Architecture : L"none";
    PCWSTR Key = Id->PublicKey ? Id->PublicKey : L"none";
    PCWSTR Lang = Id->Language ? Id->Language : L"none";
    PCWSTR Name = Id->Name ? Id->Name : L"none";
    SIZE_T Size = (wcslen(Arch) + 1 + wcslen(Name) + 1 + wcslen(Key) + 24 + 1 +
		   wcslen(Lang) + 1) * sizeof(WCHAR) + sizeof(Mskey);
    PWSTR Ret;

    if (!(Ret = RtlAllocateHeap(RtlGetProcessHeap(), 0, Size)))
	return NULL;

    wcscpy_s(Ret, Size / sizeof(WCHAR), Arch);
    wcscat_s(Ret, Size / sizeof(WCHAR), L"_");
    wcscat_s(Ret, Size / sizeof(WCHAR), Name);
    wcscat_s(Ret, Size / sizeof(WCHAR), L"_");
    wcscat_s(Ret, Size / sizeof(WCHAR), Key);
    wcscat_s(Ret, Size / sizeof(WCHAR), L"_");
    _snwprintf(Ret + wcslen(Ret), Size - wcslen(Ret), L"%u.%u.%u.%u", Id->Version.Major,
	       Id->Version.Minor, Id->Version.Build, Id->Version.Revision);
    wcscat_s(Ret, Size / sizeof(WCHAR), L"_");
    wcscat_s(Ret, Size / sizeof(WCHAR), Lang);
    wcscat_s(Ret, Size / sizeof(WCHAR), L"_");
    wcscat_s(Ret, Size / sizeof(WCHAR), Mskey);
    return Ret;
}

static inline void AppendString(PWSTR Buffer, ULONG NumWchars, PCWSTR Prefix, PCWSTR Str)
{
    PWSTR p = Buffer;

    if (!Str)
	return;
    wcscat_s(Buffer, NumWchars, Prefix);
    ULONG Len = wcslen(p);
    if (NumWchars <= Len + 1) {
	return;
    }
    NumWchars -= Len + 1;
    p += Len;
    *p++ = '"';
    wcscpy_s(p, NumWchars, Str);
    p += wcslen(p);
    *p++ = '"';
    *p = 0;
}

static PWSTR BuildAssemblyId(PCASSEMBLY_IDENTITY Id)
{
    WCHAR Version[64], *Ret;
    SIZE_T Size = 0;

    _snwprintf(Version, ARRAYSIZE(Version), L"%u.%u.%u.%u", Id->Version.Major,
	       Id->Version.Minor, Id->Version.Build, Id->Version.Revision);
    if (Id->Name)
	Size += wcslen(Id->Name) * sizeof(WCHAR);
    if (Id->Architecture)
	Size += wcslen(L",processorArchitecture=") + wcslen(Id->Architecture) + 2;
    if (Id->PublicKey)
	Size += wcslen(L",publicKeyToken=") + wcslen(Id->PublicKey) + 2;
    if (Id->Type)
	Size += wcslen(L",type=") + wcslen(Id->Type) + 2;
    Size += wcslen(L",version=") + wcslen(Version) + 2;

    if (!(Ret = RtlAllocateHeap(RtlGetProcessHeap(), 0, (Size + 1) * sizeof(WCHAR))))
	return NULL;

    if (Id->Name)
	wcscpy_s(Ret, Size + 1, Id->Name);
    else
	*Ret = 0;
    AppendString(Ret, Size + 1, L",processorArchitecture=", Id->Architecture);
    AppendString(Ret, Size + 1, L",publicKeyToken=", Id->PublicKey);
    AppendString(Ret, Size + 1, L",type=", Id->Type);
    AppendString(Ret, Size + 1, L",version=", Version);
    return Ret;
}

static ACTIVATION_CONTEXT *CheckActCtx(HANDLE h)
{
    ACTIVATION_CONTEXT *Ret = NULL, *ActCtx = h;

    if (!h || h == INVALID_HANDLE_VALUE)
	return NULL;
    __try {
	if (ActCtx->Magic == ACTCTX_MAGIC)
	    Ret = ActCtx;
    } __except (GetExceptionCode() == STATUS_ACCESS_VIOLATION) {
	DPRINT1("Invalid activation context handle!\n");
    }
    return Ret;
}

static inline void ActCtxAddRef(ACTIVATION_CONTEXT *Ctx)
{
    InterlockedIncrement(&Ctx->RefCount);
}

static void ActCtxRelease(ACTIVATION_CONTEXT *Ctx)
{
    if (!InterlockedDecrement(&Ctx->RefCount)) {
	unsigned int i, j;

	for (i = 0; i < Ctx->NumAssemblies; i++) {
	    PASSEMBLY Assembly = &Ctx->Assemblies[i];
	    for (j = 0; j < Assembly->NumDlls; j++) {
		PDLL_REDIRECT Dll = &Assembly->Dlls[j];
		FreeEntityArray(&Dll->Entities);
		RtlFreeHeap(RtlGetProcessHeap(), 0, Dll->Name);
		RtlFreeHeap(RtlGetProcessHeap(), 0, Dll->LoadFrom);
		RtlFreeHeap(RtlGetProcessHeap(), 0, Dll->Hash);
	    }
	    RtlFreeHeap(RtlGetProcessHeap(), 0, Assembly->Dlls);
	    RtlFreeHeap(RtlGetProcessHeap(), 0, Assembly->Manifest.Info);
	    RtlFreeHeap(RtlGetProcessHeap(), 0, Assembly->Directory);
	    RtlFreeHeap(RtlGetProcessHeap(), 0, Assembly->CompatContexts);
	    FreeEntityArray(&Assembly->Entities);
	    FreeAssemblyIdentity(&Assembly->Id);
	}
	RtlFreeHeap(RtlGetProcessHeap(), 0, Ctx->Config.Info);
	RtlFreeHeap(RtlGetProcessHeap(), 0, Ctx->AppDir.Info);
	RtlFreeHeap(RtlGetProcessHeap(), 0, Ctx->Assemblies);
	RtlFreeHeap(RtlGetProcessHeap(), 0, Ctx->DllRedirectSection);
	RtlFreeHeap(RtlGetProcessHeap(), 0, Ctx->WndClassSection);
	RtlFreeHeap(RtlGetProcessHeap(), 0, Ctx->TlibSection);
	RtlFreeHeap(RtlGetProcessHeap(), 0, Ctx->ComserverSection);
	RtlFreeHeap(RtlGetProcessHeap(), 0, Ctx->IfacepsSection);
	RtlFreeHeap(RtlGetProcessHeap(), 0, Ctx->ClrSurrogateSection);
	RtlFreeHeap(RtlGetProcessHeap(), 0, Ctx->ProgidSection);
	RtlFreeHeap(RtlGetProcessHeap(), 0, Ctx->ActivatableClassSection);
	Ctx->Magic = 0;
	RtlFreeHeap(RtlGetProcessHeap(), 0, Ctx);
    }
}

static BOOL SetError(PXML_BUFFER XmlBuffer)
{
    XmlBuffer->Error = TRUE;
    return FALSE;
}

static BOOL IsXmlnsAttr(PCXML_ATTRIBUTE Attr)
{
    const int Len = wcslen(L"xmlns");
    if (Attr->Name.Length < Len)
	return FALSE;
    if (wcsncmp(Attr->Name.Ptr, L"xmlns", Len))
	return FALSE;
    return (Attr->Name.Length == Len || Attr->Name.Ptr[Len] == ':');
}

static void PushXmlns(PXML_BUFFER Xmlbuf, PCXML_ATTRIBUTE Attr)
{
    const int Len = wcslen(L"xmlns");
    PXML_ATTRIBUTE Ns;

    if (Xmlbuf->NamespacePosition == MAX_NAMESPACES - 1) {
	WARN_(LDR, "too many namespaces in manifest\n");
	SetError(Xmlbuf);
	return;
    }
    Ns = &Xmlbuf->Namespaces[Xmlbuf->NamespacePosition++];
    Ns->Value = Attr->Value;
    if (Attr->Name.Length > Len) {
	Ns->Name.Ptr = Attr->Name.Ptr + Len + 1;
	Ns->Name.Length = Attr->Name.Length - Len - 1;
    } else
	Ns->Name = EmptyXmlString;
}

static XML_STRING FindXmlns(PXML_BUFFER Xmlbuf, PCXML_STRING Name)
{
    int i;

    for (i = Xmlbuf->NamespacePosition - 1; i >= 0; i--) {
	if (Xmlbuf->Namespaces[i].Name.Length == Name->Length &&
	    !wcsncmp(Xmlbuf->Namespaces[i].Name.Ptr, Name->Ptr, Name->Length))
	    return Xmlbuf->Namespaces[i].Value;
    }
    if (Xmlbuf->NamespacePosition)
	WARN_(LDR, "namespace %ws not found\n", Name->Ptr);
    return EmptyXmlString;
}

static BOOL NextXmlAttr(PXML_BUFFER Xmlbuf, PXML_ATTRIBUTE Attr, BOOL *End)
{
    PCWSTR Ptr;
    WCHAR Quote;

    if (Xmlbuf->Error)
	return FALSE;

    while (Xmlbuf->Ptr < Xmlbuf->End && RtlpIsXmlSpace(*Xmlbuf->Ptr))
	Xmlbuf->Ptr++;

    if (Xmlbuf->Ptr == Xmlbuf->End)
	return SetError(Xmlbuf);

    if (*Xmlbuf->Ptr == '/') {
	Xmlbuf->Ptr++;
	if (Xmlbuf->Ptr == Xmlbuf->End || *Xmlbuf->Ptr != '>')
	    return SetError(Xmlbuf);

	Xmlbuf->Ptr++;
	*End = TRUE;
	return FALSE;
    }

    if (*Xmlbuf->Ptr == '>') {
	Xmlbuf->Ptr++;
	return FALSE;
    }

    Ptr = Xmlbuf->Ptr;
    while (Ptr < Xmlbuf->End && *Ptr != '=' && *Ptr != '>' && !RtlpIsXmlSpace(*Ptr))
	Ptr++;

    if (Ptr == Xmlbuf->End)
	return SetError(Xmlbuf);

    Attr->Name.Ptr = Xmlbuf->Ptr;
    Attr->Name.Length = Ptr - Xmlbuf->Ptr;
    Xmlbuf->Ptr = Ptr;

    /* skip spaces before '=' */
    while (Ptr < Xmlbuf->End && *Ptr != '=' && RtlpIsXmlSpace(*Ptr))
	Ptr++;
    if (Ptr == Xmlbuf->End || *Ptr != '=')
	return SetError(Xmlbuf);

    /* skip '=' itself */
    Ptr++;
    if (Ptr == Xmlbuf->End)
	return SetError(Xmlbuf);

    /* skip spaces after '=' */
    while (Ptr < Xmlbuf->End && *Ptr != '"' && *Ptr != '\'' && RtlpIsXmlSpace(*Ptr))
	Ptr++;

    if (Ptr == Xmlbuf->End || (*Ptr != '"' && *Ptr != '\''))
	return SetError(Xmlbuf);

    Quote = *Ptr++;
    Attr->Value.Ptr = Ptr;
    if (Ptr == Xmlbuf->End)
	return SetError(Xmlbuf);

    while (Ptr < Xmlbuf->End && *Ptr != Quote)
	Ptr++;
    if (Ptr == Xmlbuf->End) {
	Xmlbuf->Ptr = Xmlbuf->End;
	return SetError(Xmlbuf);
    }

    Attr->Value.Length = Ptr - Attr->Value.Ptr;
    Xmlbuf->Ptr = Ptr + 1;
    if (Xmlbuf->Ptr != Xmlbuf->End)
	return TRUE;

    return SetError(Xmlbuf);
}

static void ReadXmlElem(PXML_BUFFER Xmlbuf, PXML_ELEMENT Elem)
{
    PCWSTR Ptr = Xmlbuf->Ptr;

    Elem->Namespace = EmptyXmlString;
    Elem->Name.Ptr = Ptr;
    while (Ptr < Xmlbuf->End && !RtlpIsXmlSpace(*Ptr) && *Ptr != '>' && *Ptr != '/') {
	if (*Ptr == ':') {
	    Elem->Namespace.Ptr = Elem->Name.Ptr;
	    Elem->Namespace.Length = Ptr - Elem->Namespace.Ptr;
	    Elem->Name.Ptr = Ptr + 1;
	}
	Ptr++;
    }
    Elem->Name.Length = Ptr - Elem->Name.Ptr;
    Xmlbuf->Ptr = Ptr;
}

static BOOL NextXmlElem(PXML_BUFFER Xmlbuf, PXML_ELEMENT Elem,
			PCXML_ELEMENT Parent)
{
    PCWSTR Ptr;
    XML_ATTRIBUTE Attr;
    XML_BUFFER AttrBuf;
    BOOL End = FALSE;

    Xmlbuf->NamespacePosition = Parent->NamespacePosition; /* restore namespace stack to parent state */

    if (Xmlbuf->Error)
	return FALSE;

    for (;;) {
	for (Ptr = Xmlbuf->Ptr; Ptr < Xmlbuf->End; Ptr++)
	    if (*Ptr == '<')
		break;
	if (Ptr == Xmlbuf->End) {
	    Xmlbuf->Ptr = Xmlbuf->End;
	    return SetError(Xmlbuf);
	}
	Ptr++;
	if (Ptr + 3 < Xmlbuf->End && Ptr[0] == '!' && Ptr[1] == '-' &&
	    Ptr[2] == '-') /* skip comment */
	{
	    for (Ptr += 3; Ptr + 3 <= Xmlbuf->End; Ptr++)
		if (Ptr[0] == '-' && Ptr[1] == '-' && Ptr[2] == '>')
		    break;

	    if (Ptr + 3 > Xmlbuf->End) {
		Xmlbuf->Ptr = Xmlbuf->End;
		return SetError(Xmlbuf);
	    }
	    Xmlbuf->Ptr = Ptr + 3;
	} else
	    break;
    }

    Xmlbuf->Ptr = Ptr;
    /* check for element terminating the parent element */
    if (Ptr < Xmlbuf->End && *Ptr == '/') {
	Xmlbuf->Ptr++;
	ReadXmlElem(Xmlbuf, Elem);
	Elem->Namespace = FindXmlns(Xmlbuf, &Elem->Namespace);
	if (!RtlpCompareXmlName(Elem, Parent)) {
	    ERR_(LDR, "wrong closing element %ws for %ws\n", Elem->Name.Ptr,
		 Parent->Name.Ptr);
	    return SetError(Xmlbuf);
	}
	while (Xmlbuf->Ptr < Xmlbuf->End && RtlpIsXmlSpace(*Xmlbuf->Ptr))
	    Xmlbuf->Ptr++;
	if (Xmlbuf->Ptr == Xmlbuf->End || *Xmlbuf->Ptr++ != '>')
	    return SetError(Xmlbuf);
	return FALSE;
    }

    ReadXmlElem(Xmlbuf, Elem);

    /* parse namespace attributes */
    AttrBuf = *Xmlbuf;
    while (NextXmlAttr(&AttrBuf, &Attr, &End)) {
	if (IsXmlnsAttr(&Attr))
	    PushXmlns(Xmlbuf, &Attr);
    }
    Elem->Namespace = FindXmlns(Xmlbuf, &Elem->Namespace);
    Elem->NamespacePosition = Xmlbuf->NamespacePosition;

    if (Xmlbuf->Ptr != Xmlbuf->End)
	return TRUE;

    return SetError(Xmlbuf);
}

static BOOL ParseXmlHeader(PXML_BUFFER Xmlbuf)
{
    /* FIXME: parse attributes */
    PCWSTR Ptr;

    for (Ptr = Xmlbuf->Ptr; Ptr < Xmlbuf->End - 1; Ptr++) {
	if (Ptr[0] == '?' && Ptr[1] == '>') {
	    Xmlbuf->Ptr = Ptr + 2;
	    return TRUE;
	}
    }
    return FALSE;
}

static BOOL ParseTextContent(PXML_BUFFER Xmlbuf, PXML_STRING Content)
{
    PCWSTR Ptr;

    if (Xmlbuf->Error)
	return FALSE;

    for (Ptr = Xmlbuf->Ptr; Ptr < Xmlbuf->End; Ptr++)
	if (*Ptr == '<')
	    break;
    if (Ptr == Xmlbuf->End)
	return SetError(Xmlbuf);

    Content->Ptr = Xmlbuf->Ptr;
    Content->Length = Ptr - Xmlbuf->Ptr;
    Xmlbuf->Ptr = Ptr;

    return TRUE;
}

static BOOL ParseVersion(PCXML_STRING Str, PASSEMBLY_VERSION Version)
{
    unsigned int Ver[4];
    unsigned int Pos;
    PCWSTR Curr;

    /* major.minor.build.revision */
    Ver[0] = Ver[1] = Ver[2] = Ver[3] = Pos = 0;
    for (Curr = Str->Ptr; Curr < Str->Ptr + Str->Length; Curr++) {
	if (*Curr >= '0' && *Curr <= '9') {
	    Ver[Pos] = Ver[Pos] * 10 + *Curr - '0';
	    if (Ver[Pos] >= 0x10000)
		goto error;
	} else if (*Curr == '.') {
	    if (++Pos >= 4)
		goto error;
	} else
	    goto error;
    }
    Version->Major = Ver[0];
    Version->Minor = Ver[1];
    Version->Build = Ver[2];
    Version->Revision = Ver[3];
    return TRUE;

error:
    INFO_(LDR, "Wrong version definition in manifest file (%ws)\n", Str->Ptr);
    return FALSE;
}

static void ParseExpectNoAttr(PXML_BUFFER Xmlbuf, BOOL *End)
{
    XML_ATTRIBUTE Attr;

    while (NextXmlAttr(Xmlbuf, &Attr, End)) {
	if (!IsXmlnsAttr(&Attr))
	    WARN_UNEXPECTED_ATTR(Attr);
    }
}

static void ParseExpectEndElem(PXML_BUFFER Xmlbuf, PCXML_ELEMENT Parent)
{
    XML_ELEMENT Elem;

    if (NextXmlElem(Xmlbuf, &Elem, Parent)) {
	WARN_UNEXPECTED_ELEM(Elem);
	SetError(Xmlbuf);
    }
}

static void ParseUnknownElem(PXML_BUFFER Xmlbuf, PCXML_ELEMENT Parent)
{
    XML_ELEMENT Elem;
    XML_ATTRIBUTE Attr;
    BOOL End = FALSE;

    while (NextXmlAttr(Xmlbuf, &Attr, &End))
	;
    if (End)
	return;

    while (NextXmlElem(Xmlbuf, &Elem, Parent))
	ParseUnknownElem(Xmlbuf, &Elem);
}

static void ParseAssemblyIdentityElement(PXML_BUFFER Xmlbuf, ACTIVATION_CONTEXT *Actctx,
					 PASSEMBLY_IDENTITY Ai,
					 PCXML_ELEMENT Parent)
{
    XML_ATTRIBUTE Attr;
    BOOL End = FALSE;

    while (NextXmlAttr(Xmlbuf, &Attr, &End)) {
	if (RtlpCompareXmlAttribute(&Attr, L"name")) {
	    if (!(Ai->Name = RtlpDuplicateXmlString(&Attr.Value)))
		SetError(Xmlbuf);
	} else if (RtlpCompareXmlAttribute(&Attr, L"type")) {
	    if (!(Ai->Type = RtlpDuplicateXmlString(&Attr.Value)))
		SetError(Xmlbuf);
	} else if (RtlpCompareXmlAttribute(&Attr, L"version")) {
	    if (!ParseVersion(&Attr.Value, &Ai->Version))
		SetError(Xmlbuf);
	} else if (RtlpCompareXmlAttribute(&Attr, L"processorArchitecture")) {
	    if (!(Ai->Architecture = RtlpDuplicateXmlString(&Attr.Value)))
		SetError(Xmlbuf);
	} else if (RtlpCompareXmlAttribute(&Attr, L"publicKeyToken")) {
	    if (!(Ai->PublicKey = RtlpDuplicateXmlString(&Attr.Value)))
		SetError(Xmlbuf);
	} else if (RtlpCompareXmlAttribute(&Attr, L"language")) {
	    if (!(Ai->Language = RtlpDuplicateXmlString(&Attr.Value)))
		SetError(Xmlbuf);
	} else if (!IsXmlnsAttr(&Attr)) {
	    WARN_UNEXPECTED_ATTR(Attr);
	}
    }

    TRACE_(LDR, "name=%ws version=" DEBUGSTR_VERSION_FMT " arch=%ws\n", Ai->Name,
	   DEBUGSTR_VERSION(&Ai->Version), Ai->Architecture);

    if (!End)
	ParseExpectEndElem(Xmlbuf, Parent);
}

static COMCLASS_THREADINGMODEL ParseComClassThreadingmodel(PXML_STRING Value)
{
    if (Value->Length == 0)
	return ThreadingModel_No;
    if (RtlpCompareXmlString(Value, L"Apartment"))
	return ThreadingModel_Apartment;
    else if (RtlpCompareXmlString(Value, L"Free"))
	return ThreadingModel_Free;
    else if (RtlpCompareXmlString(Value, L"Both"))
	return ThreadingModel_Both;
    else if (RtlpCompareXmlString(Value, L"Neutral"))
	return ThreadingModel_Neutral;
    else
	return ThreadingModel_No;
};

static OLEMISC GetOlemiscValue(PCWSTR Str, int Len)
{
    int Min, Max;

    Min = 0;
    Max = ARRAYSIZE(OlemiscValues) - 1;

    while (Min <= Max) {
	int n, c;

	n = (Min + Max) / 2;

	c = wcsncmp(OlemiscValues[n].Name, Str, Len);
	if (!c && !OlemiscValues[n].Name[Len])
	    return OlemiscValues[n].Value;

	if (c >= 0)
	    Max = n - 1;
	else
	    Min = n + 1;
    }

    WARN_(LDR, "unknown flag %ws\n", Str);
    return 0;
}

static DWORD ParseComClassMisc(PCXML_STRING Value)
{
    PCWSTR Str = Value->Ptr, Start;
    DWORD Flags = 0;
    int i = 0;

    /* it's comma separated list of flags */
    while (i < Value->Length) {
	Start = Str;
	while (*Str != ',' && (i++ < Value->Length))
	    Str++;

	Flags |= GetOlemiscValue(Start, Str - Start);

	/* skip separator */
	Str++;
	i++;
    }

    return Flags;
}

static BOOL ComClassAddProgid(PCXML_STRING Progid, PENTITY Entity)
{
    PPROGIDS Progids = &Entity->ComClass.Progids;

    if (Progids->Allocated == 0) {
	Progids->Allocated = 4;
	if (!(Progids->Progids = RtlAllocateHeap(RtlGetProcessHeap(), 0,
						 Progids->Allocated * sizeof(PWSTR))))
	    return FALSE;
    }

    if (Progids->Allocated == Progids->Count) {
	PWSTR *NewProgids = RtlReAllocateHeap(RtlGetProcessHeap(), 0, Progids->Progids,
					       2 * Progids->Allocated * sizeof(PWSTR));
	if (!NewProgids)
	    return FALSE;
	Progids->Allocated *= 2;
	Progids->Progids = NewProgids;
    }

    if (!(Progids->Progids[Progids->Count] = RtlpDuplicateXmlString(Progid)))
	return FALSE;
    Progids->Count++;

    return TRUE;
}

static void ParseComClassProgid(PXML_BUFFER Xmlbuf, PENTITY Entity,
				PCXML_ELEMENT Parent)
{
    XML_STRING Content;
    BOOL End = FALSE;

    ParseExpectNoAttr(Xmlbuf, &End);
    if (End)
	SetError(Xmlbuf);
    if (!ParseTextContent(Xmlbuf, &Content))
	return;

    if (!ComClassAddProgid(&Content, Entity))
	SetError(Xmlbuf);
    ParseExpectEndElem(Xmlbuf, Parent);
}

static void ParseComClassElem(PXML_BUFFER Xmlbuf, PDLL_REDIRECT Dll,
			      PACTCTX_LOADER Acl, PCXML_ELEMENT Parent)
{
    XML_ELEMENT Elem;
    XML_ATTRIBUTE Attr;
    BOOL End = FALSE;
    PENTITY Entity;

    if (!(Entity = AddEntity(&Dll->Entities,
			      ACTIVATION_CONTEXT_SECTION_COM_SERVER_REDIRECTION))) {
	SetError(Xmlbuf);
	return;
    }

    while (NextXmlAttr(Xmlbuf, &Attr, &End)) {
	if (RtlpCompareXmlAttribute(&Attr, L"clsid")) {
	    if (!(Entity->ComClass.Clsid = RtlpDuplicateXmlString(&Attr.Value)))
		SetError(Xmlbuf);
	} else if (RtlpCompareXmlAttribute(&Attr, L"progid")) {
	    if (!(Entity->ComClass.Progid = RtlpDuplicateXmlString(&Attr.Value)))
		SetError(Xmlbuf);
	} else if (RtlpCompareXmlAttribute(&Attr, L"tlbid")) {
	    if (!(Entity->ComClass.Tlbid = RtlpDuplicateXmlString(&Attr.Value)))
		SetError(Xmlbuf);
	} else if (RtlpCompareXmlAttribute(&Attr, L"threadingModel")) {
	    Entity->ComClass.Model = ParseComClassThreadingmodel(&Attr.Value);
	} else if (RtlpCompareXmlAttribute(&Attr, L"miscStatus")) {
	    Entity->ComClass.MiscStatus = ParseComClassMisc(&Attr.Value);
	} else if (RtlpCompareXmlAttribute(&Attr, L"miscStatusContent")) {
	    Entity->ComClass.MiscStatusContent = ParseComClassMisc(&Attr.Value);
	} else if (RtlpCompareXmlAttribute(&Attr, L"miscStatusThumbnail")) {
	    Entity->ComClass.MiscStatusThumbnail = ParseComClassMisc(&Attr.Value);
	} else if (RtlpCompareXmlAttribute(&Attr, L"miscStatusIcon")) {
	    Entity->ComClass.MiscStatusIcon = ParseComClassMisc(&Attr.Value);
	} else if (RtlpCompareXmlAttribute(&Attr, L"miscStatusDocPrint")) {
	    Entity->ComClass.MiscStatusDocPrint = ParseComClassMisc(&Attr.Value);
	} else if (RtlpCompareXmlAttribute(&Attr, L"description")) {
	    /* not stored */
	} else if (!IsXmlnsAttr(&Attr)) {
	    WARN_UNEXPECTED_ATTR(Attr);
	}
    }

    Acl->ActCtx->Sections |= SERVERREDIRECT_SECTION;
    if (Entity->ComClass.Progid)
	Acl->ActCtx->Sections |= PROGIDREDIRECT_SECTION;

    if (End)
	return;

    while (NextXmlElem(Xmlbuf, &Elem, Parent)) {
	if (RtlpCompareXmlElement(&Elem, L"progid", AssemblyV1)) {
	    ParseComClassProgid(Xmlbuf, Entity, &Elem);
	} else {
	    WARN_UNEXPECTED_ELEM(Elem);
	    ParseUnknownElem(Xmlbuf, &Elem);
	}
    }

    if (Entity->ComClass.Progids.Count)
	Acl->ActCtx->Sections |= PROGIDREDIRECT_SECTION;
}

static BOOL ParseNumMethods(PCXML_STRING Str, PENTITY Entity)
{
    PCWSTR Curr;
    ULONG Num = 0;

    for (Curr = Str->Ptr; Curr < Str->Ptr + Str->Length; Curr++) {
	if (*Curr >= '0' && *Curr <= '9')
	    Num = Num * 10 + *Curr - '0';
	else {
	    ERR_(LDR, "wrong numeric value %ws\n", Str->Ptr);
	    return FALSE;
	}
    }
    Entity->Ifaceps.NumMethods = Num;

    return TRUE;
}

static void ParseAddInterfaceClass(PXML_BUFFER Xmlbuf, PENTITY_ARRAY Entities,
				   PACTCTX_LOADER Acl, PWSTR Clsid)
{
    PENTITY Entity;
    PWSTR Str;

    if (!Clsid)
	return;

    if (!(Str = RtlpDuplicateWideString(Clsid))) {
	SetError(Xmlbuf);
	return;
    }

    if (!(Entity = AddEntity(Entities,
			      ACTIVATION_CONTEXT_SECTION_COM_SERVER_REDIRECTION))) {
	RtlFreeHeap(RtlGetProcessHeap(), 0, Str);
	SetError(Xmlbuf);
	return;
    }

    Entity->ComClass.Clsid = Str;
    Entity->ComClass.Model = ThreadingModel_Both;

    Acl->ActCtx->Sections |= SERVERREDIRECT_SECTION;
}

static void ParseCominterfaceProxyStubElem(PXML_BUFFER Xmlbuf, PDLL_REDIRECT Dll,
					   PACTCTX_LOADER Acl,
					   PCXML_ELEMENT Parent)
{
    PWSTR Psclsid = NULL;
    PENTITY Entity;
    XML_ATTRIBUTE Attr;
    BOOL End = FALSE;

    if (!(Entity = AddEntity(&Dll->Entities,
			      ACTIVATION_CONTEXT_SECTION_COM_INTERFACE_REDIRECTION))) {
	SetError(Xmlbuf);
	return;
    }

    while (NextXmlAttr(Xmlbuf, &Attr, &End)) {
	if (RtlpCompareXmlAttribute(&Attr, L"iid")) {
	    if (!(Entity->Ifaceps.Iid = RtlpDuplicateXmlString(&Attr.Value)))
		SetError(Xmlbuf);
	} else if (RtlpCompareXmlAttribute(&Attr, L"name")) {
	    if (!(Entity->Ifaceps.Name = RtlpDuplicateXmlString(&Attr.Value)))
		SetError(Xmlbuf);
	} else if (RtlpCompareXmlAttribute(&Attr, L"baseInterface")) {
	    if (!(Entity->Ifaceps.Base = RtlpDuplicateXmlString(&Attr.Value)))
		SetError(Xmlbuf);
	    Entity->Ifaceps.Mask |= BaseIface;
	} else if (RtlpCompareXmlAttribute(&Attr, L"numMethods")) {
	    if (!(ParseNumMethods(&Attr.Value, Entity)))
		SetError(Xmlbuf);
	    Entity->Ifaceps.Mask |= NumMethods;
	} else if (RtlpCompareXmlAttribute(&Attr, L"tlbid")) {
	    if (!(Entity->Ifaceps.Tlib = RtlpDuplicateXmlString(&Attr.Value)))
		SetError(Xmlbuf);
	} else if (RtlpCompareXmlAttribute(&Attr, L"proxyStubClsid32")) {
	    if (!(Psclsid = RtlpDuplicateXmlString(&Attr.Value)))
		SetError(Xmlbuf);
	}
	/* not used */
	else if (RtlpCompareXmlAttribute(&Attr, L"threadingModel")) {
	} else if (!IsXmlnsAttr(&Attr)) {
	    WARN_UNEXPECTED_ATTR(Attr);
	}
    }

    Acl->ActCtx->Sections |= IFACEREDIRECT_SECTION;
    if (!End)
	ParseExpectEndElem(Xmlbuf, Parent);

    ParseAddInterfaceClass(Xmlbuf, &Dll->Entities, Acl,
			      Psclsid ? Psclsid : Entity->Ifaceps.Iid);

    RtlFreeHeap(RtlGetProcessHeap(), 0, Psclsid);
}

static BOOL ParseTypelibFlags(PCXML_STRING Value, PENTITY Entity)
{
    WORD *Flags = &Entity->TypeLib.Flags;
    PCWSTR Str = Value->Ptr, Start;
    int i = 0;

    *Flags = 0;

    /* it's comma separated list of flags */
    while (i < Value->Length) {
	Start = Str;
	while (*Str != ',' && (i++ < Value->Length))
	    Str++;

	if (!_wcsnicmp(Start, L"RESTRICTED", Str - Start))
	    *Flags |= LIBFLAG_FRESTRICTED;
	else if (!_wcsnicmp(Start, L"CONTROL", Str - Start))
	    *Flags |= LIBFLAG_FCONTROL;
	else if (!_wcsnicmp(Start, L"HIDDEN", Str - Start))
	    *Flags |= LIBFLAG_FHIDDEN;
	else if (!_wcsnicmp(Start, L"HASDISKIMAGE", Str - Start))
	    *Flags |= LIBFLAG_FHASDISKIMAGE;
	else {
	    WARN_(LDR, "unknown flags value %ws\n", Value->Ptr);
	    return FALSE;
	}

	/* skip separator */
	Str++;
	i++;
    }

    return TRUE;
}

static BOOL ParseTypelibVersion(PCXML_STRING Str, PENTITY Entity)
{
    unsigned int Ver[2];
    unsigned int Pos;
    PCWSTR Curr;

    /* major.minor */
    Ver[0] = Ver[1] = Pos = 0;
    for (Curr = Str->Ptr; Curr < Str->Ptr + Str->Length; Curr++) {
	if (*Curr >= '0' && *Curr <= '9') {
	    Ver[Pos] = Ver[Pos] * 10 + *Curr - '0';
	    if (Ver[Pos] >= 0x10000)
		goto error;
	} else if (*Curr == '.') {
	    if (++Pos >= 2)
		goto error;
	} else
	    goto error;
    }
    Entity->TypeLib.Major = Ver[0];
    Entity->TypeLib.Minor = Ver[1];
    return TRUE;

error:
    INFO_(LDR, "wrong typelib version value (%ws)\n", Str->Ptr);
    return FALSE;
}

static void ParseTypelibElement(PXML_BUFFER Xmlbuf, PDLL_REDIRECT Dll,
				PACTCTX_LOADER Acl, PCXML_ELEMENT Parent)
{
    XML_ATTRIBUTE Attr;
    BOOL End = FALSE;
    PENTITY Entity;

    if (!(Entity = AddEntity(&Dll->Entities,
			      ACTIVATION_CONTEXT_SECTION_COM_TYPE_LIBRARY_REDIRECTION))) {
	SetError(Xmlbuf);
	return;
    }

    while (NextXmlAttr(Xmlbuf, &Attr, &End)) {
	if (RtlpCompareXmlAttribute(&Attr, L"tlbid")) {
	    if (!(Entity->TypeLib.Tlbid = RtlpDuplicateXmlString(&Attr.Value)))
		SetError(Xmlbuf);
	} else if (RtlpCompareXmlAttribute(&Attr, L"version")) {
	    if (!ParseTypelibVersion(&Attr.Value, Entity))
		SetError(Xmlbuf);
	} else if (RtlpCompareXmlAttribute(&Attr, L"helpdir")) {
	    if (!(Entity->TypeLib.HelpDir = RtlpDuplicateXmlString(&Attr.Value)))
		SetError(Xmlbuf);
	} else if (RtlpCompareXmlAttribute(&Attr, L"flags")) {
	    if (!ParseTypelibFlags(&Attr.Value, Entity))
		SetError(Xmlbuf);
	} else if (!IsXmlnsAttr(&Attr)) {
	    WARN_UNEXPECTED_ATTR(Attr);
	}
    }

    Acl->ActCtx->Sections |= TLIBREDIRECT_SECTION;
    if (!End)
	ParseExpectEndElem(Xmlbuf, Parent);
}

static inline int AlignedStringLen(int Len)
{
    return (Len + 3) & ~3;
}

static int GetAssemblyVersion(PASSEMBLY Assembly, PWSTR Ret)
{
    PASSEMBLY_VERSION Ver = &Assembly->Id.Version;
    WCHAR Buff[25];

    if (!Ret)
	Ret = Buff;
    return _snwprintf(Ret, ARRAYSIZE(Buff), L"%u.%u.%u.%u", Ver->Major, Ver->Minor,
		      Ver->Build, Ver->Revision);
}

static void ParseWindowClassElem(PXML_BUFFER Xmlbuf, PDLL_REDIRECT Dll,
				 PACTCTX_LOADER Acl,
				 PCXML_ELEMENT Parent)
{
    XML_ELEMENT Elem;
    XML_ATTRIBUTE Attr;
    XML_STRING Content;
    BOOL End = FALSE;
    PENTITY Entity;

    if (!(Entity = AddEntity(&Dll->Entities,
			      ACTIVATION_CONTEXT_SECTION_WINDOW_CLASS_REDIRECTION))) {
	SetError(Xmlbuf);
	return;
    }
    Entity->Class.Versioned = TRUE;
    while (NextXmlAttr(Xmlbuf, &Attr, &End)) {
	if (RtlpCompareXmlAttribute(&Attr, L"versioned")) {
	    if (RtlpCompareXmlStringCaseInsensitive(&Attr.Value, L"no"))
		Entity->Class.Versioned = FALSE;
	    else if (!RtlpCompareXmlStringCaseInsensitive(&Attr.Value, L"yes"))
		SetError(Xmlbuf);
	} else if (!IsXmlnsAttr(&Attr)) {
	    WARN_UNEXPECTED_ATTR(Attr);
	}
    }

    if (End)
	return;

    if (!ParseTextContent(Xmlbuf, &Content))
	return;
    if (!(Entity->Class.Name = RtlpDuplicateXmlString(&Content)))
	SetError(Xmlbuf);

    Acl->ActCtx->Sections |= WINDOWCLASS_SECTION;

    while (NextXmlElem(Xmlbuf, &Elem, Parent)) {
	WARN_UNEXPECTED_ELEM(Elem);
	ParseUnknownElem(Xmlbuf, &Elem);
    }
}

static void ParseBindingRedirectElem(PXML_BUFFER Xmlbuf, PCXML_ELEMENT Parent)
{
    XML_ATTRIBUTE Attr;
    BOOL End = FALSE;

    while (NextXmlAttr(Xmlbuf, &Attr, &End)) {
	if (RtlpCompareXmlAttribute(&Attr, L"oldVersion")) {
	    WARN_ATTR("Not stored yet", Attr);
	} else if (RtlpCompareXmlAttribute(&Attr, L"newVersion")) {
	    WARN_ATTR("Not stored yet", Attr);
	} else if (!IsXmlnsAttr(&Attr)) {
	    WARN_UNEXPECTED_ATTR(Attr);
	}
    }

    if (!End)
	ParseExpectEndElem(Xmlbuf, Parent);
}

static void ParseDescriptionElem(PXML_BUFFER Xmlbuf, PCXML_ELEMENT Parent)
{
    XML_ELEMENT Elem;
    XML_ATTRIBUTE Attr;
    XML_STRING Content;
    BOOL End = FALSE;

    while (NextXmlAttr(Xmlbuf, &Attr, &End)) {
	if (!IsXmlnsAttr(&Attr))
	    WARN_UNEXPECTED_ATTR(Attr);
    }

    if (End)
	return;
    if (!ParseTextContent(Xmlbuf, &Content))
	return;

    TRACE_(LDR, "Got description %ws\n", Content.Ptr);

    while (NextXmlElem(Xmlbuf, &Elem, Parent)) {
	WARN_UNEXPECTED_ELEM(Elem);
	ParseUnknownElem(Xmlbuf, &Elem);
    }
}

static void ParseComInterfaceExternalProxyStubElem(PXML_BUFFER Xmlbuf,
						   PASSEMBLY Assembly,
						   PACTCTX_LOADER Acl,
						   PCXML_ELEMENT Parent)
{
    XML_ATTRIBUTE Attr;
    BOOL End = FALSE;
    PENTITY Entity;

    if (!(Entity = AddEntity(&Assembly->Entities,
			      ACTIVATION_CONTEXT_SECTION_COM_INTERFACE_REDIRECTION))) {
	SetError(Xmlbuf);
	return;
    }

    while (NextXmlAttr(Xmlbuf, &Attr, &End)) {
	if (RtlpCompareXmlAttribute(&Attr, L"iid")) {
	    if (!(Entity->Ifaceps.Iid = RtlpDuplicateXmlString(&Attr.Value)))
		SetError(Xmlbuf);
	} else if (RtlpCompareXmlAttribute(&Attr, L"name")) {
	    if (!(Entity->Ifaceps.Name = RtlpDuplicateXmlString(&Attr.Value)))
		SetError(Xmlbuf);
	} else if (RtlpCompareXmlAttribute(&Attr, L"baseInterface")) {
	    if (!(Entity->Ifaceps.Base = RtlpDuplicateXmlString(&Attr.Value)))
		SetError(Xmlbuf);
	    Entity->Ifaceps.Mask |= BaseIface;
	} else if (RtlpCompareXmlAttribute(&Attr, L"numMethods")) {
	    if (!(ParseNumMethods(&Attr.Value, Entity)))
		SetError(Xmlbuf);
	    Entity->Ifaceps.Mask |= NumMethods;
	} else if (RtlpCompareXmlAttribute(&Attr, L"proxyStubClsid32")) {
	    if (!(Entity->Ifaceps.Ps32 = RtlpDuplicateXmlString(&Attr.Value)))
		SetError(Xmlbuf);
	} else if (RtlpCompareXmlAttribute(&Attr, L"tlbid")) {
	    if (!(Entity->Ifaceps.Tlib = RtlpDuplicateXmlString(&Attr.Value)))
		SetError(Xmlbuf);
	} else if (!IsXmlnsAttr(&Attr)) {
	    WARN_UNEXPECTED_ATTR(Attr);
	}
    }

    Acl->ActCtx->Sections |= IFACEREDIRECT_SECTION;
    if (!End)
	ParseExpectEndElem(Xmlbuf, Parent);
}

static void ParseClrClassElement(PXML_BUFFER Xmlbuf, PASSEMBLY Assembly,
				 PACTCTX_LOADER Acl, PCXML_ELEMENT Parent)

{
    XML_ELEMENT Elem;
    XML_ATTRIBUTE Attr;
    BOOL End = FALSE;
    PENTITY Entity;

    if (!(Entity = AddEntity(&Assembly->Entities,
			      ACTIVATION_CONTEXT_SECTION_COM_SERVER_REDIRECTION))) {
	SetError(Xmlbuf);
	return;
    }

    while (NextXmlAttr(Xmlbuf, &Attr, &End)) {
	if (RtlpCompareXmlAttribute(&Attr, L"name")) {
	    if (!(Entity->ComClass.Name = RtlpDuplicateXmlString(&Attr.Value)))
		SetError(Xmlbuf);
	} else if (RtlpCompareXmlAttribute(&Attr, L"clsid")) {
	    if (!(Entity->ComClass.Clsid = RtlpDuplicateXmlString(&Attr.Value)))
		SetError(Xmlbuf);
	} else if (RtlpCompareXmlAttribute(&Attr, L"progid")) {
	    if (!(Entity->ComClass.Progid = RtlpDuplicateXmlString(&Attr.Value)))
		SetError(Xmlbuf);
	} else if (RtlpCompareXmlAttribute(&Attr, L"tlbid")) {
	    if (!(Entity->ComClass.Tlbid = RtlpDuplicateXmlString(&Attr.Value)))
		SetError(Xmlbuf);
	} else if (RtlpCompareXmlAttribute(&Attr, L"threadingModel")) {
	    Entity->ComClass.Model = ParseComClassThreadingmodel(&Attr.Value);
	} else if (RtlpCompareXmlAttribute(&Attr, L"runtimeVersion")) {
	    if (!(Entity->ComClass.Version = RtlpDuplicateXmlString(&Attr.Value)))
		SetError(Xmlbuf);
	} else if (!IsXmlnsAttr(&Attr)) {
	    WARN_UNEXPECTED_ATTR(Attr);
	}
    }

    Acl->ActCtx->Sections |= SERVERREDIRECT_SECTION;
    if (Entity->ComClass.Progid)
	Acl->ActCtx->Sections |= PROGIDREDIRECT_SECTION;
    if (End)
	return;

    while (NextXmlElem(Xmlbuf, &Elem, Parent)) {
	if (RtlpCompareXmlElement(&Elem, L"progid", AssemblyV1)) {
	    ParseComClassProgid(Xmlbuf, Entity, &Elem);
	} else {
	    WARN_UNEXPECTED_ELEM(Elem);
	    ParseUnknownElem(Xmlbuf, &Elem);
	}
    }

    if (Entity->ComClass.Progids.Count)
	Acl->ActCtx->Sections |= PROGIDREDIRECT_SECTION;
}

static void ParseClrSurrogateElement(PXML_BUFFER Xmlbuf, PASSEMBLY Assembly,
				     PACTCTX_LOADER Acl,
				     PCXML_ELEMENT Parent)
{
    XML_ATTRIBUTE Attr;
    BOOL End = FALSE;
    PENTITY Entity;

    if (!(Entity = AddEntity(&Assembly->Entities,
			      ACTIVATION_CONTEXT_SECTION_CLR_SURROGATES))) {
	SetError(Xmlbuf);
	return;
    }

    while (NextXmlAttr(Xmlbuf, &Attr, &End)) {
	if (RtlpCompareXmlAttribute(&Attr, L"name")) {
	    if (!(Entity->ClrSurrogate.Name = RtlpDuplicateXmlString(&Attr.Value)))
		SetError(Xmlbuf);
	} else if (RtlpCompareXmlAttribute(&Attr, L"clsid")) {
	    if (!(Entity->ClrSurrogate.Clsid = RtlpDuplicateXmlString(&Attr.Value)))
		SetError(Xmlbuf);
	} else if (RtlpCompareXmlAttribute(&Attr, L"runtimeVersion")) {
	    if (!(Entity->ClrSurrogate.Version = RtlpDuplicateXmlString(&Attr.Value)))
		SetError(Xmlbuf);
	} else if (!IsXmlnsAttr(&Attr)) {
	    WARN_UNEXPECTED_ATTR(Attr);
	}
    }

    Acl->ActCtx->Sections |= CLRSURROGATES_SECTION;
    if (!End)
	ParseExpectEndElem(Xmlbuf, Parent);
}

static void ParseDependentAssemblyElement(PXML_BUFFER Xmlbuf, PACTCTX_LOADER Acl,
					  PCXML_ELEMENT Parent, BOOL Optional)
{
    XML_ELEMENT Elem;
    XML_ATTRIBUTE Attr;
    ASSEMBLY_IDENTITY Ai;
    BOOL End = FALSE;

    memset(&Ai, 0, sizeof(Ai));
    Ai.Optional = Optional;

    while (NextXmlAttr(Xmlbuf, &Attr, &End)) {
	if (RtlpCompareXmlAttribute(&Attr, L"allowDelayedBinding"))
	    Ai.Delayed = RtlpCompareXmlString(&Attr.Value, L"true");
	else if (!IsXmlnsAttr(&Attr))
	    WARN_UNEXPECTED_ATTR(Attr);
    }

    if (End)
	return;

    while (NextXmlElem(Xmlbuf, &Elem, Parent)) {
	if (RtlpCompareXmlElement(&Elem, L"assemblyIdentity", AssemblyV1)) {
	    ParseAssemblyIdentityElement(Xmlbuf, Acl->ActCtx, &Ai, &Elem);
	    /* store the newly found identity for later loading */
	    if (Ai.Architecture && !wcscmp(Ai.Architecture, L"*")) {
		RtlFreeHeap(RtlGetProcessHeap(), 0, Ai.Architecture);
		Ai.Architecture = RtlpDuplicateWideString(CurrentArchitecture);
	    }
	    TRACE_(LDR, "adding name=%ws version=" DEBUGSTR_VERSION_FMT " arch=%ws\n",
		   Ai.Name, DEBUGSTR_VERSION(&Ai.Version), Ai.Architecture);
	    if (!AddDependentAssemblyId(Acl, &Ai))
		SetError(Xmlbuf);
	} else if (RtlpCompareXmlElement(&Elem, L"bindingRedirect", AssemblyV1)) {
	    ParseBindingRedirectElem(Xmlbuf, &Elem);
	} else {
	    WARN_UNEXPECTED_ELEM(Elem);
	    ParseUnknownElem(Xmlbuf, &Elem);
	}
    }
}

static void ParseDependencyElement(PXML_BUFFER Xmlbuf, PACTCTX_LOADER Acl,
				   PCXML_ELEMENT Parent)

{
    XML_ELEMENT Elem;
    XML_ATTRIBUTE Attr;
    BOOL End = FALSE, Optional = FALSE;

    while (NextXmlAttr(Xmlbuf, &Attr, &End)) {
	if (RtlpCompareXmlAttribute(&Attr, L"optional")) {
	    Optional = RtlpCompareXmlStringCaseInsensitive(&Attr.Value, L"yes");
	    TRACE_(LDR, "optional=%ws\n", Attr.Value.Ptr);
	} else if (!IsXmlnsAttr(&Attr)) {
	    WARN_UNEXPECTED_ATTR(Attr);
	}
    }

    if (End)
	return;

    while (NextXmlElem(Xmlbuf, &Elem, Parent)) {
	if (RtlpCompareXmlElement(&Elem, L"dependentAssembly", AssemblyV1)) {
	    ParseDependentAssemblyElement(Xmlbuf, Acl, &Elem, Optional);
	} else {
	    WARN_UNEXPECTED_ELEM(Elem);
	    ParseUnknownElem(Xmlbuf, &Elem);
	}
    }
}

static void ParseNoinheritElement(PXML_BUFFER Xmlbuf, PCXML_ELEMENT Parent)
{
    BOOL End = FALSE;

    ParseExpectNoAttr(Xmlbuf, &End);
    if (!End)
	ParseExpectEndElem(Xmlbuf, Parent);
}

static void ParseNoinheritableElement(PXML_BUFFER Xmlbuf, PCXML_ELEMENT Parent)
{
    BOOL End = FALSE;

    ParseExpectNoAttr(Xmlbuf, &End);
    if (!End)
	ParseExpectEndElem(Xmlbuf, Parent);
}

static void ParseActivatableClassElement(PXML_BUFFER Xmlbuf, PDLL_REDIRECT Dll,
					 PACTCTX_LOADER Acl,
					 PCXML_ELEMENT Parent)
{
    XML_ELEMENT Elem;
    XML_ATTRIBUTE Attr;
    BOOL End = FALSE;
    PENTITY Entity;

    if (!(Entity = AddEntity(&Dll->Entities,
			      ACTIVATION_CONTEXT_SECTION_WINRT_ACTIVATABLE_CLASSES))) {
	SetError(Xmlbuf);
	return;
    }
    while (NextXmlAttr(Xmlbuf, &Attr, &End)) {
	if (RtlpCompareXmlAttribute(&Attr, L"name")) {
	    if (!(Entity->ActivatableClass.Name = RtlpDuplicateXmlString(&Attr.Value)))
		SetError(Xmlbuf);
	} else if (RtlpCompareXmlAttribute(&Attr, L"threadingModel")) {
	    if (RtlpCompareXmlStringCaseInsensitive(&Attr.Value, L"both"))
		Entity->ActivatableClass.ThreadingModel = 0;
	    else if (RtlpCompareXmlStringCaseInsensitive(&Attr.Value, L"sta"))
		Entity->ActivatableClass.ThreadingModel = 1;
	    else if (RtlpCompareXmlStringCaseInsensitive(&Attr.Value, L"mta"))
		Entity->ActivatableClass.ThreadingModel = 2;
	    else
		SetError(Xmlbuf);
	} else if (!IsXmlnsAttr(&Attr)) {
	    WARN_UNEXPECTED_ATTR(Attr);
	}
    }

    Acl->ActCtx->Sections |= ACTIVATABLE_CLASS_SECTION;

    if (End)
	return;

    while (NextXmlElem(Xmlbuf, &Elem, Parent)) {
	WARN_UNEXPECTED_ELEM(Elem);
	ParseUnknownElem(Xmlbuf, &Elem);
    }
}

static void ParseFileElement(PXML_BUFFER Xmlbuf, PASSEMBLY Assembly,
			     PACTCTX_LOADER Acl, PCXML_ELEMENT Parent)
{
    XML_ELEMENT Elem;
    XML_ATTRIBUTE Attr;
    BOOL End = FALSE;
    PDLL_REDIRECT Dll;

    if (!(Dll = AddDllRedirect(Assembly))) {
	SetError(Xmlbuf);
	return;
    }

    while (NextXmlAttr(Xmlbuf, &Attr, &End)) {
	if (RtlpCompareXmlAttribute(&Attr, L"name")) {
	    if (!(Dll->Name = RtlpDuplicateXmlString(&Attr.Value)))
		SetError(Xmlbuf);
	    TRACE_(LDR, "name=%ws\n", Attr.Value.Ptr);
	} else if (RtlpCompareXmlAttribute(&Attr, L"loadFrom")) {
	    if (!(Dll->LoadFrom = RtlpDuplicateXmlString(&Attr.Value)))
		SetError(Xmlbuf);
	} else if (RtlpCompareXmlAttribute(&Attr, L"hash")) {
	    if (!(Dll->Hash = RtlpDuplicateXmlString(&Attr.Value)))
		SetError(Xmlbuf);
	} else if (RtlpCompareXmlAttribute(&Attr, L"hashalg")) {
	    if (!RtlpCompareXmlStringCaseInsensitive(&Attr.Value, L"SHA1"))
		INFO_(LDR, "hashalg should be SHA1, got %ws\n",
		      Attr.Value.Ptr);
	} else if (!IsXmlnsAttr(&Attr)) {
	    WARN_UNEXPECTED_ATTR(Attr);
	}
    }

    if (!Dll->Name)
	SetError(Xmlbuf);

    Acl->ActCtx->Sections |= DLLREDIRECT_SECTION;

    if (End)
	return;

    while (NextXmlElem(Xmlbuf, &Elem, Parent)) {
	if (RtlpCompareXmlElement(&Elem, L"comClass", AssemblyV1)) {
	    ParseComClassElem(Xmlbuf, Dll, Acl, &Elem);
	} else if (RtlpCompareXmlElement(&Elem, L"comInterfaceProxyStub", AssemblyV1)) {
	    ParseCominterfaceProxyStubElem(Xmlbuf, Dll, Acl, &Elem);
	} else if (RtlpCompareXmlElement(&Elem, L"hash", AssemblyV2)) {
	    WARN_(LDR, "asmv2:hash (undocumented) not supported\n");
	    ParseUnknownElem(Xmlbuf, &Elem);
	} else if (RtlpCompareXmlElement(&Elem, L"typelib", AssemblyV1)) {
	    ParseTypelibElement(Xmlbuf, Dll, Acl, &Elem);
	} else if (RtlpCompareXmlElement(&Elem, L"windowClass", AssemblyV1)) {
	    ParseWindowClassElem(Xmlbuf, Dll, Acl, &Elem);
	} else if (RtlpCompareXmlElement(&Elem, L"activatableClass", WinrtV1)) {
	    ParseActivatableClassElement(Xmlbuf, Dll, Acl, &Elem);
	} else {
	    WARN_UNEXPECTED_ELEM(Elem);
	    ParseUnknownElem(Xmlbuf, &Elem);
	}
    }
}

static void ParseSupportedOsElement(PXML_BUFFER Xmlbuf, PASSEMBLY Assembly,
				    PACTCTX_LOADER Acl,
				    PCXML_ELEMENT Parent)
{
    XML_ATTRIBUTE Attr;
    BOOL End = FALSE;

    while (NextXmlAttr(Xmlbuf, &Attr, &End)) {
	if (RtlpCompareXmlAttribute(&Attr, L"Id")) {
	    COMPATIBILITY_CONTEXT_ELEMENT *Compat;
	    UNICODE_STRING Str;
	    GUID CompatId;

	    Str.Buffer = (PWSTR)Attr.Value.Ptr;
	    Str.Length = Str.MaximumLength = (USHORT)Attr.Value.Length * sizeof(WCHAR);
	    if (RtlGUIDFromString(&Str, &CompatId) == STATUS_SUCCESS) {
		if (!(Compat = AddCompatContext(Assembly))) {
		    SetError(Xmlbuf);
		    return;
		}
		Compat->Type = ACTCTX_COMPATIBILITY_ELEMENT_TYPE_OS;
		Compat->Id = CompatId;
	    } else {
		WARN_(LDR, "Invalid guid %ws\n", Attr.Value.Ptr);
	    }
	} else if (!IsXmlnsAttr(&Attr)) {
	    WARN_UNEXPECTED_ATTR(Attr);
	}
    }

    if (!End)
	ParseExpectEndElem(Xmlbuf, Parent);
}

static void ParseMaxVersionTestedElement(PXML_BUFFER Xmlbuf, PASSEMBLY Assembly,
					 PACTCTX_LOADER Acl,
					 PCXML_ELEMENT Parent)
{
    XML_ATTRIBUTE Attr;
    BOOL End = FALSE;

    while (NextXmlAttr(Xmlbuf, &Attr, &End)) {
	if (RtlpCompareXmlAttribute(&Attr, L"Id")) {
	    COMPATIBILITY_CONTEXT_ELEMENT *Compat;
	    ASSEMBLY_VERSION Version;

	    if (!(Compat = AddCompatContext(Assembly))) {
		SetError(Xmlbuf);
		return;
	    }
	    ParseVersion(&Attr.Value, &Version);
	    Compat->Type = ACTCTX_COMPATIBILITY_ELEMENT_TYPE_MAXVERSIONTESTED;
	    Compat->MaxVersionTested = (ULONGLONG)Version.Major << 48 |
				       (ULONGLONG)Version.Minor << 32 |
				       Version.Build << 16 | Version.Revision;
	} else if (!IsXmlnsAttr(&Attr)) {
	    WARN_UNEXPECTED_ATTR(Attr);
	}
    }

    if (!End)
	ParseExpectEndElem(Xmlbuf, Parent);
}

static void ParseCompatibilityApplicationElement(PXML_BUFFER Xmlbuf,
						 PASSEMBLY Assembly,
						 PACTCTX_LOADER Acl,
						 PCXML_ELEMENT Parent)
{
    XML_ELEMENT Elem;

    while (NextXmlElem(Xmlbuf, &Elem, Parent)) {
	if (RtlpCompareXmlElement(&Elem, L"supportedOS", CompatibilityNS)) {
	    ParseSupportedOsElement(Xmlbuf, Assembly, Acl, &Elem);
	}
#if (NTDDI_VERSION >= NTDDI_WIN10_19H1)
	else if (RtlpCompareXmlElement(&Elem, L"maxversiontested", CompatibilityNS)) {
	    ParseMaxVersionTestedElement(Xmlbuf, Assembly, Acl, &Elem);
	}
#endif // NTDDI_VERSION >= NTDDI_WIN10_19H1
	else {
	    WARN_UNEXPECTED_ELEM(Elem);
	    ParseUnknownElem(Xmlbuf, &Elem);
	}
    }
}

static void ParseCompatibilityElement(PXML_BUFFER Xmlbuf, PASSEMBLY Assembly,
				      PACTCTX_LOADER Acl,
				      PCXML_ELEMENT Parent)
{
    XML_ELEMENT Elem;

    while (NextXmlElem(Xmlbuf, &Elem, Parent)) {
	if (RtlpCompareXmlElement(&Elem, L"application", CompatibilityNS)) {
	    ParseCompatibilityApplicationElement(Xmlbuf, Assembly, Acl, &Elem);
	} else {
	    WARN_UNEXPECTED_ELEM(Elem);
	    ParseUnknownElem(Xmlbuf, &Elem);
	}
    }
}

static void ParseSettingsElement(PXML_BUFFER Xmlbuf, PASSEMBLY Assembly,
				 PACTCTX_LOADER Acl, PXML_ELEMENT Parent)
{
    XML_ELEMENT Elem;
    XML_ATTRIBUTE Attr;
    XML_STRING Content;
    BOOL End = FALSE;
    PENTITY Entity;

    while (NextXmlAttr(Xmlbuf, &Attr, &End)) {
	if (!IsXmlnsAttr(&Attr))
	    WARN_UNEXPECTED_ATTR(Attr);
    }

    if (End)
	return;

    if (!ParseTextContent(Xmlbuf, &Content))
	return;
    TRACE_(LDR, "got %ws %ws\n", Parent->Name.Ptr, Content.Ptr);

    Entity = AddEntity(&Assembly->Entities,
			ACTIVATION_CONTEXT_SECTION_APPLICATION_SETTINGS);
    if (!Entity) {
	SetError(Xmlbuf);
	return;
    }
    Entity->Settings.Name = RtlpDuplicateXmlString(&Parent->Name);
    Entity->Settings.Value = RtlpDuplicateXmlString(&Content);
    Entity->Settings.Namespace = RtlpDuplicateXmlString(&Parent->Namespace);

    while (NextXmlElem(Xmlbuf, &Elem, Parent)) {
	WARN_UNEXPECTED_ELEM(Elem);
	ParseUnknownElem(Xmlbuf, &Elem);
    }
}

static void ParseWindowsSettingsElement(PXML_BUFFER Xmlbuf, PASSEMBLY Assembly,
					PACTCTX_LOADER Acl,
					PCXML_ELEMENT Parent)
{
    XML_ELEMENT Elem;

    while (NextXmlElem(Xmlbuf, &Elem, Parent)) {
	if (RtlpCompareXmlElement(&Elem, L"activeCodePage", WindowsSettings2019NS) ||
	    RtlpCompareXmlElement(&Elem, L"autoElevate", WindowsSettings2005NS) ||
	    RtlpCompareXmlElement(&Elem, L"disableTheming", WindowsSettings2005NS) ||
	    RtlpCompareXmlElement(&Elem, L"disableWindowFiltering", WindowsSettings2011NS) ||
	    RtlpCompareXmlElement(&Elem, L"dpiAware", WindowsSettings2005NS) ||
	    RtlpCompareXmlElement(&Elem, L"dpiAwareness", WindowsSettings2016NS) ||
	    RtlpCompareXmlElement(&Elem, L"gdiScaling", WindowsSettings2017NS) ||
	    RtlpCompareXmlElement(&Elem, L"heapType", WindowsSettings2020NS) ||
	    RtlpCompareXmlElement(&Elem, L"highResolutionScrollingAware",
			 WindowsSettings2017NS) ||
	    RtlpCompareXmlElement(&Elem, L"longPathAware", WindowsSettings2016NS) ||
	    RtlpCompareXmlElement(&Elem, L"magicFutureSetting", WindowsSettings2017NS) ||
	    RtlpCompareXmlElement(&Elem, L"printerDriverIsolation", WindowsSettings2011NS) ||
	    RtlpCompareXmlElement(&Elem, L"ultraHighResolutionScrollingAware",
			 WindowsSettings2017NS)) {
	    ParseSettingsElement(Xmlbuf, Assembly, Acl, &Elem);
	} else {
	    WARN_UNEXPECTED_ELEM(Elem);
	    ParseUnknownElem(Xmlbuf, &Elem);
	}
    }
}

static void ParseApplicationElement(PXML_BUFFER Xmlbuf, PASSEMBLY Assembly,
				    PACTCTX_LOADER Acl,
				    PCXML_ELEMENT Parent)
{
    XML_ELEMENT Elem;
    XML_ATTRIBUTE Attr;
    BOOL End = FALSE;

    while (NextXmlAttr(Xmlbuf, &Attr, &End)) {
	if (!IsXmlnsAttr(&Attr))
	    WARN_UNEXPECTED_ATTR(Attr);
    }

    if (End)
	return;

    while (NextXmlElem(Xmlbuf, &Elem, Parent)) {
	if (RtlpCompareXmlElement(&Elem, L"windowsSettings", AssemblyV1)) {
	    ParseWindowsSettingsElement(Xmlbuf, Assembly, Acl, &Elem);
	} else {
	    WARN_UNEXPECTED_ELEM(Elem);
	    ParseUnknownElem(Xmlbuf, &Elem);
	}
    }
}

static void ParseRequestedExecutionLevelElement(PXML_BUFFER Xmlbuf,
						PASSEMBLY Assembly,
						PACTCTX_LOADER Acl,
						PCXML_ELEMENT Parent)
{
    XML_ELEMENT Elem;
    XML_ATTRIBUTE Attr;
    BOOL End = FALSE;

    /* Multiple requestedExecutionLevel elements are not supported. */
    if (Assembly->RunLevel != ACTCTX_RUN_LEVEL_UNSPECIFIED)
	SetError(Xmlbuf);

    while (NextXmlAttr(Xmlbuf, &Attr, &End)) {
	if (RtlpCompareXmlAttribute(&Attr, L"level")) {
	    if (RtlpCompareXmlStringCaseInsensitive(&Attr.Value, L"asInvoker"))
		Assembly->RunLevel = ACTCTX_RUN_LEVEL_AS_INVOKER;
	    else if (RtlpCompareXmlStringCaseInsensitive(&Attr.Value, L"highestAvailable"))
		Assembly->RunLevel = ACTCTX_RUN_LEVEL_HIGHEST_AVAILABLE;
	    else if (RtlpCompareXmlStringCaseInsensitive(&Attr.Value, L"requireAdministrator"))
		Assembly->RunLevel = ACTCTX_RUN_LEVEL_REQUIRE_ADMIN;
	    else
		INFO_(LDR, "unknown execution level: %ws\n", Attr.Value.Ptr);
	} else if (RtlpCompareXmlAttribute(&Attr, L"uiAccess")) {
	    if (RtlpCompareXmlStringCaseInsensitive(&Attr.Value, L"false"))
		Assembly->UiAccess = FALSE;
	    else if (RtlpCompareXmlStringCaseInsensitive(&Attr.Value, L"true"))
		Assembly->UiAccess = TRUE;
	    else
		INFO_(LDR, "unknown uiAccess value: %ws\n", Attr.Value.Ptr);
	} else if (!IsXmlnsAttr(&Attr))
	    WARN_UNEXPECTED_ATTR(Attr);
    }

    if (End)
	return;

    while (NextXmlElem(Xmlbuf, &Elem, Parent)) {
	WARN_UNEXPECTED_ELEM(Elem);
	ParseUnknownElem(Xmlbuf, &Elem);
    }
}

static void ParseRequestedPrivilegesElement(PXML_BUFFER Xmlbuf, PASSEMBLY Assembly,
					    PACTCTX_LOADER Acl,
					    PCXML_ELEMENT Parent)
{
    XML_ELEMENT Elem;

    while (NextXmlElem(Xmlbuf, &Elem, Parent)) {
	if (RtlpCompareXmlElement(&Elem, L"requestedExecutionLevel", AssemblyV1)) {
	    ParseRequestedExecutionLevelElement(Xmlbuf, Assembly, Acl, &Elem);
	} else {
	    WARN_UNEXPECTED_ELEM(Elem);
	    ParseUnknownElem(Xmlbuf, &Elem);
	}
    }
}

static void ParseSecurityElement(PXML_BUFFER Xmlbuf, PASSEMBLY Assembly,
				 PACTCTX_LOADER Acl, PCXML_ELEMENT Parent)
{
    XML_ELEMENT Elem;

    while (NextXmlElem(Xmlbuf, &Elem, Parent)) {
	if (RtlpCompareXmlElement(&Elem, L"requestedPrivileges", AssemblyV1)) {
	    ParseRequestedPrivilegesElement(Xmlbuf, Assembly, Acl, &Elem);
	} else {
	    WARN_UNEXPECTED_ELEM(Elem);
	    ParseUnknownElem(Xmlbuf, &Elem);
	}
    }
}

static void ParseTrustInfoElement(PXML_BUFFER Xmlbuf, PASSEMBLY Assembly,
				  PACTCTX_LOADER Acl,
				  PCXML_ELEMENT Parent)
{
    XML_ELEMENT Elem;

    while (NextXmlElem(Xmlbuf, &Elem, Parent)) {
	if (RtlpCompareXmlElement(&Elem, L"security", AssemblyV1)) {
	    ParseSecurityElement(Xmlbuf, Assembly, Acl, &Elem);
	} else {
	    WARN_UNEXPECTED_ELEM(Elem);
	    ParseUnknownElem(Xmlbuf, &Elem);
	}
    }
}

static void ParseAssemblyElement(PXML_BUFFER Xmlbuf, PASSEMBLY Assembly,
				 PACTCTX_LOADER Acl, PCXML_ELEMENT Parent,
				 PASSEMBLY_IDENTITY ExpectedAi)
{
    XML_ELEMENT Elem;
    XML_ATTRIBUTE Attr;
    BOOL End = FALSE, Version = FALSE;

    TRACE_(LDR, "(%p)\n", Xmlbuf);

    while (NextXmlAttr(Xmlbuf, &Attr, &End)) {
	if (RtlpCompareXmlAttribute(&Attr, L"manifestVersion")) {
	    if (!RtlpCompareXmlString(&Attr.Value, L"1.0")) {
		INFO_(LDR, "wrong version %ws\n", Attr.Value.Ptr);
		break;
	    }
	    Version = TRUE;
	} else if (!IsXmlnsAttr(&Attr)) {
	    WARN_UNEXPECTED_ATTR(Attr);
	}
    }

    if (!Version) {
	SetError(Xmlbuf);
	return;
    }

    if (End)
	return;

    while (NextXmlElem(Xmlbuf, &Elem, Parent)) {
	if (Assembly->Type == APPLICATION_MANIFEST &&
	    RtlpCompareXmlElement(&Elem, L"noInherit", AssemblyV1)) {
	    ParseNoinheritElement(Xmlbuf, &Elem);
	    Assembly->NoInherit = TRUE;
	} else if (RtlpCompareXmlElement(&Elem, L"noInheritable", AssemblyV1)) {
	    ParseNoinheritableElement(Xmlbuf, &Elem);
	} else if (RtlpCompareXmlElement(&Elem, L"description", AssemblyV1)) {
	    ParseDescriptionElem(Xmlbuf, &Elem);
	} else if (RtlpCompareXmlElement(&Elem, L"comInterfaceExternalProxyStub", AssemblyV1)) {
	    ParseComInterfaceExternalProxyStubElem(Xmlbuf, Assembly, Acl, &Elem);
	} else if (RtlpCompareXmlElement(&Elem, L"dependency", AssemblyV1)) {
	    ParseDependencyElement(Xmlbuf, Acl, &Elem);
	} else if (RtlpCompareXmlElement(&Elem, L"file", AssemblyV1)) {
	    ParseFileElement(Xmlbuf, Assembly, Acl, &Elem);
	} else if (RtlpCompareXmlElement(&Elem, L"clrClass", AssemblyV1)) {
	    ParseClrClassElement(Xmlbuf, Assembly, Acl, &Elem);
	} else if (RtlpCompareXmlElement(&Elem, L"clrSurrogate", AssemblyV1)) {
	    ParseClrSurrogateElement(Xmlbuf, Assembly, Acl, &Elem);
	} else if (RtlpCompareXmlElement(&Elem, L"trustInfo", AssemblyV1)) {
	    ParseTrustInfoElement(Xmlbuf, Assembly, Acl, &Elem);
	} else if (RtlpCompareXmlElement(&Elem, L"assemblyIdentity", AssemblyV1)) {
	    ParseAssemblyIdentityElement(Xmlbuf, Acl->ActCtx, &Assembly->Id, &Elem);

	    if (!Xmlbuf->Error && ExpectedAi) {
		/* FIXME: more tests */
		if (Assembly->Type == ASSEMBLY_MANIFEST &&
		    memcmp(&Assembly->Id.Version, &ExpectedAi->Version,
			   sizeof(Assembly->Id.Version))) {
		    INFO_(LDR,
			  "wrong version for assembly manifest: %u.%u.%u.%u / "
			  "%u.%u.%u.%u\n",
			  ExpectedAi->Version.Major, ExpectedAi->Version.Minor,
			  ExpectedAi->Version.Build, ExpectedAi->Version.Revision,
			  Assembly->Id.Version.Major, Assembly->Id.Version.Minor,
			  Assembly->Id.Version.Build, Assembly->Id.Version.Revision);
		    SetError(Xmlbuf);
		} else if (Assembly->Type == ASSEMBLY_SHARED_MANIFEST &&
			   (Assembly->Id.Version.Major != ExpectedAi->Version.Major ||
			    Assembly->Id.Version.Minor != ExpectedAi->Version.Minor ||
			    Assembly->Id.Version.Build < ExpectedAi->Version.Build ||
			    (Assembly->Id.Version.Build == ExpectedAi->Version.Build &&
			     Assembly->Id.Version.Revision <
				 ExpectedAi->Version.Revision))) {
		    INFO_(LDR, "wrong version for shared assembly manifest\n");
		    SetError(Xmlbuf);
		}
	    }
	} else if (RtlpCompareXmlElement(&Elem, L"compatibility", CompatibilityNS)) {
	    ParseCompatibilityElement(Xmlbuf, Assembly, Acl, &Elem);
	} else if (RtlpCompareXmlElement(&Elem, L"application", AssemblyV1)) {
	    ParseApplicationElement(Xmlbuf, Assembly, Acl, &Elem);
	} else {
	    WARN_UNEXPECTED_ELEM(Elem);
	    ParseUnknownElem(Xmlbuf, &Elem);
	}
    }

    if ((Assembly->Type == ASSEMBLY_MANIFEST ||
	 Assembly->Type == ASSEMBLY_SHARED_MANIFEST) &&
	Assembly->NoInherit) {
	SetError(Xmlbuf);
    }
}

static NTSTATUS ParseManifestBuffer(PACTCTX_LOADER Acl,
				    PASSEMBLY Assembly,
				    PASSEMBLY_IDENTITY Ai,
				    PXML_BUFFER Xmlbuf)
{
    XML_ELEMENT Elem;
    XML_ELEMENT Parent = { 0 };

    Xmlbuf->Error = FALSE;
    Xmlbuf->NamespacePosition = 0;

    if (!NextXmlElem(Xmlbuf, &Elem, &Parent))
	return STATUS_SXS_CANT_GEN_ACTCTX;

    if (RtlpCompareXmlString(&Elem.Name, L"?xml") &&
	(!ParseXmlHeader(Xmlbuf) || !NextXmlElem(Xmlbuf, &Elem, &Parent)))
	return STATUS_SXS_CANT_GEN_ACTCTX;

    if (!RtlpCompareXmlElement(&Elem, L"assembly", AssemblyV1)) {
	WARN_ELEM("expected root element <assembly>, found ", Elem);
	return STATUS_SXS_CANT_GEN_ACTCTX;
    }

    ParseAssemblyElement(Xmlbuf, Assembly, Acl, &Elem, Ai);
    if (Xmlbuf->Error) {
	INFO_(LDR, "failed to parse manifest %ws\n", Assembly->Manifest.Info);
	return STATUS_SXS_CANT_GEN_ACTCTX;
    }

    if (NextXmlElem(Xmlbuf, &Elem, &Parent)) {
	WARN_UNEXPECTED_ELEM(Elem);
	return STATUS_SXS_CANT_GEN_ACTCTX;
    }

    if (Xmlbuf->Ptr != Xmlbuf->End) {
	INFO_(LDR, "parse error\n");
	return STATUS_SXS_CANT_GEN_ACTCTX;
    }
    return STATUS_SUCCESS;
}

static NTSTATUS ParseManifest(PACTCTX_LOADER Acl, PASSEMBLY_IDENTITY Ai,
			      LPCWSTR Filename, HANDLE Module, LPCWSTR Directory,
			      BOOL Shared, const void *Buffer, SIZE_T Size)
{
    XML_BUFFER Xmlbuf;
    NTSTATUS Status;
    PASSEMBLY Assembly;
    int UnicodeTests;

    TRACE_(LDR, "parsing manifest loaded from %ws base dir %ws\n", Filename,
	   Directory);

    if (!(Assembly = AddAssembly(Acl->ActCtx,
				  Shared ? ASSEMBLY_SHARED_MANIFEST : ASSEMBLY_MANIFEST)))
	return STATUS_SXS_CANT_GEN_ACTCTX;

    if (Directory && !(Assembly->Directory = RtlpDuplicateWideString(Directory)))
	return STATUS_NO_MEMORY;

    if (!Filename) {
	UNICODE_STRING ModulePath;
	if ((Status = GetModuleFilename(Module, &ModulePath, 0)))
	    return Status;
	Assembly->Manifest.Info = ModulePath.Buffer;
    } else if (!(Assembly->Manifest.Info = RtlpDuplicateWideString(Filename + 4 /* skip \??\ prefix */)))
	return STATUS_NO_MEMORY;

    Assembly->Manifest.Type = Assembly->Manifest.Info ?
				  ACTIVATION_CONTEXT_PATH_TYPE_WIN32_FILE :
				  ACTIVATION_CONTEXT_PATH_TYPE_NONE;

    UnicodeTests = IS_TEXT_UNICODE_SIGNATURE | IS_TEXT_UNICODE_REVERSE_SIGNATURE;
    if (RtlIsTextUnicode(Buffer, Size, &UnicodeTests)) {
	Xmlbuf.Ptr = Buffer;
	Xmlbuf.End = Xmlbuf.Ptr + Size / sizeof(WCHAR);
	Status = ParseManifestBuffer(Acl, Assembly, Ai, &Xmlbuf);
    } else if (UnicodeTests & IS_TEXT_UNICODE_REVERSE_SIGNATURE) {
	PCWSTR Buf = Buffer;
	PWSTR NewBuff;
	unsigned int i;

	if (!(NewBuff = RtlAllocateHeap(RtlGetProcessHeap(), 0, Size)))
	    return STATUS_NO_MEMORY;
	for (i = 0; i < Size / sizeof(WCHAR); i++)
	    NewBuff[i] = RtlUshortByteSwap(Buf[i]);
	Xmlbuf.Ptr = NewBuff;
	Xmlbuf.End = Xmlbuf.Ptr + Size / sizeof(WCHAR);
	Status = ParseManifestBuffer(Acl, Assembly, Ai, &Xmlbuf);
	RtlFreeHeap(RtlGetProcessHeap(), 0, NewBuff);
    } else {
	DWORD Len;
	PWSTR NewBuff;

	/* let's assume utf-8 for now */
	Status = RtlUTF8ToUnicodeN(NULL, 0, &Len, Buffer, Size);
	if (!NT_SUCCESS(Status)) {
	    DPRINT1("RtlMultiByteToUnicodeSize failed with %x\n", Status);
	    return STATUS_SXS_CANT_GEN_ACTCTX;
	}

	if (!(NewBuff = RtlAllocateHeap(RtlGetProcessHeap(), 0, Len)))
	    return STATUS_NO_MEMORY;
	Status = RtlUTF8ToUnicodeN(NewBuff, Len, &Len, Buffer, Size);
	if (!NT_SUCCESS(Status)) {
	    DPRINT1("RtlMultiByteToUnicodeN failed with %x\n", Status);
	    return STATUS_SXS_CANT_GEN_ACTCTX;
	}

	Xmlbuf.Ptr = NewBuff;
	Xmlbuf.End = Xmlbuf.Ptr + Len / sizeof(WCHAR);
	Status = ParseManifestBuffer(Acl, Assembly, Ai, &Xmlbuf);
	RtlFreeHeap(RtlGetProcessHeap(), 0, NewBuff);
    }
    return Status;
}

static NTSTATUS OpenNtFile(HANDLE *Handle, UNICODE_STRING *Name)
{
    OBJECT_ATTRIBUTES Attr;
    IO_STATUS_BLOCK Io;

    Attr.Length = sizeof(Attr);
    Attr.RootDirectory = 0;
    Attr.Attributes = OBJ_CASE_INSENSITIVE;
    Attr.ObjectName = Name;
    Attr.SecurityDescriptor = NULL;
    Attr.SecurityQualityOfService = NULL;
    return NtOpenFile(Handle, GENERIC_READ | SYNCHRONIZE, &Attr, &Io,
		      FILE_SHARE_READ | FILE_SHARE_DELETE, FILE_SYNCHRONOUS_IO_ALERT);
}

static NTSTATUS FindFirstManifestResourceInModule(HANDLE HModule,
						  const WCHAR **Resname)
{
    static LDR_RESOURCE_INFO ManifestResInfo = { RT_MANIFEST };
    const IMAGE_RESOURCE_DIRECTORY_ENTRY *EntryBase, *Entry;
    IMAGE_RESOURCE_DIRECTORY *Resdir;
    NTSTATUS Status;

    Status = LdrFindResourceDirectory_U(HModule, &ManifestResInfo, 1, &Resdir);
    if (Status != STATUS_SUCCESS)
	return Status;

    if (!Resdir->NumberOfIdEntries)
	return STATUS_RESOURCE_NAME_NOT_FOUND;
    EntryBase = (const IMAGE_RESOURCE_DIRECTORY_ENTRY *)(Resdir + 1);
    Entry = EntryBase + Resdir->NumberOfNamedEntries;
    *Resname = (PCWSTR)(ULONG_PTR)Entry->Id;

    return STATUS_SUCCESS;
}

static NTSTATUS GetManifestInModule(PACTCTX_LOADER Acl,
				    PASSEMBLY_IDENTITY Ai, LPCWSTR Filename,
				    LPCWSTR Directory, BOOL Shared, HANDLE HModule,
				    LPCWSTR Resname, ULONG Lang)
{
    NTSTATUS Status;
    UNICODE_STRING NameW;
    LDR_RESOURCE_INFO Info;
    IMAGE_RESOURCE_DATA_ENTRY *Entry = NULL;
    void *Ptr;

    // DPRINT( "looking for res %s in module %p %s\n", resname,
    //                 hModule, filename );
    DPRINT("GetManifestInModule %p\n", HModule);

    if (!Resname) {
	Status = FindFirstManifestResourceInModule(HModule, &Resname);
	if (Status != STATUS_SUCCESS)
	    return Status;
    }

    Info.Type = RT_MANIFEST;
    Info.Language = Lang;
    if (!((ULONG_PTR)Resname >> 16)) {
	Info.Name = (ULONG_PTR)Resname;
	Status = LdrFindResource_U(HModule, &Info, 3, &Entry);
    } else if (Resname[0] == '#') {
	ULONG Value;
	RtlInitUnicodeString(&NameW, Resname + 1);
	if (RtlUnicodeStringToInteger(&NameW, 10, &Value) != STATUS_SUCCESS ||
	    HIWORD(Value))
	    return STATUS_INVALID_PARAMETER;
	Info.Name = Value;
	Status = LdrFindResource_U(HModule, &Info, 3, &Entry);
    } else {
	RtlCreateUnicodeString(&NameW, Resname);
	RtlUpcaseUnicodeString(&NameW, &NameW, FALSE);
	Info.Name = (ULONG_PTR)NameW.Buffer;
	Status = LdrFindResource_U(HModule, &Info, 3, &Entry);
	RtlFreeUnicodeString(&NameW);
    }
    if (Status == STATUS_SUCCESS)
	Status = LdrAccessResource(HModule, Entry, &Ptr, NULL);

    if (Status == STATUS_SUCCESS)
	Status = ParseManifest(Acl, Ai, Filename, HModule, Directory, Shared, Ptr,
				Entry->Size);

    return Status;
}

static NTSTATUS SearchManifestInModule(PACTCTX_LOADER Acl,
				       PASSEMBLY_IDENTITY Ai, LPCWSTR Filename,
				       LPCWSTR Directory, BOOL Shared, HANDLE HModule,
				       ULONG Lang)
{
    ULONG Size;
    PVOID Root, Ptr;
    IMAGE_RESOURCE_DIRECTORY *Resdirptr;
    IMAGE_RESOURCE_DATA_ENTRY *Entry;
    NTSTATUS Status;

    Root = RtlImageDirectoryEntryToData(HModule, TRUE, IMAGE_DIRECTORY_ENTRY_RESOURCE,
					&Size);
    if (!Root)
	return STATUS_RESOURCE_DATA_NOT_FOUND;
    if (Size < sizeof(*Resdirptr))
	return STATUS_RESOURCE_DATA_NOT_FOUND;
    Resdirptr = Root;

    if (!(Ptr = RtlpFindResourceEntryByName(Resdirptr, (LPCWSTR)RT_MANIFEST, Root, 1)))
	return STATUS_RESOURCE_TYPE_NOT_FOUND;

    Resdirptr = Ptr;
    if (!(Ptr = RtlpFindFirstResourceEntry(Resdirptr, Root, 1)))
	return STATUS_RESOURCE_TYPE_NOT_FOUND;

    Resdirptr = Ptr;
    if (!(Ptr = RtlpFindFirstResourceEntry(Resdirptr, Root, 0)))
	return STATUS_RESOURCE_TYPE_NOT_FOUND;

    Entry = Ptr;
    Status = LdrAccessResource(HModule, Entry, &Ptr, NULL);

    if (Status == STATUS_SUCCESS)
	Status = ParseManifest(Acl, Ai, Filename, HModule, Directory, Shared, Ptr,
				Entry->Size);

    return Status;
}

static NTSTATUS GetManifestInPeFile(PACTCTX_LOADER Acl,
				    PASSEMBLY_IDENTITY Ai, LPCWSTR Filename,
				    LPCWSTR Directory, BOOL Shared, HANDLE File,
				    LPCWSTR Resname, ULONG Lang)
{
    HANDLE Mapping;
    OBJECT_ATTRIBUTES Attr;
    LARGE_INTEGER Size;
    LARGE_INTEGER Offset;
    NTSTATUS Status;
    SIZE_T Count;
    void *Base;
    WCHAR ResnameBuf[20];
    LPCWSTR Resptr = Resname;

    if ((!((ULONG_PTR)Resname >> 16))) {
	swprintf(ResnameBuf, L"#%u", PtrToUlong(Resname));
	Resptr = ResnameBuf;
    }

    DPRINT("looking for res %S in %S\n", Resptr, Filename ? Filename : L"<NULL>");

    Attr.Length = sizeof(Attr);
    Attr.RootDirectory = 0;
    Attr.ObjectName = NULL;
    Attr.Attributes = OBJ_CASE_INSENSITIVE | OBJ_OPENIF;
    Attr.SecurityDescriptor = NULL;
    Attr.SecurityQualityOfService = NULL;

    Size.QuadPart = 0;
    Status = NtCreateSection(&Mapping,
			     STANDARD_RIGHTS_REQUIRED | SECTION_QUERY | SECTION_MAP_READ,
			     &Attr, &Size, PAGE_READONLY, SEC_COMMIT, File);
    if (Status != STATUS_SUCCESS)
	return Status;

    Offset.QuadPart = 0;
    Count = 0;
    Base = NULL;
    Status = NtMapViewOfSection(Mapping, NtCurrentProcess(), &Base, 0, 0, &Offset,
				&Count, ViewShare, 0, PAGE_READONLY);
    NtClose(Mapping);
    if (Status != STATUS_SUCCESS)
	return Status;

    if (RtlImageNtHeader(Base)) /* we got a PE file */
    {
	HANDLE Module = (HMODULE)((ULONG_PTR)Base | 1); /* make it a
							   LOAD_LIBRARY_AS_DATAFILE handle
							 */
	if (Resname)
	    Status = GetManifestInModule(Acl, Ai, Filename, Directory, Shared, Module,
					    Resname, Lang);
	else
	    Status = SearchManifestInModule(Acl, Ai, Filename, Directory, Shared,
					       Module, Lang);
    } else
	Status = STATUS_INVALID_IMAGE_FORMAT;

    NtUnmapViewOfSection(NtCurrentProcess(), Base);
    return Status;
}

static NTSTATUS GetManifestInManifestFile(PACTCTX_LOADER Acl,
					  PASSEMBLY_IDENTITY Ai,
					  LPCWSTR Filename, LPCWSTR Directory,
					  BOOL Shared, HANDLE File)
{
    FILE_END_OF_FILE_INFORMATION Info;
    IO_STATUS_BLOCK Io;
    HANDLE Mapping;
    OBJECT_ATTRIBUTES Attr;
    LARGE_INTEGER Size;
    LARGE_INTEGER Offset;
    NTSTATUS Status;
    SIZE_T Count;
    void *Base;

    TRACE_(LDR, "loading manifest file %ws\n", Filename);

    Attr.Length = sizeof(Attr);
    Attr.RootDirectory = 0;
    Attr.ObjectName = NULL;
    Attr.Attributes = OBJ_CASE_INSENSITIVE | OBJ_OPENIF;
    Attr.SecurityDescriptor = NULL;
    Attr.SecurityQualityOfService = NULL;

    Size.QuadPart = 0;
    Status = NtCreateSection(&Mapping,
			     STANDARD_RIGHTS_REQUIRED | SECTION_QUERY | SECTION_MAP_READ,
			     &Attr, &Size, PAGE_READONLY, SEC_COMMIT, File);
    if (Status != STATUS_SUCCESS)
	return Status;

    Offset.QuadPart = 0;
    Count = 0;
    Base = NULL;
    Status = NtMapViewOfSection(Mapping, NtCurrentProcess(), &Base, 0, 0, &Offset,
				&Count, ViewShare, 0, PAGE_READONLY);
    NtClose(Mapping);
    if (Status != STATUS_SUCCESS)
	return Status;

    Status = NtQueryInformationFile(File, &Io, &Info, sizeof(Info),
				    FileEndOfFileInformation);
    if (Status == STATUS_SUCCESS)
	Status = ParseManifest(Acl, Ai, Filename, NULL, Directory, Shared, Base,
				Info.EndOfFile.QuadPart);

    NtUnmapViewOfSection(NtCurrentProcess(), Base);
    return Status;
}

/* try to load the .manifest file associated to the file */
static NTSTATUS GetManifestInAssociatedManifest(PACTCTX_LOADER Acl,
						PASSEMBLY_IDENTITY Ai,
						LPCWSTR Filename, LPCWSTR Directory,
						HMODULE Module, LPCWSTR Resname)
{
    PWSTR Buffer;
    NTSTATUS Status;
    UNICODE_STRING NameW;
    HANDLE File;
    UINT Resid = CREATEPROCESS_MANIFEST_RESOURCE_ID;

    if (!((ULONG_PTR)Resname >> 16))
	Resid = LOWORD(Resname);

    TRACE_(LDR, "looking for manifest associated with %ws id %u\n", Filename,
	   Resid);

    if (Module) /* use the module filename */
    {
	UNICODE_STRING Name;

	if (!(Status = GetModuleFilename(Module, &Name,
					 sizeof(L".manifest") + 10 * sizeof(WCHAR)))) {
	    if (Resid != 1)
		_snwprintf(Name.Buffer + wcslen(Name.Buffer), 10, L".%u", Resid);
	    wcscat_s(Name.Buffer, Name.MaximumLength / sizeof(WCHAR), L".manifest");
	    if (!RtlDosPathNameToNtPathName_U(Name.Buffer, &NameW, NULL, NULL))
		Status = STATUS_RESOURCE_DATA_NOT_FOUND;
	    RtlFreeUnicodeString(&Name);
	}
	if (Status)
	    return Status;
    } else {
	ULONG Size = (wcslen(Filename) + 10) * sizeof(WCHAR) + sizeof(L".manifest");
	if (!(Buffer = RtlAllocateHeap(RtlGetProcessHeap(), 0, Size)))
	    return STATUS_NO_MEMORY;
	wcscpy_s(Buffer, Size / sizeof(WCHAR), Filename);
	if (Resid != 1)
	    _snwprintf(Buffer + wcslen(Buffer), 10, L".%u", Resid);
	wcscat_s(Buffer, Size / sizeof(WCHAR), L".manifest");
	RtlInitUnicodeString(&NameW, Buffer);
    }

    if (!OpenNtFile(&File, &NameW)) {
	Status = GetManifestInManifestFile(Acl, Ai, NameW.Buffer, Directory, FALSE,
					       File);
	NtClose(File);
    } else
	Status = STATUS_RESOURCE_NAME_NOT_FOUND;
    RtlFreeUnicodeString(&NameW);
    return Status;
}

static PWSTR LookupManifestFile(HANDLE Dir, PASSEMBLY_IDENTITY Ai)
{
    static const WCHAR LookupFmtW[] = L"%s_%s_%s_%u.%u.*.*_%s_*.manifest";
    static const WCHAR WineTrailerW[] = { 'd', 'e', 'a', 'd', 'b', 'e', 'e', 'f', '.',
					   'm', 'a', 'n', 'i', 'f', 'e', 's', 't' };

    PWSTR Lookup, Ret = NULL;
    UNICODE_STRING LookupUs;
    IO_STATUS_BLOCK Io;
    PCWSTR Lang = Ai->Language;
    unsigned int DataPos = 0, DataLen, Len;
    char Buffer[8192];

    if (!Lang || !_wcsicmp(Lang, L"neutral"))
	Lang = L"*";

    Len = wcslen(Ai->Architecture) + wcslen(Ai->Name) + wcslen(Ai->PublicKey) + wcslen(Lang) +
	  20 + ARRAYSIZE(LookupFmtW);
    if (!(Lookup = RtlAllocateHeap(RtlGetProcessHeap(), 0, Len * sizeof(WCHAR))))
	return NULL;
    _snwprintf(Lookup, Len, LookupFmtW, Ai->Architecture, Ai->Name, Ai->PublicKey,
	       Ai->Version.Major, Ai->Version.Minor, Lang);
    RtlInitUnicodeString(&LookupUs, Lookup);

#ifdef __arm64ec__
    if (!wcsncmp(lookup, L"amd64_", 6))
	memcpy(lookup, L"a??", 3 * sizeof(WCHAR));
#endif

    if (!NtQueryDirectoryFile(Dir, 0, NULL, NULL, &Io, Buffer, sizeof(Buffer),
			      FileBothDirectoryInformation, FALSE, &LookupUs, TRUE)) {
	ULONG MinBuild = Ai->Version.Build, MinRevision = Ai->Version.Revision;
	FILE_BOTH_DIR_INFORMATION *DirInfo;
	PWSTR Tmp;
	ULONG Build, Revision;

	DataLen = Io.Information;

	for (;;) {
	    if (DataPos >= DataLen) {
		if (NtQueryDirectoryFile(Dir, 0, NULL, NULL, &Io, Buffer, sizeof(Buffer),
					 FileBothDirectoryInformation, FALSE, &LookupUs,
					 FALSE))
		    break;
		DataLen = Io.Information;
		DataPos = 0;
	    }
	    DirInfo = (FILE_BOTH_DIR_INFORMATION *)(Buffer + DataPos);

	    if (DirInfo->NextEntryOffset)
		DataPos += DirInfo->NextEntryOffset;
	    else
		DataPos = DataLen;

	    Tmp = (PWSTR)DirInfo->FileName + (wcschr(Lookup, '*') - Lookup);
	    Build = wcstoul(Tmp, NULL, 10);
	    if (Build < MinBuild)
		continue;
	    Tmp = wcschr(Tmp, '.') + 1;
	    Revision = wcstoul(Tmp, NULL, 10);
	    if (Build == MinBuild && Revision < MinRevision)
		continue;
	    Tmp = wcschr(Tmp, '_') + 1;
	    Tmp = wcschr(Tmp, '_') + 1;
	    if (DirInfo->FileNameLength - (Tmp - DirInfo->FileName) * sizeof(WCHAR) ==
		    sizeof(WineTrailerW) &&
		!_wcsnicmp(Tmp, WineTrailerW, ARRAYSIZE(WineTrailerW))) {
		/* prefer a non-Wine manifest if we already have one */
		/* we'll still load the builtin dll if specified through DllOverrides */
		if (Ret)
		    continue;
	    } else {
		MinBuild = Build;
		MinRevision = Revision;
	    }
	    Ai->Version.Build = Build;
	    Ai->Version.Revision = Revision;
	    RtlFreeHeap(RtlGetProcessHeap(), 0, Ret);
	    if ((Ret = RtlAllocateHeap(RtlGetProcessHeap(), 0,
				       DirInfo->FileNameLength + sizeof(WCHAR)))) {
		memcpy(Ret, DirInfo->FileName, DirInfo->FileNameLength);
		Ret[DirInfo->FileNameLength / sizeof(WCHAR)] = 0;
	    }
	}
    } else
	WARN_(LDR, "no matching file for %ws\n", Lookup);
    RtlFreeHeap(RtlGetProcessHeap(), 0, Lookup);
    return Ret;
}

static NTSTATUS LookupWinsxs(PACTCTX_LOADER Acl, PASSEMBLY_IDENTITY Ai)
{
    ASSEMBLY_IDENTITY SxsAi;
    UNICODE_STRING PathUs;
    OBJECT_ATTRIBUTES Attr;
    IO_STATUS_BLOCK Io;
    PWSTR Path, File = NULL;
    HANDLE Handle;

    if (!Ai->Architecture || !Ai->Name || !Ai->PublicKey)
	return STATUS_NO_SUCH_FILE;

    ULONG Size = sizeof(L"\\winsxs\\manifests") +
	wcslen(SharedUserData->NtSystemRoot) * sizeof(WCHAR);
    if (!(Path = RtlAllocateHeap(RtlGetProcessHeap(), 0, Size)))
	return STATUS_NO_MEMORY;

    wcscpy_s(Path, Size / sizeof(WCHAR), SharedUserData->NtSystemRoot);
    wcscat_s(Path, Size / sizeof(WCHAR), L"\\winsxs\\manifests");

    if (!RtlDosPathNameToNtPathName_U(Path, &PathUs, NULL, NULL)) {
	RtlFreeHeap(RtlGetProcessHeap(), 0, Path);
	return STATUS_NO_SUCH_FILE;
    }
    RtlFreeHeap(RtlGetProcessHeap(), 0, Path);

    Attr.Length = sizeof(Attr);
    Attr.RootDirectory = 0;
    Attr.Attributes = OBJ_CASE_INSENSITIVE;
    Attr.ObjectName = &PathUs;
    Attr.SecurityDescriptor = NULL;
    Attr.SecurityQualityOfService = NULL;

    if (!NtOpenFile(&Handle, GENERIC_READ | SYNCHRONIZE, &Attr, &Io,
		    FILE_SHARE_READ | FILE_SHARE_WRITE,
		    FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT)) {
	SxsAi = *Ai;
	File = LookupManifestFile(Handle, &SxsAi);
	NtClose(Handle);
    }
    if (!File) {
	RtlFreeUnicodeString(&PathUs);
	return STATUS_NO_SUCH_FILE;
    }

    /* append file name to directory path */
    ULONG FileNameLength = wcslen(File);
    if (!(Path = RtlReAllocateHeap(RtlGetProcessHeap(), 0, PathUs.Buffer,
				   PathUs.Length + (FileNameLength + 2) * sizeof(WCHAR)))) {
	RtlFreeHeap(RtlGetProcessHeap(), 0, File);
	RtlFreeUnicodeString(&PathUs);
	return STATUS_NO_MEMORY;
    }

    Path[PathUs.Length / sizeof(WCHAR)] = '\\';
    wcscpy_s(Path + PathUs.Length / sizeof(WCHAR) + 1, FileNameLength + 1, File);
    RtlInitUnicodeString(&PathUs, Path);
    *wcsrchr(File, '.') = 0; /* remove .manifest extension */

    if (!OpenNtFile(&Handle, &PathUs)) {
	Io.Status = GetManifestInManifestFile(Acl, &SxsAi, PathUs.Buffer, File,
						  TRUE, Handle);
	NtClose(Handle);
    } else
	Io.Status = STATUS_NO_SUCH_FILE;

    RtlFreeHeap(RtlGetProcessHeap(), 0, File);
    RtlFreeUnicodeString(&PathUs);
    return Io.Status;
}

static NTSTATUS LookupAssembly(PACTCTX_LOADER Acl, PASSEMBLY_IDENTITY Ai)
{
    unsigned int i;
    PWSTR Buffer, Directory;
    NTSTATUS Status;
    UNICODE_STRING NameW;
    HANDLE File;
    DWORD Len;

    TRACE_(LDR, "looking for name=%ws version=" DEBUGSTR_VERSION_FMT "arch=%ws\n", Ai->Name,
	   DEBUGSTR_VERSION(&Ai->Version), Ai->Architecture);

    if ((Status = LookupWinsxs(Acl, Ai)) != STATUS_NO_SUCH_FILE)
	return Status;

    /* FIXME: add support for language specific lookup */

    Len = max(RtlGetFullPathName_U(Acl->ActCtx->Assemblies->Manifest.Info, 0, NULL, NULL) /
	      sizeof(WCHAR), wcslen(Acl->ActCtx->AppDir.Info));

    NameW.Buffer = NULL;
    ULONG BufferSize = (Len + 2 * wcslen(Ai->Name) + 2) * sizeof(WCHAR) + sizeof(L".manifest");
    if (!(Buffer = RtlAllocateHeap(RtlGetProcessHeap(), 0, BufferSize)))
	return STATUS_NO_MEMORY;

    if (!(Directory = BuildAssemblyDir(Ai))) {
	RtlFreeHeap(RtlGetProcessHeap(), 0, Buffer);
	return STATUS_NO_MEMORY;
    }

    /* Lookup in <dir>\name.dll
     *           <dir>\name.manifest
     *           <dir>\name\name.dll
     *           <dir>\name\name.manifest
     *
     * First 'appdir' is used as <dir>, if that failed
     * it tries application manifest file path.
     */
    wcscpy_s(Buffer, BufferSize / sizeof(WCHAR), Acl->ActCtx->AppDir.Info);
    for (i = 0; i < 4; i++) {
	if (i == 2) {
	    PASSEMBLY Assembly = Acl->ActCtx->Assemblies;
	    PWSTR FileName = NULL;
	    if (!RtlGetFullPathName_U(Assembly->Manifest.Info, Len * sizeof(WCHAR),
				      Buffer, &FileName))
		break;
	    FileName[0] = L'0';
	} else
	    wcscat_s(Buffer, BufferSize / sizeof(WCHAR), L"\\");

	wcscat_s(Buffer, BufferSize / sizeof(WCHAR), Ai->Name);
	wcscat_s(Buffer, BufferSize / sizeof(WCHAR), L".dll");
	if (RtlDosPathNameToNtPathName_U(Buffer, &NameW, NULL, NULL)) {
	    Status = OpenNtFile(&File, &NameW);
	    if (!Status) {
		Status = GetManifestInPeFile(Acl, Ai, NameW.Buffer, Directory, FALSE,
					     File, NULL, 0);
		NtClose(File);
		if (Status == STATUS_SUCCESS)
		    break;
	    }
	    RtlFreeUnicodeString(&NameW);
	}

	wcscat_s(Buffer, BufferSize / sizeof(WCHAR), L".manifest");
	if (RtlDosPathNameToNtPathName_U(Buffer, &NameW, NULL, NULL)) {
	    Status = OpenNtFile(&File, &NameW);
	    if (!Status) {
		Status = GetManifestInManifestFile(Acl, Ai, NameW.Buffer, Directory,
						   FALSE, File);
		NtClose(File);
		break;
	    }
	    RtlFreeUnicodeString(&NameW);
	}
	Status = STATUS_SXS_ASSEMBLY_NOT_FOUND;
    }
    RtlFreeUnicodeString(&NameW);
    RtlFreeHeap(RtlGetProcessHeap(), 0, Directory);
    RtlFreeHeap(RtlGetProcessHeap(), 0, Buffer);
    return Status;
}

static NTSTATUS ParseDependManifests(PACTCTX_LOADER Acl)
{
    NTSTATUS Status = STATUS_SUCCESS;
    unsigned int i;

    for (i = 0; i < Acl->NumDependencies; i++) {
	if (LookupAssembly(Acl, &Acl->Dependencies[i]) != STATUS_SUCCESS) {
	    if (!Acl->Dependencies[i].Optional && !Acl->Dependencies[i].Delayed) {
		INFO_(LDR, "Could not find dependent assembly %ws (" DEBUGSTR_VERSION_FMT ")\n",
		      Acl->Dependencies[i].Name,
		      DEBUGSTR_VERSION(&Acl->Dependencies[i].Version));
		Status = STATUS_SXS_CANT_GEN_ACTCTX;
		break;
	    }
	}
    }
    /* FIXME should now iterate through all refs */
    return Status;
}

static HANDLE GetCurrentActCtxNoAddRef(void)
{
    ACTIVATION_CONTEXT_STACK *ActctxStack = NtCurrentTeb()->ActivationContextStackPointer;

    if (ActctxStack->ActiveFrame)
	return ActctxStack->ActiveFrame->ActivationContext;

    return NULL;
}

/* find the appropriate activation context for RtlQueryInformationActivationContext */
static NTSTATUS FindQueryActCtx(HANDLE *Handle, DWORD Flags, ULONG Class)
{
    NTSTATUS Status = STATUS_SUCCESS;

    if (Flags & RTL_QUERY_ACTIVATION_CONTEXT_FLAG_USE_ACTIVE_ACTIVATION_CONTEXT) {
	if (*Handle)
	    return STATUS_INVALID_PARAMETER;

	*Handle = GetCurrentActCtxNoAddRef();
    } else if (Flags & (RTL_QUERY_ACTIVATION_CONTEXT_FLAG_IS_ADDRESS |
			RTL_QUERY_ACTIVATION_CONTEXT_FLAG_IS_HMODULE)) {
	ULONG_PTR Magic;
	LDR_DATA_TABLE_ENTRY *Pldr;

	if (!*Handle)
	    return STATUS_INVALID_PARAMETER;

	LdrLockLoaderLock(0, NULL, &Magic);
	if (!LdrFindEntryForAddress(*Handle, &Pldr)) {
	    if ((Flags & RTL_QUERY_ACTIVATION_CONTEXT_FLAG_IS_HMODULE) &&
		*Handle != Pldr->DllBase)
		Status = STATUS_DLL_NOT_FOUND;
	    else
		*Handle = Pldr->EntryPointActivationContext;
	} else
	    Status = STATUS_DLL_NOT_FOUND;
	LdrUnlockLoaderLock(0, Magic);
    } else if (!*Handle && (Class != ActivationContextBasicInformation))
	*Handle = ProcessActCtx;

    return Status;
}

static NTSTATUS BuildDllRedirectSection(ACTIVATION_CONTEXT *Actctx,
					PSTRSECTION_HEADER *Section)
{
    unsigned int i, j, TotalLen = 0, DllCount = 0;
    PSTRSECTION_HEADER Header;
    ACTIVATION_CONTEXT_DATA_DLL_REDIRECTION *Data;
    ACTIVATION_CONTEXT_DATA_DLL_REDIRECTION_PATH_SEGMENT *Path;
    PSTRING_INDEX Index;
    ULONG NameOffset;

    DPRINT("actctx %p, num_assemblies %d\n", Actctx, Actctx->NumAssemblies);

    /* compute section length */
    for (i = 0; i < Actctx->NumAssemblies; i++) {
	PASSEMBLY Assembly = &Actctx->Assemblies[i];
	for (j = 0; j < Assembly->NumDlls; j++) {
	    PDLL_REDIRECT Dll = &Assembly->Dlls[j];

	    /* each entry needs index, data and string data */
	    TotalLen += sizeof(*Index);
	    TotalLen += AlignedStringLen((wcslen(Dll->Name) + 1) * sizeof(WCHAR));
	    TotalLen += sizeof(*Data);
	    if (Dll->LoadFrom) {
		TotalLen += sizeof(*Path);
		TotalLen += AlignedStringLen(wcslen(Dll->LoadFrom) * sizeof(WCHAR));
	    }

	    DPRINT("assembly %d (%p), dll %d: dll name %S\n", i, Assembly, j, Dll->Name);
	}

	DllCount += Assembly->NumDlls;
    }

    TotalLen += sizeof(*Header);

    Header = RtlAllocateHeap(RtlGetProcessHeap(), 0, TotalLen);
    if (!Header)
	return STATUS_NO_MEMORY;

    memset(Header, 0, sizeof(*Header));
    Header->Magic = STRSECTION_MAGIC;
    Header->Size = sizeof(*Header);
    Header->Count = DllCount;
    Header->IndexOffset = sizeof(*Header);
    Index = (PSTRING_INDEX)((BYTE *)Header + Header->IndexOffset);
    NameOffset = Header->IndexOffset + Header->Count * sizeof(*Index);

    for (i = 0; i < Actctx->NumAssemblies; i++) {
	PASSEMBLY Assembly = &Actctx->Assemblies[i];

	DPRINT("assembly->num_dlls %d\n", Assembly->NumDlls);

	for (j = 0; j < Assembly->NumDlls; j++) {
	    PDLL_REDIRECT Dll = &Assembly->Dlls[j];
	    UNICODE_STRING Str;
	    PWSTR PtrW;

	    DPRINT("%d: dll name %S\n", j, Dll->Name);
	    /* setup new index entry */
	    Str.Buffer = Dll->Name;
	    Str.Length = wcslen(Dll->Name) * sizeof(WCHAR);
	    Str.MaximumLength = Str.Length + sizeof(WCHAR);
	    /* hash original class name */
	    RtlHashUnicodeString(&Str, TRUE, HASH_STRING_ALGORITHM_X65599, &Index->Hash);

	    Index->NameOffset = NameOffset;
	    Index->NameLength = Str.Length;
	    Index->DataOffset = Index->NameOffset +
				 AlignedStringLen(Str.MaximumLength);
	    Index->DataLength = sizeof(*Data);
	    Index->RosterIndex = i + 1;

	    /* dll name */
	    PtrW = (PWSTR)((BYTE *)Header + Index->NameOffset);
	    memcpy(PtrW, Dll->Name, Index->NameLength);
	    PtrW[Index->NameLength / sizeof(WCHAR)] = 0;
	    NameOffset += AlignedStringLen(Str.MaximumLength);

	    /* setup data */
	    Data = (ACTIVATION_CONTEXT_DATA_DLL_REDIRECTION *)((BYTE *)Header +
							       Index->DataOffset);
	    if (Dll->LoadFrom) {
		ULONG Len = wcslen(Dll->LoadFrom) * sizeof(WCHAR);
		Data->Size = sizeof(*Data) + sizeof(*Path);
		Data->Flags = 0;
		Data->TotalPathLength = AlignedStringLen(Len);
		Data->PathSegmentCount = 1;
		Data->PathSegmentOffset = Index->DataOffset + sizeof(*Data);
		Path = (ACTIVATION_CONTEXT_DATA_DLL_REDIRECTION_PATH_SEGMENT *)(Data + 1);
		Path->Offset = Index->DataOffset + Data->Size;
		Path->Length = Len;
		PtrW = (PWSTR)((BYTE *)Header + Path->Offset);
		memcpy(PtrW, Dll->LoadFrom, Len);
		if (wcschr(Dll->LoadFrom, '%'))
		    Data->Flags |= ACTIVATION_CONTEXT_DATA_DLL_REDIRECTION_PATH_EXPAND;
	    } else {
		Data->Size = sizeof(*Data);
		Data->Flags =
		    ACTIVATION_CONTEXT_DATA_DLL_REDIRECTION_PATH_OMITS_ASSEMBLY_ROOT;
		Data->TotalPathLength = 0;
		Data->PathSegmentCount = 0;
		Data->PathSegmentOffset = 0;
	    }
	    NameOffset += Data->Size + Data->TotalPathLength;

	    Index++;
	}
    }

    *Section = Header;

    return STATUS_SUCCESS;
}

static PSTRING_INDEX FindStringIndex(PCSTRSECTION_HEADER Section,
				     PCUNICODE_STRING Name)
{
    PSTRING_INDEX Iter, Index = NULL;
    UNICODE_STRING Str;
    ULONG Hash = 0;

    DPRINT("section %p, name %wZ\n", Section, Name);
    RtlHashUnicodeString(Name, TRUE, HASH_STRING_ALGORITHM_X65599, &Hash);
    Iter = (PSTRING_INDEX)((BYTE *)Section + Section->IndexOffset);

    for (ULONG i = 0; i < Section->Count; i++) {
	DPRINT("iter->hash 0x%x ?= 0x%x\n", Iter->Hash, Hash);
	DPRINT("iter->name %S\n", (PWSTR)((BYTE *)Section + Iter->NameOffset));
	if (Iter->Hash == Hash) {
	    Str.Buffer = (PWSTR)((BYTE *)Section + Iter->NameOffset);
	    Str.Length = Iter->NameLength;
	    if (RtlEqualUnicodeString(&Str, Name, TRUE)) {
		Index = Iter;
		break;
	    } else
		WARN_(LDR, "hash collision 0x%08x, %wZ, %wZ\n", Hash, Name, &Str);
	}
	Iter++;
    }

    return Index;
}

static PGUID_INDEX FindGuidIndex(PCGUIDSECTION_HEADER Section,
				 const GUID *Guid)
{
    PGUID_INDEX Iter, Index = NULL;
    ULONG i;

    Iter = (PGUID_INDEX)((BYTE *)Section + Section->IndexOffset);

    for (i = 0; i < Section->Count; i++) {
	if (!memcmp(Guid, &Iter->Guid, sizeof(*Guid))) {
	    Index = Iter;
	    break;
	}
	Iter++;
    }

    return Index;
}

static inline ACTIVATION_CONTEXT_DATA_DLL_REDIRECTION *
GetDllRedirectData(ACTIVATION_CONTEXT *Ctxt, PSTRING_INDEX Index)
{
    return (ACTIVATION_CONTEXT_DATA_DLL_REDIRECTION *)((BYTE *)Ctxt->DllRedirectSection +
						       Index->DataOffset);
}

static NTSTATUS FindDllRedirection(ACTIVATION_CONTEXT *Actctx,
				   const UNICODE_STRING *Name,
				   PACTCTX_SECTION_KEYED_DATA Data)
{
    ACTIVATION_CONTEXT_DATA_DLL_REDIRECTION *Dll;
    PSTRING_INDEX Index;

    DPRINT("sections: 0x%08X\n", Actctx->Sections);
    if (!(Actctx->Sections & DLLREDIRECT_SECTION))
	return STATUS_SXS_KEY_NOT_FOUND;

    DPRINT("actctx->dllredirect_section: %p\n", Actctx->DllRedirectSection);
    if (!Actctx->DllRedirectSection) {
	PSTRSECTION_HEADER Section;

	NTSTATUS Status = BuildDllRedirectSection(Actctx, &Section);
	if (Status)
	    return Status;

	if (InterlockedCompareExchangePointer((void **)&Actctx->DllRedirectSection,
					      Section, NULL))
	    RtlFreeHeap(RtlGetProcessHeap(), 0, Section);
    }

    Index = FindStringIndex(Actctx->DllRedirectSection, Name);
    DPRINT("index: %p\n", Index);
    if (!Index)
	return STATUS_SXS_KEY_NOT_FOUND;

    if (Data) {
	Dll = GetDllRedirectData(Actctx, Index);

	Data->ulDataFormatVersion = 1;
	Data->lpData = Dll;
	Data->ulLength = Dll->Size;
	Data->lpSectionGlobalData = NULL;
	Data->ulSectionGlobalDataLength = 0;
	Data->lpSectionBase = Actctx->DllRedirectSection;
	Data->ulSectionTotalLength = RtlSizeHeap(RtlGetProcessHeap(), 0,
						 Actctx->DllRedirectSection);
	Data->hActCtx = NULL;

	if (Data->cbSize >=
	    FIELD_OFFSET(ACTCTX_SECTION_KEYED_DATA, ulAssemblyRosterIndex) +
		sizeof(ULONG))
	    Data->ulAssemblyRosterIndex = Index->RosterIndex;
    }

    return STATUS_SUCCESS;
}

static inline PSTRING_INDEX GetWndClassFirstIndex(ACTIVATION_CONTEXT *Actctx)
{
    return (PVOID)((BYTE *)Actctx->WndClassSection + Actctx->WndClassSection->IndexOffset);
}

static inline PWNDCLASS_REDIRECT_DATA GetWndClassData(ACTIVATION_CONTEXT *Ctxt,
						      PSTRING_INDEX Index)
{
    return (PVOID)((BYTE *)Ctxt->WndClassSection + Index->DataOffset);
}

static NTSTATUS BuildWndClassSection(ACTIVATION_CONTEXT *Actctx,
				     PSTRSECTION_HEADER *Section)
{
    unsigned int i, j, k, TotalLen = 0, ClassCount = 0;
    PWNDCLASS_REDIRECT_DATA Data;
    PSTRSECTION_HEADER Header;
    PSTRING_INDEX Index;
    ULONG NameOffset;

    /* compute section length */
    for (i = 0; i < Actctx->NumAssemblies; i++) {
	PASSEMBLY Assembly = &Actctx->Assemblies[i];
	for (j = 0; j < Assembly->NumDlls; j++) {
	    PDLL_REDIRECT Dll = &Assembly->Dlls[j];
	    for (k = 0; k < Dll->Entities.Count; k++) {
		PENTITY Entity = &Dll->Entities.Base[k];
		if (Entity->Kind == ACTIVATION_CONTEXT_SECTION_WINDOW_CLASS_REDIRECTION) {
		    int ClassLen = wcslen(Entity->Class.Name) + 1;
		    int Len;

		    /* each class entry needs index, data and string data */
		    TotalLen += sizeof(*Index);
		    TotalLen += sizeof(*Data);
		    /* original name is stored separately */
		    TotalLen += AlignedStringLen(ClassLen * sizeof(WCHAR));
		    /* versioned name and module name are stored one after another */
		    if (Entity->Class.Versioned)
			Len = GetAssemblyVersion(Assembly, NULL) + ClassLen +
			      1 /* '!' separator */;
		    else
			Len = ClassLen;
		    Len += wcslen(Dll->Name) + 1;
		    TotalLen += AlignedStringLen(Len * sizeof(WCHAR));

		    ClassCount++;
		}
	    }
	}
    }

    TotalLen += sizeof(*Header);

    Header = RtlAllocateHeap(RtlGetProcessHeap(), 0, TotalLen);
    if (!Header)
	return STATUS_NO_MEMORY;

    memset(Header, 0, sizeof(*Header));
    Header->Magic = STRSECTION_MAGIC;
    Header->Size = sizeof(*Header);
    Header->Count = ClassCount;
    Header->IndexOffset = sizeof(*Header);
    Index = (PSTRING_INDEX)((BYTE *)Header + Header->IndexOffset);
    NameOffset = Header->IndexOffset + Header->Count * sizeof(*Index);

    for (i = 0; i < Actctx->NumAssemblies; i++) {
	PASSEMBLY Assembly = &Actctx->Assemblies[i];
	for (j = 0; j < Assembly->NumDlls; j++) {
	    PDLL_REDIRECT Dll = &Assembly->Dlls[j];
	    for (k = 0; k < Dll->Entities.Count; k++) {
		PENTITY Entity = &Dll->Entities.Base[k];
		if (Entity->Kind == ACTIVATION_CONTEXT_SECTION_WINDOW_CLASS_REDIRECTION) {
		    ULONG VersionedLen, ModuleLen;
		    UNICODE_STRING Str;
		    PWSTR PtrW;

		    /* setup new index entry */
		    Str.Buffer = Entity->Class.Name;
		    Str.Length = wcslen(Entity->Class.Name) * sizeof(WCHAR);
		    Str.MaximumLength = Str.Length + sizeof(WCHAR);
		    /* hash original class name */
		    RtlHashUnicodeString(&Str, TRUE, HASH_STRING_ALGORITHM_X65599,
					 &Index->Hash);

		    /* include '!' separator too */
		    if (Entity->Class.Versioned)
			VersionedLen = (GetAssemblyVersion(Assembly, NULL) + 1) *
			    sizeof(WCHAR) + Str.Length;
		    else
			VersionedLen = Str.Length;
		    ModuleLen = wcslen(Dll->Name) * sizeof(WCHAR);

		    Index->NameOffset = NameOffset;
		    Index->NameLength = Str.Length;
		    Index->DataOffset = Index->NameOffset +
					 AlignedStringLen(Str.MaximumLength);
		    Index->DataLength = sizeof(*Data) + VersionedLen + ModuleLen +
				      2 * sizeof(WCHAR) /* two nulls */;
		    Index->RosterIndex = i + 1;

		    /* setup data */
		    Data = (PWNDCLASS_REDIRECT_DATA)((BYTE *)Header + Index->DataOffset);
		    Data->Size = sizeof(*Data);
		    Data->Resource = 0;
		    Data->NameLength = VersionedLen;
		    Data->NameOffset = sizeof(*Data);
		    Data->ModuleLength = ModuleLen;
		    Data->ModuleOffset = Index->DataOffset + Data->NameOffset +
					  Data->NameLength + sizeof(WCHAR);

		    /* original class name */
		    PtrW = (PWSTR)((BYTE *)Header + Index->NameOffset);
		    memcpy(PtrW, Entity->Class.Name, Index->NameLength);
		    PtrW[Index->NameLength / sizeof(WCHAR)] = 0;

		    /* module name */
		    PtrW = (PWSTR)((BYTE *)Header + Data->ModuleOffset);
		    memcpy(PtrW, Dll->Name, Data->ModuleLength);
		    PtrW[Data->ModuleLength / sizeof(WCHAR)] = 0;

		    /* versioned name */
		    PtrW = (PWSTR)((BYTE *)Data + Data->NameOffset);
		    if (Entity->Class.Versioned) {
			GetAssemblyVersion(Assembly, PtrW);
			wcscat_s(PtrW, VersionedLen / sizeof(WCHAR) + 1, L"!");
			wcscat_s(PtrW, VersionedLen / sizeof(WCHAR) + 1, Entity->Class.Name);
		    } else {
			memcpy(PtrW, Entity->Class.Name, Index->NameLength);
			PtrW[Index->NameLength / sizeof(WCHAR)] = 0;
		    }

		    NameOffset += sizeof(*Data);
		    NameOffset += AlignedStringLen(Str.MaximumLength) +
				   AlignedStringLen(VersionedLen + ModuleLen +
						      2 * sizeof(WCHAR));

		    Index++;
		}
	    }
	}
    }

    *Section = Header;

    return STATUS_SUCCESS;
}

static NTSTATUS FindWindowClass(ACTIVATION_CONTEXT *ActCtx, const UNICODE_STRING *Name,
				PACTCTX_SECTION_KEYED_DATA Data)
{
    PSTRING_INDEX Iter, Index = NULL;
    PWNDCLASS_REDIRECT_DATA Class;
    UNICODE_STRING Str;
    ULONG Hash;
    int i;

    if (!(ActCtx->Sections & WINDOWCLASS_SECTION))
	return STATUS_SXS_KEY_NOT_FOUND;

    if (!ActCtx->WndClassSection) {
	PSTRSECTION_HEADER Section;

	NTSTATUS Status = BuildWndClassSection(ActCtx, &Section);
	if (Status)
	    return Status;

	if (InterlockedCompareExchangePointer((void **)&ActCtx->WndClassSection, Section,
					      NULL))
	    RtlFreeHeap(RtlGetProcessHeap(), 0, Section);
    }

    Hash = 0;
    RtlHashUnicodeString(Name, TRUE, HASH_STRING_ALGORITHM_X65599, &Hash);
    Iter = GetWndClassFirstIndex(ActCtx);

    for (i = 0; i < ActCtx->WndClassSection->Count; i++) {
	if (Iter->Hash == Hash) {
	    Str.Buffer = (PWSTR)((BYTE *)ActCtx->WndClassSection + Iter->NameOffset);
	    Str.Length = Iter->NameLength;
	    if (RtlEqualUnicodeString(&Str, Name, TRUE)) {
		Index = Iter;
		break;
	    } else
		WARN_(LDR, "hash collision 0x%08x, %wZ, %wZ\n", Hash, Name, &Str);
	}
	Iter++;
    }

    if (!Index)
	return STATUS_SXS_KEY_NOT_FOUND;

    if (Data) {
	Class = GetWndClassData(ActCtx, Index);

	Data->ulDataFormatVersion = 1;
	Data->lpData = Class;
	/* full length includes string length with nulls */
	Data->ulLength = Class->Size + Class->NameLength + Class->ModuleLength +
			 2 * sizeof(WCHAR);
	Data->lpSectionGlobalData = NULL;
	Data->ulSectionGlobalDataLength = 0;
	Data->lpSectionBase = ActCtx->WndClassSection;
	Data->ulSectionTotalLength = RtlSizeHeap(RtlGetProcessHeap(), 0,
						 ActCtx->WndClassSection);
	Data->hActCtx = NULL;

	if (Data->cbSize >=
	    FIELD_OFFSET(ACTCTX_SECTION_KEYED_DATA, ulAssemblyRosterIndex) +
		sizeof(ULONG))
	    Data->ulAssemblyRosterIndex = Index->RosterIndex;
    }

    return STATUS_SUCCESS;
}

static inline PSTRING_INDEX GetActivatableClassFirstIndex(ACTIVATION_CONTEXT *Actctx)
{
    return (PVOID)((BYTE *)Actctx->ActivatableClassSection +
		   Actctx->ActivatableClassSection->IndexOffset);
}

static inline PACTIVATABLE_CLASS_DATA
GetActivatableClassData(ACTIVATION_CONTEXT *Ctxt, PSTRING_INDEX Index)
{
    return (PVOID)((BYTE *)Ctxt->ActivatableClassSection + Index->DataOffset);
}

static NTSTATUS BuildActivatableClassSection(ACTIVATION_CONTEXT *Actctx,
					     PSTRSECTION_HEADER *Section)
{
    unsigned int i, j, k, TotalLen = 0, ClassCount = 0, GlobalOffset = 0,
			  GlobalLen = 0;
    PACTIVATABLE_CLASS_DATA Data;
    PSTRSECTION_HEADER Header;
    PSTRING_INDEX Index;
    ULONG NameOffset;

    /* compute section length */
    for (i = 0; i < Actctx->NumAssemblies; i++) {
	PASSEMBLY Assembly = &Actctx->Assemblies[i];
	for (j = 0; j < Assembly->NumDlls; j++) {
	    PDLL_REDIRECT Dll = &Assembly->Dlls[j];
	    BOOL HasClass = FALSE;

	    for (k = 0; k < Dll->Entities.Count; k++) {
		PENTITY Entity = &Dll->Entities.Base[k];
		if (Entity->Kind ==
		    ACTIVATION_CONTEXT_SECTION_WINRT_ACTIVATABLE_CLASSES) {
		    int ClassLen = wcslen(Entity->ActivatableClass.Name) + 1;

		    /* each class entry needs index, data and string data */
		    TotalLen += sizeof(*Index);
		    TotalLen += AlignedStringLen(ClassLen * sizeof(WCHAR));
		    TotalLen += sizeof(*Data);

		    ClassCount++;
		    HasClass = TRUE;
		}
	    }

	    if (HasClass) {
		int ModuleLen = wcslen(Dll->Name) + 1;
		GlobalLen += AlignedStringLen(ModuleLen * sizeof(WCHAR));
	    }
	}
    }

    TotalLen += sizeof(*Header) + GlobalLen;

    Header = RtlAllocateHeap(RtlGetProcessHeap(), 0, TotalLen);
    if (!Header)
	return STATUS_NO_MEMORY;

    memset(Header, 0, sizeof(*Header));
    Header->Magic = STRSECTION_MAGIC;
    Header->Size = sizeof(*Header);
    Header->Count = ClassCount;
    Header->GlobalOffset = Header->Size;
    Header->GlobalLength = GlobalLen;
    Header->IndexOffset = Header->GlobalOffset + Header->GlobalLength;
    Index = (PSTRING_INDEX)((BYTE *)Header + Header->IndexOffset);
    NameOffset = Header->IndexOffset + Header->Count * sizeof(*Index);

    GlobalOffset = Header->Size;
    for (i = 0; i < Actctx->NumAssemblies; i++) {
	PASSEMBLY Assembly = &Actctx->Assemblies[i];
	for (j = 0; j < Assembly->NumDlls; j++) {
	    PDLL_REDIRECT Dll = &Assembly->Dlls[j];
	    int ModuleLen = wcslen(Dll->Name) * sizeof(WCHAR);
	    BOOL HasClass = FALSE;

	    for (k = 0; k < Dll->Entities.Count; k++) {
		PENTITY Entity = &Dll->Entities.Base[k];

		if (Entity->Kind ==
		    ACTIVATION_CONTEXT_SECTION_WINRT_ACTIVATABLE_CLASSES) {
		    UNICODE_STRING Str;
		    PWSTR PtrW;

		    /* setup new index entry */
		    Str.Buffer = Entity->ActivatableClass.Name;
		    Str.Length = wcslen(Entity->ActivatableClass.Name) * sizeof(WCHAR);
		    Str.MaximumLength = Str.Length + sizeof(WCHAR);
		    /* hash class name */
		    RtlHashUnicodeString(&Str, TRUE, HASH_STRING_ALGORITHM_X65599,
					 &Index->Hash);

		    Index->NameOffset = NameOffset;
		    Index->NameLength = Str.Length;
		    Index->DataOffset = Index->NameOffset +
					 AlignedStringLen(Str.MaximumLength);
		    Index->DataLength = sizeof(*Data);
		    Index->RosterIndex = i + 1;

		    /* class name */
		    PtrW = (PWSTR)((BYTE *)Header + Index->NameOffset);
		    memcpy(PtrW, Entity->ActivatableClass.Name, Index->NameLength);
		    PtrW[Index->NameLength / sizeof(WCHAR)] = 0;

		    /* class data */
		    Data = (PACTIVATABLE_CLASS_DATA)((BYTE *)Header + Index->DataOffset);
		    Data->Size = sizeof(*Data);
		    Data->ThreadingModel = Entity->ActivatableClass.ThreadingModel;
		    Data->ModuleLength = ModuleLen;
		    Data->ModuleOffset = GlobalOffset;

		    NameOffset += AlignedStringLen(Str.MaximumLength);
		    NameOffset += sizeof(*Data);

		    Index++;
		    HasClass = TRUE;
		}
	    }

	    if (HasClass) {
		PWSTR PtrW = (PWSTR)((BYTE *)Header + GlobalOffset);
		memcpy(PtrW, Dll->Name, ModuleLen);
		PtrW[ModuleLen / sizeof(WCHAR)] = 0;
		GlobalOffset += AlignedStringLen(ModuleLen + sizeof(WCHAR));
	    }
	}
    }

    *Section = Header;

    return STATUS_SUCCESS;
}

static NTSTATUS FindActivatableClass(ACTIVATION_CONTEXT *ActCtx,
				     const UNICODE_STRING *Name,
				     PACTCTX_SECTION_KEYED_DATA Data)
{
    PSTRING_INDEX Iter, Index = NULL;
    PACTIVATABLE_CLASS_DATA Class;
    UNICODE_STRING Str;
    ULONG Hash;
    int i;

    if (!(ActCtx->Sections & ACTIVATABLE_CLASS_SECTION))
	return STATUS_SXS_KEY_NOT_FOUND;

    if (!ActCtx->ActivatableClassSection) {
	PSTRSECTION_HEADER Section;

	NTSTATUS Status = BuildActivatableClassSection(ActCtx, &Section);
	if (Status)
	    return Status;

	if (InterlockedCompareExchangePointer((void **)&ActCtx->ActivatableClassSection,
					      Section, NULL))
	    RtlFreeHeap(RtlGetProcessHeap(), 0, Section);
    }

    Hash = 0;
    RtlHashUnicodeString(Name, TRUE, HASH_STRING_ALGORITHM_X65599, &Hash);
    Iter = GetActivatableClassFirstIndex(ActCtx);

    for (i = 0; i < ActCtx->ActivatableClassSection->Count; i++) {
	if (Iter->Hash == Hash) {
	    Str.Buffer = (PWSTR)((BYTE *)ActCtx->ActivatableClassSection +
				 Iter->NameOffset);
	    Str.Length = Iter->NameLength;
	    if (RtlEqualUnicodeString(&Str, Name, TRUE)) {
		Index = Iter;
		break;
	    } else
		WARN_(LDR, "hash collision 0x%08x, %wZ, %wZ\n", Hash, Name, &Str);
	}
	Iter++;
    }

    if (!Index)
	return STATUS_SXS_KEY_NOT_FOUND;

    if (Data) {
	Class = GetActivatableClassData(ActCtx, Index);

	Data->ulDataFormatVersion = 1;
	Data->lpData = Class;
	/* full length includes string length with nulls */
	Data->ulLength = Class->Size + Class->ModuleLength + sizeof(WCHAR);
	Data->lpSectionGlobalData = (BYTE *)ActCtx->ActivatableClassSection +
	    ActCtx->ActivatableClassSection->GlobalOffset;
	Data->ulSectionGlobalDataLength = ActCtx->ActivatableClassSection->GlobalLength;
	Data->lpSectionBase = ActCtx->ActivatableClassSection;
	Data->ulSectionTotalLength = RtlSizeHeap(RtlGetProcessHeap(), 0,
						 ActCtx->ActivatableClassSection);
	Data->hActCtx = NULL;

	if (Data->cbSize >=
	    FIELD_OFFSET(ACTCTX_SECTION_KEYED_DATA, ulAssemblyRosterIndex) +
		sizeof(ULONG))
	    Data->ulAssemblyRosterIndex = Index->RosterIndex;
    }

    return STATUS_SUCCESS;
}

static NTSTATUS BuildTlibSection(ACTIVATION_CONTEXT *Actctx,
				 PGUIDSECTION_HEADER *Section)
{
    unsigned int i, j, k, TotalLen = 0, TlibCount = 0, NamesLen = 0;
    PGUIDSECTION_HEADER Header;
    ULONG ModuleOffset, DataOffset;
    PTLIBREDIRECT_DATA Data;
    PGUID_INDEX Index;

    /* compute section length */
    for (i = 0; i < Actctx->NumAssemblies; i++) {
	PASSEMBLY Assembly = &Actctx->Assemblies[i];
	for (j = 0; j < Assembly->NumDlls; j++) {
	    PDLL_REDIRECT Dll = &Assembly->Dlls[j];
	    for (k = 0; k < Dll->Entities.Count; k++) {
		PENTITY Entity = &Dll->Entities.Base[k];
		if (Entity->Kind ==
		    ACTIVATION_CONTEXT_SECTION_COM_TYPE_LIBRARY_REDIRECTION) {
		    /* each entry needs index, data and string data for module name and
		     * help string */
		    TotalLen += sizeof(*Index);
		    TotalLen += sizeof(*Data);
		    /* help string is stored separately */
		    if (*Entity->TypeLib.HelpDir)
			TotalLen += AlignedStringLen(
			    (wcslen(Entity->TypeLib.HelpDir) + 1) * sizeof(WCHAR));

		    /* module names are packed one after another */
		    NamesLen += (wcslen(Dll->Name) + 1) * sizeof(WCHAR);

		    TlibCount++;
		}
	    }
	}
    }

    TotalLen += AlignedStringLen(NamesLen);
    TotalLen += sizeof(*Header);

    Header = RtlAllocateHeap(RtlGetProcessHeap(), 0, TotalLen);
    if (!Header)
	return STATUS_NO_MEMORY;

    memset(Header, 0, sizeof(*Header));
    Header->Magic = GUIDSECTION_MAGIC;
    Header->Size = sizeof(*Header);
    Header->Count = TlibCount;
    Header->IndexOffset = sizeof(*Header) + AlignedStringLen(NamesLen);
    Index = (PGUID_INDEX)((BYTE *)Header + Header->IndexOffset);
    ModuleOffset = sizeof(*Header);
    DataOffset = Header->IndexOffset + TlibCount * sizeof(*Index);

    for (i = 0; i < Actctx->NumAssemblies; i++) {
	PASSEMBLY Assembly = &Actctx->Assemblies[i];
	for (j = 0; j < Assembly->NumDlls; j++) {
	    PDLL_REDIRECT Dll = &Assembly->Dlls[j];
	    for (k = 0; k < Dll->Entities.Count; k++) {
		PENTITY Entity = &Dll->Entities.Base[k];
		if (Entity->Kind ==
		    ACTIVATION_CONTEXT_SECTION_COM_TYPE_LIBRARY_REDIRECTION) {
		    ULONG ModuleLen, HelpLen;
		    UNICODE_STRING Str;
		    PWSTR PtrW;
		    NTSTATUS Status;

		    if (*Entity->TypeLib.HelpDir)
			HelpLen = wcslen(Entity->TypeLib.HelpDir) * sizeof(WCHAR);
		    else
			HelpLen = 0;

		    ModuleLen = wcslen(Dll->Name) * sizeof(WCHAR);

		    /* setup new index entry */
		    RtlInitUnicodeString(&Str, Entity->TypeLib.Tlbid);
		    Status = RtlGUIDFromString(&Str, &Index->Guid);
		    if (!NT_SUCCESS(Status)) {
			RtlFreeHeap(RtlGetProcessHeap(), 0, Header);
			return Status;
		    }
		    Index->DataOffset = DataOffset;
		    Index->DataLength = sizeof(*Data) + AlignedStringLen(HelpLen);
		    Index->RosterIndex = i + 1;

		    /* setup data */
		    Data = (PTLIBREDIRECT_DATA)((BYTE *)Header + Index->DataOffset);
		    Data->Size = sizeof(*Data);
		    Data->Resource = 0;
		    Data->NameLength = ModuleLen;
		    Data->NameOffset = ModuleOffset;
		    /* FIXME: resourceid handling is really weird, and it doesn't seem to
		     * be useful */
		    Data->LangId = 0;
		    Data->Flags = Entity->TypeLib.Flags;
		    Data->HelpLength = HelpLen;
		    Data->HelpOffset = sizeof(*Data);
		    Data->MajorVersion = Entity->TypeLib.Major;
		    Data->MinorVersion = Entity->TypeLib.Minor;

		    /* module name */
		    PtrW = (PWSTR)((BYTE *)Header + Data->NameOffset);
		    memcpy(PtrW, Dll->Name, Data->NameLength);
		    PtrW[Data->NameLength / sizeof(WCHAR)] = 0;

		    /* help string */
		    if (Data->HelpLength) {
			PtrW = (PWSTR)((BYTE *)Data + Data->HelpOffset);
			memcpy(PtrW, Entity->TypeLib.HelpDir, Data->HelpLength);
			PtrW[Data->HelpLength / sizeof(WCHAR)] = 0;
		    }

		    DataOffset += sizeof(*Data);
		    if (HelpLen)
			DataOffset += AlignedStringLen(HelpLen + sizeof(WCHAR));

		    ModuleOffset += ModuleLen + sizeof(WCHAR);

		    Index++;
		}
	    }
	}
    }

    *Section = Header;

    return STATUS_SUCCESS;
}

static inline PTLIBREDIRECT_DATA GetTlibData(ACTIVATION_CONTEXT *Actctx,
					     PGUID_INDEX Index)
{
    return (PVOID)((BYTE *)Actctx->TlibSection + Index->DataOffset);
}

static NTSTATUS FindTlibRedirection(ACTIVATION_CONTEXT *Actctx, const GUID *Guid,
				    ACTCTX_SECTION_KEYED_DATA *Data)
{
    PGUID_INDEX Index = NULL;
    PTLIBREDIRECT_DATA Tlib;

    if (!(Actctx->Sections & TLIBREDIRECT_SECTION))
	return STATUS_SXS_KEY_NOT_FOUND;

    if (!Actctx->TlibSection) {
	PGUIDSECTION_HEADER Section;

	NTSTATUS Status = BuildTlibSection(Actctx, &Section);
	if (Status)
	    return Status;

	if (InterlockedCompareExchangePointer((void **)&Actctx->TlibSection, Section,
					      NULL))
	    RtlFreeHeap(RtlGetProcessHeap(), 0, Section);
    }

    Index = FindGuidIndex(Actctx->TlibSection, Guid);
    if (!Index)
	return STATUS_SXS_KEY_NOT_FOUND;

    Tlib = GetTlibData(Actctx, Index);

    Data->ulDataFormatVersion = 1;
    Data->lpData = Tlib;
    /* full length includes string length with nulls */
    Data->ulLength = Tlib->Size + Tlib->HelpLength + sizeof(WCHAR);
    Data->lpSectionGlobalData = (BYTE *)Actctx->TlibSection +
				Actctx->TlibSection->NamesOffset;
    Data->ulSectionGlobalDataLength = Actctx->TlibSection->NamesLength;
    Data->lpSectionBase = Actctx->TlibSection;
    Data->ulSectionTotalLength = RtlSizeHeap(RtlGetProcessHeap(), 0, Actctx->TlibSection);
    Data->hActCtx = NULL;

    if (Data->cbSize >=
	FIELD_OFFSET(ACTCTX_SECTION_KEYED_DATA, ulAssemblyRosterIndex) + sizeof(ULONG))
	Data->ulAssemblyRosterIndex = Index->RosterIndex;

    return STATUS_SUCCESS;
}

static void GenerateUuid(ULONG *Seed, GUID *Guid)
{
    ULONG *Ptr = (ULONG *)Guid;
    int i;

    /* GUID is 16 bytes long */
    for (i = 0; i < sizeof(GUID) / sizeof(ULONG); i++, Ptr++)
	*Ptr = RtlUniform(Seed);

    Guid->Data3 &= 0x0fff;
    Guid->Data3 |= (4 << 12);
    Guid->Data4[0] &= 0x3f;
    Guid->Data4[0] |= 0x80;
}

static void GetComserverDatalen(PCENTITY_ARRAY Entities,
				PCDLL_REDIRECT Dll, unsigned int *Count,
				unsigned int *Len, unsigned int *ModuleLen)
{
    unsigned int i;

    for (i = 0; i < Entities->Count; i++) {
	PENTITY Entity = &Entities->Base[i];
	if (Entity->Kind == ACTIVATION_CONTEXT_SECTION_COM_SERVER_REDIRECTION) {
	    /* each entry needs two index entries, extra one goes for alias GUID */
	    *Len += 2 * sizeof(GUID_INDEX);
	    /* To save some memory we don't allocated two data structures,
	       instead alias index and normal index point to the same data structure. */
	    *Len += sizeof(COMCLASSREDIRECT_DATA);

	    /* for clrClass store some more */
	    if (Entity->ComClass.Name) {
		unsigned int StrLen;

		/* all string data is stored together in aligned block */
		StrLen = wcslen(Entity->ComClass.Name) + 1;
		if (Entity->ComClass.Progid)
		    StrLen += wcslen(Entity->ComClass.Progid) + 1;
		if (Entity->ComClass.Version)
		    StrLen += wcslen(Entity->ComClass.Version) + 1;

		*Len += sizeof(CLRCLASS_DATA);
		*Len += AlignedStringLen(StrLen * sizeof(WCHAR));

		/* module name is forced to mscoree.dll, and stored two times with
		 * different case */
		*ModuleLen += sizeof(L"MSCOREE.DLL") + sizeof(L"mscoree.dll");
	    } else {
		/* progid string is stored separately */
		if (Entity->ComClass.Progid)
		    *Len += AlignedStringLen((wcslen(Entity->ComClass.Progid) + 1) *
					       sizeof(WCHAR));

		*ModuleLen += (wcslen(Dll->Name) + 1) * sizeof(WCHAR);
	    }

	    *Count += 1;
	}
    }
}

static NTSTATUS AddComServerRecord(PCGUIDSECTION_HEADER Section,
				   PCENTITY_ARRAY Entities,
				   PCDLL_REDIRECT Dll,
				   PGUID_INDEX *Index,
				   ULONG *DataOffset,
				   ULONG *ModuleOffset,
				   ULONG *Seed,
				   ULONG Rosterindex)
{
    unsigned int i;
    NTSTATUS Status;

    for (i = 0; i < Entities->Count; i++) {
	PENTITY Entity = &Entities->Base[i];
	if (Entity->Kind == ACTIVATION_CONTEXT_SECTION_COM_SERVER_REDIRECTION) {
	    ULONG ModuleLen, ProgidLen, StrLen = 0, Miscmask;
	    PCOMCLASSREDIRECT_DATA Data;
	    PGUID_INDEX AliasIndex;
	    PCLRCLASS_DATA Clrdata;
	    UNICODE_STRING Str;
	    PWSTR PtrW;

	    if (Entity->ComClass.Progid)
		ProgidLen = wcslen(Entity->ComClass.Progid) * sizeof(WCHAR);
	    else
		ProgidLen = 0;

	    ModuleLen = Dll ? wcslen(Dll->Name) * sizeof(WCHAR) :
			       wcslen(L"MSCOREE.DLL") * sizeof(WCHAR);

	    /* setup new index entry */
	    RtlInitUnicodeString(&Str, Entity->ComClass.Clsid);
	    Status = RtlGUIDFromString(&Str, &(*Index)->Guid);
	    if (!NT_SUCCESS(Status))
		return Status;

	    (*Index)->DataOffset = *DataOffset;
	    (*Index)->DataLength = sizeof(*Data); /* additional length added later */
	    (*Index)->RosterIndex = Rosterindex;

	    /* Setup new index entry for alias guid. Alias index records are placed after
	       normal records, so normal guids are hit first on search. Note that class
	       count is doubled. */
	    AliasIndex = (*Index) + Section->Count / 2;
	    GenerateUuid(Seed, &AliasIndex->Guid);
	    AliasIndex->DataOffset = (*Index)->DataOffset;
	    AliasIndex->DataLength = 0;
	    AliasIndex->RosterIndex = (*Index)->RosterIndex;

	    /* setup data */
	    Data = (PCOMCLASSREDIRECT_DATA)((BYTE *)Section + (*Index)->DataOffset);
	    Data->Size = sizeof(*Data);
	    Data->Model = Entity->ComClass.Model;
	    Data->ClassId1 = (*Index)->Guid;
	    Data->Alias = AliasIndex->Guid;
	    Data->ClassId2 = Data->ClassId1;
	    if (Entity->ComClass.Tlbid) {
		RtlInitUnicodeString(&Str, Entity->ComClass.Tlbid);
		Status = RtlGUIDFromString(&Str, &Data->Tlbid);
		if (!NT_SUCCESS(Status))
		    return Status;
	    } else
		memset(&Data->Tlbid, 0, sizeof(Data->Tlbid));
	    Data->NameLength = ModuleLen;
	    Data->NameOffset = *ModuleOffset;
	    Data->ProgidLength = ProgidLen;
	    Data->ProgidOffset = Data->ProgidLength ? Data->Size : 0; /* in case of
									clrClass
									additional offset
									is added later */
	    Data->ClrdataLength = 0; /* will be set later */
	    Data->ClrdataOffset = Entity->ComClass.Name ? sizeof(*Data) : 0;
	    Data->MiscStatus = Entity->ComClass.MiscStatus;
	    Data->MiscStatusContent = Entity->ComClass.MiscStatusContent;
	    Data->MiscStatusThumbnail = Entity->ComClass.MiscStatusThumbnail;
	    Data->MiscStatusIcon = Entity->ComClass.MiscStatusIcon;
	    Data->MiscStatusDocPrint = Entity->ComClass.MiscStatusDocPrint;

	    /* mask describes which misc* data is available */
	    Miscmask = 0;
	    if (Data->MiscStatus)
		Miscmask |= MiscStatus;
	    if (Data->MiscStatusContent)
		Miscmask |= MiscStatusContent;
	    if (Data->MiscStatusThumbnail)
		Miscmask |= MiscStatusThumbnail;
	    if (Data->MiscStatusIcon)
		Miscmask |= MiscStatusIcon;
	    if (Data->MiscStatusDocPrint)
		Miscmask |= MiscStatusDocPrint;
	    Data->Flags = Miscmask << 8;

	    if (Data->ClrdataOffset) {
		Clrdata = (PCLRCLASS_DATA)((BYTE *)Data + Data->ClrdataOffset);

		Clrdata->Size = sizeof(*Clrdata);
		Clrdata->Resource[0] = 0;
		Clrdata->Resource[1] = 2; /* FIXME: unknown field */
		Clrdata->ModuleLength = wcslen(L"MSCOREE.DLL") * sizeof(WCHAR);
		Clrdata->ModuleOffset = *ModuleOffset + Data->NameLength + sizeof(WCHAR);
		Clrdata->NameLength = wcslen(Entity->ComClass.Name) * sizeof(WCHAR);
		Clrdata->NameOffset = Clrdata->Size;
		Clrdata->VersionLength = Entity->ComClass.Version ?
					   wcslen(Entity->ComClass.Version) *
					       sizeof(WCHAR) :
					   0;
		Clrdata->VersionOffset = Clrdata->VersionLength ?
					      Clrdata->NameOffset + Clrdata->NameLength +
						  sizeof(WCHAR) :
					      0;
		Clrdata->Resource2[0] = 0;
		Clrdata->Resource2[1] = 0;

		Data->ClrdataLength = Clrdata->Size + Clrdata->NameLength + sizeof(WCHAR);

		/* module name */
		PtrW = (PWSTR)((BYTE *)Section + Clrdata->ModuleOffset);
		memcpy(PtrW, L"mscoree.dll", Clrdata->ModuleLength);
		PtrW[Clrdata->ModuleLength / sizeof(WCHAR)] = 0;

		PtrW = (PWSTR)((BYTE *)Section + Data->NameOffset);
		memcpy(PtrW, L"MSCOREE.DLL", Data->NameLength);
		PtrW[Data->NameLength / sizeof(WCHAR)] = 0;

		/* class name */
		PtrW = (PWSTR)((BYTE *)Clrdata + Clrdata->NameOffset);
		memcpy(PtrW, Entity->ComClass.Name, Clrdata->NameLength);
		PtrW[Clrdata->NameLength / sizeof(WCHAR)] = 0;

		/* runtime version, optional */
		if (Clrdata->VersionLength) {
		    Data->ClrdataLength += Clrdata->VersionLength + sizeof(WCHAR);

		    PtrW = (PWSTR)((BYTE *)Clrdata + Clrdata->VersionOffset);
		    memcpy(PtrW, Entity->ComClass.Version, Clrdata->VersionLength);
		    PtrW[Clrdata->VersionLength / sizeof(WCHAR)] = 0;
		}

		if (Data->ProgidLength)
		    Data->ProgidOffset += Data->ClrdataLength;
		(*Index)->DataLength += sizeof(*Clrdata);
	    } else {
		Clrdata = NULL;

		/* module name */
		PtrW = (PWSTR)((BYTE *)Section + Data->NameOffset);
		memcpy(PtrW, Dll->Name, Data->NameLength);
		PtrW[Data->NameLength / sizeof(WCHAR)] = 0;
	    }

	    /* progid string */
	    if (Data->ProgidLength) {
		PtrW = (PWSTR)((BYTE *)Data + Data->ProgidOffset);
		memcpy(PtrW, Entity->ComClass.Progid, Data->ProgidLength);
		PtrW[Data->ProgidLength / sizeof(WCHAR)] = 0;
	    }

	    /* string block length */
	    StrLen = 0;
	    if (Clrdata) {
		StrLen += Clrdata->NameLength + sizeof(WCHAR);
		if (Clrdata->VersionLength)
		    StrLen += Clrdata->VersionLength + sizeof(WCHAR);
	    }
	    if (ProgidLen)
		StrLen += ProgidLen + sizeof(WCHAR);

	    (*Index)->DataLength += AlignedStringLen(StrLen);
	    AliasIndex->DataLength = (*Index)->DataLength;

	    /* move to next data record */
	    (*DataOffset) += sizeof(*Data) + AlignedStringLen(StrLen);
	    (*ModuleOffset) += ModuleLen + sizeof(WCHAR);

	    if (Clrdata) {
		(*DataOffset) += sizeof(*Clrdata);
		(*ModuleOffset) += Clrdata->ModuleLength + sizeof(WCHAR);
	    }
	    (*Index) += 1;
	}
    }

    return STATUS_SUCCESS;
}

static NTSTATUS BuildComServerSection(ACTIVATION_CONTEXT *Actctx,
				      PGUIDSECTION_HEADER *Section)
{
    unsigned int i, j, TotalLen = 0, ClassCount = 0, NamesLen = 0;
    PGUIDSECTION_HEADER Header;
    ULONG ModuleOffset, DataOffset;
    PGUID_INDEX Index;
    ULONG Seed;
    NTSTATUS Status;

    /* compute section length */
    for (i = 0; i < Actctx->NumAssemblies; i++) {
	PASSEMBLY Assembly = &Actctx->Assemblies[i];
	GetComserverDatalen(&Assembly->Entities, NULL, &ClassCount, &TotalLen,
			      &NamesLen);
	for (j = 0; j < Assembly->NumDlls; j++) {
	    PDLL_REDIRECT Dll = &Assembly->Dlls[j];
	    GetComserverDatalen(&Dll->Entities, Dll, &ClassCount, &TotalLen,
				  &NamesLen);
	}
    }

    TotalLen += AlignedStringLen(NamesLen);
    TotalLen += sizeof(*Header);

    Header = RtlAllocateHeap(RtlGetProcessHeap(), 0, TotalLen);
    if (!Header)
	return STATUS_NO_MEMORY;

    memset(Header, 0, sizeof(*Header));
    Header->Magic = GUIDSECTION_MAGIC;
    Header->Size = sizeof(*Header);
    Header->Count = 2 * ClassCount;
    Header->IndexOffset = sizeof(*Header) + AlignedStringLen(NamesLen);
    Index = (PGUID_INDEX)((BYTE *)Header + Header->IndexOffset);
    ModuleOffset = sizeof(*Header);
    DataOffset = Header->IndexOffset + 2 * ClassCount * sizeof(*Index);

    LARGE_INTEGER SystemTime;
    NtQuerySystemTime(&SystemTime);
    Seed = SystemTime.LowPart;
    for (i = 0; i < Actctx->NumAssemblies; i++) {
	PASSEMBLY Assembly = &Actctx->Assemblies[i];
	Status = AddComServerRecord(Header, &Assembly->Entities, NULL, &Index,
				      &DataOffset, &ModuleOffset, &Seed, i + 1);
	if (!NT_SUCCESS(Status)) {
	    RtlFreeHeap(RtlGetProcessHeap(), 0, Header);
	    return Status;
	}
	for (j = 0; j < Assembly->NumDlls; j++) {
	    PDLL_REDIRECT Dll = &Assembly->Dlls[j];
	    Status = AddComServerRecord(Header, &Dll->Entities, Dll, &Index,
					  &DataOffset, &ModuleOffset, &Seed, i + 1);
	    if (!NT_SUCCESS(Status)) {
		RtlFreeHeap(RtlGetProcessHeap(), 0, Header);
		return Status;
	    }
	}
    }

    *Section = Header;

    return STATUS_SUCCESS;
}

static inline PCOMCLASSREDIRECT_DATA GetComClassData(ACTIVATION_CONTEXT *Actctx,
						     PGUID_INDEX Index)
{
    return (PVOID)((BYTE *)Actctx->ComserverSection + Index->DataOffset);
}

static NTSTATUS FindComServerRedirection(ACTIVATION_CONTEXT *Actctx, const GUID *Guid,
					 ACTCTX_SECTION_KEYED_DATA *Data)
{
    PCOMCLASSREDIRECT_DATA Comclass;
    PGUID_INDEX Index = NULL;

    if (!(Actctx->Sections & SERVERREDIRECT_SECTION))
	return STATUS_SXS_KEY_NOT_FOUND;

    if (!Actctx->ComserverSection) {
	PGUIDSECTION_HEADER Section;

	NTSTATUS Status = BuildComServerSection(Actctx, &Section);
	if (Status)
	    return Status;

	if (InterlockedCompareExchangePointer((void **)&Actctx->ComserverSection,
					      Section, NULL))
	    RtlFreeHeap(RtlGetProcessHeap(), 0, Section);
    }

    Index = FindGuidIndex(Actctx->ComserverSection, Guid);
    if (!Index)
	return STATUS_SXS_KEY_NOT_FOUND;

    Comclass = GetComClassData(Actctx, Index);

    Data->ulDataFormatVersion = 1;
    Data->lpData = Comclass;
    /* full length includes string length with nulls */
    Data->ulLength = Comclass->Size + Comclass->ClrdataLength;
    if (Comclass->ProgidLength)
	Data->ulLength += Comclass->ProgidLength + sizeof(WCHAR);
    Data->lpSectionGlobalData = (BYTE *)Actctx->ComserverSection +
				Actctx->ComserverSection->NamesOffset;
    Data->ulSectionGlobalDataLength = Actctx->ComserverSection->NamesLength;
    Data->lpSectionBase = Actctx->ComserverSection;
    Data->ulSectionTotalLength = RtlSizeHeap(RtlGetProcessHeap(), 0,
					     Actctx->ComserverSection);
    Data->hActCtx = NULL;

    if (Data->cbSize >=
	FIELD_OFFSET(ACTCTX_SECTION_KEYED_DATA, ulAssemblyRosterIndex) + sizeof(ULONG))
	Data->ulAssemblyRosterIndex = Index->RosterIndex;

    return STATUS_SUCCESS;
}

static void GetIfacepsDatalen(PCENTITY_ARRAY Entities, unsigned int *Count,
			      unsigned int *Len)
{
    unsigned int i;

    for (i = 0; i < Entities->Count; i++) {
	PENTITY Entity = &Entities->Base[i];
	if (Entity->Kind == ACTIVATION_CONTEXT_SECTION_COM_INTERFACE_REDIRECTION) {
	    *Len += sizeof(GUID_INDEX) + sizeof(IFACEPSREDIRECT_DATA);
	    if (Entity->Ifaceps.Name)
		*Len += AlignedStringLen((wcslen(Entity->Ifaceps.Name) + 1) *
					   sizeof(WCHAR));
	    *Count += 1;
	}
    }
}

static NTSTATUS AddIfacepsRecord(PGUIDSECTION_HEADER Section,
				 PENTITY_ARRAY Entities,
				 PGUID_INDEX *Index,
				 ULONG *DataOffset,
				 ULONG Rosterindex)
{
    unsigned int i;

    for (i = 0; i < Entities->Count; i++) {
	PENTITY Entity = &Entities->Base[i];
	if (Entity->Kind == ACTIVATION_CONTEXT_SECTION_COM_INTERFACE_REDIRECTION) {
	    PIFACEPSREDIRECT_DATA Data = (PVOID)((BYTE *)Section + *DataOffset);
	    UNICODE_STRING Str;
	    ULONG NameLen;
	    NTSTATUS Status;

	    if (Entity->Ifaceps.Name)
		NameLen = wcslen(Entity->Ifaceps.Name) * sizeof(WCHAR);
	    else
		NameLen = 0;

	    /* setup index */
	    RtlInitUnicodeString(&Str, Entity->Ifaceps.Iid);
	    Status = RtlGUIDFromString(&Str, &(*Index)->Guid);
	    if (!NT_SUCCESS(Status))
		return Status;
	    (*Index)->DataOffset = *DataOffset;
	    (*Index)->DataLength = sizeof(*Data) + NameLen ?
				     AlignedStringLen(NameLen + sizeof(WCHAR)) :
				     0;
	    (*Index)->RosterIndex = Rosterindex;

	    /* setup data record */
	    Data->Size = sizeof(*Data);
	    Data->Mask = Entity->Ifaceps.Mask;

	    /* proxyStubClsid32 value is only stored for external PS,
	       if set it's used as iid, otherwise 'iid' attribute value is used */
	    if (Entity->Ifaceps.Ps32) {
		RtlInitUnicodeString(&Str, Entity->Ifaceps.Ps32);
		Status = RtlGUIDFromString(&Str, &Data->Iid);
		if (!NT_SUCCESS(Status))
		    return Status;
	    } else
		Data->Iid = (*Index)->Guid;

	    Data->NumMethods = Entity->Ifaceps.NumMethods;

	    if (Entity->Ifaceps.Tlib) {
		RtlInitUnicodeString(&Str, Entity->Ifaceps.Tlib);
		Status = RtlGUIDFromString(&Str, &Data->Tlbid);
		if (!NT_SUCCESS(Status))
		    return Status;
	    } else
		memset(&Data->Tlbid, 0, sizeof(Data->Tlbid));

	    if (Entity->Ifaceps.Base) {
		RtlInitUnicodeString(&Str, Entity->Ifaceps.Base);
		Status = RtlGUIDFromString(&Str, &Data->Base);
		if (!NT_SUCCESS(Status))
		    return Status;
	    } else
		memset(&Data->Base, 0, sizeof(Data->Base));

	    Data->NameLength = NameLen;
	    Data->NameOffset = Data->NameLength ? sizeof(*Data) : 0;

	    /* name string */
	    if (Data->NameLength) {
		PWSTR PtrW = (PWSTR)((BYTE *)Data + Data->NameOffset);
		memcpy(PtrW, Entity->Ifaceps.Name, Data->NameLength);
		PtrW[Data->NameLength / sizeof(WCHAR)] = 0;
	    }

	    /* move to next record */
	    (*Index) += 1;
	    *DataOffset += sizeof(*Data);
	    if (Data->NameLength)
		*DataOffset += AlignedStringLen(Data->NameLength + sizeof(WCHAR));
	}
    }

    return STATUS_SUCCESS;
}

static NTSTATUS BuildIfacepsSection(ACTIVATION_CONTEXT *Actctx,
				    PGUIDSECTION_HEADER *Section)
{
    unsigned int i, j, TotalLen = 0, Count = 0;
    PGUIDSECTION_HEADER Header;
    PGUID_INDEX Index;
    ULONG DataOffset;

    /* compute section length */
    for (i = 0; i < Actctx->NumAssemblies; i++) {
	PASSEMBLY Assembly = &Actctx->Assemblies[i];

	GetIfacepsDatalen(&Assembly->Entities, &Count, &TotalLen);
	for (j = 0; j < Assembly->NumDlls; j++) {
	    PDLL_REDIRECT Dll = &Assembly->Dlls[j];
	    GetIfacepsDatalen(&Dll->Entities, &Count, &TotalLen);
	}
    }

    TotalLen += sizeof(*Header);

    Header = RtlAllocateHeap(RtlGetProcessHeap(), 0, TotalLen);
    if (!Header)
	return STATUS_NO_MEMORY;

    memset(Header, 0, sizeof(*Header));
    Header->Magic = GUIDSECTION_MAGIC;
    Header->Size = sizeof(*Header);
    Header->Count = Count;
    Header->IndexOffset = sizeof(*Header);
    Index = (PGUID_INDEX)((BYTE *)Header + Header->IndexOffset);
    DataOffset = Header->IndexOffset + Count * sizeof(*Index);

    for (i = 0; i < Actctx->NumAssemblies; i++) {
	PASSEMBLY Assembly = &Actctx->Assemblies[i];
	NTSTATUS Status;

	Status = AddIfacepsRecord(Header, &Assembly->Entities, &Index, &DataOffset,
				    i + 1);
	if (!NT_SUCCESS(Status)) {
	    RtlFreeHeap(RtlGetProcessHeap(), 0, Header);
	    return Status;
	}

	for (j = 0; j < Assembly->NumDlls; j++) {
	    PDLL_REDIRECT Dll = &Assembly->Dlls[j];
	    Status = AddIfacepsRecord(Header, &Dll->Entities, &Index, &DataOffset,
					i + 1);
	    if (!NT_SUCCESS(Status)) {
		RtlFreeHeap(RtlGetProcessHeap(), 0, Header);
		return Status;
	    }
	}
    }

    *Section = Header;

    return STATUS_SUCCESS;
}

static inline PIFACEPSREDIRECT_DATA GetIfacepsData(ACTIVATION_CONTEXT *Actctx,
						   PGUID_INDEX Index)
{
    return (PVOID)((BYTE *)Actctx->IfacepsSection + Index->DataOffset);
}

static NTSTATUS FindCominterfaceRedirection(ACTIVATION_CONTEXT *Actctx,
					    const GUID *Guid,
					    ACTCTX_SECTION_KEYED_DATA *Data)
{
    PIFACEPSREDIRECT_DATA Iface;
    PGUID_INDEX Index = NULL;

    if (!(Actctx->Sections & IFACEREDIRECT_SECTION))
	return STATUS_SXS_KEY_NOT_FOUND;

    if (!Actctx->IfacepsSection) {
	PGUIDSECTION_HEADER Section;

	NTSTATUS Status = BuildIfacepsSection(Actctx, &Section);
	if (Status)
	    return Status;

	if (InterlockedCompareExchangePointer((void **)&Actctx->IfacepsSection, Section,
					      NULL))
	    RtlFreeHeap(RtlGetProcessHeap(), 0, Section);
    }

    Index = FindGuidIndex(Actctx->IfacepsSection, Guid);
    if (!Index)
	return STATUS_SXS_KEY_NOT_FOUND;

    Iface = GetIfacepsData(Actctx, Index);

    Data->ulDataFormatVersion = 1;
    Data->lpData = Iface;
    Data->ulLength = Iface->Size +
		     (Iface->NameLength ? Iface->NameLength + sizeof(WCHAR) : 0);
    Data->lpSectionGlobalData = NULL;
    Data->ulSectionGlobalDataLength = 0;
    Data->lpSectionBase = Actctx->IfacepsSection;
    Data->ulSectionTotalLength = RtlSizeHeap(RtlGetProcessHeap(), 0,
					     Actctx->IfacepsSection);
    Data->hActCtx = NULL;

    if (Data->cbSize >=
	FIELD_OFFSET(ACTCTX_SECTION_KEYED_DATA, ulAssemblyRosterIndex) + sizeof(ULONG))
	Data->ulAssemblyRosterIndex = Index->RosterIndex;

    return STATUS_SUCCESS;
}

static NTSTATUS BuildClrSurrogateSection(ACTIVATION_CONTEXT *Actctx,
					 PGUIDSECTION_HEADER *Section)
{
    unsigned int i, j, TotalLen = 0, Count = 0;
    PGUIDSECTION_HEADER Header;
    PCLRSURROGATE_DATA Data;
    PGUID_INDEX Index;
    ULONG DataOffset;

    /* compute section length */
    for (i = 0; i < Actctx->NumAssemblies; i++) {
	PASSEMBLY Assembly = &Actctx->Assemblies[i];
	for (j = 0; j < Assembly->Entities.Count; j++) {
	    PENTITY Entity = &Assembly->Entities.Base[j];
	    if (Entity->Kind == ACTIVATION_CONTEXT_SECTION_CLR_SURROGATES) {
		ULONG Len;

		TotalLen += sizeof(*Index) + sizeof(*Data);
		Len = wcslen(Entity->ClrSurrogate.Name) + 1;
		if (Entity->ClrSurrogate.Version)
		    Len += wcslen(Entity->ClrSurrogate.Version) + 1;
		TotalLen += AlignedStringLen(Len * sizeof(WCHAR));

		Count++;
	    }
	}
    }

    TotalLen += sizeof(*Header);

    Header = RtlAllocateHeap(RtlGetProcessHeap(), 0, TotalLen);
    if (!Header)
	return STATUS_NO_MEMORY;

    memset(Header, 0, sizeof(*Header));
    Header->Magic = GUIDSECTION_MAGIC;
    Header->Size = sizeof(*Header);
    Header->Count = Count;
    Header->IndexOffset = sizeof(*Header);
    Index = (PGUID_INDEX)((BYTE *)Header + Header->IndexOffset);
    DataOffset = Header->IndexOffset + Count * sizeof(*Index);

    for (i = 0; i < Actctx->NumAssemblies; i++) {
	PASSEMBLY Assembly = &Actctx->Assemblies[i];
	for (j = 0; j < Assembly->Entities.Count; j++) {
	    PENTITY Entity = &Assembly->Entities.Base[j];
	    if (Entity->Kind == ACTIVATION_CONTEXT_SECTION_CLR_SURROGATES) {
		ULONG VersionLen, NameLen;
		UNICODE_STRING Str;
		PWSTR PtrW;
		NTSTATUS Status;

		if (Entity->ClrSurrogate.Version)
		    VersionLen = wcslen(Entity->ClrSurrogate.Version) * sizeof(WCHAR);
		else
		    VersionLen = 0;
		NameLen = wcslen(Entity->ClrSurrogate.Name) * sizeof(WCHAR);

		/* setup new index entry */
		RtlInitUnicodeString(&Str, Entity->ClrSurrogate.Clsid);
		Status = RtlGUIDFromString(&Str, &Index->Guid);
		if (!NT_SUCCESS(Status)) {
		    RtlFreeHeap(RtlGetProcessHeap(), 0, Header);
		    return Status;
		}

		Index->DataOffset = DataOffset;
		Index->DataLength = sizeof(*Data) +
				  AlignedStringLen(
				      NameLen + sizeof(WCHAR) +
				      (VersionLen ? VersionLen + sizeof(WCHAR) : 0));
		Index->RosterIndex = i + 1;

		/* setup data */
		Data = (PCLRSURROGATE_DATA)((BYTE *)Header + Index->DataOffset);
		Data->Size = sizeof(*Data);
		Data->Resource = 0;
		Data->Clsid = Index->Guid;
		Data->VersionOffset = VersionLen ? Data->Size : 0;
		Data->VersionLength = VersionLen;
		Data->NameOffset = Data->Size + VersionLen;
		if (VersionLen)
		    Data->NameOffset += sizeof(WCHAR);
		Data->NameLength = NameLen;

		/* surrogate name */
		PtrW = (PWSTR)((BYTE *)Data + Data->NameOffset);
		memcpy(PtrW, Entity->ClrSurrogate.Name, Data->NameLength);
		PtrW[Data->NameLength / sizeof(WCHAR)] = 0;

		/* runtime version */
		if (Data->VersionLength) {
		    PtrW = (PWSTR)((BYTE *)Data + Data->VersionOffset);
		    memcpy(PtrW, Entity->ClrSurrogate.Version, Data->VersionLength);
		    PtrW[Data->VersionLength / sizeof(WCHAR)] = 0;
		}

		DataOffset += Index->DataLength;
		Index++;
	    }
	}
    }

    *Section = Header;

    return STATUS_SUCCESS;
}

static inline PCLRSURROGATE_DATA GetSurrogateData(ACTIVATION_CONTEXT *Actctx,
						  PCGUID_INDEX Index)
{
    return (PVOID)((BYTE *)Actctx->ClrSurrogateSection + Index->DataOffset);
}

static NTSTATUS FindClrSurrogate(ACTIVATION_CONTEXT *Actctx, const GUID *Guid,
				 ACTCTX_SECTION_KEYED_DATA *Data)
{
    PCLRSURROGATE_DATA Surrogate;
    PGUID_INDEX Index = NULL;

    if (!(Actctx->Sections & CLRSURROGATES_SECTION))
	return STATUS_SXS_KEY_NOT_FOUND;

    if (!Actctx->ClrSurrogateSection) {
	PGUIDSECTION_HEADER Section;

	NTSTATUS Status = BuildClrSurrogateSection(Actctx, &Section);
	if (Status)
	    return Status;

	if (InterlockedCompareExchangePointer((void **)&Actctx->ClrSurrogateSection,
					      Section, NULL))
	    RtlFreeHeap(RtlGetProcessHeap(), 0, Section);
    }

    Index = FindGuidIndex(Actctx->ClrSurrogateSection, Guid);
    if (!Index)
	return STATUS_SXS_KEY_NOT_FOUND;

    Surrogate = GetSurrogateData(Actctx, Index);

    Data->ulDataFormatVersion = 1;
    Data->lpData = Surrogate;
    /* full length includes string length with nulls */
    Data->ulLength = Surrogate->Size + Surrogate->NameLength + sizeof(WCHAR);
    if (Surrogate->VersionLength)
	Data->ulLength += Surrogate->VersionLength + sizeof(WCHAR);

    Data->lpSectionGlobalData = NULL;
    Data->ulSectionGlobalDataLength = 0;
    Data->lpSectionBase = Actctx->ClrSurrogateSection;
    Data->ulSectionTotalLength = RtlSizeHeap(RtlGetProcessHeap(), 0,
					     Actctx->ClrSurrogateSection);
    Data->hActCtx = NULL;

    if (Data->cbSize >=
	FIELD_OFFSET(ACTCTX_SECTION_KEYED_DATA, ulAssemblyRosterIndex) + sizeof(ULONG))
	Data->ulAssemblyRosterIndex = Index->RosterIndex;

    return STATUS_SUCCESS;
}

static void GetProgidDatalen(PENTITY_ARRAY Entities, unsigned int *Count,
			     unsigned int *TotalLen)
{
    unsigned int i, j, SingleLen;

    SingleLen = sizeof(PROGIDREDIRECT_DATA) + sizeof(STRING_INDEX) +
		 sizeof(GUID);
    for (i = 0; i < Entities->Count; i++) {
	PENTITY Entity = &Entities->Base[i];
	if (Entity->Kind == ACTIVATION_CONTEXT_SECTION_COM_SERVER_REDIRECTION) {
	    if (Entity->ComClass.Progid) {
		*TotalLen += SingleLen +
			      AlignedStringLen((wcslen(Entity->ComClass.Progid) + 1) *
						 sizeof(WCHAR));
		*Count += 1;
	    }

	    for (j = 0; j < Entity->ComClass.Progids.Count; j++)
		*TotalLen += AlignedStringLen(
		    (wcslen(Entity->ComClass.Progids.Progids[j]) + 1) * sizeof(WCHAR));

	    *TotalLen += SingleLen * Entity->ComClass.Progids.Count;
	    *Count += Entity->ComClass.Progids.Count;
	}
    }
}

static void WriteProgidRecord(PSTRSECTION_HEADER Section, PCWSTR Progid,
			      const GUID *Alias, PSTRING_INDEX *Index,
			      ULONG *DataOffset, ULONG *GlobalOffset,
			      ULONG Rosterindex)
{
    PPROGIDREDIRECT_DATA Data;
    UNICODE_STRING Str;
    GUID *GuidPtr;
    PWSTR PtrW;

    /* setup new index entry */

    /* hash progid name */
    RtlInitUnicodeString(&Str, Progid);
    RtlHashUnicodeString(&Str, TRUE, HASH_STRING_ALGORITHM_X65599, &(*Index)->Hash);

    (*Index)->NameOffset = *DataOffset;
    (*Index)->NameLength = Str.Length;
    (*Index)->DataOffset = (*Index)->NameOffset + AlignedStringLen(Str.MaximumLength);
    (*Index)->DataLength = sizeof(*Data);
    (*Index)->RosterIndex = Rosterindex;

    *DataOffset += AlignedStringLen(Str.MaximumLength);

    /* setup data structure */
    Data = (PPROGIDREDIRECT_DATA)((BYTE *)Section + *DataOffset);
    Data->Size = sizeof(*Data);
    Data->Reserved = 0;
    Data->ClsidOffset = *GlobalOffset;

    /* write progid string */
    PtrW = (PWSTR)((BYTE *)Section + (*Index)->NameOffset);
    memcpy(PtrW, Progid, (*Index)->NameLength);
    PtrW[(*Index)->NameLength / sizeof(WCHAR)] = 0;

    /* write guid to global area */
    GuidPtr = (GUID *)((BYTE *)Section + Data->ClsidOffset);
    *GuidPtr = *Alias;

    /* to next entry */
    *GlobalOffset += sizeof(GUID);
    *DataOffset += Data->Size;
    (*Index) += 1;
}

static NTSTATUS AddProgidRecord(ACTIVATION_CONTEXT *Actctx,
				PSTRSECTION_HEADER Section,
				PCENTITY_ARRAY Entities,
				PSTRING_INDEX *Index,
				ULONG *DataOffset,
				ULONG *GlobalOffset,
				ULONG Rosterindex)
{
    unsigned int i, j;
    NTSTATUS Status;

    for (i = 0; i < Entities->Count; i++) {
	PENTITY Entity = &Entities->Base[i];
	if (Entity->Kind == ACTIVATION_CONTEXT_SECTION_COM_SERVER_REDIRECTION) {
	    PCPROGIDS Progids = &Entity->ComClass.Progids;
	    PCOMCLASSREDIRECT_DATA Comclass;
	    PGUID_INDEX GuidIndex;
	    UNICODE_STRING Str;
	    GUID Clsid;

	    RtlInitUnicodeString(&Str, Entity->ComClass.Clsid);
	    Status = RtlGUIDFromString(&Str, &Clsid);
	    if (!NT_SUCCESS(Status))
		return Status;

	    GuidIndex = FindGuidIndex(Actctx->ComserverSection, &Clsid);
	    Comclass = GetComClassData(Actctx, GuidIndex);

	    if (Entity->ComClass.Progid)
		WriteProgidRecord(Section, Entity->ComClass.Progid, &Comclass->Alias,
				    Index, DataOffset, GlobalOffset, Rosterindex);

	    for (j = 0; j < Progids->Count; j++)
		WriteProgidRecord(Section, Progids->Progids[j], &Comclass->Alias, Index,
				    DataOffset, GlobalOffset, Rosterindex);
	}
    }
    return Status;
}

static NTSTATUS BuildProgidSection(ACTIVATION_CONTEXT *Actctx,
				   PSTRSECTION_HEADER *Section)
{
    unsigned int i, j, TotalLen = 0, Count = 0;
    PSTRSECTION_HEADER Header;
    ULONG DataOffset, GlobalOffset;
    PSTRING_INDEX Index;
    NTSTATUS Status;

    /* compute section length */
    for (i = 0; i < Actctx->NumAssemblies; i++) {
	PASSEMBLY Assembly = &Actctx->Assemblies[i];

	GetProgidDatalen(&Assembly->Entities, &Count, &TotalLen);
	for (j = 0; j < Assembly->NumDlls; j++) {
	    PDLL_REDIRECT Dll = &Assembly->Dlls[j];
	    GetProgidDatalen(&Dll->Entities, &Count, &TotalLen);
	}
    }

    TotalLen += sizeof(*Header);

    Header = RtlAllocateHeap(RtlGetProcessHeap(), 0, TotalLen);
    if (!Header)
	return STATUS_NO_MEMORY;

    memset(Header, 0, sizeof(*Header));
    Header->Magic = STRSECTION_MAGIC;
    Header->Size = sizeof(*Header);
    Header->Count = Count;
    Header->GlobalOffset = Header->Size;
    Header->GlobalLength = Count * sizeof(GUID);
    Header->IndexOffset = Header->Size + Header->GlobalLength;

    Index = (PSTRING_INDEX)((BYTE *)Header + Header->IndexOffset);
    DataOffset = Header->IndexOffset + Count * sizeof(*Index);
    GlobalOffset = Header->GlobalOffset;

    for (i = 0; i < Actctx->NumAssemblies; i++) {
	PASSEMBLY Assembly = &Actctx->Assemblies[i];

	Status = AddProgidRecord(Actctx, Header, &Assembly->Entities, &Index,
				   &DataOffset, &GlobalOffset, i + 1);
	if (!NT_SUCCESS(Status)) {
	    RtlFreeHeap(RtlGetProcessHeap(), 0, Header);
	    return Status;
	}

	for (j = 0; j < Assembly->NumDlls; j++) {
	    PDLL_REDIRECT Dll = &Assembly->Dlls[j];
	    Status = AddProgidRecord(Actctx, Header, &Dll->Entities, &Index,
				       &DataOffset, &GlobalOffset, i + 1);
	    if (!NT_SUCCESS(Status)) {
		RtlFreeHeap(RtlGetProcessHeap(), 0, Header);
		return Status;
	    }
	}
    }

    *Section = Header;

    return STATUS_SUCCESS;
}

static inline PPROGIDREDIRECT_DATA
GetProgidData(ACTIVATION_CONTEXT *Actctx, PCSTRING_INDEX Index)
{
    return (PVOID)((BYTE *)Actctx->ProgidSection + Index->DataOffset);
}

static NTSTATUS FindProgidRedirection(ACTIVATION_CONTEXT *Actctx,
				      const UNICODE_STRING *Name,
				      PACTCTX_SECTION_KEYED_DATA Data)
{
    PPROGIDREDIRECT_DATA Progid;
    PSTRING_INDEX Index;

    if (!(Actctx->Sections & PROGIDREDIRECT_SECTION))
	return STATUS_SXS_KEY_NOT_FOUND;

    if (!Actctx->ComserverSection) {
	PGUIDSECTION_HEADER Section;

	NTSTATUS Status = BuildComServerSection(Actctx, &Section);
	if (Status)
	    return Status;

	if (InterlockedCompareExchangePointer((void **)&Actctx->ComserverSection,
					      Section, NULL))
	    RtlFreeHeap(RtlGetProcessHeap(), 0, Section);
    }

    if (!Actctx->ProgidSection) {
	PSTRSECTION_HEADER Section;

	NTSTATUS Status = BuildProgidSection(Actctx, &Section);
	if (Status)
	    return Status;

	if (InterlockedCompareExchangePointer((void **)&Actctx->ProgidSection, Section,
					      NULL))
	    RtlFreeHeap(RtlGetProcessHeap(), 0, Section);
    }

    Index = FindStringIndex(Actctx->ProgidSection, Name);
    if (!Index)
	return STATUS_SXS_KEY_NOT_FOUND;

    if (Data) {
	Progid = GetProgidData(Actctx, Index);

	Data->ulDataFormatVersion = 1;
	Data->lpData = Progid;
	Data->ulLength = Progid->Size;
	Data->lpSectionGlobalData = (BYTE *)Actctx->ProgidSection +
				    Actctx->ProgidSection->GlobalOffset;
	Data->ulSectionGlobalDataLength = Actctx->ProgidSection->GlobalLength;
	Data->lpSectionBase = Actctx->ProgidSection;
	Data->ulSectionTotalLength = RtlSizeHeap(RtlGetProcessHeap(), 0,
						 Actctx->ProgidSection);
	Data->hActCtx = NULL;

	if (Data->cbSize >=
	    FIELD_OFFSET(ACTCTX_SECTION_KEYED_DATA, ulAssemblyRosterIndex) +
		sizeof(ULONG))
	    Data->ulAssemblyRosterIndex = Index->RosterIndex;
    }

    return STATUS_SUCCESS;
}

static NTSTATUS FindString(ACTIVATION_CONTEXT *ActCtx, ULONG SectionKind,
			   const UNICODE_STRING *SectionName, DWORD Flags,
			   PACTCTX_SECTION_KEYED_DATA Data)
{
    NTSTATUS Status;

    switch (SectionKind) {
    case ACTIVATION_CONTEXT_SECTION_ASSEMBLY_INFORMATION:
	DPRINT1("Unsupported yet section_kind %x\n", SectionKind);
	return STATUS_SXS_KEY_NOT_FOUND;
    case ACTIVATION_CONTEXT_SECTION_DLL_REDIRECTION:
	Status = FindDllRedirection(ActCtx, SectionName, Data);
	break;
    case ACTIVATION_CONTEXT_SECTION_WINDOW_CLASS_REDIRECTION:
	Status = FindWindowClass(ActCtx, SectionName, Data);
	break;
    case ACTIVATION_CONTEXT_SECTION_COM_PROGID_REDIRECTION:
	Status = FindProgidRedirection(ActCtx, SectionName, Data);
	break;
    case ACTIVATION_CONTEXT_SECTION_GLOBAL_OBJECT_RENAME_TABLE:
	INFO_(LDR, "Unsupported yet section_kind %x\n", SectionKind);
	return STATUS_SXS_SECTION_NOT_FOUND;
    case ACTIVATION_CONTEXT_SECTION_WINRT_ACTIVATABLE_CLASSES:
	Status = FindActivatableClass(ActCtx, SectionName, Data);
	break;
    default:
	WARN_(LDR, "Unknown section_kind %x\n", SectionKind);
	return STATUS_SXS_SECTION_NOT_FOUND;
    }

    if (Status != STATUS_SUCCESS)
	return Status;

    if (Data && (Flags & FIND_ACTCTX_SECTION_KEY_RETURN_HACTCTX)) {
	ActCtxAddRef(ActCtx);
	Data->hActCtx = ActCtx;
    }
    return STATUS_SUCCESS;
}

static NTSTATUS FindGuid(ACTIVATION_CONTEXT *ActCtx, ULONG SectionKind,
			 const GUID *Guid, DWORD Flags, PACTCTX_SECTION_KEYED_DATA Data)
{
    NTSTATUS Status;

    switch (SectionKind) {
    case ACTIVATION_CONTEXT_SECTION_COM_TYPE_LIBRARY_REDIRECTION:
	Status = FindTlibRedirection(ActCtx, Guid, Data);
	break;
    case ACTIVATION_CONTEXT_SECTION_COM_SERVER_REDIRECTION:
	Status = FindComServerRedirection(ActCtx, Guid, Data);
	break;
    case ACTIVATION_CONTEXT_SECTION_COM_INTERFACE_REDIRECTION:
	Status = FindCominterfaceRedirection(ActCtx, Guid, Data);
	break;
    case ACTIVATION_CONTEXT_SECTION_CLR_SURROGATES:
	Status = FindClrSurrogate(ActCtx, Guid, Data);
	break;
    default:
	WARN_(LDR, "Unknown section_kind %x\n", SectionKind);
	return STATUS_SXS_SECTION_NOT_FOUND;
    }

    if (Status != STATUS_SUCCESS)
	return Status;

    if (Flags & FIND_ACTCTX_SECTION_KEY_RETURN_HACTCTX) {
	ActCtxAddRef(ActCtx);
	Data->hActCtx = ActCtx;
    }
    return STATUS_SUCCESS;
}

static PCWSTR FindAppSettings(ACTIVATION_CONTEXT *ActCtx, PCWSTR Settings,
			      PCWSTR Namespace)
{
    for (ULONG i = 0; i < ActCtx->NumAssemblies; i++) {
	PASSEMBLY Assembly = &ActCtx->Assemblies[i];
	for (ULONG j = 0; j < Assembly->Entities.Count; j++) {
	    PENTITY Entity = &Assembly->Entities.Base[j];
	    if (Entity->Kind == ACTIVATION_CONTEXT_SECTION_APPLICATION_SETTINGS &&
		!wcscmp(Entity->Settings.Name, Settings) &&
		!wcscmp(Entity->Settings.Namespace, Namespace))
		return Entity->Settings.Value;
	}
    }
    return NULL;
}

/* Initialize the activation context for the current process */
static VOID InitActCtx(VOID)
{
    ACTCTXW Ctx = {};
    HANDLE Handle;

    Ctx.cbSize = sizeof(Ctx);
    Ctx.lpSource = NULL;
    Ctx.dwFlags = ACTCTX_FLAG_RESOURCE_NAME_VALID | ACTCTX_FLAG_HMODULE_VALID;
    Ctx.hModule = NtCurrentTeb()->ProcessEnvironmentBlock->ImageBaseAddress;
    Ctx.lpResourceName = (LPCWSTR)CREATEPROCESS_MANIFEST_RESOURCE_ID;

    if (NT_SUCCESS(RtlCreateActivationContext(0, (PVOID)&Ctx, 0, NULL, NULL, &Handle))) {
	ProcessActCtx = CheckActCtx(Handle);
    }

    NtCurrentTeb()->ProcessEnvironmentBlock->ActivationContextData =
	ProcessActCtx->ActivationContextData;
}

/***********************************************************************
 * RtlCreateActivationContext (NTDLL.@)
 *
 * Create an activation context.
 */
NTAPI NTSTATUS RtlCreateActivationContext(IN ULONG Flags,
					  IN PACTIVATION_CONTEXT_DATA ActivationContextData,
					  IN ULONG ExtraBytes, IN PVOID NotificationRoutine,
					  IN PVOID NotificationContext,
					  OUT PACTIVATION_CONTEXT *ActCtx)
{
    const ACTCTXW *pActCtx = (PVOID)ActivationContextData;
    PCWSTR Directory = NULL;
    ACTIVATION_CONTEXT *Actctx;
    UNICODE_STRING NameW;
    ULONG Lang = 0;
    NTSTATUS Status = STATUS_NO_MEMORY;
    HANDLE File = 0;
    ACTCTX_LOADER Acl;

    TRACE_(LDR, "%p %08x\n", pActCtx, pActCtx ? pActCtx->dwFlags : 0);

#define CHECK_LIMIT(field) (pActCtx->cbSize >= RTL_SIZEOF_THROUGH_FIELD(ACTCTXW, field))
    if (!pActCtx || (pActCtx->dwFlags & ~ACTCTX_FLAGS_ALL) || !CHECK_LIMIT(lpSource) ||
	((pActCtx->dwFlags & ACTCTX_FLAG_PROCESSOR_ARCHITECTURE_VALID) &&
	 !CHECK_LIMIT(wProcessorArchitecture)) ||
	((pActCtx->dwFlags & ACTCTX_FLAG_LANGID_VALID) && !CHECK_LIMIT(wLangId)) ||
	((pActCtx->dwFlags & ACTCTX_FLAG_ASSEMBLY_DIRECTORY_VALID) &&
	 !CHECK_LIMIT(lpAssemblyDirectory)) ||
	((pActCtx->dwFlags & ACTCTX_FLAG_RESOURCE_NAME_VALID) &&
	 !CHECK_LIMIT(lpResourceName)) ||
	((pActCtx->dwFlags & ACTCTX_FLAG_APPLICATION_NAME_VALID) &&
	 !CHECK_LIMIT(lpApplicationName)) ||
	((pActCtx->dwFlags & ACTCTX_FLAG_HMODULE_VALID) && !CHECK_LIMIT(hModule)))
	return STATUS_INVALID_PARAMETER;
#undef CHECK_LIMIT

    if ((pActCtx->dwFlags & ACTCTX_FLAG_RESOURCE_NAME_VALID) && !pActCtx->lpResourceName)
	return STATUS_INVALID_PARAMETER;

    if (!(Actctx = RtlAllocateHeap(RtlGetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*Actctx))))
	return STATUS_NO_MEMORY;

    Actctx->Magic = ACTCTX_MAGIC;
    Actctx->RefCount = 1;
    Actctx->Config.Type = ACTIVATION_CONTEXT_PATH_TYPE_NONE;
    Actctx->Config.Info = NULL;
    Actctx->AppDir.Type = ACTIVATION_CONTEXT_PATH_TYPE_WIN32_FILE;
    if (pActCtx->dwFlags & ACTCTX_FLAG_APPLICATION_NAME_VALID) {
	if (!(Actctx->AppDir.Info = RtlpDuplicateWideString(pActCtx->lpApplicationName)))
	    goto error;
    } else {
	UNICODE_STRING Dir;
	PWSTR p;
	HMODULE Module;

	if (pActCtx->dwFlags & ACTCTX_FLAG_HMODULE_VALID)
	    Module = pActCtx->hModule;
	else
	    Module = NtCurrentTeb()->ProcessEnvironmentBlock->ImageBaseAddress;

	Status = GetModuleFilename(Module, &Dir, 0);
	if (!NT_SUCCESS(Status))
	    goto error;
	if ((p = wcsrchr(Dir.Buffer, '\\')))
	    p[1] = 0;
	Actctx->AppDir.Info = Dir.Buffer;
    }

    NameW.Buffer = NULL;

    /* open file only if it's going to be used */
    if (pActCtx->lpSource && !((pActCtx->dwFlags & ACTCTX_FLAG_RESOURCE_NAME_VALID) &&
			       (pActCtx->dwFlags & ACTCTX_FLAG_HMODULE_VALID))) {
	PWSTR Source = NULL;
	BOOLEAN Ret;

	if (pActCtx->dwFlags & ACTCTX_FLAG_ASSEMBLY_DIRECTORY_VALID &&
	    RtlDetermineDosPathNameType_U(pActCtx->lpSource) == RtlPathTypeRelative) {
	    DWORD DirLen, SourceLen;

	    DirLen = wcslen(pActCtx->lpAssemblyDirectory);
	    SourceLen = wcslen(pActCtx->lpSource);
	    if (!(Source = RtlAllocateHeap(RtlGetProcessHeap(), 0,
					   (DirLen + SourceLen + 2) * sizeof(WCHAR)))) {
		Status = STATUS_NO_MEMORY;
		goto error;
	    }

	    memcpy(Source, pActCtx->lpAssemblyDirectory, DirLen * sizeof(WCHAR));
	    Source[DirLen] = '\\';
	    memcpy(Source + DirLen + 1, pActCtx->lpSource,
		   (SourceLen + 1) * sizeof(WCHAR));
	}

	Ret = RtlDosPathNameToNtPathName_U(Source ? Source : pActCtx->lpSource, &NameW,
					   NULL, NULL);
	RtlFreeHeap(RtlGetProcessHeap(), 0, Source);
	if (!Ret) {
	    Status = STATUS_NO_SUCH_FILE;
	    goto error;
	}
	Status = OpenNtFile(&File, &NameW);
	if (!NT_SUCCESS(Status)) {
	    RtlFreeUnicodeString(&NameW);
	    goto error;
	}
    }

    Acl.ActCtx = Actctx;
    Acl.Dependencies = NULL;
    Acl.NumDependencies = 0;
    Acl.AllocatedDependencies = 0;

    if (pActCtx->dwFlags & ACTCTX_FLAG_LANGID_VALID)
	Lang = pActCtx->wLangId;
    if (pActCtx->dwFlags & ACTCTX_FLAG_ASSEMBLY_DIRECTORY_VALID)
	Directory = pActCtx->lpAssemblyDirectory;

    if (pActCtx->dwFlags & ACTCTX_FLAG_RESOURCE_NAME_VALID) {
	/* if we have a resource it's a PE file */
	if (pActCtx->dwFlags & ACTCTX_FLAG_HMODULE_VALID) {
	    Status = GetManifestInModule(&Acl, NULL, NULL, Directory, FALSE,
					    pActCtx->hModule, pActCtx->lpResourceName,
					    Lang);
	    if (Status && Status != STATUS_SXS_CANT_GEN_ACTCTX)
		/* FIXME: what to do if pActCtx->lpSource is set */
		Status = GetManifestInAssociatedManifest(&Acl, NULL, NULL, Directory,
							     pActCtx->hModule,
							     pActCtx->lpResourceName);
	} else if (pActCtx->lpSource && pActCtx->lpResourceName) {
	    Status = GetManifestInPeFile(&Acl, NULL, NameW.Buffer, Directory, FALSE,
					     File, pActCtx->lpResourceName, Lang);
	    if (Status && Status != STATUS_SXS_CANT_GEN_ACTCTX)
		Status = GetManifestInAssociatedManifest(&Acl, NULL, NameW.Buffer,
							     Directory, NULL,
							     pActCtx->lpResourceName);
	} else
	    Status = STATUS_INVALID_PARAMETER;
    } else {
	Status = GetManifestInManifestFile(&Acl, NULL, NameW.Buffer, Directory, FALSE,
					       File);
    }

    if (File)
	NtClose(File);
    RtlFreeUnicodeString(&NameW);

    if (NT_SUCCESS(Status))
	Status = ParseDependManifests(&Acl);
    FreeDependManifests(&Acl);

    if (NT_SUCCESS(Status))
	*ActCtx = Actctx;
    else
	ActCtxRelease(Actctx);
    return Status;

error:
    if (File)
	NtClose(File);
    ActCtxRelease(Actctx);
    return Status;
}

/***********************************************************************
 *		RtlAddRefActivationContext (NTDLL.@)
 */
NTAPI VOID RtlAddRefActivationContext(HANDLE Handle)
{
    ACTIVATION_CONTEXT *Actctx;

    if ((Actctx = CheckActCtx(Handle)))
	ActCtxAddRef(Actctx);
}

/******************************************************************
 *		RtlReleaseActivationContext (NTDLL.@)
 */
NTAPI VOID RtlReleaseActivationContext(HANDLE Handle)
{
    ACTIVATION_CONTEXT *Actctx;

    if ((Actctx = CheckActCtx(Handle)))
	ActCtxRelease(Actctx);
}

/******************************************************************
 *              RtlZombifyActivationContext (NTDLL.@)
 *
 * FIXME: function prototype might be wrong
 */
NTAPI NTSTATUS RtlZombifyActivationContext(HANDLE Handle)
{
    INFO_(LDR, "%p: stub\n", Handle);

    if (Handle == ACTCTX_FAKE_HANDLE)
	return STATUS_SUCCESS;

    return STATUS_NOT_IMPLEMENTED;
}

/******************************************************************
 *		RtlActivateActivationContext (NTDLL.@)
 */
NTAPI NTSTATUS RtlActivateActivationContext(ULONG Unknown, HANDLE Handle,
					    PULONG_PTR Cookie)
{
    return RtlActivateActivationContextEx(0, NtCurrentTeb(), Handle, Cookie);
}

/******************************************************************
 *		RtlActivateActivationContextEx (NTDLL.@)
 */
NTAPI NTSTATUS RtlActivateActivationContextEx(ULONG Flags, TEB *Teb, HANDLE Handle,
					      ULONG_PTR *Cookie)
{
    ACTIVATION_CONTEXT_STACK *ActctxStack = Teb->ActivationContextStackPointer;
    RTL_ACTIVATION_CONTEXT_STACK_FRAME *Frame;

    Frame = RtlAllocateHeap(RtlGetProcessHeap(), HEAP_GENERATE_EXCEPTIONS, sizeof(*Frame));
    Frame->Previous = ActctxStack->ActiveFrame;
    Frame->ActivationContext = Handle;
    Frame->Flags = 0;

    DPRINT("ActiveSP %p: ACTIVATE (ActiveFrame %p -> NewFrame %p, Context %p)\n",
	   Teb->ActivationContextStackPointer,
	   ((PACTIVATION_CONTEXT_STACK)Teb->ActivationContextStackPointer)->ActiveFrame,
	   Frame, Handle);

    ActctxStack->ActiveFrame = Frame;
    RtlAddRefActivationContext(Handle);

    *Cookie = (ULONG_PTR)Frame;
    TRACE_(LDR, "%p cookie=%Ix\n", Handle, *Cookie);
    return STATUS_SUCCESS;
}

/***********************************************************************
 *		RtlDeactivateActivationContext (NTDLL.@)
 */
NTAPI NTSTATUS RtlDeactivateActivationContext(ULONG Flags, ULONG_PTR Cookie)
{
    ACTIVATION_CONTEXT_STACK *ActctxStack = NtCurrentTeb()->ActivationContextStackPointer;
    RTL_ACTIVATION_CONTEXT_STACK_FRAME *Frame, *Top;

    TRACE_(LDR, "%x cookie=%Ix\n", Flags, Cookie);

    /* find the right frame */
    Top = ActctxStack->ActiveFrame;
    for (Frame = Top; Frame; Frame = Frame->Previous)
	if ((ULONG_PTR)Frame == Cookie)
	    break;

    if (!Frame)
	RtlRaiseStatus(STATUS_SXS_INVALID_DEACTIVATION);

    if (Frame != Top &&
	!(Flags & RTL_DEACTIVATE_ACTIVATION_CONTEXT_FLAG_FORCE_EARLY_DEACTIVATION))
	RtlRaiseStatus(STATUS_SXS_EARLY_DEACTIVATION);

    DPRINT("ActiveSP %p: DEACTIVATE (ActiveFrame %p -> PreviousFrame %p)\n",
	   NtCurrentTeb()->ActivationContextStackPointer,
	   CURRENT_ACTIVE_FRAME, Frame->Previous);

    /* pop everything up to and including frame */
    ActctxStack->ActiveFrame = Frame->Previous;

    while (Top != ActctxStack->ActiveFrame) {
	Frame = Top->Previous;
	RtlReleaseActivationContext(Top->ActivationContext);
	RtlFreeHeap(RtlGetProcessHeap(), 0, Top);
	Top = Frame;
    }

    return STATUS_SUCCESS;
}

/******************************************************************
 *		RtlFreeThreadActivationContextStack (NTDLL.@)
 */
NTAPI VOID RtlFreeThreadActivationContextStack(void)
{
    RtlFreeActivationContextStack(NtCurrentTeb()->ActivationContextStackPointer);
    NtCurrentTeb()->ActivationContextStackPointer = NULL;
}

/******************************************************************
 *		RtlFreeActivationContextStack (NTDLL.@)
 */
NTAPI VOID RtlFreeActivationContextStack(ACTIVATION_CONTEXT_STACK *ActctxStack)
{
    RTL_ACTIVATION_CONTEXT_STACK_FRAME *Frame;

    /* Nothing to do if there is no stack */
    if (!ActctxStack)
	return;

    Frame = ActctxStack->ActiveFrame;
    while (Frame) {
	RTL_ACTIVATION_CONTEXT_STACK_FRAME *Prev = Frame->Previous;
	RtlReleaseActivationContext(Frame->ActivationContext);
	RtlFreeHeap(RtlGetProcessHeap(), 0, Frame);
	Frame = Prev;
    }
    ActctxStack->ActiveFrame = NULL;

    /* TODO: Empty the Frame List Cache */
    ASSERT(IsListEmpty(&ActctxStack->FrameListCache));

    /* Free activation stack memory */
    RtlFreeHeap(RtlGetProcessHeap(), 0, ActctxStack);
}

/******************************************************************
 *		RtlGetActiveActivationContext (NTDLL.@)
 */
NTAPI NTSTATUS RtlGetActiveActivationContext(HANDLE *Handle)
{
    RtlAddRefActivationContext(*Handle = GetCurrentActCtxNoAddRef());
    return STATUS_SUCCESS;
}

/******************************************************************
 *		RtlIsActivationContextActive (NTDLL.@)
 */
NTAPI BOOLEAN RtlIsActivationContextActive(HANDLE Handle)
{
    ACTIVATION_CONTEXT_STACK *ActctxStack = NtCurrentTeb()->ActivationContextStackPointer;
    RTL_ACTIVATION_CONTEXT_STACK_FRAME *Frame;

    for (Frame = ActctxStack->ActiveFrame; Frame; Frame = Frame->Previous)
	if (Frame->ActivationContext == Handle)
	    return TRUE;
    return FALSE;
}

/***********************************************************************
 *		RtlQueryInformationActivationContext (NTDLL.@)
 *
 * Get information about an activation context.
 * FIXME: function signature/prototype may be wrong
 */
NTAPI NTSTATUS RtlQueryInformationActivationContext(ULONG Flags, HANDLE Handle,
						    PVOID Subinst, ULONG Class,
						    PVOID Buffer, SIZE_T Bufsize,
						    SIZE_T *Retlen)
{
    ACTIVATION_CONTEXT *Actctx;
    NTSTATUS Status;

    TRACE_(LDR, "%08x %p %p %u %p %Id %p\n", Flags, Handle, Subinst, Class, Buffer,
	   Bufsize, Retlen);

    if (Retlen)
	*Retlen = 0;
    if ((Status = FindQueryActCtx(&Handle, Flags, Class)))
	return Status;

    switch (Class) {
    case ActivationContextBasicInformation: {
	ACTIVATION_CONTEXT_BASIC_INFORMATION *Info = Buffer;

	if (Retlen)
	    *Retlen = sizeof(*Info);
	if (!Info || Bufsize < sizeof(*Info))
	    return STATUS_BUFFER_TOO_SMALL;

	Info->hActCtx = Handle;
	Info->dwFlags = 0; /* FIXME */
	if (!(Flags & RTL_QUERY_ACTIVATION_CONTEXT_FLAG_NO_ADDREF))
	    RtlAddRefActivationContext(Handle);
    } break;

    case ActivationContextDetailedInformation: {
	ACTIVATION_CONTEXT_DETAILED_INFORMATION *Acdi = Buffer;
	PASSEMBLY Assembly = NULL;
	SIZE_T Len, ManifestLen = 0, ConfigLen = 0, AppdirLen = 0;
	LPWSTR Ptr;

	if (!(Actctx = CheckActCtx(Handle)))
	    return STATUS_INVALID_PARAMETER;

	if (Actctx->NumAssemblies)
	    Assembly = Actctx->Assemblies;

	if (Assembly && Assembly->Manifest.Info)
	    ManifestLen = wcslen(Assembly->Manifest.Info) + 1;
	if (Actctx->Config.Info)
	    ConfigLen = wcslen(Actctx->Config.Info) + 1;
	if (Actctx->AppDir.Info)
	    AppdirLen = wcslen(Actctx->AppDir.Info) + 1;
	Len = sizeof(*Acdi) + (ManifestLen + ConfigLen + AppdirLen) * sizeof(WCHAR);

	if (Retlen)
	    *Retlen = Len;
	if (!Buffer || Bufsize < Len)
	    return STATUS_BUFFER_TOO_SMALL;

	Acdi->dwFlags = 0;
	Acdi->ulFormatVersion = Assembly ? 1 : 0; /* FIXME */
	Acdi->ulAssemblyCount = Actctx->NumAssemblies;
	Acdi->ulRootManifestPathType = Assembly ? Assembly->Manifest.Type : 0 /* FIXME */;
	Acdi->ulRootManifestPathChars = Assembly && Assembly->Manifest.Info ?
					    ManifestLen - 1 :
					    0;
	Acdi->ulRootConfigurationPathType = Actctx->Config.Type;
	Acdi->ulRootConfigurationPathChars = Actctx->Config.Info ? ConfigLen - 1 : 0;
	Acdi->ulAppDirPathType = Actctx->AppDir.Type;
	Acdi->ulAppDirPathChars = Actctx->AppDir.Info ? AppdirLen - 1 : 0;
	Ptr = (LPWSTR)(Acdi + 1);
	if (ManifestLen) {
	    Acdi->lpRootManifestPath = Ptr;
	    memcpy(Ptr, Assembly->Manifest.Info, ManifestLen * sizeof(WCHAR));
	    Ptr += ManifestLen;
	} else
	    Acdi->lpRootManifestPath = NULL;
	if (ConfigLen) {
	    Acdi->lpRootConfigurationPath = Ptr;
	    memcpy(Ptr, Actctx->Config.Info, ConfigLen * sizeof(WCHAR));
	    Ptr += ConfigLen;
	} else
	    Acdi->lpRootConfigurationPath = NULL;
	if (AppdirLen) {
	    Acdi->lpAppDirPath = Ptr;
	    memcpy(Ptr, Actctx->AppDir.Info, AppdirLen * sizeof(WCHAR));
	} else
	    Acdi->lpAppDirPath = NULL;
    } break;

    case AssemblyDetailedInformationInActivationContext: {
	ACTIVATION_CONTEXT_ASSEMBLY_DETAILED_INFORMATION *Afdi = Buffer;
	PASSEMBLY Assembly;
	PWSTR AssemblyId;
	DWORD Index;
	SIZE_T Len, IdLen = 0, AdLen = 0, PathLen = 0;
	LPWSTR Ptr;

	if (!(Actctx = CheckActCtx(Handle)))
	    return STATUS_INVALID_PARAMETER;
	if (!Subinst)
	    return STATUS_INVALID_PARAMETER;

	Index = *(DWORD *)Subinst;
	if (!Index || Index > Actctx->NumAssemblies)
	    return STATUS_INVALID_PARAMETER;

	Assembly = &Actctx->Assemblies[Index - 1];

	if (!(AssemblyId = BuildAssemblyId(&Assembly->Id)))
	    return STATUS_NO_MEMORY;
	IdLen = wcslen(AssemblyId) + 1;
	if (Assembly->Directory)
	    AdLen = wcslen(Assembly->Directory) + 1;

	if (Assembly->Manifest.Info && (Assembly->Type == ASSEMBLY_MANIFEST ||
					Assembly->Type == ASSEMBLY_SHARED_MANIFEST))
	    PathLen = wcslen(Assembly->Manifest.Info) + 1;

	Len = sizeof(*Afdi) + (IdLen + AdLen + PathLen) * sizeof(WCHAR);

	if (Retlen)
	    *Retlen = Len;
	if (!Buffer || Bufsize < Len) {
	    RtlFreeHeap(RtlGetProcessHeap(), 0, AssemblyId);
	    return STATUS_BUFFER_TOO_SMALL;
	}

	Afdi->ulFlags = 0; /* FIXME */
	Afdi->ulEncodedAssemblyIdentityLength = (IdLen - 1) * sizeof(WCHAR);
	Afdi->ulManifestPathType = Assembly->Manifest.Type;
	Afdi->ulManifestPathLength = Assembly->Manifest.Info ?
					 (PathLen - 1) * sizeof(WCHAR) :
					 0;
	/* FIXME afdi->liManifestLastWriteTime = 0; */
	Afdi->ulPolicyPathType = ACTIVATION_CONTEXT_PATH_TYPE_NONE; /* FIXME */
	Afdi->ulPolicyPathLength = 0;
	/* FIXME afdi->liPolicyLastWriteTime = 0; */
	Afdi->ulMetadataSatelliteRosterIndex = 0; /* FIXME */
	Afdi->ulManifestVersionMajor = 1;
	Afdi->ulManifestVersionMinor = 0;
	Afdi->ulPolicyVersionMajor = 0; /* FIXME */
	Afdi->ulPolicyVersionMinor = 0; /* FIXME */
	Afdi->ulAssemblyDirectoryNameLength = AdLen ? (AdLen - 1) * sizeof(WCHAR) : 0;
	Ptr = (LPWSTR)(Afdi + 1);
	Afdi->lpAssemblyEncodedAssemblyIdentity = Ptr;
	memcpy(Ptr, AssemblyId, IdLen * sizeof(WCHAR));
	Ptr += IdLen;
	if (PathLen) {
	    Afdi->lpAssemblyManifestPath = Ptr;
	    memcpy(Ptr, Assembly->Manifest.Info, PathLen * sizeof(WCHAR));
	    Ptr += PathLen;
	} else
	    Afdi->lpAssemblyManifestPath = NULL;
	Afdi->lpAssemblyPolicyPath = NULL; /* FIXME */
	if (AdLen) {
	    Afdi->lpAssemblyDirectoryName = Ptr;
	    memcpy(Ptr, Assembly->Directory, AdLen * sizeof(WCHAR));
	} else
	    Afdi->lpAssemblyDirectoryName = NULL;
	RtlFreeHeap(RtlGetProcessHeap(), 0, AssemblyId);
    } break;

    case FileInformationInAssemblyOfAssemblyInActivationContext: {
	const ACTIVATION_CONTEXT_QUERY_INDEX *Acqi = Subinst;
	ASSEMBLY_FILE_DETAILED_INFORMATION *Afdi = Buffer;
	PASSEMBLY Assembly;
	PDLL_REDIRECT Dll;
	SIZE_T Len, DllLen = 0;
	LPWSTR Ptr;

	if (!(Actctx = CheckActCtx(Handle)))
	    return STATUS_INVALID_PARAMETER;
	if (!Acqi)
	    return STATUS_INVALID_PARAMETER;

	if (Acqi->ulAssemblyIndex >= Actctx->NumAssemblies)
	    return STATUS_INVALID_PARAMETER;
	Assembly = &Actctx->Assemblies[Acqi->ulAssemblyIndex];

	if (Acqi->ulFileIndexInAssembly >= Assembly->NumDlls)
	    return STATUS_INVALID_PARAMETER;
	Dll = &Assembly->Dlls[Acqi->ulFileIndexInAssembly];

	if (Dll->Name)
	    DllLen = wcslen(Dll->Name) + 1;
	Len = sizeof(*Afdi) + DllLen * sizeof(WCHAR);

	if (!Buffer || Bufsize < Len) {
	    if (Retlen)
		*Retlen = Len;
	    return STATUS_BUFFER_TOO_SMALL;
	}
	if (Retlen)
	    *Retlen = 0; /* yes that's what native does !! */
	Afdi->ulFlags = ACTIVATION_CONTEXT_SECTION_DLL_REDIRECTION;
	Afdi->ulFilenameLength = DllLen ? (DllLen - 1) * sizeof(WCHAR) : 0;
	Afdi->ulPathLength = 0; /* FIXME */
	Ptr = (LPWSTR)(Afdi + 1);
	if (DllLen) {
	    Afdi->lpFileName = Ptr;
	    memcpy(Ptr, Dll->Name, DllLen * sizeof(WCHAR));
	} else
	    Afdi->lpFileName = NULL;
	Afdi->lpFilePath = NULL; /* FIXME */
    } break;

    case CompatibilityInformationInActivationContext: {
	struct _ACCI {
	    DWORD ElementCount;
	    COMPATIBILITY_CONTEXT_ELEMENT Elements[1];
	} *Acci = Buffer;
	PASSEMBLY Assembly = NULL;
	ULONG NumCompatContexts = 0, n;
	SIZE_T Len;

	if (!(Actctx = CheckActCtx(Handle)))
	    return STATUS_INVALID_PARAMETER;

	if (Actctx->NumAssemblies)
	    Assembly = Actctx->Assemblies;

	if (Assembly)
	    NumCompatContexts = Assembly->NumCompatContexts;
	Len = offsetof(struct _ACCI, Elements[NumCompatContexts]);

	if (Retlen)
	    *Retlen = Len;
	if (!Buffer || Bufsize < Len)
	    return STATUS_BUFFER_TOO_SMALL;

	Acci->ElementCount = NumCompatContexts;
	for (n = 0; n < NumCompatContexts; ++n) {
	    Acci->Elements[n] = Assembly->CompatContexts[n];
	}
    } break;

    case RunlevelInformationInActivationContext: {
	ACTIVATION_CONTEXT_RUN_LEVEL_INFORMATION *Acrli = Buffer;
	PASSEMBLY Assembly;
	SIZE_T Len;

	if (!(Actctx = CheckActCtx(Handle)))
	    return STATUS_INVALID_PARAMETER;

	Len = sizeof(*Acrli);
	if (Retlen)
	    *Retlen = Len;
	if (!Buffer || Bufsize < Len)
	    return STATUS_BUFFER_TOO_SMALL;

	Assembly = Actctx->Assemblies;

	Acrli->ulFlags = 0;
	Acrli->RunLevel = Assembly ? Assembly->RunLevel : ACTCTX_RUN_LEVEL_UNSPECIFIED;
	Acrli->UiAccess = Assembly ? Assembly->UiAccess : 0;
    } break;

    default:
	INFO_(LDR, "class %u not implemented\n", Class);
	return STATUS_NOT_IMPLEMENTED;
    }
    return STATUS_SUCCESS;
}

NTAPI NTSTATUS RtlQueryInformationActiveActivationContext(ULONG UlInfoClass,
							  PVOID PvBuffer,
							  SIZE_T OPTIONAL CbBuffer,
							  SIZE_T OPTIONAL *PcbWrittenOrRequired)
{
    return RtlQueryInformationActivationContext(
	RTL_QUERY_ACTIVATION_CONTEXT_FLAG_USE_ACTIVE_ACTIVATION_CONTEXT, NULL, NULL,
	UlInfoClass, PvBuffer, CbBuffer, PcbWrittenOrRequired);
}

#define FIND_ACTCTX_RETURN_FLAGS 0x00000002
#define FIND_ACTCTX_RETURN_ASSEMBLY_METADATA 0x00000004
#define FIND_ACTCTX_VALID_MASK                                           \
    (FIND_ACTCTX_SECTION_KEY_RETURN_HACTCTX | FIND_ACTCTX_RETURN_FLAGS | \
     FIND_ACTCTX_RETURN_ASSEMBLY_METADATA)

static NTSTATUS RtlpFindActivationContextSection_CheckParameters(ULONG Flags,
								 const GUID *Guid,
								 ULONG SectionKind,
								 PCUNICODE_STRING SectionName,
								 PACTCTX_SECTION_KEYED_DATA Data)
{
    /* Check general parameter combinations */
    if (!SectionName || !SectionName->Buffer || (Flags & ~FIND_ACTCTX_VALID_MASK) ||
	((Flags & FIND_ACTCTX_VALID_MASK) && !Data) ||
	(Data &&
	 Data->cbSize < offsetof(ACTCTX_SECTION_KEYED_DATA, ulAssemblyRosterIndex))) {
	DPRINT1("invalid parameter\n");
	return STATUS_INVALID_PARAMETER;
    }

    /* TODO */
    if (Flags & FIND_ACTCTX_RETURN_FLAGS ||
	Flags & FIND_ACTCTX_RETURN_ASSEMBLY_METADATA) {
	DPRINT1("unknown flags %08x\n", Flags);
	return STATUS_INVALID_PARAMETER;
    }

    return STATUS_SUCCESS;
}

/***********************************************************************
 *		RtlFindActivationContextSectionString (NTDLL.@)
 *
 * Find information about a string in an activation context.
 * FIXME: function signature/prototype may be wrong
 */
NTAPI NTSTATUS RtlFindActivationContextSectionString(ULONG Flags,
						     const GUID *Guid,
						     ULONG SectionKind,
						     PCUNICODE_STRING SectionName,
						     PVOID Ptr)
{
    PACTCTX_SECTION_KEYED_DATA Data = Ptr;
    NTSTATUS Status = STATUS_SXS_KEY_NOT_FOUND;
    ACTIVATION_CONTEXT *Actctx;

    TRACE_(LDR, "%08x " DEBUGSTR_GUID_FMT " %u %wZ %p\n", Flags,
	   DEBUGSTR_GUID(Guid), SectionKind,
	   SectionName, Data);

    Status = RtlpFindActivationContextSection_CheckParameters(Flags, Guid, SectionKind,
							      SectionName, Data);
    if (!NT_SUCCESS(Status)) {
	DPRINT1("RtlFindActivationContextSectionString() failed with status %x\n",
		Status);
	return Status;
    }

    Status = STATUS_SXS_KEY_NOT_FOUND;

    /* if there is no data, but params are valid,
       we return that sxs key is not found to be at least somehow compatible */
    if (!Data) {
	DPRINT("RtlFindActivationContextSectionString() failed with status %x\n", Status);
	return Status;
    }

    Actctx = CheckActCtx(GetCurrentActCtxNoAddRef());
    if (Actctx)
	Status = FindString(Actctx, SectionKind, SectionName, Flags, Data);

    DPRINT("status %x\n", Status);
    if (Status != STATUS_SUCCESS)
	Status = FindString(ProcessActCtx, SectionKind, SectionName, Flags, Data);

    if (Status != STATUS_SUCCESS)
	Status = FindString(ImplicitActCtx, SectionKind, SectionName, Flags, Data);

    DPRINT("RtlFindActivationContextSectionString() returns status %x\n", Status);
    return Status;
}

/***********************************************************************
 *		RtlFindActivationContextSectionGuid (NTDLL.@)
 *
 * Find information about a GUID in an activation context.
 * FIXME: function signature/prototype may be wrong
 */
NTAPI NTSTATUS RtlFindActivationContextSectionGuid(ULONG Flags, const GUID *Extguid,
						   ULONG SectionKind, const GUID *Guid,
						   void *Ptr)
{
    ACTCTX_SECTION_KEYED_DATA *Data = Ptr;
    NTSTATUS Status = STATUS_SXS_KEY_NOT_FOUND;
    ACTIVATION_CONTEXT *Actctx;

    TRACE_(LDR, "%08x " DEBUGSTR_GUID_FMT " %u " DEBUGSTR_GUID_FMT " %p\n",
	   Flags, DEBUGSTR_GUID(Extguid), SectionKind,
	   DEBUGSTR_GUID(Guid), Data);

    if (Extguid) {
	INFO_(LDR, "expected extguid == NULL\n");
	return STATUS_INVALID_PARAMETER;
    }

    if (Flags & ~FIND_ACTCTX_SECTION_KEY_RETURN_HACTCTX) {
	INFO_(LDR, "unknown flags %08x\n", Flags);
	return STATUS_INVALID_PARAMETER;
    }

    if (!Data ||
	Data->cbSize < FIELD_OFFSET(ACTCTX_SECTION_KEYED_DATA, ulAssemblyRosterIndex) ||
	!Guid)
	return STATUS_INVALID_PARAMETER;

    Actctx = CheckActCtx(GetCurrentActCtxNoAddRef());
    if (Actctx)
	Status = FindGuid(Actctx, SectionKind, Guid, Flags, Data);

    if (Status != STATUS_SUCCESS)
	Status = FindGuid(ProcessActCtx, SectionKind, Guid, Flags, Data);

    if (Status != STATUS_SUCCESS)
	Status = FindGuid(ImplicitActCtx, SectionKind, Guid, Flags, Data);

    return Status;
}

/***********************************************************************
 *		RtlQueryActivationContextApplicationSettings (NTDLL.@)
 */
NTAPI NTSTATUS RtlQueryActivationContextApplicationSettings(DWORD Flags, HANDLE Handle,
							    PCWSTR Ns,
							    PCWSTR Settings,
							    PWSTR Buffer, SIZE_T Size,
							    SIZE_T *Written)
{
    ACTIVATION_CONTEXT *Actctx;
    PCWSTR Res;

    if (Flags) {
	WARN_(LDR, "unknown flags %08x\n", Flags);
	return STATUS_INVALID_PARAMETER;
    }

    if (Ns) {
	if (wcscmp(Ns, WindowsSettings2005NS) && wcscmp(Ns, WindowsSettings2011NS) &&
	    wcscmp(Ns, WindowsSettings2016NS) && wcscmp(Ns, WindowsSettings2017NS) &&
	    wcscmp(Ns, WindowsSettings2019NS) && wcscmp(Ns, WindowsSettings2020NS))
	    return STATUS_INVALID_PARAMETER;
    } else
	Ns = WindowsSettings2005NS;

    if (!Handle)
	Handle = ProcessActCtx;
    if (!(Actctx = CheckActCtx(Handle)))
	return STATUS_INVALID_PARAMETER;

    if (!(Res = FindAppSettings(Actctx, Settings, Ns)))
	return STATUS_SXS_KEY_NOT_FOUND;

    if (Written)
	*Written = wcslen(Res) + 1;
    if (Size < wcslen(Res))
	return STATUS_BUFFER_TOO_SMALL;
    wcscpy_s(Buffer, Size, Res);
    return STATUS_SUCCESS;
}

/* Stubs */
NTAPI NTSTATUS RtlAllocateActivationContextStack(IN PACTIVATION_CONTEXT_STACK *Stack)
{
    PACTIVATION_CONTEXT_STACK ContextStack;

    /* Check if it's already allocated */
    if (*Stack)
	return STATUS_SUCCESS;

    /* Allocate space for the context stack */
    ContextStack = RtlAllocateHeap(RtlGetProcessHeap(), HEAP_ZERO_MEMORY,
				   sizeof(ACTIVATION_CONTEXT_STACK));
    if (!ContextStack) {
	return STATUS_NO_MEMORY;
    }

    /* Initialize the context stack */
    ContextStack->Flags = 0;
    ContextStack->ActiveFrame = NULL;
    InitializeListHead(&ContextStack->FrameListCache);
    ContextStack->NextCookieSequenceNumber = 1;
    ContextStack->StackId = 1; // TODO: Timer-based

    *Stack = ContextStack;

    return STATUS_SUCCESS;
}

FASTCALL PRTL_ACTIVATION_CONTEXT_STACK_FRAME RtlActivateActivationContextUnsafeFast(
    IN PRTL_CALLER_ALLOCATED_ACTIVATION_CONTEXT_STACK_FRAME_EXTENDED Frame,
    IN PVOID Context)
{
    RTL_ACTIVATION_CONTEXT_STACK_FRAME *NewFrame;
    RTL_ACTIVATION_CONTEXT_STACK_FRAME *ActiveFrame;
    PACTIVATION_CONTEXT_STACK Stack = NtCurrentTeb()->ActivationContextStackPointer;

    /* Get the current active frame */
    ActiveFrame = Stack->ActiveFrame;

    DPRINT("ActiveSP %p: ACTIVATE (ActiveFrame %p -> NewFrame %p, Context %p)\n",
	   Stack, ActiveFrame, &Frame->Frame, Context);

    /* Ensure it's in the right format and at least fits basic info */
    ASSERT(Frame->Format ==
	   RTL_CALLER_ALLOCATED_ACTIVATION_CONTEXT_STACK_FRAME_FORMAT_WHISTLER);
    ASSERT(Frame->Size >=
	   sizeof(RTL_CALLER_ALLOCATED_ACTIVATION_CONTEXT_STACK_FRAME_BASIC));

    /* Set debug info if size allows*/
    if (Frame->Size >=
	sizeof(RTL_CALLER_ALLOCATED_ACTIVATION_CONTEXT_STACK_FRAME_EXTENDED)) {
	Frame->Extra1 = (PVOID)(~(ULONG_PTR)ActiveFrame);
	Frame->Extra2 = (PVOID)(~(ULONG_PTR)Context);
	// Frame->Extra3 = ...;
    }

    if (ActiveFrame) {
	/*ASSERT((ActiveFrame->Flags &
	    (RTL_ACTIVATION_CONTEXT_STACK_FRAME_FLAG_ACTIVATED |
	     RTL_ACTIVATION_CONTEXT_STACK_FRAME_FLAG_DEACTIVATED |
	     RTL_ACTIVATION_CONTEXT_STACK_FRAME_FLAG_NOT_REALLY_ACTIVATED)) ==
	   RTL_ACTIVATION_CONTEXT_STACK_FRAME_FLAG_ACTIVATED);*/

	if (!(ActiveFrame->Flags &
	      RTL_ACTIVATION_CONTEXT_STACK_FRAME_FLAG_HEAP_ALLOCATED)) {
	    // TODO: Perform some additional checks if it was not heap allocated
	}
    }

    /* Save pointer to the new activation frame */
    NewFrame = &Frame->Frame;

    /* Actually activate it */
    Frame->Frame.Previous = ActiveFrame;
    Frame->Frame.ActivationContext = Context;
    Frame->Frame.Flags = RTL_ACTIVATION_CONTEXT_STACK_FRAME_FLAG_ACTIVATED;

    /* Check if we can activate this context */
    if ((ActiveFrame && (ActiveFrame->ActivationContext != Context)) || Context) {
	/* Set new active frame */
	DPRINT("Setting new active frame %p instead of old %p\n", NewFrame, ActiveFrame);
	CURRENT_ACTIVE_FRAME = NewFrame;
	return NewFrame;
    }

    /* We can get here only one way: it was already activated */
    DPRINT("Trying to activate already activated activation context\n");

    /* Activate only if we are allowing multiple activation */
    // Activate it anyway
    CURRENT_ACTIVE_FRAME = NewFrame;

    /* Return pointer to the activation frame */
    return NewFrame;
}

FASTCALL PRTL_ACTIVATION_CONTEXT_STACK_FRAME RtlDeactivateActivationContextUnsafeFast(
    IN PRTL_CALLER_ALLOCATED_ACTIVATION_CONTEXT_STACK_FRAME_EXTENDED Frame)
{
    PRTL_ACTIVATION_CONTEXT_STACK_FRAME ActiveFrame, NewFrame;

    ActiveFrame = CURRENT_ACTIVE_FRAME;

    /* Ensure it's in the right format and at least fits basic info */
    ASSERT(Frame->Format ==
	   RTL_CALLER_ALLOCATED_ACTIVATION_CONTEXT_STACK_FRAME_FORMAT_WHISTLER);
    ASSERT(Frame->Size >=
	   sizeof(RTL_CALLER_ALLOCATED_ACTIVATION_CONTEXT_STACK_FRAME_BASIC));

    /* Make sure it is not deactivated and it is activated */
    ASSERT((Frame->Frame.Flags & RTL_ACTIVATION_CONTEXT_STACK_FRAME_FLAG_DEACTIVATED) == 0);
    ASSERT(Frame->Frame.Flags & RTL_ACTIVATION_CONTEXT_STACK_FRAME_FLAG_ACTIVATED);
    ASSERT((Frame->Frame.Flags & (RTL_ACTIVATION_CONTEXT_STACK_FRAME_FLAG_ACTIVATED |
				  RTL_ACTIVATION_CONTEXT_STACK_FRAME_FLAG_DEACTIVATED)) ==
	   RTL_ACTIVATION_CONTEXT_STACK_FRAME_FLAG_ACTIVATED);

    /* Check debug info if it is present */
    if (Frame->Size >=
	sizeof(RTL_CALLER_ALLOCATED_ACTIVATION_CONTEXT_STACK_FRAME_EXTENDED)) {
	ASSERT(Frame->Extra1 == (PVOID)(~(ULONG_PTR)Frame->Frame.Previous));
	ASSERT(Frame->Extra2 == (PVOID)(~(ULONG_PTR)Frame->Frame.ActivationContext));
	// Frame->Extra3 = ...;
    }

    if (ActiveFrame) {
	// TODO: Perform some additional checks here
    }

    /* Special handling for not-really-activated */
    if (Frame->Frame.Flags &
	RTL_ACTIVATION_CONTEXT_STACK_FRAME_FLAG_NOT_REALLY_ACTIVATED) {
	DPRINT1("Deactivating not really activated activation context\n");
	Frame->Frame.Flags |= RTL_ACTIVATION_CONTEXT_STACK_FRAME_FLAG_DEACTIVATED;
	return &Frame->Frame;
    }

    /* find the right frame */
    NewFrame = &Frame->Frame;
    if (ActiveFrame != NewFrame) {
	DPRINT1("Deactivating wrong active frame: %p != %p\n", ActiveFrame, NewFrame);
    }

    DPRINT("ActiveSP %p: DEACTIVATE (ActiveFrame %p -> PreviousFrame %p)\n",
	   NtCurrentTeb()->ActivationContextStackPointer, NewFrame, NewFrame->Previous);

    /* Pop everything up to and including frame */
    CURRENT_ACTIVE_FRAME = NewFrame->Previous;

    Frame->Frame.Flags |= RTL_ACTIVATION_CONTEXT_STACK_FRAME_FLAG_DEACTIVATED;
    return NewFrame->Previous;
}

NTSTATUS RtlpInitializeActCtx(VOID)
{
    ACTCTXW Ctx = {};
    HANDLE Handle;
    WCHAR Buffer[1024];
    NTSTATUS Status;

    InitActCtx();

    Ctx.cbSize = sizeof(Ctx);
    Ctx.dwFlags = 0;
    Ctx.hModule = NULL;
    Ctx.lpResourceName = NULL;
    Ctx.lpSource = Buffer;
    RtlStringCchCopyW(Buffer, RTL_NUMBER_OF(Buffer), SharedUserData->NtSystemRoot);
    RtlStringCchCatW(Buffer, RTL_NUMBER_OF(Buffer),
		     L"\\winsxs\\manifests\\systemcompatible.manifest");

    Status = RtlCreateActivationContext(0, (PVOID)&Ctx, 0, NULL, NULL, &Handle);
    if (NT_SUCCESS(Status)) {
	ImplicitActCtx = CheckActCtx(Handle);
    } else {
	DPRINT1("Failed to create the implicit act ctx. Status: 0x%x!!!\n", Status);
    }

    return Status;
}
