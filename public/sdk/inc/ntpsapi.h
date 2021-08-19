/* This file is stolen shamelessly from reactos/sdk/lib/crt/wine/winternl.h */

#pragma once

typedef struct _PEB_LDR_DATA {
    ULONG               Length;
    BOOLEAN             Initialized;
    PVOID               SsHandle;
    LIST_ENTRY          InLoadOrderModuleList;
    LIST_ENTRY          InMemoryOrderModuleList;
    LIST_ENTRY          InInitializationOrderModuleList;
    PVOID               EntryInProgress;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _GDI_TEB_BATCH {
    ULONG  Offset;
    HANDLE HDC;
    ULONG  Buffer[0x136];
} GDI_TEB_BATCH;

typedef struct _ACTIVATION_CONTEXT_STACK {
    ULONG                               Flags;
    ULONG                               NextCookieSequenceNumber;
    RTL_ACTIVATION_CONTEXT_STACK_FRAME* ActiveFrame;
    LIST_ENTRY                          FrameListCache;
} ACTIVATION_CONTEXT_STACK, * PACTIVATION_CONTEXT_STACK;

typedef struct _TEB_ACTIVE_FRAME_CONTEXT {
    ULONG       Flags;
    const char* FrameName;
} TEB_ACTIVE_FRAME_CONTEXT, * PTEB_ACTIVE_FRAME_CONTEXT;

typedef struct _TEB_ACTIVE_FRAME {
    ULONG                     Flags;
    struct _TEB_ACTIVE_FRAME* Previous;
    TEB_ACTIVE_FRAME_CONTEXT* Context;
} TEB_ACTIVE_FRAME, * PTEB_ACTIVE_FRAME;

typedef struct _PEB {                                             /* win32/win64 */
    BOOLEAN                      InheritedAddressSpace;             /* 000/000 */
    BOOLEAN                      ReadImageFileExecOptions;          /* 001/001 */
    BOOLEAN                      BeingDebugged;                     /* 002/002 */
    BOOLEAN                      SpareBool;                         /* 003/003 */
    HANDLE                       Mutant;                            /* 004/008 */
    HMODULE                      ImageBaseAddress;                  /* 008/010 */
    PPEB_LDR_DATA                LdrData;                           /* 00c/018 */
    RTL_USER_PROCESS_PARAMETERS *ProcessParameters;                 /* 010/020 */
    PVOID                        SubSystemData;                     /* 014/028 */
    HANDLE                       ProcessHeap;                       /* 018/030 */
    PRTL_CRITICAL_SECTION        FastPebLock;                       /* 01c/038 */
    PVOID /*PPEBLOCKROUTINE*/    FastPebLockRoutine;                /* 020/040 */
    PVOID /*PPEBLOCKROUTINE*/    FastPebUnlockRoutine;              /* 024/048 */
    ULONG                        EnvironmentUpdateCount;            /* 028/050 */
    PVOID                        KernelCallbackTable;               /* 02c/058 */
    ULONG                        Reserved[2];                       /* 030/060 */
    PVOID /*PPEB_FREE_BLOCK*/    FreeList;                          /* 038/068 */
    ULONG                        TlsExpansionCounter;               /* 03c/070 */
    PRTL_BITMAP                  TlsBitmap;                         /* 040/078 */
    ULONG                        TlsBitmapBits[2];                  /* 044/080 */
    PVOID                        ReadOnlySharedMemoryBase;          /* 04c/088 */
    PVOID                        ReadOnlySharedMemoryHeap;          /* 050/090 */
    PVOID                       *ReadOnlyStaticServerData;          /* 054/098 */
    PVOID                        AnsiCodePageData;                  /* 058/0a0 */
    PVOID                        OemCodePageData;                   /* 05c/0a8 */
    PVOID                        UnicodeCaseTableData;              /* 060/0b0 */
    ULONG                        NumberOfProcessors;                /* 064/0b8 */
    ULONG                        NtGlobalFlag;                      /* 068/0bc */
    LARGE_INTEGER                CriticalSectionTimeout;            /* 070/0c0 */
    SIZE_T                       HeapSegmentReserve;                /* 078/0c8 */
    SIZE_T                       HeapSegmentCommit;                 /* 07c/0d0 */
    SIZE_T                       HeapDeCommitTotalFreeThreshold;    /* 080/0d8 */
    SIZE_T                       HeapDeCommitFreeBlockThreshold;    /* 084/0e0 */
    ULONG                        NumberOfHeaps;                     /* 088/0e8 */
    ULONG                        MaximumNumberOfHeaps;              /* 08c/0ec */
    PVOID                       *ProcessHeaps;                      /* 090/0f0 */
    PVOID                        GdiSharedHandleTable;              /* 094/0f8 */
    PVOID                        ProcessStarterHelper;              /* 098/100 */
    PVOID                        GdiDCAttributeList;                /* 09c/108 */
    PVOID                        LoaderLock;                        /* 0a0/110 */
    ULONG                        OSMajorVersion;                    /* 0a4/118 */
    ULONG                        OSMinorVersion;                    /* 0a8/11c */
    ULONG                        OSBuildNumber;                     /* 0ac/120 */
    ULONG                        OSPlatformId;                      /* 0b0/124 */
    ULONG                        ImageSubSystem;                    /* 0b4/128 */
    ULONG                        ImageSubSystemMajorVersion;        /* 0b8/12c */
    ULONG                        ImageSubSystemMinorVersion;        /* 0bc/130 */
    ULONG                        ImageProcessAffinityMask;          /* 0c0/134 */
    HANDLE                       GdiHandleBuffer[28];               /* 0c4/138 */
    ULONG                        unknown[6];                        /* 134/218 */
    PVOID                        PostProcessInitRoutine;            /* 14c/230 */
    PRTL_BITMAP                  TlsExpansionBitmap;                /* 150/238 */
    ULONG                        TlsExpansionBitmapBits[32];        /* 154/240 */
    ULONG                        SessionId;                         /* 1d4/2c0 */
    ULARGE_INTEGER               AppCompatFlags;                    /* 1d8/2c8 */
    ULARGE_INTEGER               AppCompatFlagsUser;                /* 1e0/2d0 */
    PVOID                        ShimData;                          /* 1e8/2d8 */
    PVOID                        AppCompatInfo;                     /* 1ec/2e0 */
    UNICODE_STRING               CSDVersion;                        /* 1f0/2e8 */
    PVOID                        ActivationContextData;             /* 1f8/2f8 */
    PVOID                        ProcessAssemblyStorageMap;         /* 1fc/300 */
    PVOID                        SystemDefaultActivationData;       /* 200/308 */
    PVOID                        SystemAssemblyStorageMap;          /* 204/310 */
    SIZE_T                       MinimumStackCommit;                /* 208/318 */
    PVOID                       *FlsCallback;                       /* 20c/320 */
    LIST_ENTRY                   FlsListHead;                       /* 210/328 */
    PRTL_BITMAP                  FlsBitmap;                         /* 218/338 */
    ULONG                        FlsBitmapBits[4];                  /* 21c/340 */
} PEB, *PPEB;

typedef struct _EXCEPTION_REGISTRATION_RECORD {
    struct _EXCEPTION_REGISTRATION_RECORD *Next;
    PEXCEPTION_ROUTINE Handler;
} EXCEPTION_REGISTRATION_RECORD, *PEXCEPTION_REGISTRATION_RECORD;

typedef struct _NT_TIB {
    struct _EXCEPTION_REGISTRATION_RECORD *ExceptionList;
    PVOID StackBase;
    PVOID StackLimit;
    union {
	PVOID SubSystemTib;
	PPVOID PtrSystemDllTlsRegion;
    };
    union {
	PVOID FiberData;
	ULONG Version;
    };
    PVOID ArbitraryUserPointer;
    struct _NT_TIB *Self;
} NT_TIB, *PNT_TIB;

typedef struct _TEB {                                             /* win32/win64 */
    NT_TIB                       Tib;                               /* 000/0000 */
    PVOID                        EnvironmentPointer;                /* 01c/0038 */
    CLIENT_ID                    ClientId;                          /* 020/0040 */
    PVOID                        ActiveRpcHandle;                   /* 028/0050 */
    PVOID                        ThreadLocalStoragePointer;         /* 02c/0058 */
    PPEB                         Peb;                               /* 030/0060 */
    ULONG                        LastErrorValue;                    /* 034/0068 */
    ULONG                        CountOfOwnedCriticalSections;      /* 038/006c */
    PVOID                        CsrClientThread;                   /* 03c/0070 */
    PVOID                        Win32ThreadInfo;                   /* 040/0078 */
    ULONG                        Win32ClientInfo[31];               /* 044/0080 used for user32 private data in Wine */
    PVOID                        WOW32Reserved;                     /* 0c0/0100 */
    ULONG                        CurrentLocale;                     /* 0c4/0108 */
    ULONG                        FpSoftwareStatusRegister;          /* 0c8/010c */
    PVOID                        SystemReserved1[54];               /* 0cc/0110 used for kernel32 private data in Wine */
    LONG                         ExceptionCode;                     /* 1a4/02c0 */
    ACTIVATION_CONTEXT_STACK     ActivationContextStack;            /* 1a8/02c8 */
    BYTE                         SpareBytes1[24];                   /* 1bc/02e8 */
    PVOID                        SystemReserved2[10];               /* 1d4/0300 used for ntdll platform-specific private data in Wine */
    GDI_TEB_BATCH                GdiTebBatch;                       /* 1fc/0350 used for ntdll private data in Wine */
    HANDLE                       gdiRgn;                            /* 6dc/0838 */
    HANDLE                       gdiPen;                            /* 6e0/0840 */
    HANDLE                       gdiBrush;                          /* 6e4/0848 */
    CLIENT_ID                    RealClientId;                      /* 6e8/0850 */
    HANDLE                       GdiCachedProcessHandle;            /* 6f0/0860 */
    ULONG                        GdiClientPID;                      /* 6f4/0868 */
    ULONG                        GdiClientTID;                      /* 6f8/086c */
    PVOID                        GdiThreadLocaleInfo;               /* 6fc/0870 */
    ULONG                        UserReserved[5];                   /* 700/0878 */
    PVOID                        glDispatchTable[280];              /* 714/0890 */
    PVOID                        glReserved1[26];                   /* b74/1150 */
    PVOID                        glReserved2;                       /* bdc/1220 */
    PVOID                        glSectionInfo;                     /* be0/1228 */
    PVOID                        glSection;                         /* be4/1230 */
    PVOID                        glTable;                           /* be8/1238 */
    PVOID                        glCurrentRC;                       /* bec/1240 */
    PVOID                        glContext;                         /* bf0/1248 */
    ULONG                        LastStatusValue;                   /* bf4/1250 */
    UNICODE_STRING               StaticUnicodeString;               /* bf8/1258 used by advapi32 */
    WCHAR                        StaticUnicodeBuffer[261];          /* c00/1268 used by advapi32 */
    PVOID                        DeallocationStack;                 /* e0c/1478 */
    PVOID                        TlsSlots[64];                      /* e10/1480 */
    LIST_ENTRY                   TlsLinks;                          /* f10/1680 */
    PVOID                        Vdm;                               /* f18/1690 */
    PVOID                        ReservedForNtRpc;                  /* f1c/1698 */
    PVOID                        DbgSsReserved[2];                  /* f20/16a0 */
    ULONG                        HardErrorDisabled;                 /* f28/16b0 */
    PVOID                        Instrumentation[16];               /* f2c/16b8 */
    PVOID                        WinSockData;                       /* f6c/1738 */
    ULONG                        GdiBatchCount;                     /* f70/1740 */
    ULONG                        Spare2;                            /* f74/1744 */
    ULONG                        GuaranteedStackBytes;              /* f78/1748 */
    PVOID                        ReservedForPerf;                   /* f7c/1750 */
    PVOID                        ReservedForOle;                    /* f80/1758 */
    ULONG                        WaitingOnLoaderLock;               /* f84/1760 */
    PVOID                        Reserved5[3];                      /* f88/1768 */
    PVOID                       *TlsExpansionSlots;                 /* f94/1780 */
#ifdef _WIN64
    PVOID                        DeallocationBStore;                /*    /1788 */
    PVOID                        BStoreLimit;                       /*    /1790 */
#endif
    ULONG                        ImpersonationLocale;               /* f98/1798 */
    ULONG                        IsImpersonating;                   /* f9c/179c */
    PVOID                        NlsCache;                          /* fa0/17a0 */
    PVOID                        ShimData;                          /* fa4/17a8 */
    ULONG                        HeapVirtualAffinity;               /* fa8/17b0 */
    PVOID                        CurrentTransactionHandle;          /* fac/17b8 */
    TEB_ACTIVE_FRAME            *ActiveFrame;                       /* fb0/17c0 */
    PVOID                       *FlsSlots;                          /* fb4/17c8 */
    PVOID                        SystemDllTlsRegion;                /* fb8/17d0 */
} TEB, *PTEB;
