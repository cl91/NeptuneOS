#pragma once

#include <ntdef.h>

typedef struct _ELF_HEADER {
    UCHAR Magic[4];
    UCHAR Class;		/* ELF32 or ELF64 */
    UCHAR ByteOrder;
    UCHAR HeaderVersion;
    UCHAR OsAbi;
    UCHAR AbiVersion;
    UCHAR Padding[7];
    USHORT ImageType;
    USHORT Architecture;
    ULONG FileVersion;
    ULONG_PTR EntryPoint;
    ULONG_PTR OffsetToProgramHeaders;
    ULONG_PTR OffsetToSectionHeaders;
    ULONG Flags;
    USHORT ElfHeaderSize;
    USHORT ProgramHeaderEntrySize;
    USHORT NumberfOfProgramHeaderEntries;
    USHORT SectionHeaderEntrySize;
    USHORT NumberOfSectionHeaderEntries;
    USHORT IndexOfSectionNameStringTable;
} ELF_HEADER, *PELF_HEADER;

/* ELF_HEADER.Magic */
#define ELF_MAGIC0	0x7F
#define ELF_MAGIC1	'E'
#define ELF_MAGIC2	'L'
#define ELF_MAGIC3	'F'

/* ELF_HEADER.Class */
#define ELF_CLASS32	1
#define ELF_CLASS64	2

/* ELF_HEADER.ByteOrder */
#define ELF_LITTLE_ENDIAN	1
#define ELF_BIG_ENDIAN		2

/* ELF_HEADER.HeaderVersion, ELF_HEADER.FileVersion */
#define ELF_CURRENT_VERSION	1

/* ELF_HEADER.ImageType */
#define ELF_IMAGE_TYPE_EXE	2
#define ELF_IMAGE_TYPE_DLL	3

/* ELF_HEADER.Architecture */
#define ELF_ARCHITECTURE_I386	3
#define ELF_ARCHITECTURE_AMD64	62
#define ELF_ARCHITECTURE_ARM64	183
#define ELF_ARCHITECTURE_RISCV	243

typedef struct _ELF_PROGRAM_HEADER {
    ULONG Type;
#ifdef _WIN64
    ULONG Flags;
#endif
    ULONG_PTR FileOffset;
    ULONG_PTR VirtualAddress;
    ULONG_PTR PhysicalAddress;
    ULONG_PTR SizeOnDisk;
    ULONG_PTR SizeInMemory;
#ifndef _WIN64
    ULONG Flags;
#endif
    ULONG_PTR Alignment;    /* Alignment both on disk and in memory */
} ELF_PROGRAM_HEADER, *PELF_PROGRAM_HEADER;

/* ELF_PROGRAM_HEADER.Type */
#define ELF_PROGRAM_HEADER_TYPE_LOAD    1

/* ELF_PROGRAM_HEADER.Flags */
#define ELF_PROGRAM_HEADER_FLAG_READ	0x4
#define ELF_PROGRAM_HEADER_FLAG_WRITE	0x2
#define ELF_PROGRAM_HEADER_FLAG_EXECUTE	0x1
