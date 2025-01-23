/*
 * Copyright (c) 1999-2004 University of New South Wales
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/*
  Authors: Luke Deller, Ben Leslie
  Created: 24/Sep/1999
*/

/**
\file

\brief Generic ELF library

The ELF library is designed to make the task of parsing and getting information
out of an ELF file easier.

It provides function to obtain the various different fields in the ELF header, and
the program and segment information.

Also importantly, it provides a function elf_loadFile which will load a given
ELF file into memory.

*/

#pragma once

#include <types.h>
#include <printf.h>

#include "elf32.h"
#include "elf64.h"

#define ISELF32(elfFile) ( ((struct Elf32_Header*)elfFile)->e_ident[EI_CLASS] == ELFCLASS32 )
#define ISELF64(elfFile) ( ((struct Elf64_Header*)elfFile)->e_ident[EI_CLASS] == ELFCLASS64 )

/*
 * constants for Elf32_Phdr.p_flags
 */

#define PF_R        4   /* readable segment */
#define PF_W        2   /* writeable segment */
#define PF_X        1   /* executable segment */

/*
 * constants for indexing into Elf64_Header_t.e_ident
 */
#define EI_MAG0     0
#define EI_MAG1     1
#define EI_MAG2     2
#define EI_MAG3     3
#define EI_CLASS    4
#define EI_DATA     5
#define EI_VERSION  6

#define ELFMAG0         '\177'
#define ELFMAG1         'E'
#define ELFMAG2         'L'
#define ELFMAG3         'F'

#define ELFCLASS32      1
#define ELFCLASS64      2

#define PT_NULL 0
#define PT_LOAD 1
#define PT_DYNAMIC 2
#define PT_INTERP 3
#define PT_NOTE 4
#define PT_SHLIB 5
#define PT_PHDR 6
#define PT_TLS 7
#define PT_NUM 8

#define ELFDATA2LSB 1
#define ELFDATA2MSB 2

/* Section Header type bits */
#define SHT_PROGBITS 1
#define SHT_SYMTAB 2
#define SHT_NOBITS 8
#define SHT_REL 9

/* Section Header flag bits */
#define SHF_WRITE 1
#define SHF_ALLOC 2
#define SHF_EXECINSTR  4

/* Dynamic section entry types */
#define DT_NULL 0
#define DT_HASH 4
#define DT_STRTAB 5
#define DT_SYMTAB 6
#define DT_RELA 7
#define DT_RELASZ 8
#define DT_RELAENT 9
#define DT_STRSZ 10
#define DT_SYMENT 11
#define DT_REL 17
#define DT_RELSZ 18
#define DT_RELENT 19

/**/
#define ELF_PRINT_PROGRAM_HEADERS 1
#define ELF_PRINT_SECTIONS 2
#define ELF_PRINT_ALL (ELF_PRINT_PROGRAM_HEADERS | ELF_PRINT_SECTIONS)

/**
 * Checks that elfFile points to a valid elf file.
 *
 * @param elfFile Potential ELF file to check
 *
 * \return 0 on success. -1 if not and elf, -2 if not 32 bit.
 */
int elf_checkFile(
    void const *elfFile);

/**
 * Determine number of sections in an ELF file.
 *
 * @param elfFile Pointer to a valid ELF header.
 *
 * \return Number of sections in the ELF file.
 */
unsigned elf_getNumSections(
    void const *elfFile);

/**
 * Determine number of program headers in an ELF file.
 *
 * @param elfFile Pointer to a valid ELF header.
 *
 * \return Number of program headers in the ELF file.
 */
uint16_t elf_getNumProgramHeaders(
    void const *elfFile);

/**
 * Return the base physical address of given program header in an ELF file
 *
 * @param elfFile Pointer to a valid ELF header
 * @param ph Index of the program header
 *
 * \return The memory size of the specified program header
 */
uint64_t elf_getProgramHeaderPaddr(
    void const *elfFile,
    uint16_t ph);

/**
 * Return the base virtual address of given program header in an ELF file
 *
 * @param elfFile Pointer to a valid ELF header
 * @param ph Index of the program header
 *
 * \return The memory size of the specified program header
 */
uint64_t elf_getProgramHeaderVaddr(
    void const *elfFile,
    uint16_t ph);

/**
 * Return the memory size of a given program header in an ELF file
 *
 * @param elfFile Pointer to a valid ELF header
 * @param ph Index of the program header
 *
 * \return The memory size of the specified program header
 */
uint64_t elf_getProgramHeaderMemorySize(
    void const *elfFile,
    uint16_t ph);

/**
 * Return the file size of a given program header in an ELF file
 *
 * @param elfFile Pointer to a valid ELF header
 * @param ph Index of the program header
 *
 * \return The file size of the specified program header
 */
uint64_t elf_getProgramHeaderFileSize(
    void const *elfFile,
    uint16_t ph);

/**
 * Return the start offset of he file
 *
 * @param elfFile Pointer to a valid ELF header
 * @param ph Index of the program header
 *
 * \return The offset of this program header with relation to the start
 * of the elfFile.
 */
uint64_t elf_getProgramHeaderOffset(
    void const *elfFile,
    uint16_t ph);

/**
 * Return the flags for a given program header
 *
 * @param elfFile Pointer to a valid ELF header
 * @param ph Index of the program header
 *
 * \return The flags of a given program header
 */
uint32_t elf_getProgramHeaderFlags(
    void const *elfFile,
    uint16_t ph);

/**
 * Return the type for a given program header
 *
 * @param elfFile Pointer to a valid ELF header
 * @param ph Index of the program header
 *
 * \return The type of a given program header
 */
uint32_t elf_getProgramHeaderType(
    void const *elfFile,
    uint16_t ph);

/**
 * Return the physical translation of a physical address, with respect
 * to a given program header
 *
 */
uint64_t elf_vtopProgramHeader(
    void const *elfFile,
    uint16_t ph,
    uint64_t vaddr);

/**
 *
 * \return true if the address in in this program header
 */
int elf_vaddrInProgramHeader(
    void const *elfFile,
    uint16_t ph,
    uint64_t vaddr);

/**
 * Determine the memory bounds of an ELF file
 *
 * @param elfFile Pointer to a valid ELF header
 * @param phys If true return bounds of physical memory, otherwise return
 *   bounds of virtual memory
 * @param min Pointer to return value of the minimum
 * @param max Pointer to return value of the maximum
 *
 * \return true on success. false on failure, if for example, it is an invalid ELF file
 */
int elf_getMemoryBounds(
    void const *elfFile,
    int phys,
    uint64_t *min,
    uint64_t *max);

/**
 * Find the entry point of an ELF file.
 *
 * @param elfFile Pointer to a valid ELF header
 *
 * \return The entry point address as a 64-bit integer.
 */
uint64_t elf_getEntryPoint(
    void const *elfFile);

/**
 * Load an ELF file into memory
 *
 * @param elfFile Pointer to a valid ELF file
 * @param phys If true load using the physical address, otherwise using the virtual addresses
 *
 * \return true on success, false on failure.
 *
 * The function assumes that the ELF file is loaded in memory at some
 * address different to the target address at which it will be loaded.
 * It also assumes direct access to the source and destination address, i.e:
 * Memory must be able to be loaded with a simple memcpy.
 *
 * Obviously this also means that if we are loading a 64bit ELF on a 32bit
 * platform, we assume that any memory addresses are within the first 4GB.
 *
 */
int elf_loadFile(
    void const *elfFile,
    int phys);

char const *elf_getStringTable(
    void const *elfFile,
    int string_segment);

char const *elf_getSegmentStringTable(
    void const *elfFile);

void const *elf_getSectionNamed(
    void const *elfFile,
    char const *str);

char const *elf_getSectionName(
    void const *elfFile,
    int i);

uint64_t elf_getSectionSize(
    void const *elfFile,
    int i);

uint64_t elf_getSectionAddr(
    void const *elfFile,
    int i);

/**
 * Return the flags for a given sections
 *
 * @param elfFile Pointer to a valid ELF header
 * @param i Index of the sections
 *
 * \return The flags of a given section
 */
uint32_t elf_getSectionFlags(
    void const *elfFile,
    int i);

/**
 * Return the type for a given sections
 *
 * @param elfFile Pointer to a valid ELF header
 * @param i Index of the sections
 *
 * \return The type of a given section
 */
uint32_t elf_getSectionType(
    void const *elfFile,
    int i);

void const *elf_getSection(
    void const *elfFile,
    int i);

void elf_getProgramHeaderInfo(
    void const *elfFile,
    uint16_t ph,
    uint64_t *p_vaddr,
    uint64_t *p_paddr,
    uint64_t *p_filesz,
    uint64_t *p_offset,
    uint64_t *p_memsz);

#if 0
/*
 * Returns a pointer to the program segment table, which is an array of
 * ELF64_Phdr_t structs.  The size of the array can be found by calling
 * getNumProgramSegments.
 */
struct Elf32_Phdr const *elf_getProgramSegmentTable(
    void const *elfFile);
#endif

#if 0
/**
 * Returns a pointer to the program segment table, which is an array of
 * ELF64_Phdr_t structs.  The size of the array can be found by calling
 * getNumProgramSegments.
 */
struct Elf32_Shdr const *elf_getSectionTable(
    void const *elfFile);
#endif

