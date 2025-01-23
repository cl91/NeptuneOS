/*
 * Copyright (c) 1999-2004 University of New South Wales
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <strops.h>
#include <binaries/elf/elf.h>

/*
 * Checks that elfFile points to a valid elf file. Returns 0 if the elf
 * file is valid, < 0 if invalid.
 */

int elf_checkFile(
    void const *elfFile)
{
    return ISELF32(elfFile)
           ? elf32_checkFile(elfFile)
           : elf64_checkFile(elfFile);
}

/* Program Headers Access functions */
uint16_t elf_getNumProgramHeaders(
    void const *elfFile)
{
    return ISELF32(elfFile)
           ? elf32_getNumProgramHeaders(elfFile)
           : elf64_getNumProgramHeaders(elfFile);
}

uint32_t elf_getProgramHeaderFlags(
    void const *elfFile,
    uint16_t ph)
{
    return ISELF32(elfFile)
           ? elf32_getProgramHeaderFlags(elfFile, ph)
           : elf64_getProgramHeaderFlags(elfFile, ph);
}

uint32_t elf_getProgramHeaderType(
    void const *elfFile,
    uint16_t ph)
{
    return ISELF32(elfFile)
           ? elf32_getProgramHeaderType(elfFile, ph)
           : elf64_getProgramHeaderType(elfFile, ph);
}

uint64_t elf_getProgramHeaderPaddr(
    void const *elfFile,
    uint16_t ph)
{
    return ISELF32(elfFile)
           ? elf32_getProgramHeaderPaddr(elfFile, ph)
           : elf64_getProgramHeaderPaddr(elfFile, ph);
}

uint64_t elf_getProgramHeaderVaddr(
    void const *elfFile,
    uint16_t ph)
{
    return ISELF32(elfFile)
           ? elf32_getProgramHeaderVaddr(elfFile, ph)
           : elf64_getProgramHeaderVaddr(elfFile, ph);
}

uint64_t elf_getProgramHeaderMemorySize(
    void const *elfFile,
    uint16_t ph)
{
    return ISELF32(elfFile)
           ? elf32_getProgramHeaderMemorySize(elfFile, ph)
           : elf64_getProgramHeaderMemorySize(elfFile, ph);
}

uint64_t elf_getProgramHeaderFileSize(
    void const *elfFile,
    uint16_t ph)
{
    return ISELF32(elfFile)
           ? elf32_getProgramHeaderFileSize(elfFile, ph)
           : elf64_getProgramHeaderFileSize(elfFile, ph);
}

uint64_t elf_getProgramHeaderOffset(
    void const *elfFile,
    uint16_t ph)
{
    return ISELF32(elfFile)
           ? elf32_getProgramHeaderOffset(elfFile, ph)
           : elf64_getProgramHeaderOffset(elfFile, ph);
}

char const *elf_getSegmentStringTable(
    void const *elfFile)
{
    return ISELF32(elfFile)
           ? elf32_getSegmentStringTable(elfFile)
           : elf64_getSegmentStringTable(elfFile);
}

char const *elf_getStringTable(
    void const *elfFile,
    int string_segment)
{
    return ISELF32(elfFile)
           ? elf32_getStringTable(elfFile)
           : elf64_getStringTable(elfFile, string_segment);
}

unsigned elf_getNumSections(
    void const *elfFile)
{
    return ISELF32(elfFile)
           ? elf32_getNumSections(elfFile)
           : elf64_getNumSections(elfFile);
}

char const *elf_getSectionName(
    void const *elfFile,
    int i)
{
    return ISELF32(elfFile)
           ? elf32_getSectionName(elfFile, i)
           : elf64_getSectionName(elfFile, i);
}

uint32_t elf_getSectionFlags(
    void const *elfFile,
    int i)
{
    return ISELF32(elfFile)
           ? elf32_getSectionFlags(elfFile, i)
           : elf64_getSectionFlags(elfFile, i);
}

uint32_t elf_getSectionType(
    void const *elfFile,
    int i)
{
    return ISELF32(elfFile)
           ? elf32_getSectionType(elfFile, i)
           : elf64_getSectionType(elfFile, i);
}

uint64_t elf_getSectionSize(
    void const *elfFile,
    int i)
{
    return ISELF32(elfFile)
           ? elf32_getSectionSize(elfFile, i)
           : elf64_getSectionSize(elfFile, i);
}

uint64_t elf_getSectionAddr(
    void const *elfFile,
    int i)
{
    return ISELF32(elfFile)
           ? elf32_getSectionAddr(elfFile, i)
           : elf64_getSectionAddr(elfFile, i);
}

void const *elf_getSection(
    void const *elfFile,
    int i)
{
    return ISELF32(elfFile)
           ? elf32_getSection(elfFile, i)
           : elf64_getSection(elfFile, i);
}

void const *elf_getSectionNamed(
    void const *elfFile,
    char const *_str)
{
    return ISELF32(elfFile)
           ? elf32_getSectionNamed(elfFile, _str)
           : elf64_getSectionNamed(elfFile, _str);
}

void elf_getProgramHeaderInfo(
    void const *elfFile,
    uint16_t ph,
    uint64_t *p_vaddr,
    uint64_t *p_paddr,
    uint64_t *p_filesz,
    uint64_t *p_offset,
    uint64_t *p_memsz)
{
    *p_vaddr = elf_getProgramHeaderVaddr(elfFile, ph);
    *p_paddr = elf_getProgramHeaderPaddr(elfFile, ph);
    *p_filesz = elf_getProgramHeaderFileSize(elfFile, ph);
    *p_offset = elf_getProgramHeaderOffset(elfFile, ph);
    *p_memsz = elf_getProgramHeaderMemorySize(elfFile, ph);
}

uint64_t elf_getEntryPoint(
    void const *elfFile)
{
    return ISELF32(elfFile)
           ? elf32_getEntryPoint (elfFile)
           : elf64_getEntryPoint (elfFile);
}

int elf_getMemoryBounds(
    void const *elfFile,
    int phys,
    uint64_t *min,
    uint64_t *max)
{
    uint64_t mem_min = UINT64_MAX;
    uint64_t mem_max = 0;

    if (elf_checkFile(elfFile) != 0) {
        return 0;
    }

    for (unsigned int i = 0; i < elf_getNumProgramHeaders(elfFile); i++) {
        uint64_t sect_min, sect_max;

        if (elf_getProgramHeaderMemorySize(elfFile, i) == 0) {
            continue;
        }

        if (phys) {
            sect_min = elf_getProgramHeaderPaddr(elfFile, i);
        } else {
            sect_min = elf_getProgramHeaderVaddr(elfFile, i);
        }

        sect_max = sect_min + elf_getProgramHeaderMemorySize(elfFile, i);

        if (sect_max > mem_max) {
            mem_max = sect_max;
        }
        if (sect_min < mem_min) {
            mem_min = sect_min;
        }
    }
    *min = mem_min;
    *max = mem_max;

    return 1;
}

int elf_vaddrInProgramHeader(
    void const *elfFile,
    uint16_t ph,
    uint64_t vaddr)
{
    uint64_t min = elf_getProgramHeaderVaddr(elfFile, ph);
    uint64_t max = min + elf_getProgramHeaderMemorySize(elfFile, ph);
    if (vaddr >= min && vaddr < max) {
        return 1;
    } else {
        return 0;
    }
}

uint64_t elf_vtopProgramHeader(
    void const *elfFile,
    uint16_t ph,
        uint64_t vaddr)
{
    uint64_t ph_phys = elf_getProgramHeaderPaddr(elfFile, ph);
    uint64_t ph_virt = elf_getProgramHeaderVaddr(elfFile, ph);
    uint64_t paddr;

    paddr = vaddr - ph_virt + ph_phys;

    return paddr;
}

int elf_loadFile(
    void const *elfFile,
    int phys)
{
    if (elf_checkFile(elfFile) != 0) {
        return 0;
    }

    for (unsigned int i = 0; i < elf_getNumProgramHeaders(elfFile); i++) {
        /* Load that section */
        uint64_t dest, src;
        size_t len;
        if (phys) {
            dest = elf_getProgramHeaderPaddr(elfFile, i);
        } else {
            dest = elf_getProgramHeaderVaddr(elfFile, i);
        }
        len = elf_getProgramHeaderFileSize(elfFile, i);
        src = (uint64_t) (uintptr_t) elfFile + elf_getProgramHeaderOffset(elfFile, i);
        memcpy((void*) (uintptr_t) dest, (void*) (uintptr_t) src, len);
        dest += len;
        memset((void*) (uintptr_t) dest, 0, elf_getProgramHeaderMemorySize(elfFile, i) - len);
    }

    return 1;
}
