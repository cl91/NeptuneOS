/*
 * Copyright (c) 1999-2004 University of New South Wales
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#pragma once

#include <types.h>

#define R_AARCH64_NONE            0 /* No relocation.  */
#define R_AARCH64_RELATIVE     1027 /* Adjust by program base.  */
#define ELF64_R_TYPE(i)         ((i) & 0xffffffff)
/*
 * File header
 */
struct Elf64_Header {
    unsigned char   e_ident[16];
    uint16_t        e_type;     /* Relocatable=1, Executable=2 (+ some more ..) */
    uint16_t        e_machine;  /* Target architecture: MIPS=8 */
    uint32_t        e_version;  /* Elf version (should be 1) */
    uint64_t        e_entry;    /* Code entry point */
    uint64_t        e_phoff;    /* Program header table */
    uint64_t        e_shoff;    /* Section header table */
    uint32_t        e_flags;    /* Flags */
    uint16_t        e_ehsize;   /* ELF header size */
    uint16_t        e_phentsize;/* Size of one program segment header */
    uint16_t        e_phnum;    /* Number of program segment headers */
    uint16_t        e_shentsize;/* Size of one section header */
    uint16_t        e_shnum;    /* Number of section headers */
    uint16_t        e_shstrndx; /* Section header index of the string table for
                                 * section header names
                                 */
};

/*
 * Section header
*/
struct Elf64_Shdr {
    uint32_t        sh_name;
    uint32_t        sh_type;
    uint64_t        sh_flags;
    uint64_t        sh_addr;
    uint64_t        sh_offset;
    uint64_t        sh_size;
    uint32_t        sh_link;
    uint32_t        sh_info;
    uint64_t        sh_addralign;
    uint64_t        sh_entsize;
};

/*
 * Program header
 */
struct Elf64_Phdr {
    uint32_t        p_type;     /* Segment type: Loadable segment = 1 */
    uint32_t        p_flags;    /* Flags: logical "or" of PF_constants below */
    uint64_t        p_offset;   /* Offset of segment in file */
    uint64_t        p_vaddr;    /* Reqd virtual address of segment when loading */
    uint64_t        p_paddr;    /* Reqd physical address of segment */
    uint64_t        p_filesz;   /* How many bytes this segment occupies in file */
    uint64_t        p_memsz;    /* How many bytes this segment should occupy in
                                 * memory (when loading, expand the segment by
                                 * concatenating enough zero bytes to it)
                                 */
    uint64_t        p_align;    /* Reqd alignment of segment in memory */
};

/*
 * Dynamic section
 */
struct Elf64_Dyn {
    uint64_t d_tag;
    union {
        uint64_t d_val;
        uint64_t d_ptr;
    } d_un;
};

struct Elf64_Rela {
    uint64_t r_offset;  /* Address */
    uint64_t r_info;    /* Relocation type and symbol index */
    uint64_t r_addend;  /* Addend */
};

int elf64_checkFile(
    void const *elfFile);

struct Elf64_Phdr const *elf64_getProgramSegmentTable(
    void const *elfFile);

unsigned elf64_getNumSections(
    void const *elfFile);

char const *elf64_getStringTable(
    void const *elfFile,
    unsigned int string_segment);

char const *elf64_getSegmentStringTable(
    void const *elfFile);

/* Assume the field is at least 4-byte aligned and little-endian */
static uint64_t elf64_read64(
    void const *addr)
{
    uint64_t ret;
    if (((uintptr_t)addr) % 8 == 0) {
        ret = *((uint64_t *)addr);
    } else {
        ret = *((uint32_t *)(((uintptr_t)addr) + 4));
        ret = ret << 32;
        ret |= *((uint32_t *)addr);
    }
    return ret;
}

static inline struct Elf64_Shdr const *elf64_getSectionTable(
    struct Elf64_Header const *file)
{
    /* Cast heaven! */
    return (struct Elf64_Shdr *)(uintptr_t)(((uintptr_t) file) + file->e_shoff);
}

/* accessor functions */
static inline uint32_t elf64_getSectionType(
    struct Elf64_Header const *file,
    uint16_t s)
{
    return elf64_getSectionTable(file)[s].sh_type;
}

static inline uint32_t elf64_getSectionFlags(
    struct Elf64_Header const *file,
    uint16_t s)
{
    return elf64_getSectionTable(file)[s].sh_flags;
}

char const *elf64_getSectionName(
    void const *elfFile,
    unsigned int i);

uint64_t elf64_getSectionSize(
    void const *elfFile,
    unsigned int i);

uint64_t elf64_getSectionAddr(
    struct Elf64_Header const *elfFile,
    unsigned int i);

void const *elf64_getSection(
    void const *elfFile,
    unsigned int i);

void const *elf64_getSectionNamed(
    void const *elfFile,
    char const *str);

uint32_t elf64_getSegmentType(
    void const *elfFile,
    unsigned int segment);

void elf64_getSegmentInfo(
    void const *elfFile,
    unsigned int segment,
    uint64_t *p_vaddr,
    uint64_t *p_paddr,
    uint64_t *p_filesz,
    uint64_t *p_offset,
    uint64_t *p_memsz);

void elf64_showDetails(
    void const *elfFile,
    int size,
    char const *name);

uint64_t elf64_getEntryPoint(
    struct Elf64_Header const *elfFile);

/* Program Headers functions */
/* Program header functions */
uint16_t elf64_getNumProgramHeaders(
    struct Elf64_Header const *file);

static inline struct Elf64_Phdr const *elf64_getProgramHeaderTable(
    struct Elf64_Header const *file)
{
    /* Cast hell! */
    uint64_t e_phoff = elf64_read64(&file->e_phoff);
    return (struct Elf64_Phdr *)(uintptr_t)(((uintptr_t) file) + e_phoff);
}

/* accessor functions */
static inline uint32_t elf64_getProgramHeaderFlags(
    struct Elf64_Header const *file,
    uint16_t ph)
{
    return elf64_getProgramHeaderTable(file)[ph].p_flags;
}

static inline uint32_t elf64_getProgramHeaderType(
    struct Elf64_Header const *file,
    uint16_t ph)
{
    return elf64_getProgramHeaderTable(file)[ph].p_type;
}

static inline uint64_t elf64_getProgramHeaderFileSize(
    struct Elf64_Header const *file,
    uint16_t ph)
{
    struct Elf64_Phdr const *phdr = &elf64_getProgramHeaderTable(file)[ph];
    return elf64_read64(&phdr->p_filesz);
}

static inline uint64_t elf64_getProgramHeaderMemorySize(
    struct Elf64_Header const *file,
    uint16_t ph)
{
    struct Elf64_Phdr const *phdr = &elf64_getProgramHeaderTable(file)[ph];
    return elf64_read64(&phdr->p_memsz);
}

static inline uint64_t elf64_getProgramHeaderVaddr(
    struct Elf64_Header const *file,

    uint16_t ph)
{
    struct Elf64_Phdr const *phdr = &elf64_getProgramHeaderTable(file)[ph];
    return elf64_read64(&phdr->p_vaddr);
}

static inline uint64_t elf64_getProgramHeaderPaddr(
    struct Elf64_Header const *file,
    uint16_t ph)
{
    struct Elf64_Phdr const *phdr = &elf64_getProgramHeaderTable(file)[ph];
    return elf64_read64(&phdr->p_paddr);
}

static inline uint64_t elf64_getProgramHeaderOffset(
    struct Elf64_Header const *file,
    uint16_t ph)
{
    struct Elf64_Phdr const *phdr = &elf64_getProgramHeaderTable(file)[ph];
    return elf64_read64(&phdr->p_offset);
}

