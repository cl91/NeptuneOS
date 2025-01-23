/*
 * Copyright (c) 1999-2004 University of New South Wales
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#pragma once

#include <types.h>

#define ELF32_R_TYPE(val)   ((val) & 0xff)
#define R_ARM_NONE          0   /* No reloc */
#define R_ARM_RELATIVE      23  /* Adjust by program base */
/*
 * File header
 */
struct Elf32_Header {
    unsigned char   e_ident[16];
    uint16_t        e_type;     /* Relocatable=1, Executable=2 (+ some more ..) */
    uint16_t        e_machine;  /* Target architecture: MIPS=8 */
    uint32_t        e_version;  /* Elf version (should be 1) */
    uint32_t        e_entry;    /* Code entry point */
    uint32_t        e_phoff;    /* Program header table */
    uint32_t        e_shoff;    /* Section header table */
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
struct Elf32_Shdr {
    uint32_t        sh_name;
    uint32_t        sh_type;
    uint32_t        sh_flags;
    uint32_t        sh_addr;
    uint32_t        sh_offset;
    uint32_t        sh_size;
    uint32_t        sh_link;
    uint32_t        sh_info;
    uint32_t        sh_addralign;
    uint32_t        sh_entsize;
};

/*
 * Program header
 */
struct Elf32_Phdr {
    uint32_t p_type;    /* Segment type: Loadable segment = 1 */
    uint32_t p_offset;  /* Offset of segment in file */
    uint32_t p_vaddr;   /* Reqd virtual address of segment when loading */
    uint32_t p_paddr;   /* Reqd physical address of segment (ignore) */
    uint32_t p_filesz;  /* How many bytes this segment occupies in file */
    uint32_t p_memsz;   /* How many bytes this segment should occupy in memory
                         * (when loading, expand the segment by concatenating
                         * enough zero bytes to it)
                         */
    uint32_t p_flags;   /* Flags: logical "or" of PF_ constants below */
    uint32_t p_align;   /* Reqd alignment of segment in memory */
};

/*
 * Dynamic header
 */
struct Elf32_Dyn {
    uint32_t d_tag;       /* Dynamic entry type */
    union {
        uint32_t d_val;   /* Integer value */
        uint32_t d_ptr;   /* Address value */
    } d_un;
};


/*
 * Relocation
 */
struct Elf32_Rel {
    uint32_t r_offset;    /* Address */
    uint32_t r_info;      /* Relocation type and symbol index */
};


int elf32_checkFile(
    struct Elf32_Header const *file);

struct Elf32_Phdr const *elf32_getProgramSegmentTable(
    struct Elf32_Header const *file);

unsigned elf32_getNumSections(
    struct Elf32_Header const *file);

char const *elf32_getStringTable(
    struct Elf32_Header const *file);

char const *elf32_getSegmentStringTable(
    struct Elf32_Header const *file);

static inline struct Elf32_Shdr const *elf32_getSectionTable(
    struct Elf32_Header const *file)
{
    /* Cast heaven! */
    return (struct Elf32_Shdr const *)((uintptr_t)file + file->e_shoff);
}

/* accessor functions */
static inline uint32_t elf32_getSectionType(
    struct Elf32_Header const *file,
    uint16_t s)
{
    return elf32_getSectionTable(file)[s].sh_type;
}

static inline uint32_t elf32_getSectionFlags(
    struct Elf32_Header const *file,
    uint16_t s)
{
    return elf32_getSectionTable(file)[s].sh_flags;
}

char const *elf32_getSectionName(
    struct Elf32_Header const *file,
    unsigned int i);

uint32_t elf32_getSectionSize(
    struct Elf32_Header const *file,
    unsigned int i);

uint32_t elf32_getSectionAddr(
    struct Elf32_Header const *elfFile,
    unsigned int i);

void const *elf32_getSection(
    struct Elf32_Header const *file,
    unsigned int i);

void const *elf32_getSectionNamed(
    struct Elf32_Header const *file,
    char const *str);

uint32_t elf32_getSegmentType(
    struct Elf32_Header const *file,
    unsigned int segment);

void elf32_getSegmentInfo(
    struct Elf32_Header const *file,
    unsigned int segment,
    uint64_t *p_vaddr,
    uint64_t *p_paddr,
    uint64_t *p_filesz,
    uint64_t *p_offset,
    uint64_t *p_memsz);

uint32_t elf32_getEntryPoint(
    struct Elf32_Header const *file);

/* Program header functions */
uint16_t elf32_getNumProgramHeaders(
    struct Elf32_Header const *file);

static inline struct Elf32_Phdr const *elf32_getProgramHeaderTable(
    struct Elf32_Header const *file)
{
    /* Cast heaven! */
    return (struct Elf32_Phdr const *)((uintptr_t)file + file->e_phoff);
}

/* accessor functions */
static inline uint32_t elf32_getProgramHeaderFlags(
    struct Elf32_Header const *file,
    uint16_t ph)
{
    return elf32_getProgramHeaderTable(file)[ph].p_flags;
}

static inline uint32_t elf32_getProgramHeaderType(
    struct Elf32_Header const *file,
    uint16_t ph)
{
    return elf32_getProgramHeaderTable(file)[ph].p_type;
}

static inline uint32_t elf32_getProgramHeaderFileSize(
    struct Elf32_Header const *file,
    uint16_t ph)
{
    return elf32_getProgramHeaderTable(file)[ph].p_filesz;
}

static inline uint32_t elf32_getProgramHeaderMemorySize(
    struct Elf32_Header const *file,
    uint16_t ph)
{
    return elf32_getProgramHeaderTable(file)[ph].p_memsz;
}

static inline uint32_t elf32_getProgramHeaderVaddr(
    struct Elf32_Header const *file,
    uint16_t ph)
{
    return elf32_getProgramHeaderTable(file)[ph].p_vaddr;
}

static inline uint32_t elf32_getProgramHeaderPaddr(
    struct Elf32_Header const *file,
    uint16_t ph)
{
    return elf32_getProgramHeaderTable(file)[ph].p_paddr;
}

static inline uint32_t elf32_getProgramHeaderOffset(
    struct Elf32_Header const *file,
    uint16_t ph)
{
    return elf32_getProgramHeaderTable(file)[ph].p_offset;
}

