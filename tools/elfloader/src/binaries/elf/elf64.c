/*
 * Copyright (c) 1999-2004 University of New South Wales
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <strops.h>
#include <binaries/elf/elf.h>

int elf64_checkFile(
    void const *elfFile)
{
    struct Elf64_Header *fileHdr = (struct Elf64_Header *) elfFile;
    if (fileHdr->e_ident[EI_MAG0] != ELFMAG0
        || fileHdr->e_ident[EI_MAG1] != ELFMAG1
        || fileHdr->e_ident[EI_MAG2] != ELFMAG2
        || fileHdr->e_ident[EI_MAG3] != ELFMAG3) {
        return -1;    /* not an elf file */
    }
    if (fileHdr->e_ident[EI_CLASS] != ELFCLASS64) {
        return -2;    /* not 64-bit file */
    }
#if 0
    if (fileHdr->e_ident[EI_DATA] != ELFDATA2LSB) {
        return -3;    /* not big-endian file */
    }
    if (fileHdr->e_ident[EI_VERSION] != 1) {
        return -4;    /* wrong version of elf */
    }
    if (fileHdr->e_machine != 8) {
        return -5;    /* wrong architecture (not MIPS) */
    }
    if (fileHdr->e_type != 2) {
        return -6;    /* not an executable program */
    }
    if (fileHdr->e_phentsize != sizeof(struct Elf64_Phdr)) {
        return -7;
    }   /* unexpected size of program segment header */
    if (fileHdr->e_phnum == 0) {
        return -8;    /* no program segments */
    }
    if ((fileHdr->e_flags & 0x7e) != 0) {
        return -9;
    }   /* wrong flags (did you forgot to compile with -mno-abicalls?) */
#endif
    return 0;       /* elf file looks OK */
}

/*
 * Returns a pointer to the program segment table, which is an array of
 * ELF64_Phdr_t structs.  The size of the array can be found by calling
 * getNumProgramSegments.
 */
struct Elf64_Phdr const *elf64_getProgramSegmentTable(
    void const *elfFile)
{
    struct Elf64_Header const *fileHdr = elfFile;
    return (struct Elf64_Phdr *)((size_t)fileHdr->e_phoff + (size_t) elfFile);
}

/*
 * Returns the number of program segments in this elf file.
 */
unsigned int elf64_getNumSections(
    void const *elfFile)
{
    struct Elf64_Header const *fileHdr = elfFile;
    return fileHdr->e_shnum;
}

char const *elf64_getStringTable(
    void const *elfFile,
    unsigned int string_segment)
{
    struct Elf64_Shdr const *sections = elf64_getSectionTable(elfFile);
    return (char *) elfFile + sections[string_segment].sh_offset;
}

char const *elf64_getSegmentStringTable(
    void const *elfFile)
{
    struct Elf64_Header const *fileHdr = elfFile;
    if (fileHdr->e_shstrndx == 0) {
        return NULL;
    } else {
        return elf64_getStringTable(elfFile, fileHdr->e_shstrndx);
    }
}

char const *elf64_getSectionName(
    void const *elfFile,
    unsigned int i)
{
    struct Elf64_Shdr const *sections = elf64_getSectionTable(elfFile);
    char const *str_table = elf64_getSegmentStringTable(elfFile);
    if (str_table == NULL) {
        return "<corrupted>";
    } else {
        return str_table + sections[i].sh_name;
    }
}

uint64_t elf64_getSectionSize(
    void const *elfFile,
    unsigned int i)
{
    struct Elf64_Shdr const *sections = elf64_getSectionTable(elfFile);
    return sections[i].sh_size;
}

uint64_t elf64_getSectionAddr(
    struct Elf64_Header const *elfFile,
    unsigned int i)
{
    struct Elf64_Shdr const *sections = elf64_getSectionTable(elfFile);
    return sections[i].sh_addr;
}

void const *elf64_getSection(
    void const *elfFile,
    unsigned int i)
{
    struct Elf64_Shdr const *sections = elf64_getSectionTable(elfFile);
    return (char *)elfFile + sections[i].sh_offset;
}

void const *elf64_getSectionNamed(
    void const *elfFile,
    char const *str)
{
    unsigned int numSections = elf64_getNumSections(elfFile);
    for (unsigned int i = 0; i < numSections; i++) {
        if (strcmp(str, elf64_getSectionName(elfFile, i)) == 0) {
            return elf64_getSection(elfFile, i);
        }
    }
    return NULL;
}

uint16_t elf64_getNumProgramHeaders(
    struct Elf64_Header const *elfFile)
{
    return elfFile->e_phnum;
}

uint32_t elf64_getSegmentType(
    void const *elfFile,
    unsigned int segment)
{
    return elf64_getProgramSegmentTable(elfFile)[segment].p_type;
}

void elf64_getSegmentInfo(
    void const *elfFile,
    unsigned int segment,
    uint64_t *p_vaddr,
    uint64_t *p_paddr,
    uint64_t *p_filesz,
    uint64_t *p_offset,
    uint64_t *p_memsz)
{
    struct Elf64_Phdr const *segments = elf64_getProgramSegmentTable(elfFile);
    *p_vaddr = segments[segment].p_vaddr;
    *p_paddr = segments[segment].p_paddr;
    *p_filesz = segments[segment].p_filesz;
    *p_offset = segments[segment].p_offset;
    *p_memsz = segments[segment].p_memsz;
}

uint64_t elf64_getEntryPoint(
    struct Elf64_Header const *elfFile)
{
    return elf64_read64(&elfFile->e_entry);
}

/*
 * Debugging functions
 */

#if 0
/*
 * prints out some details of one elf file
 */
void elf64_showDetails(
    void const *elfFile,
    int size,
    char const *name)
{
    struct Elf64_Phdr const *segments;
    unsigned int numSegments;
    struct Elf64_Shdr const *sections;
    unsigned int numSections;
    int r;
    char *str_table;

    printf("Found an elf64 file called \"%s\" located "
           "at address 0x%lx\n", name, elfFile);

    if ((r = elf64_checkFile(elfFile)) != 0) {
        char           *magic = elfFile;
        printf("Invalid elf file (%d)\n", r);
        printf("Magic is: %02.2hhx %02.2hhx %02.2hhx %02.2hhx\n",
               magic[0], magic[1], magic[2], magic[3]);
        return;
    }

    str_table = elf64_getSegmentStringTable(elfFile);

    printf("Got str_table... %p\n", str_table);

    /*
     * get a pointer to the table of program segments
     */
    segments = elf64_getProgramSegmentTable(elfFile);
    numSegments = elf64_getNumProgramSegments(elfFile);

    sections = elf64_getSectionTable(elfFile);
    numSections = elf64_getNumSections(elfFile);

    if ((void *) sections > (void *) elfFile + size ||
        (((uintptr_t) sections & 0xf) != 0)) {
        printf("Corrupted elfFile..\n");
        return;
    }
    printf("Sections: %p\n", sections);
    /*
     * print out info about each section
     */

    /*
     * print out info about each program segment
     */
    printf("Program Headers:\n");
    printf("  Type           Offset   VirtAddr   PhysAddr   "
           "FileSiz MemSiz  Flg Align\n");
    for (unsigned int i = 0; i < numSegments; i++) {

        if (segments[i].p_type != 1) {
            printf("segment %d is not loadable, "
                   "skipping\n", i);
        } else {
            printf("  LOAD           0x%06lx 0x%08lx 0x%08lx"
                   " 0x%05lx 0x%05lx %c%c%c 0x%04lx\n",
                   segments[i].p_offset, segments[i].p_vaddr,
                   segments[i].p_vaddr,
                   segments[i].p_filesz, segments[i].p_memsz,
                   segments[i].p_flags & PF_R ? 'R' : ' ',
                   segments[i].p_flags & PF_W ? 'W' : ' ',
                   segments[i].p_flags & PF_X ? 'E' : ' ',
                   segments[i].p_align);
        }
    }

    printf("Section Headers:\n");
    printf("  [Nr] Name              Type            Addr     Off\n");
    for (unsigned int i = 0; i < numSections; i++) {
        if (elf_checkSection(elfFile, i) == 0) {
            printf("%-17.17s %-15.15s %08x %06x\n", elf64_getSectionName(elfFile, i), " "   /* sections[i].sh_type
                                                     */,
                   sections[i].sh_addr, sections[i].sh_offset);
        }
    }
}
#endif
