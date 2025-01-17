/*
 * COPYRIGHT:       See COPYING in the top level directory
 * PROJECT:         ReactOS Kernel
 * FILE:            include/asm/asm.inc
 * PURPOSE:         ASM macros for GAS and MASM/ML64
 * PROGRAMMERS:     Timo Kreuzer (timo.kreuzer@reactos.org)
 */

#ifndef __ASM_INC__
#define __ASM_INC__

/*
 * Common definitions for the FPO macro.
 * See https://docs.microsoft.com/en-us/windows/desktop/api/winnt/ns-winnt-_fpo_data
 */
#define FRAME_FPO    0
#define FRAME_TRAP   1
#define FRAME_TSS    2
#define FRAME_NONFPO 3

/* Force intel syntax */
.intel_syntax noprefix

/* Put dwarf debug info in the .dwarf_debug section, which will be properly stripped */
.cfi_sections .debug_frame

.altmacro

/* Explicit radix in GAS syntax */
#define BIN(x) 0b##x
#define OCT(x) 0##x
#define DEC(x) x
#define HEX(x) 0x##x

/* Macro values need to be marked */
#define VAL(x) \x

#define CR  "\r"
#define LF  "\n"
#define NUL "\0"

/* Due to MASM's reverse syntax, we are forced to use a precompiler macro */
#define MACRO(...) .macro __VA_ARGS__
#define ENDM .endm

/* To avoid reverse syntax we provide a new macro .PROC, replacing PROC... */
.macro .PROC name
#ifdef _X86_
    .func \name
#else
    .global \name
#endif
    \name:
#ifdef _X86_
    .cfi_startproc
#else
    .seh_proc \name
#endif
.endm
#define FUNC .PROC

/* ... and .ENDP, replacing ENDP */
.macro .ENDP
#ifdef _X86_
    .cfi_endproc
#else
    .seh_endproc
#endif
#ifdef _X86_
    .endfunc
#endif
.endm
#define ENDFUNC .ENDP

/* MASM compatible PUBLIC */
.macro PUBLIC symbol
    .global \symbol
.endm

/* No special marking of global labels */
.macro GLOBAL_LABEL label
    \label:
.endm

/* Dummy ASSUME */
.macro ASSUME p1 p2 p3 p4 p5 p6 p7 p8
.endm

/* MASM needs an end tag for segments */
.macro .endcode16
.endm

/* MASM compatible ALIGN */
#define ALIGN .align

/* MASM compatible REPEAT, additional ENDR */
#define REPEAT .rept
#define ENDR .endr

.macro ljmp segment, offset
    jmp far ptr \segment:\offset
.endm

.macro ljmp16 segment, offset
    jmp far ptr \segment:\offset
.endm

.macro retf
    lret
.endm

/* MASM compatible EXTERN */
.macro EXTERN name
.endm

/* MASM needs an END tag */
#define END

.macro .MODEL model
.endm

.macro .code
    .text
.endm

.macro .const
    .section .rdata
.endm

/*
 * See https://docs.microsoft.com/en-us/cpp/assembler/masm/dot-fpo
 * and https://docs.microsoft.com/en-us/windows/desktop/api/winnt/ns-winnt-_fpo_data
 */
.macro FPO cdwLocals, cdwParams, cbProlog, cbRegs, fUseBP, cbFrame
    .if (cbFrame == FRAME_TRAP)
        .cfi_signal_frame
    .endif
.endm

/* Macros for x64 stack unwind OPs */
.macro .allocstack size
    .seh_stackalloc \size
.endm

.macro .pushframe param
    /*
     * FIXME. .seh_pushframe doesn't accept code argument.
     * Patch sent.
     */
    .seh_pushframe \param
.endm

.macro .pushreg reg
    .seh_pushreg \reg
.endm

.macro .savereg reg, offset
    .seh_savereg \reg, \offset
.endm

.macro .savexmm128 reg, offset
    .seh_savexmm \reg, \offset
.endm

.macro .setframe reg, offset
    .seh_setframe \reg, \offset
.endm

.macro .endprolog
    .seh_endprologue
.endm

.macro absolute address
    __absolute__address__ = \address
.endm

.macro resb name, size
    \name = __absolute__address__
    __absolute__address__ = __absolute__address__ + \size
.endm

/* MASM/ML uses ".if" for runtime conditionals, and "if" for compile time
   conditionals. We therefore use "if", too. .if shouldn't be used at all */
#define if .if
#define endif .endif
#define else .else
#define elseif .elseif

/* CFI annotations */
#define CFI_STARTPROC .cfi_startproc
#define CFI_ENDPROC .cfi_endproc
#define CFI_DEF_CFA .cfi_def_cfa
#define CFI_DEF_CFA_OFFSET .cfi_def_cfa_offset
#define CFI_DEF_CFA_REGISTER .cfi_def_cfa_register
#define CFI_ADJUST_CFA_OFFSET .cfi_adjust_cfa_offset
#define CFI_OFFSET .cfi_offset
#define CFI_REGISTER .cfi_register
#define CFI_REL_OFFSET .cfi_rel_offset
#define CFI_SAME_VALUE .cfi_same_value

#endif /* __ASM_INC__ */
