/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 * Copyright: Linux Kernel team
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * The code in here is derived from the Linux kernel
 */

OUTPUT_FORMAT("elf64-littleaarch64", "elf64-littleaarch64", "elf64-littleaarch64")
OUTPUT_ARCH(aarch64)
ENTRY(_gnuefi_start)
SECTIONS
{
  .text 0x0 : {
    _text = .;
    *(.text.head)
    *(.text)
    *(.text.*)
    *(.gnu.linkonce.t.*)
    *(.srodata)
    *(.rodata*)
    . = ALIGN(16);
  }
  _etext = .;
  _text_size = . - _text;
  .dynamic  : { *(.dynamic) }
  .data : ALIGN(4096)
  {
   _data = .;
   *(.sdata)
   *(.data)
   *(.data1)
   *(.data.*)
   *(.got.plt)
   *(.got)

   /* the EFI loader doesn't seem to like a .bss section, so we stick
      it all into .data: */
   . = ALIGN(16);
   _bss = .;
   *(.sbss)
   *(.scommon)
   *(.dynbss)
   *(.bss)
   *(COMMON)
   . = ALIGN(16);
   _bss_end = .;
  }

  .rela.dyn : { *(.rela.dyn) }
  .rela.plt : { *(.rela.plt) }
  .rela.got : { *(.rela.got) }
  .rela.data : { *(.rela.data) *(.rela.data*) }
  . = ALIGN(512);
  _edata = .;
  _data_size = . - _data;

  . = ALIGN(4096);
  .dynsym   : { *(.dynsym) }
  . = ALIGN(4096);
  .dynstr   : { *(.dynstr) }
  . = ALIGN(4096);
  .note.gnu.build-id : { *(.note.gnu.build-id) }
  /DISCARD/ :
  {
    *(.rel.reloc)
    *(.eh_frame)
    *(.note.GNU-stack)
  }
  .comment 0 : { *(.comment) }
}
