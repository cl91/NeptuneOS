/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 * Copyright: Linux Kernel team
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * The code in here is derived from the Linux kernel
 */

OUTPUT_FORMAT("elf32-littlearm", "elf32-littlearm", "elf32-littlearm")
OUTPUT_ARCH(arm)
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
  .data :
  {
   _data = .;
   *(.sdata)
   *(.data)
   *(.data1)
   *(.data.*)
   *(.got.plt)
   *(.got)

   __start__driver_list = .;
   *(_driver_list)
   __stop__driver_list = .;

   . = ALIGN(8);
   _archive_start = .;
   *(._archive_cpio)
   _archive_end = .;

   /* the EFI loader doesn't seem to like a .bss section, so we stick
      it all into .data: */
   . = ALIGN(16);
   _bss = .;
   *(.sbss)
   *(.scommon)
   *(.dynbss)
   *(.bss)
   *(.bss.*)
   *(COMMON)
   . = ALIGN(16);
   _bss_end = .;
  }

  .rel.dyn : { *(.rel.dyn) }
  .rel.plt : { *(.rel.plt) }
  .rel.got : { *(.rel.got) }
  .rel.data : { *(.rel.data) *(.rel.data*) }
  _edata = .;
  _data_size = . - _etext;

  . = ALIGN(4096);
  .dynsym   : { *(.dynsym) }
  . = ALIGN(4096);
  .dynstr   : { *(.dynstr) }
  . = ALIGN(4096);
  .note.gnu.build-id : { *(.note.gnu.build-id) }

  _end = .;
  /DISCARD/ :
  {
    *(.rel.reloc)
    *(.eh_frame)
    *(.note.GNU-stack)
  }
  .comment 0 : { *(.comment) }
}
