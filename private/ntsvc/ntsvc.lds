ENTRY(_KiSystemStartup)

SECTIONS
{
  . = 0x00100000;
  .text : { *(.text) }
  .data : { *(.data) }
  .bss : { *(.bss) }
}
