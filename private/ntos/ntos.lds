ENTRY(_KiSystemStartup)

SECTIONS
{
  . = 0x00100000;
  .text :
    {
        _text_start = . ;
	*(.text)
	_text_end = . ;
    }
  .rodata :
    {
        _rodata_start = . ;
	*(.rodata)
	_rodata_end = . ;
	. = ALIGN(4096);
	_ntdll_start = .;
	*(ntdll)
	_ntdll_end = .;
	. = ALIGN(4096);
    }
  .data :
    {
        _data_start = . ;
	*(.data)
	_data_end = . ;
    }
  .tdata :
    {
        _tdata_start = . ;
        *(.tdata .tdata.* .gnu.linkonce.td.*)
        _tdata_end = . ;
    }
  .bss :
    {
        _bss_start = . ;
	*(.bss)
	_bss_end = . ;
    }
  .tbss :
    {
        _tbss_start = . ;
        *(.tbss .tbss.* .gnu.linkonce.tb.*) *(.tcommon)
        _tbss_end = . ;
    }
}
