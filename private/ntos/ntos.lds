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
	. = ALIGN(4096) ;
	_rodata_start = . ;
	*(.rodata)
	_rodata_end = . ;
    }
    .initcpio :
    {
	. = ALIGN(4096) ;
	_initcpio_start = . ;
	*(initcpio)
	_initcpio_end = . ;
    }
    .data :
    {
	. = ALIGN(4096) ;
	_data_start = . ;
	*(.data)
	_data_end = . ;
    }
    .bss :
    {
	. = ALIGN(32) ;
	_bss_start = . ;
	*(.bss)
	_bss_end = . ;
    }
    .tdata :
    {
	. = ALIGN(4096) ;
	_tdata_start = . ;
	*(.tdata .tdata.* .gnu.linkonce.td.*)
	_tdata_end = . ;
    }
    .tbss :
    {
	. = ALIGN(32) ;
	_tbss_start = . ;
	*(.tbss .tbss.* .gnu.linkonce.tb.*) *(.tcommon)
	_tbss_end = . ;
    }
}
