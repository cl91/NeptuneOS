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
	. = ALIGN(16) ;
	_rodata_start = . ;
	*(.rodata)
	_rodata_end = . ;
    }
    .initcpio :
    {
	. = ALIGN(16) ;
	_initcpio_start = . ;
	*(initcpio)
	_initcpio_end = . ;
    }
    .data :
    {
	. = ALIGN(16) ;
	_data_start = . ;
	*(.data)
	_data_end = . ;
    }
    .tdata :
    {
	. = ALIGN(16) ;
	_tdata_start = . ;
	*(.tdata .tdata.* .gnu.linkonce.td.*)
	_tdata_end = . ;
    }
    .bss :
    {
	. = ALIGN(16) ;
	_bss_start = . ;
	*(.bss)
	*(.stack)
	_bss_end = . ;
    }
    .tbss :
    {
	. = ALIGN(16) ;
	_tbss_start = . ;
	*(.tbss .tbss.* .gnu.linkonce.tb.*) *(.tcommon)
	_tbss_end = . ;
    }
}
