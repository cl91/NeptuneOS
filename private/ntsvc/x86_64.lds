/*
* Copyright 2017, Data61
* Commonwealth Scientific and Industrial Research Organisation (CSIRO)
* ABN 41 687 119 230.
*
* This software may be distributed and modified according to the terms of
* the BSD 2-Clause license. Note that NO WARRANTY is provided.
* See "LICENSE_BSD2.txt" for details.
*
* @TAG(DATA61_BSD)
*/

SECTIONS
{
    .tdata :
    {
        _tdata_start = . ;
        *(.tdata .tdata.* .gnu.linkonce.td.*)
        _tdata_end = . ;
    }
    .tbss :
    {
        _tbss_start = . ;
        *(.tbss .tbss.* .gnu.linkonce.tb.*) *(.tcommon)
        _tbss_end = . ;
    }
}
INSERT AFTER .rodata;
