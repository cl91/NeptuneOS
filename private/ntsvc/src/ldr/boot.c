#include <stdint.h>
#include <sel4/sel4.h>
#include <cpio/cpio.h>
#include <ntsvc.h>

extern UCHAR _binary_initcpio_start[];
extern UCHAR _binary_initcpio_end[];

void LdrLoadBootModules()
{
    for (PUCHAR p = &_binary_initcpio_start[0]; p < &_binary_initcpio_end[0]; p++) {
    	if ((p - &_binary_initcpio_start[0]) % 8 == 0) {
    	    DbgPrint("\n");
    	}
    	DbgPrint("%02x ", *p, *p);
    }
}
