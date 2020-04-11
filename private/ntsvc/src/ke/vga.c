#include <nt.h>
#include <ntos.h>
#include <ntsvc.h>

#define VGA_BASE_ADDR	(0x80000000)

VOID KiVgaWriteString(LONG Color, PCSTR String)
{
    volatile PCHAR Video = (volatile PCHAR) (VGA_BASE_ADDR | 0xB8000);
    while (*String != 0) {
	*Video++ = *String++;
	*Video++ = Color;
    }
}

VOID KiInitVga()
{
    /* LoopOverUntyped(cap, desc, BootEnvironment) { */
    /* 	if (desc->isDevice && desc->paddr == 0x0) { */
    /* 	    UNTYPED_DESCRIPTOR Untyped = */
    /* 		{ */
    /* 		 .CapSpace = CapSpace, */
    /* 		 .Cap = cap, */
    /* 		 .Log2Size = desc->sizeBits, */
    /* 		 .Split = FALSE */
    /* 		}; */
    /* 	    /\* PAGE_DESCRIPTOR Page = *\/ */
    /* 	    /\* 	{ *\/ */
    /* 	    /\* 	 .Untyped = &Untyped, *\/ */
    /* 	    /\* 	 .CapSpace = CapSpace, *\/ */
    /* 	    /\* 	 .Cap = 0, *\/ */
    /* 	    /\* 	 .VSpaceCap = seL4_CapInitThreadVSpace, *\/ */
    /* 	    /\* 	 .Log2Size = desc->sizeBits, *\/ */
    /* 	    /\* 	 .Mapped = FALSE, *\/ */
    /* 	    /\* 	 .VirtualAddr = VGA_BASE_ADDR, *\/ */
    /* 	    /\* 	 .Rights = seL4_ReadWrite, *\/ */
    /* 	    /\* 	 .Attributes = seL4_X86_Default_VMAttributes *\/ */
    /* 	    /\* 	}; *\/ */
    /* 	    /\* DbgPrint("MmMapTopLevelPage Status = %p", MmMapTopLevelPage(Page)); *\/ */
    /* 	} */
    /* } */

    //KiVgaWriteString(1, "Hello, world!");
}
