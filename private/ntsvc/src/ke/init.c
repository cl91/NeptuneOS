#include <sel4/sel4.h>

/*
 * As this file is only included when we are running a root server,
 * these symbols must exist and be provided for this file to function
 * properly.
 *
 * This will generate a link time error if this function is used outside
 * of a root server.
 */

extern unsigned int _tdata_start[];
extern unsigned int _tdata_end[];
extern unsigned int _tbss_end[];

int main()
{
    char *str = "Hello, World!\n";

    for (char *p = str; *p != '\0'; p++) {
	seL4_DebugPutChar(*p);
    }

    return 0;
}

void KiInitializeSystem(seL4_BootInfo *boot_info) {
    main();
}
