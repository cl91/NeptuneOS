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

/*
 * The entrypoint into a root task is somewhat different to the
 * entrypoint into a regular process. The kernel does not provide a
 * stack to the root task nor does it conform to System-V ABI; instead
 * it simply starts execution at the entrypoint with the first argument
 * being the pointer to the seL4_BootInfo.
 *
 * This is invoked by _sel4_start, which simply sets up a static stack
 * and passes the argument to us.
 */
void KiInitializeSystem(seL4_BootInfo *boot_info) {
    main();
}

int main()
{
    char *str = "Hello, World!\n";

    for (char *p = str; *p != '\0'; p++) {
	seL4_DebugPutChar(*p);
    }

    return 0;
}
