#include "tests.h"

VOID KeRunAllTests()
{
    ExRunTests();
    MmRunTests();
    /* Loop forever */
    DbgTrace("All tests done.\n");
    while (TRUE) ;
}
