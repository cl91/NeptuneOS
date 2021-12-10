#include <ks386.h>

/* Must match offset of ThreadLocalStoragePointer in TEB struct */
.global __tls_array
.equ __tls_array, TbThreadLocalStoragePointer
