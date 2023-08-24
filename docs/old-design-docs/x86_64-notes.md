On amd64 WIN64 ABI defines LONG to be 32bit. Unix System-V ABI defines long to be 64bit.
libsel4 assumes that long is 64bit on amd64.
Some magic needs to happen in order for libsel4 to be usable from NTDLL and all NT clients,
since they are compiled with WIN64 ABI.
We probably need to produce a "sanitized" version of libsel4 headers such that all long types
are replaced with long long.
