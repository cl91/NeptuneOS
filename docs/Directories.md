Directory Organization
======================

| Directory		| Description			|
| --------------------- | ----------------------------- |
| public		| Public headers                |
| public/crt/inc	| C Runtime Library headers	|
| public/ndk/inc	| NT Client public headers	|
| public/sdk/inc	| Win32 public headers		|
| private		| seL4 root task and stub dll	|
| private/ntos		| Main NTOS root task	  	|
| private/ntdll		| Stub dll which calls NTOS	|
| base			| Base native NT clients	|
| base/smss		| Session Manager Subsystem	|
| win32			| Win32 Subsystem (native exes) |
| shell			| Win32 applications	  	|

All code that makes seL4 calls and refers to seL4 headers should go under `private`. No code outside `private` can make any seL4 system calls or include any seL4 headers.

All executables and DLLs under `base` and `win32` are native NT clients. Projects under `base` cannot include Win32 headers. Projects under `win32` can (and typically do).

All executables and DLLs under `shell` are Win32 applications. Projects under `shell` should not make native NT api calls (although we don't explicitly forbid this).