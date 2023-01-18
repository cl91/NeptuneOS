Directory Organization
======================

| Directory		 | Description			   |
| ---------------------  | ------------------------------- |
| public		 | Public headers                  |
| public/crt/inc	 | C Runtime Library headers	   |
| public/ndk/inc	 | NT Client public headers	   |
| public/sdk/inc	 | Win32 public headers		   |
| private		 | seL4 root task and stub dll	   |
| private/ntos		 | Main NTOS root task	  	   |
| private/ntdll		 | Stub dll which calls NTOS	   |
| private/wdm		 | Device driver interface	   |
| base			 | Base native NT clients	   |
| base/smss		 | Session Manager Subsystem	   |
| drivers                | Device drivers                  |
| drivers/base           | Base device drivers             |
| drivers/base/pnp       | PNP root enumerator             |
| drivers/input          | Input device drivers            |
| drivers/input/kbdclass | Keyboard class driver           |
| drivers/input/i8042prt | i8042 port driver               |
| drivers/storage        | Storage device drivers          |
| drivers/storage/fdc    | Floppy device driver            |
| win32			 | Win32 Subsystem (native exes)   |
| shell			 | Win32 applications (win32 exes) |

All code that makes seL4 calls and refers to seL4 headers should go under `private`. No code outside `private` can make any seL4 system calls or include any seL4 headers.

All executables and DLLs under `base` and `win32` are native NT clients. Projects under `base` cannot include Win32 headers. Projects under `win32` can (and typically do) include Win32 headers.

All executables and DLLs under `shell` are Win32 applications. Projects under `shell` should not make native NT api calls (although we don't explicitly forbid this).