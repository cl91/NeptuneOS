# Neptune OS: a WinNT personality of the seL4 microkernel

Neptune OS is a Windows NT personality of the seL4 microkernel. It implements what
Microsoft calls the "NT Executive", the upper layer of the Windows kernel `NTOSKRNL.EXE`,
as a user process under the seL4 microkernel. The NT Executive implements the so-called
NT Native API, the native system call interface of Windows upon which the more familiar
Win32 API is built. These are exposed to the user mode via stub functions in `NTDLL.DLL`
(a somewhat redundant name if you ask me) with names such as `NtCreateProcess`. The NT
Executive is also responsible for the Windows kernel driver interface (known as the
Windows driver model), which includes functions like `IoConnectInterrupt` and `IoCallDriver`.
On Windows these are loaded into kernel mode and linked with the `NTOSKRNL.EXE` image.
On Neptune OS, we run all the Windows kernel driver in user mode and they communicate
with the NT Executive process via standard seL4 IPC primitives.

The eventual goal of the Neptune OS project is to implement enough NT semantics such
that a ReactOS user land can be ported under Neptune OS, as well as most ReactOS kernel
drivers. In theory we should be able to achieve binary compatibility with native Windows
executables provided that our implementation of the NT Native API is sufficiently faithful.
We should also be able to achieve a high degree of source code compatibility with Windows
kernel drivers. The main obstacle of achieving binary compatibility of kernel drivers is
that many Windows kernel drivers do not follow the standard Windows driver communication
protocol (ie. passing IRPs when you need to call another driver) and instead just pass
pointers around and call into other drivers directly. In Neptune OS unless it's a
driver-minidriver pair we always run "kernel" drivers in their separate processes so it
is not possible to do that.

The status of the project right now is that we have implemented enough NT primitives
to load a basic keyboard driver stack, which includes the keyboard class driver
`kbdclass.sys` and the PS/2 port driver `i8042prt.sys`, as well as a basic command
prompt `ntcmd.exe`, taken from the ReactOS project. Pretty much none of the shell
command actually work but the keyboard stack is stable. The debug builds might be
a bit slow because we generate too much debug logs. You can turn these off in the
code (see `private/ntos/inc`). We also include a `beep.sys` driver which makes an
annoying sound on the PC speaker. You will need to unmute to hear it (especially if
you use `pulseaudio`). All drivers run in user space! The entire system fits in a
floppy and can be downloaded from [Release v0.1.0001](https://github.com/cl91/NeptuneOS/releases/tag/v0.1.0001).
You can also build it yourself, the procedure
of which is described in the next section.

## Building

You will need to build under Linux (seL4 doesn't build in any other operating system).
You will need the following Python dependencies, and probably more.
```
jinja2
future
ply
```
You will also need `cmake`, `clang`, and `lld` as a basic toolchain. The build
system will need compilers that can generate both ELF and PE targets. `clang` is a
native cross compiler so this is not a problem. If you want to use `gcc` there is
a `gcc` profile although it's not tested so it probably doesn't work. You will also
need both an ELF toolchain and a PE toolchain if you want to use `gcc`. Have a look
at `build.sh` for the build script.

Clone the project first (make sure you use `git clone --recurse-submodules` since
we include the seL4 kernel as a submodule) and then run
```
./build.sh [amd64] [release]
```
If you don't specify `amd64`, then it's an `i686` build. If you don't specify
`release`, then it's a debug build. To simulate using qemu, run
```
./run.sh [amd64] [release]
```
To create the boot floopy, type
```
./mkfloopy.sh [amd64] [release]
```
You might need to type your password because the script needs to invoke `sudo`.
eVeRYtHiNg iS a fILe!!!

## Architecture

The story is that allegedly Windows NT was originally intended to be a microkernel
operating system which comprises of a microkernel that implements basic process and
memory management as well as IPC, and on top of which a "NT Executive" is implemented.
The NT Executive is
...write this later. This section is unfinished. TODO! We hope to demonstrate that with
modern progress in microkernel design it is indeed possible to realize the original
NT design as an object oriented, message-passing based, client-server model microkernel OS.
