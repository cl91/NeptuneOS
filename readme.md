# Neptune OS: a WinNT personality of the seL4 microkernel

Neptune OS is a Windows NT personality for the seL4 microkernel. It implements what
Microsoft calls the "NT Executive", the upper layer of the Windows kernel `NTOSKRNL.EXE`,
as a user process under the seL4 microkernel. The NT Executive implements the so-called
NT Native API, the native system call interface of Windows upon which the more familiar
Win32 API is built. These are exposed to the user mode via stub functions in `NTDLL.DLL`
with names such as `NtCreateProcess`. The NT Executive is also responsible for exposing
a programming interface to device drivers. Said interface includes functions like
`IoConnectInterrupt` and `IoCallDriver`. Our architecture enables device drivers to
run in separate userspace processes and communicate with the NT Executive process via
standard seL4 IPC primitives.

The eventual goal of the Neptune OS project is to implement enough NT semantics such
that a ReactOS user land can be ported under Neptune OS, as well as most ReactOS kernel
drivers. In theory we should be able to achieve binary compatibility with native Windows
executables provided that our implementation of the NT Native API is sufficiently faithful.
We should also be able to achieve a high degree of source code portability with Windows
device drivers and file system drivers, although we do not aim for complete, line-for-line
source code compatibility due to the architectural differences with Windows/ReactOS that
make this goal non-realistic. Please see the [Documentation](#documentations) section for
more information.

## Project Status

The current status of the project is that we have implemented enough NT Executive
components to support a reasonably complete file system stack with read-ahead and
write-back caching support, that includes the FAT12/16/32 file system driver `fatfs.sys`
and a floppy controller driver `fdc.sys`. We also have a basic keyboard driver stack,
that includes the keyboard class driver `kbdclass.sys` and the PS/2 port driver
`i8042prt.sys`. These allow us to run a basic command prompt `ntcmd.exe`, taken
from the ReactOS project, that supports most of the common shell commands, such as
`pwd`, `cd`, `copy`, `move`, `del`, `mount`, and `umount`. We also include a
`beep.sys` driver which makes an annoying sound on the PC speaker.

The entire system fits in a floppy and can be downloaded from
[Release v0.2.0002](https://github.com/cl91/NeptuneOS/releases/tag/v0.2.0002).
You can watch a short demo on [YouTube](https://www.youtube.com/watch?v=o3FLRnkh0ic).
You can also build it yourself. See the section on [Building](#building-and-running).

### Planned Features
For the next release we are planning to port the ATA/AHCI driver stack from ReactOS
so we can support most PATA/SATA hard disks. We also plan to write/port a disk
benchmark suite so we can demonstrate that a microkernel design does not lead to
unacceptable performance penalties.

## Minimal System Requirements

For i386 systems (should probably be called i686):

1. CPU: At least a Pentium 2 or equivalent: the default clang target is i686 which
   can generate instructions not implemented by 386, 486, and Pentium. Also, on x86
   the seL4 kernel assumes that the processor supports global pages (bit PGE in CR4).
   This is only supported in Pentium Pro (i686) and later. There is no way to disable
   this at compile time (see assembly routine `enable_paging` in `sel4/src/arch/x86/32/head.S`).
2. RAM: 32MB should be safe, can probably go lower.
3. VGA-compatible graphics controller.
4. PS2 keyboard. Most BIOSes offer PS2 emulation for USB keyboards so connecting a USB
   keyboard should also work.
5. PC BIOS or compatible, with a conformant ACPI implementation. This is more of a seL4
   requirement as it needs at least ACPI 3.0 for detecting the number of CPU cores. Note
   that most early 32-bit era PCs don't necessarily have a conformant ACPI (let alone
   ACPI 3.0) implementation, so this pretty much restricts you to Core 2 Duo era machines.
   Thinkpad X60 is a 32-bit laptop that has been tested to work.

For amd64 systems:

1. CPU: At least Intel Ivy Bridge or equivalent: the default seL4 kernel is built with
   the `fsgsbase` instruction enabled. This is only supported on Ivy Bridge and later.
   To run amd64 builds on earlier CPUs you can disable fsgsbase instruction in
   `private/ntos/cmake/sel4.cmake`. Also we require cmpxchg16b, which is available since
   Nehalem, and quite possibly earlier (earlier Core 2 processors might need a microcode
   update).
2. RAM: 128MB should be safe, can probably go lower.
3. VGA-compatible graphics controller.
4. Legacy BIOS or UEFI-based BIOS that supports at least ACPI 3.0.

For `amd64` machines, Thinkpad X230 has been tested to work.

## Building and running

You will need to build under Linux (seL4 doesn't build under any other operating system).
You will need the following Python dependencies, and probably more.
```
jinja2
future
ply
setuptools
six
lxml
```
You will also need `cmake`, `clang`, `llvm` and `lld` as a basic toolchain. `clang`
is a native cross compiler that can generate both ELF and PE targets. GCC is not
supported but in theory can be made to work. You will need both an ELF toolchain
and a PE toolchain (and probably a ton of patience) if you want to make GCC work.
You also need the `windmc` which is the PE message resource compiler from `mingw`.
Have a look at `build.sh` for the build script. The preferred clang version is 15
but recent versions should all work. You also need the `cpio` utility for building
the initcpio. Finally, for the boot floppy and boot iso you will need the following
tools: `syslinux` (for boot floppy), `grub` and `xorriso` (for boot iso), and
`mtools` (for both).

It is recommended to use a language server-enabled IDE to browse the source code.
The tested setup is the `lsp-mode` package on `emacs` with `clangd` as the language
server. The `build.sh` script will generate the `compile_commands.json` file for
`clangd`. You will need to install [jq](https://jqlang.github.io/jq/) for this
purpose.

Clone the project first (make sure you use `git clone --recurse-submodules` since
we include the seL4 kernel as a submodule) and then run
```
./build.sh [amd64] [release]
```
If you don't specify `amd64`, then it's an `i686` build. If you don't specify
`release`, then it's a debug build. To create boot floppies, type
```
./mkfloopy.sh [amd64] [release]
```
To create boot isos, type
```
./mkiso.sh [amd64] [release]
```
To simulate using QEMU, run
```
./run.sh [direct|iso|uefi] [amd64] [release] [extra-qemu-args]
```
If you specify `direct`, then QEMU will load the seL4 kernel and the NTOS image
directly (using `-kernel` and `-initrd`). If you specify `iso` or `uefi`, it will
load the boot iso built by `mkiso.sh`. The `uefi` option will also configure QEMU
to load the UEFI firmware, which provides a nice high definition framebuffer console.
Otherwise, the boot floppy created by `mkfloppy.sh`
is used. Extra arguments are passed to QEMU. For instance, to run the `i386`
release build with PC speaker enabled in QEMU you can pass the following (this
assumes you are using a recent QEMU version and have pulseaudio)
```
./run.sh release -machine pcspk-audiodev=snd0 -audiodev pa,id=snd0
```
The debug build might run slowly especially if you turn on serial port logging.
You can turn off logging by modifying the master header of the NT Executive project
(see `private/ntos/inc/ntos.h`).

### Cross-compiling
We use the LLVM toolchain so cross-compiling in theory should simply work without any
special handling. In practice, on `i386`/`amd64` the linker script for the final seL4
kernel executable relies on features that only the GNU LD linker supports, so we cannot
use the LLVM linker (LLD) to link the seL4 kernel. This means that you will need the GNU
LD cross-linkers for the target triples `i686-pc-linux-gnu` and `x86_64-pc-linux-gnu`
installed in the usual place (`/usr/bin`) so `clang` can find them and invoke them
correctly when linking the seL4 kernel. The PE part of the toolchain is completely
self-contained and requires no special handling when cross-compiling (it is already
a cross-toolchain because we are targeting Windows on a Linux host).

Cross-compiling is tested on Archlinux running on Loongarch64 (Loongson 3A5000
processor) with `llvm-14` and seems to generate the correct code. Please open an
issue if you run into any problem.

Note that if your grub is built for the native platform rather than i686/amd64,
the boot iso generated by `mkiso.sh` will not work as `grub-mkrescue` will try to
copy the native platform's boot files to the ISO. To fix this, cross-build the grub
package for i686/amd64 (or simply run the final iso generation on an i686/amd64
system).

## Documentations

Documentations are located under the `docs` directory. For developers and those interested
in understanding the inner workings of Neptune OS, read the `Developer-Guide.md` which
starts with an architectural overview of the operating system and proceeds to explain
the various design decisions of individual OS components. It also contains the driver
porting guide for those interested in porting drivers from ReactOS.
