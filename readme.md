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
make this gole non-realistic. Please see the [Documentation](#documentations) section for
more information.

## Project Status

The status of the project right now is that we have implemented enough NT primitives
to load a basic keyboard driver stack, which includes the keyboard class driver
`kbdclass.sys` and the PS/2 port driver `i8042prt.sys`, as well as a basic command
prompt `ntcmd.exe`, taken from the ReactOS project. Pretty much none of the shell
command actually work but the keyboard stack is stable. The debug builds might be
a bit slow because we generate too much debug logs. You can turn these off in the
code (see `private/ntos/inc`). We also include a `beep.sys` driver which makes an
annoying sound on the PC speaker. You will need to unmute to hear it (especially if
you use `pulseaudio`). All drivers run in user space! The entire system fits in a
floppy and can be downloaded from [Release v0.1.0001](https://github.com/cl91/NeptuneOS/releases/tag/v0.1.0001). You can also build it yourself. See the section on [Building](#building).

## Minimal System Requirements

For i386 systems (should probably be called i686):

1. CPU: At least a Pentium 2 or equivalent: the default clang target is i686 which
   can generate instructions not implemented by 386, 486, and Pentium. Also, on x86
   the seL4 kernel assumes that the processor supports global pages (bit PGE in CR4).
   This is only supported in Pentium Pro (i686) and later. There is no way to disable
   this at compile time (see assembly routine `enable_paging` in `sel4/src/arch/x86/32/head.S`).
2. RAM: 32MB should be safe, can probably go lower.
3. VGA-compatible graphics controller.
4. PS2 keyboard.
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
4. Legacy BIOS booting. Most UEFI firmware can boot from legacy BIOS boot loaders by
   enabling a setting. We haven't implemented UEFI booting yet although this shouldn't
   take too much work. The only thing needed is drawing text on the linear framebuffer.
   We might also want to support coreboot linear framebuffer.

For `amd64` machines, Thinkpad X230 has been tested to work.

## Building

You will need to build under Linux (seL4 doesn't build under any other operating system).
You will need the following Python dependencies, and probably more.
```
jinja2
future
ply
setuptools
six
```
You will also need `cmake`, `clang`, `llvm` and `lld` as a basic toolchain. `clang`
is a native cross compiler that can generate both ELF and PE targets. GCC is not
supported but in theory can be made to work. You will need both an ELF toolchain
and a PE toolchain (and probably a ton of patience) if you want to make GCC work.
Have a look at `build.sh` for the build script. The preferred clang version is 15
but recent versions should all work. You also need the `cpio` utility for building
the initcpio. Finally, for the boot floppy and boot iso you will need the following
tools: `syslinux` (for boot floppy), `grub` and `xorriso` (for boot iso), and
`mtools` (for both).

Clone the project first (make sure you use `git clone --recurse-submodules` since
we include the seL4 kernel as a submodule) and then run
```
./build.sh [amd64] [release]
```
If you don't specify `amd64`, then it's an `i686` build. If you don't specify
`release`, then it's a debug build. To simulate using QEMU, run
```
./run.sh [amd64] [release] [extra-qemu-args]
```
Extra arguments are passed to QEMU. For instance, to run the `i386` release
build with PC speaker enabled in QEMU you can pass the following (this assumes
you are using a recent QEMU version and have pulseaudio)
```
./run.sh release -machine pcspk-audiodev=snd0 -audiodev pa,id=snd0
```
To create boot floopies, type
```
./mkfloopy.sh [amd64] [release]
```
You might need to type your password because the script needs to invoke `sudo`.
eVeRYtHiNg iS a fILe!!!

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

## Documentations

Documentations are located under the `docs` directory. For developers and those interested
in understanding the inner workings of Neptune OS, read the `Developer-Guide.md` which
starts with an architectural overview of the operating system and proceeds to explain
the various design decisions of individual OS components. It also contains the driver
porting guide for those interested in porting drivers from ReactOS.
