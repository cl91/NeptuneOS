# Neptune OS: a Windows NT personality for the seL4 microkernel

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
components to support a reasonably complete storage driver and file system driver stack
with read-ahead and write-back caching support. This includes the storage class driver pair
(`classpnp.sys` and `disk.sys`), the `storport.sys` port driver, two storage miniport drivers
for AHCI (`storahci.sys`, from [Microsoft](https://github.com/microsoft/Windows-driver-samples/tree/main/storage/miniports/storahci)) and NVME (`stornvme.sys`, from [Open Fabrics Alliance](https://nvmexpress.org/open-fabrics-alliance-nvm-express-window-driver-1-4-released-december-8-2014/)) drives, as well as the partition manager
(`partmgr.sys`) and mount manager (`mountmgr.sys`). We also have a floppy controller
driver `fdc.sys` for the standard floppy controller on the PC. So far only one file system
driver, the FAT12/16/32 file system driver `fatfs.sys`, has been ported, but more is planned
in the future (in particular, `ext2fsd` so we can support ext2/3/4). Together with a
basic keyboard driver stack (keyboard class driver `kbdclass.sys` and the PS/2 port driver
`i8042prt.sys`), these allow us to run a basic command prompt `ntcmd.exe`, taken from the
ReactOS project, that supports most of the common shell commands, such as `pwd`, `cd`, `copy`,
`move`, `del`, `mount`, and `umount`. We also include a `beep.sys` driver which makes an
annoying sound on the PC speaker.

The entire system fits in a floppy and can be downloaded from
[Release v0.3.0003](https://github.com/cl91/NeptuneOS/releases/tag/v0.3.0003).
You can watch a short demo on [YouTube](https://www.youtube.com/watch?v=ejNeS7A5qq0).
You can also build it yourself. See the section on [Building](#building-and-running).

### Planned Features
Due to the lack of high quality open-source Windows device drivers, the main goal of the
next release is to design a subsystem which allows reusing of the Linux kernel device
drivers. The basic idea is building the Linux kernel as a library using the work done in
the LKL project, and writing a shim that facilitates communication between the NT Executive
process and the Linux device driver library using the standard IRP driver interface. For
more details, see issue [#19](https://github.com/cl91/NeptuneOS/issues/19).

## Minimal System Requirements

For i386 systems:

1. CPU: At least a Pentium 2 or equivalent: the default clang target is i686 which
   can generate instructions not implemented by 386, 486, and Pentium. Also, on x86
   the seL4 kernel assumes that the processor supports global pages (bit PGE in CR4).
   This is only supported in Pentium Pro (i686) and later. There is no way to disable
   this at compile time (see assembly routine `enable_paging` in `sel4/src/arch/x86/32/head.S`).
2. RAM: 32MB should be safe, can probably go lower.
3. BIOS or UEFI-based firmware, with a conformant ACPI implementation. This is more of a seL4
   requirement as it needs at least ACPI 3.0 for detecting the number of CPU cores. Note
   that most early 32-bit era PCs don't necessarily have a conformant ACPI (let alone
   ACPI 3.0) implementation, so this pretty much restricts you to Core 2 Duo era machines.
   Thinkpad X60 is a 32-bit laptop that has been tested to work.
4. VGA-compatible graphics controller. If you are booting under UEFI, the GOP linear
   framebuffer is used to render the text console. Similarly, if you use coreboot as
   your boot firmware and have enabled its builtin graphics initialization routines,
   its linear framebuffer will also be used to render our text console. Otherwise, the
   VGA text console will be used.
5. PS2 keyboard. Many BIOSes offer PS2 emulation for USB keyboards so connecting a USB
   keyboard might also work.

For amd64 systems the CPU and RAM requirements are slightly different:

1. CPU: At least Intel Ivy Bridge or equivalent: the default seL4 kernel is built with
   the `fsgsbase` instruction enabled. This is only supported on Ivy Bridge and later.
   To run amd64 builds on earlier CPUs you can disable fsgsbase instruction in
   `private/ntos/cmake/sel4.cmake`. Also we require cmpxchg16b, which is available since
   Nehalem, and quite possibly earlier (earlier Core 2 processors might need a microcode
   update).
2. RAM: 128MB should be safe, can probably go lower.

For `amd64` machines, Thinkpad X230, T420, X2100 (from 51NB), and the GPD Micropc (1st gen)
have all been tested to work.

## Building and running

You will need to build under Linux (macOS can potentially work, but I have not tested it).
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
To emulate using QEMU, run
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
To emulate an AHCI drive under QEMU, add the following extra QEMU arguments:
```
-drive file=disk.img,if=none,id=disk0 -device ich9-ahci,id=ahci0 -device ide-hd,drive=disk0,bus=ahci0.0
```
Replace `disk.img` with the path to your disk image. You may need to add `-boot a` so QEMU
will boot from the floppy disk. To emulate an NVME drive under QEMU, add the following
extra QEMU arguments:
```
-drive file=disk.img,format=raw,if=none,id=drv0 -device nvme,serial=deadbeef,drive=drv0,id=nvme0
```

### Debugging

By default, the debug build is built with serial port logging enabled. The default IO port
for the serial terminal that the seL4 kernel uses to output the debug logs is `0x3f8` and
can be configured in the boot command line using `console_port=0x###` and `debug_port=0x###`.
If your machine does not have a built-in serial port (a common case for laptops), you can use
a PCI(E) serial card or a Cardbus (expresscard) serial card. The form factor does not matter,
as long as the device shows up as a PCI device when the firmware enumerates the PCI bus. The
PCI(E) serial card must support IO port decoding. A tested PCI(E) serial bridge chip is Asix
Electronics AX99100. You can find products based on this chip in the form of PCIE/mini-PCIE/M2
and Cardbus/expresscard. In the picture below, an AX99100 M.2 serial bridge is connected to a
cardbus adapter, which is then plugged into the laptop's expresscard slot to enable serial
debugging.

![An AX99100 M.2 serial bridge connected to a cardbus adapter, which is then plugged into the
laptop's expresscard slot to enable serial debugging](docs/serial.jpg)

You need to find the bus/device/function number of the serial card you added as well as its
IO port range that the firmware has configured. Under GRUB, both information is available
using the `lspci -i` command. Look for the output such as
```
04:00.0 125b:9100 [0700] (Serial controller)
    I/O ports at d000 [size=8]
    Memory at fea00000 [size=4K]
```
Record the IO port ranges that the card decodes, and add `console_port=0xd000 debug_port=0xd000`
to the GRUB boot command line for seL4. If your boot firmware did not enable IO port decoding
for the card (this is quite common, so you most likely will need to do it), you will need to
manually enable it before loading the seL4 kernel, using `setpci -s 04:00.0 0x4.w=0x7`, where
`04:00.0` is the bus/device/function number of the serial port card. A full example is
```
menuentry 'Neptune OS amd64 release' --class os {
    insmod all_video
    insmod gzio
    insmod part_gpt
    insmod ext2
    echo 'Enabling serial port...'
    setpci -s 04:00.0 0x4.w=0x7
    echo 'Loading seL4 kernel ...'
    multiboot2 /neptuneos-kernel-amd64-release console_port=0xd000 debug_port=0xd000
    echo 'Loading NT Executive ...'
    module2 /neptuneos-ntos-amd64-release
}
```

Note USB serial ports will never work as these are USB devices rather than PCI(E) devices.

The debug build might run slowly especially if you turn on serial port logging.
You can turn off logging by modifying the master header of the NT Executive project
(see `private/ntos/inc/ntos.h`).

### Benchmarking

We have a basic disk IO benchmarking tool under `base/umtests`. It is a very simple-minded,
completely unscientific tool generated by ChatGPT that does random 4K and sequential 1MB read
(via Linux `read()` and NT `NtReadFile()`), single-threaded and uncached (`O_DIRECT` and
NT equivalent are applied to relevant system calls). It can be compiled and executed under
Linux using
```
cc -Wall -O3 base/umtests/diskbench.c
sudo ./a.out /dev/nvme0n1
```
You should see output such as the following
```
Random 4K Reads: 50.14 MB/s (7.079 seconds)
Sequential 1MB Reads: 3200.00 MB/s (0.080 seconds)
```
When compiled for Neptune OS, the tool will benchmark disk and file system IO for the first
harddrive and its first volume, respectively. The disk IO is sent to the storage driver stack
directly, and the volume IO is sent to the file system driver, which then forwards the IO to
the storage drivers. Consequently, the volume IO is significantly slower than the file system
driver due to the overhead of context switches and IRP serialization and deserialization. It
is expected that caching will improve overall system IO performance, but this remains to be
tested. For the raw disk reads, we seem to be able to saturate the AHCI bandwidth without any
problem, but getting the full NVME speed is a work-in-progress (see issue
[#40](https://github.com/cl91/NeptuneOS/issues/40)). If you have run any performance benchmarks
on your own machine, it would be appreciated if you could report them in the issue linked above.

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
