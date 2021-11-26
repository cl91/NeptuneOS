Minimal System Requirements
===========================

For i386 systems (should probably be called i686):

1. CPU: At least a Pentium 2 or equivalent: the default clang target is i686 which can generate instructions not implemented by 386, 486, and Pentium.
2. RAM: 32MB should be safe, can probably go lower.
3. VGA-compatible graphics controller.
4. PC BIOS or compatible. We haven't implemented UEFI yet although this shouldn't take too much work. The only thing needed is drawing text on the linear framebuffer. We might also support coreboot linear framebuffer.

For amd64 systems:

1. CPU: At least Intel Ivy Bridge or equivalent: the default seL4 kernel is built with the fsgsbase instruction enabled. This is only supported on Ivy Bridge and later. To run amd64 builds on earlier CPUs you can disable fsgsbase instruction in `private/ntos/cmake/sel4.cmake`. Also we require cmpxchg16b, which is available since Nehalem, and quite possibly earlier (earlier Core 2 processors might need a microcode update).
2. RAM: 128MB should be safe, can probably go lower.
3. VGA-compatible graphics controller.
4. Legacy BIOS booting. Most UEFI firmware can boot from legacy BIOS operating systems by enabling a setting.