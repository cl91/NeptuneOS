qemu-system-x86_64  -cpu Nehalem,-vme,+pdpe1gb,-xsave,-xsaveopt,-xsavec,-fsgsbase,-invpcid,enforce -m size=512M  -kernel build/kernel-ia32-pc99 -initrd build/ntsvc
