qemu-system-i386  -cpu pentium3,-vme,-pdpe1gb,-xsave,-xsaveopt,-xsavec,-fsgsbase,-invpcid,enforce -m size=400M  -kernel build/images/kernel -initrd build/images/ntos -serial stdio $@
