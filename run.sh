qemu-system-x86_64  -cpu Nehalem,-vme,+pdpe1gb,-xsave,-xsaveopt,-xsavec,+fsgsbase,-invpcid,enforce -m size=400M  -kernel build/images/kernel -initrd build/images/ntos,build/pe/initcpio
