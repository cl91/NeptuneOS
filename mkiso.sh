ARCH=i386
BUILD_TYPE=Debug

args=(${@,,})

if [[ ${args[@]} =~ "release" ]]; then
    BUILD_TYPE=Release
elif [[ ${args[@]} =~ "reldbginfo" ]]; then
    BUILD_TYPE=RelWithDebInfo
fi

if [[ ${args[@]} =~ "amd64" ]]; then
    ARCH=amd64
fi

if [[ ${BUILD_TYPE} == Release ]]; then
    KERNEL=kernel
    NTOS=ntos
else
    KERNEL=kernel-stripped
    NTOS=ntos-stripped
fi

BUILDDIR="build-$ARCH-${BUILD_TYPE,,}"
IMAGEDIR="images-$ARCH-${BUILD_TYPE,,}"

cd "$(dirname "$0")"
cd $BUILDDIR
mkdir -p iso/boot/grub
gzip -c $IMAGEDIR/$KERNEL > iso/kernel.gz
gzip -c $IMAGEDIR/$NTOS > iso/ntos.gz
echo "set timeout=2" > iso/boot/grub/grub.cfg
echo "menuentry 'Neptune OS $ARCH ($BUILD_TYPE Build)' --class fedora --class gnu-linux --class gnu --class os {" >> iso/boot/grub/grub.cfg
cat <<EOF >> iso/boot/grub/grub.cfg
    insmod all_video
    insmod gzio
    insmod part_msdos
    insmod ext2
    set gfxmode=1024x768
    echo 'Loading seL4 Microkernel...'
    multiboot2 /kernel.gz
    echo 'Loading NT Executive...'
    module2 /ntos.gz
}
EOF
grub-mkrescue -o boot.iso iso/

IMG="efi_disk.img"
SIZE_MB=300

# 1. Create raw disk image
dd if=/dev/zero of="$IMG" bs=1M count=$SIZE_MB status=progress

# 2. Create GPT partition table + one EFI partition
#    - partition 1: type EF00 (EFI System Partition)
#    - starts at 1MiB (2048 sectors)
sgdisk -o "$IMG"
sgdisk -n 1:2048:0 -t 1:ef00 -c 1:"EFI System Partition" "$IMG"

# 3. Compute partition offset (in bytes) and total sectors
#    GPT + alignment => partition starts at sector 2048
#    FAT will be written directly using mtools offset syntax
PART_OFFSET=$(($(sgdisk -i 1 "$IMG"  | grep 'First sector' | cut -d' ' -f3) * 512))
PART_SECTORS=$(sgdisk -i 1 "$IMG" | grep 'Partition size' | cut -d' ' -f3)

# 4. Format partition as FAT32
#    "::" is the FAT root directory
mformat -i "${IMG}@@${PART_OFFSET}" -T $PART_SECTORS -F ::

# Build standalone EFI binary
grub-mkstandalone \
    -O x86_64-efi \
    -o BOOTX64.EFI \
    -d /usr/lib/grub/x86_64-efi \
    "boot/grub/grub.cfg=iso/boot/grub/grub.cfg" \
    "kernel.gz=iso/kernel.gz" \
    "ntos.gz=iso/ntos.gz"

# 6. Copy GRUB EFI binary into FAT partition
mmd -i "${IMG}@@${PART_OFFSET}" ::/EFI
mmd -i "${IMG}@@${PART_OFFSET}" ::/EFI/BOOT

mcopy -i "${IMG}@@${PART_OFFSET}" BOOTX64.EFI ::/EFI/BOOT/
mcopy -i "${IMG}@@${PART_OFFSET}" base/umtests/umtests.exe ::/umtests.exe

rm BOOTX64.EFI

echo "Done: $IMG created"
