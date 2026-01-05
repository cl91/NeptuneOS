ARCH=i386
OVMFARCH=x64
BUILD_TYPE=Debug
BOOT_TYPE=iso
UEFI_BOOT=0

for var in "$@"; do
    if [ "${var,,}" == 'release' ]; then
        BUILD_TYPE=release
    fi
    if [ "${var,,}" == 'reldbginfo' ]; then
        BUILD_TYPE=relwithdebinfo
    fi
    if [ "${var,,}" == 'amd64' ]; then
        ARCH=amd64
        OVMFARCH=x64
    fi
    if [ "${var,,}" == 'direct' ]; then
        BOOT_TYPE=direct
    fi
    if [ "${var,,}" == 'floppy' ]; then
        BOOT_TYPE=floppy
    fi
    if [ "${var,,}" == 'iso' ]; then
        BOOT_TYPE=iso
    fi
    if [ "${var,,}" == 'uefi' ]; then
        UEFI_BOOT=1
    fi
done

BUILDDIR="build-$ARCH-${BUILD_TYPE,,}"
IMAGEDIR="images-$ARCH-${BUILD_TYPE,,}"

cd "$(dirname "$0")"

if [[ ARCH == "i386" ]]; then
    QEMU="qemu-system-i386  -cpu pentium3,-vme,-pdpe1gb,-xsave,-xsaveopt,-xsavec,-fsgsbase,-invpcid,enforce"
else
    QEMU="qemu-system-x86_64  -cpu IvyBridge,+fsgsbase,-pdpe1gb -machine q35"
fi

QEMU+=" -vga virtio -device pvpanic-pci -action panic=pause"

declare -a ARGS
for var in "$@"; do
    # Ignore known bad arguments
    if [ "${var,,}" == 'release' ]; then
        continue
    fi
    if [ "${var,,}" == 'reldbginfo' ]; then
        continue
    fi
    if [ "${var,,}" == 'debug' ]; then
        continue
    fi
    if [ "${var,,}" == 'amd64' ]; then
        continue
    fi
    if [ "${var,,}" == 'i386' ]; then
        continue
    fi
    if [ "${var,,}" == 'direct' ]; then
        continue
    fi
    if [ "${var,,}" == 'floppy' ]; then
        continue
    fi
    if [ "${var,,}" == 'iso' ]; then
        continue
    fi
    if [ "${var,,}" == 'uefi' ]; then
        continue
    fi
    ARGS[${#ARGS[@]}]="$var"
done

if [[ $BOOT_TYPE == "direct" ]]; then
    BOOTMEDIA="-kernel $BUILDDIR/$IMAGEDIR/kernel -initrd $BUILDDIR/$IMAGEDIR/ntos"
elif [[ $BOOT_TYPE == "floppy" ]]; then
    BOOTMEDIA="-fda $BUILDDIR/floppy.img"
elif [[ $BOOT_TYPE == "iso" ]]; then
    BOOTMEDIA="-cdrom $BUILDDIR/boot.iso"
fi

if (( $UEFI_BOOT )); then
    BIOS="-bios /usr/share/ovmf/$OVMFARCH/OVMF.4m.fd"
else
    BIOS=""
fi

$QEMU -m size=400M -serial stdio $BOOTMEDIA $BIOS "${ARGS[@]}"
