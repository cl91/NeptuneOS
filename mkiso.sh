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
