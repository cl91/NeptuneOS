ARCH=i386
BUILD_TYPE=Debug

if [[ ${1,,} == "release" || ${2,,} == "release" ]]; then
    BUILD_TYPE=Release
fi

if [[ $1 == "amd64" || $2 == "amd64" ]]; then
    ARCH=amd64
fi

BUILDDIR="build-$ARCH-${BUILD_TYPE,,}"
IMAGEDIR="images-$ARCH-${BUILD_TYPE,,}"

cd "$(dirname "$0")"
cd $BUILDDIR
mkdir -p iso/boot/grub
cp $IMAGEDIR/kernel iso/
cp $IMAGEDIR/ntos iso/
echo "set timeout=2" > iso/boot/grub/grub.cfg
echo "menuentry 'Neptune OS $ARCH ($BUILD_TYPE Build)' --class fedora --class gnu-linux --class gnu --class os {" >> iso/boot/grub/grub.cfg
cat <<EOF >> iso/boot/grub/grub.cfg
    insmod all_video
    insmod gzio
    insmod part_msdos
    insmod ext2
    set gfxmode=1024x768
    echo 'Loading seL4 Microkernel...'
    multiboot2 /kernel
    echo 'Loading NT Executive...'
    module2 /ntos
}
EOF
grub-mkrescue -o boot.iso iso/
