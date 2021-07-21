ARCH=i386
BUILD_TYPE=Debug

if [[ ${1,,} == "release" || ${2,,} == "release" ]]; then
    BUILD_TYPE=release
fi

if [[ $1 == "amd64" || $2 == "amd64" ]]; then
    ARCH=amd64
fi

BUILDDIR="build-$ARCH-${BUILD_TYPE,,}"
IMAGEDIR="images-$ARCH-${BUILD_TYPE,,}"

cd "$(dirname "$0")"

qemu-system-i386  -cpu pentium3,-vme,-pdpe1gb,-xsave,-xsaveopt,-xsavec,-fsgsbase,-invpcid,enforce -m size=400M -serial stdio  -kernel $BUILDDIR/$IMAGEDIR/kernel -initrd $BUILDDIR/$IMAGEDIR/ntos
