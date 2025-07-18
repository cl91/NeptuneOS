ARCH=i386
BUILD_TYPE=Debug
BUILD_TAG=CHK

if [[ ${1,,} == "release" || ${2,,} == "release" ]]; then
    BUILD_TYPE=Release
    BUILD_TAG=FRE
fi

if [[ $1 == "amd64" || $2 == "amd64" ]]; then
    ARCH=amd64
fi

BUILDDIR="build-$ARCH-${BUILD_TYPE,,}"

cd "$(dirname "$0")"
cd $BUILDDIR
FLOPPYIMG=posix.img
if [[ -e $FLOPPYIMG ]]; then
    rm $FLOPPYIMG
fi
mkfs.msdos -C $FLOPPYIMG 1440 -n PSX${ARCH^^}${BUILD_TAG}
mcopy -i $FLOPPYIMG posix/psxss/psxss.exe ::psxss.exe
mcopy -i $FLOPPYIMG posix/psxdll/psxdll.so ::psxdll.so
