if [[ $(which syslinux) == "" ]]; then
    echo "You need to install syslinux"
    exit 1
fi

SYSLINUX_FILES="/usr/lib/syslinux/bios"
if ! [[ -f "${SYSLINUX_FILES}/mboot.c32" ]]; then
    echo "You need to edit the SYSLINUX_FILES variable of this script" \
	 "to point to where the syslinux boot files are located."
    exit 1
fi

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

if [[ ${BUILD_TYPE} == Release ]]; then
    KERNEL=kernel
    NTOS=ntos
else
    KERNEL=kernel-stripped
    NTOS=ntos-stripped
fi

cd "$(dirname "$0")"
cd $BUILDDIR
FLOPPYIMG=floppy.img
FLOPPYOUT=floppyimgroot
if [[ -e $FLOPPYIMG ]]; then
    rm $FLOPPYIMG
fi
if [[ -e $FLOPPYOUT ]]; then
    rm -rf $FLOPPYOUT
fi
SYSLINUXCFGTMP=$(mktemp /tmp/syslinux.XXXXXXXX)
mkdir -p $FLOPPYOUT
mkfs.msdos -C $FLOPPYIMG 1440
syslinux --install $FLOPPYIMG
cat <<EOF > $SYSLINUXCFGTMP
DEFAULT neptune
SERIAL 0 115200
PROMPT 0
TIMEOUT 300
UI menu.c32
EOF
echo "MENU TITLE Neptune OS $ARCH ${BUILD_TYPE}" >> $SYSLINUXCFGTMP
cat <<EOF >> $SYSLINUXCFGTMP
MENU COLOR border       30;44   #40ffffff #a0000000 std
MENU COLOR title        1;36;44 #9033ccff #a0000000 std
MENU COLOR sel          7;37;40 #e0ffffff #20ffffff all
MENU COLOR unsel        37;44   #50ffffff #a0000000 std
MENU COLOR help         37;40   #c0ffffff #a0000000 std
MENU COLOR timeout_msg  37;40   #80ffffff #00000000 std
MENU COLOR timeout      1;37;40 #c0ffffff #00000000 std
MENU COLOR msg07        37;40   #90ffffff #a0000000 std
MENU COLOR tabmsg       31;40   #30ffffff #00000000 std

LABEL neptune
EOF
echo "    MENU LABEL Neptune OS $ARCH ${BUILD_TYPE}" >> $SYSLINUXCFGTMP
cat <<EOF >> $SYSLINUXCFGTMP
    KERNEL mboot.c32
    APPEND kernel --- ntos
EOF

KERNELTMP=$(mktemp /tmp/neptuneos-kernel.XXXXXXXX)
NTOSTMP=$(mktemp /tmp/neptuneos-ntos.XXXXXXXX)
gzip -c $IMAGEDIR/$KERNEL > $KERNELTMP
gzip -c $IMAGEDIR/$NTOS > $NTOSTMP

echo "This script will now ask for your password, because eVeRyThInG iS a fIlE"
sudo mount $FLOPPYIMG $FLOPPYOUT
sudo cp $KERNELTMP $FLOPPYOUT/kernel
sudo cp $NTOSTMP $FLOPPYOUT/ntos
sudo cp $SYSLINUX_FILES/mboot.c32 $FLOPPYOUT
sudo cp $SYSLINUX_FILES/menu.c32 $FLOPPYOUT
sudo cp $SYSLINUX_FILES/libutil.c32 $FLOPPYOUT
sudo cp $SYSLINUX_FILES/libcom32.c32 $FLOPPYOUT
sudo cp $SYSLINUXCFGTMP $FLOPPYOUT/syslinux.cfg
sudo umount $FLOPPYOUT

rm $KERNELTMP $NTOSTMP $SYSLINUXCFGTMP
