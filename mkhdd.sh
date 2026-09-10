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
elif [[ ${1,,} == "reldbginfo" || ${2,,} == "reldbginfo" ]]; then
    BUILD_TYPE=RelWithDebInfo
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
mkdir -p hdd
SYSLINUXCFG=hdd/syslinux.cfg
cat <<EOF > $SYSLINUXCFG
DEFAULT neptune
SERIAL 0 115200
PROMPT 0
TIMEOUT 300
UI menu.c32
EOF
echo "MENU TITLE Neptune OS $ARCH ${BUILD_TYPE}" >> $SYSLINUXCFG
cat <<EOF >> $SYSLINUXCFG
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
echo "    MENU LABEL Neptune OS $ARCH ${BUILD_TYPE}" >> $SYSLINUXCFG
cat <<EOF >> $SYSLINUXCFG
    KERNEL mboot.c32
    APPEND kernel --- ntos
EOF

KERNELGZ=hdd/kernel.gz
NTOSGZ=hdd/ntos.gz
gzip -c $IMAGEDIR/$KERNEL > $KERNELGZ
gzip -c $IMAGEDIR/$NTOS > $NTOSGZ

IMG="disk.img"
SIZE_MB=300

dd if=/dev/zero of="$IMG" bs=1M count=$SIZE_MB status=progress

PART_START=2048
PART_OFFSET=$(($PART_START * 512))
NSECTORS=$(($SIZE_MB * 2048))
LAST_SECTOR=$(($NSECTORS - 1))
PART_SECTORS=$(($NSECTORS - $PART_START))

printf "o\nn\np\n1\n$PART_START\n$LAST_SECTORS\nt\nc\na\nw\n" > hdd/script

cat hdd/script | fdisk $IMG
mformat -i "${IMG}@@${PART_OFFSET}" -T $PART_SECTORS -F ::
dd if="$SYSLINUX_FILES/mbr.bin" of="$IMG" conv=notrunc
syslinux -t $PART_OFFSET --install "$IMG"

mcopy -i "${IMG}@@${PART_OFFSET}" $KERNELGZ ::kernel
mcopy -i "${IMG}@@${PART_OFFSET}" $NTOSGZ ::ntos
mcopy -i "${IMG}@@${PART_OFFSET}" $SYSLINUXCFG ::syslinux.cfg
mcopy -i "${IMG}@@${PART_OFFSET}" $SYSLINUX_FILES/mboot.c32 $SYSLINUX_FILES/menu.c32 $SYSLINUX_FILES/libutil.c32 $SYSLINUX_FILES/libcom32.c32 ::
mcopy -i "${IMG}@@${PART_OFFSET}" base/umtests/umtests.exe ::

echo "Done: $IMG created"
