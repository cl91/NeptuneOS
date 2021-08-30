ARCH=i386
BUILD_TYPE=Debug
TOOLCHAIN=llvm

if [[ ${1,,} == "release" || ${2,,} == "release" ]]; then
    BUILD_TYPE=Release
fi

if [[ $1 == "amd64" || $2 == "amd64" ]]; then
    ARCH=amd64
fi

if [[ ${ARCH} == "i386" ]]; then
    CLANG_ARCH=i686
    SEL4_ARCH=ia32
elif [[ ${ARCH} == "amd64" ]]; then
    CLANG_ARCH=x86_64
    SEL4_ARCH=x86_64
else
    echo "Unsupported arch ${ARCH}"
    exit 1
fi

BUILDDIR="build-$ARCH-${BUILD_TYPE,,}"
IMAGEDIR="images-$ARCH-${BUILD_TYPE,,}"

function build_failed
{
    echo "#################################"
    echo "         Build failed."
    echo "#################################"
    exit 1
}

echo
echo "####################################################"
echo "     Building ${BUILD_TYPE} version for ${ARCH}"
echo "####################################################"

cd "$(dirname "$0")"

mkdir -p $BUILDDIR/{pe,elf,$IMAGEDIR}

# Build ntos with ELF toolchain
cd $BUILDDIR/elf
echo
echo "---- Building ELF targets ----"
echo
cmake ../../private/ntos \
      -DTRIPLE=${CLANG_ARCH}-pc-none-elf \
      -DCMAKE_TOOLCHAIN_FILE=../../sel4/${TOOLCHAIN}.cmake \
      -DCMAKE_BUILD_TYPE=${BUILD_TYPE} \
      -DSTRUCTURES_GEN_H_ORIG=${PWD}/kernel/generated/arch/object/structures_gen.h \
      -DSTRUCTURES_GEN_DIR=${PWD} \
      -DGIT_HEAD_SHA_SHORT="$(git rev-parse --short HEAD)" \
      -DKernelSel4Arch=$SEL4_ARCH -G Ninja
ninja all-elf || build_failed

# Build ntdll and NT clients with PE toolchain
cd ../pe
echo
echo "---- Building PE targets ----"
echo
# For amd64 PE targets, since the ELF toolchain assumes sizeof(long) == 8
# and the PE toolchain assumes sizeof(long) == 4, we need to modify the
# libsel4 sel4_arch headers to undefine the macro SEL4_INT64_IS_LONG and
# define SEL4_INT64_IS_LONG_LONG. So far this seems to work and produce
# valid seL4 system calls. However we need to be very careful.
mkdir -p libsel4-pe/generated
cp ../elf/structures_gen.h libsel4-pe/generated || build_failed
cp -r ../../sel4/libsel4/sel4_arch_include/$SEL4_ARCH libsel4-pe/sel4_arch_include || build_failed
cp -r ../elf/kernel/gen_config libsel4-pe/generated/kernelconfig || build_failed
for i in gen_config autoconf include arch_include sel4_arch_include; do
    cp -r ../elf/libsel4/$i libsel4-pe/generated || build_failed
done
if [[ $ARCH == "amd64" ]]; then
    cat <<EOF > libsel4-pe/sel4_arch_include/sel4/sel4_arch/simple_types.h
#pragma once

#define SEL4_WORD_IS_UINT64
#define SEL4_INT64_IS_LONG_LONG
EOF
    sed -i '/assert_size_correct(long/d' libsel4-pe/generated/include/interfaces/sel4_client.h || build_failed
    sed -i '/assert_size_correct(seL4_X86_VMAttributes,/d' libsel4-pe/generated/include/interfaces/sel4_client.h || build_failed
fi
cmake ../../private/ntdll \
      -DArch=${ARCH} \
      -DTRIPLE=${CLANG_ARCH}-pc-windows-msvc \
      -DCMAKE_TOOLCHAIN_FILE=../../private/ntdll/cmake/${TOOLCHAIN}.cmake \
      -DLIBSEL4_PE_HEADERS_DIR="${PWD}/libsel4-pe" \
      -DSTRUCTURES_GEN_DIR=${PWD}/libsel4-pe/generated \
      -G Ninja
ninja || build_failed

# Build initcpio
echo
echo "---- Building INITCPIO ----"
echo
if [[ ${CLANG_ARCH} == i686 ]]; then
    ELF_TARGET=elf32-i386
    ELF_ARCH=i386
    LLD_TARGET=elf_i386
else
    ELF_TARGET=elf64-x86-64
    ELF_ARCH=i386:x86-64
    LLD_TARGET=elf_x86_64
fi
echo 'ntdll' > image-list
cpio -H newc -o < image-list > initcpio
objcopy --input binary --output ${ELF_TARGET} --binary-architecture ${ELF_ARCH} \
	--rename-section .data=initcpio,CONTENTS,ALLOC,LOAD,READONLY,DATA \
	initcpio initcpio.o
if [[ $? == 0 ]]; then
    echo "Success."
else
    build_failed
fi

# Link ntos and initcpio into final ntos image
echo
echo "---- Linking NTOS image ----"
echo
cd ../$IMAGEDIR
cp ../elf/kernel-$SEL4_ARCH-pc99 kernel || build_failed
if [[ ${BUILD_TYPE} == Release ]]; then
    LLD_OPTIONS="--gc-sections -O 3"
else
    LLD_OPTIONS=""
fi
ld.lld -m ${LLD_TARGET} ${LLD_OPTIONS} \
       --allow-multiple-definition \
       ../elf/libntos.a \
       ../elf/rtl/librtl.a \
       ../pe/initcpio.o \
       -T ../../private/ntos/ntos.lds \
       -o ntos
if [[ $? == 0 ]]; then
    echo "Success."
else
    build_failed
fi

if [[ ${BUILD_TYPE} == Release ]]; then
    echo
    echo "---- Stripping symbols for release build ----"
    echo
    strip kernel
    strip ntos
    if [[ $? == 0 ]]; then
	echo "Success."
    fi
fi
echo
echo "####################################"
echo "         Build succeeded!"
echo "####################################"
