ARCH=i386
BUILD_TYPE=Debug
#BUILD_TYPE=Release
TOOLCHAIN=llvm

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

mkdir -p build/{pe,elf,images}

# Build ntos with ELF toolchain
cd build/elf
cmake ../../private/ntos \
      -DTRIPLE=${CLANG_ARCH}-pc-none-elf \
      -DCMAKE_TOOLCHAIN_FILE=../../sel4/${TOOLCHAIN}.cmake \
      -DCMAKE_BUILD_TYPE=${BUILD_TYPE} \
      -DKernelSel4Arch=$SEL4_ARCH -G Ninja
ninja all-elf

# Build ntdll and NT clients with PE toolchain
cd ../pe
cmake ../../private/ntdll \
      -DArch=${ARCH} \
      -DTRIPLE=${CLANG_ARCH}-pc-windows-msvc \
      -DCMAKE_TOOLCHAIN_FILE=../../private/ntdll/cmake/${TOOLCHAIN}.cmake \
      -DBUILD_ELF_OUT_DIR="${PWD}/../elf" \
      -G Ninja
ninja

# Build initcpio
if [[ ${CLANG_ARCH} == i686 ]]; then
    ELF_TARGET=elf32-i386
    ELF_ARCH=i386
    LLD_TARGET=elf_i386
else
    ELF_TARGET=elf64-x86-64
    ELF_ARCH=i386:x86-64
    LLD_TARGET=elf_x86_64
fi
#echo 'ntdll' > image-list
#cpio -H newc -o < image-list > initcpio
objcopy --input binary --output ${ELF_TARGET} --binary-architecture ${ELF_ARCH} \
	--rename-section .data=ntdll,CONTENTS,ALLOC,LOAD,READONLY,DATA \
	ntdll ntdll.o

# Link ntos and initcpio into final ntos image
cd ../images
if [[ ${BUILD_TYPE} == Release ]]; then
    LLD_OPTIONS="--gc-sections -O 3"
else
    LLD_OPTIONS=""
fi
ld.lld -m ${LLD_TARGET} ${LLD_OPTIONS} \
       --allow-multiple-definition \
       ../elf/libntos.a \
       ../elf/rtl/librtl.a \
       ../pe/ntdll.o \
       -T ../../private/ntos/ntos.lds \
       -o ntos
cp ../elf/kernel-$SEL4_ARCH-pc99 kernel

if [[ ${BUILD_TYPE} == Release ]]; then
    strip kernel
    strip ntos
fi
