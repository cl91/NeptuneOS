#CLANG_ARCH=x86_64
#SEL4_ARCH=x86_64
CLANG_ARCH=i686
SEL4_ARCH=ia32
BUILD_TYPE=Debug
#BUILD_TYPE=Release
TOOLCHAIN=llvm

mkdir -p build/{pe,elf,images}
cd build/elf
cmake ../../private/ntsvc -DCMAKE_TOOLCHAIN_FILE=../../sel4/${TOOLCHAIN}.cmake	\
    -DTRIPLE=${CLANG_ARCH}-pc-none-elf -DCMAKE_BUILD_TYPE=${BUILD_TYPE}		\
    -DKernelSel4Arch=$SEL4_ARCH -G Ninja
ninja
cd ../pe
echo 'Hello, world!' > hello.txt
echo 'hello.txt' > image-list
cpio -o < image-list > initcpio
if [[ ${CLANG_ARCH} == i686 ]]; then
    ELF_TARGET=elf32-i386
    ELF_ARCH=i386
    LLD_TARGET=elf_i386
else
    ELF_TARGET=elf64-x86-64
    ELF_ARCH=i386:x86-64
    LLD_TARGET=elf_x86_64
fi
objcopy --input binary --output ${ELF_TARGET} --binary-architecture ${ELF_ARCH} \
	--rename-section .data=.rodata,CONTENTS,ALLOC,LOAD,READONLY,DATA \
	initcpio initcpio.o

cd ../images
ld.lld -m ${LLD_TARGET} \
       ../elf/libntsvc.a \
       ../elf/ntos/libntos.a ../elf/rtl/librtl.a \
       ../pe/initcpio.o \
       -T ../../private/ntsvc/ntsvc.lds \
       -o ntos
cp ../elf/kernel-$SEL4_ARCH-pc99 kernel

if [[ ${BUILD_TYPE} == Release ]]; then
    strip kernel
    strip ntos
fi
