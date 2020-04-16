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
objcopy --add-section initcpio=initcpio ../elf/ntsvc ../images/ntos
cp ../elf/kernel-$SEL4_ARCH-pc99 ../images/kernel

cd ..

if [[ ${BUILD_TYPE} == Release ]]; then
    strip images/kernel
    strip images/ntos
fi
