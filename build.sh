#CLANG_ARCH=x86_64
#SEL4_ARCH=x86_64
CLANG_ARCH=i686
SEL4_ARCH=ia32

mkdir -p build/{pe,elf,images}
cd build/elf
cmake ../../private/ntsvc -DCMAKE_TOOLCHAIN_FILE=../../sel4/llvm.cmake -DTRIPLE=${CLANG_ARCH}-pc-none-elf -DCMAKE_BUILD_TYPE=Debug -DKernelSel4Arch=$SEL4_ARCH -G Ninja
ninja
cd ../pe
echo 'Hello, world!' > hello.txt
echo 'hello.txt' > image-list
cpio -o < image-list > initcpio
objcopy --add-section initcpio=initcpio ../elf/ntsvc ../images/ntos
cp ../elf/kernel-$SEL4_ARCH-pc99 ../images/kernel
