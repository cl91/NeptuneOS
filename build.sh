mkdir -p build/{pe,elf,images}
cd build/elf
cmake ../../private/ntsvc -DCMAKE_TOOLCHAIN_FILE=../../sel4/llvm.cmake -DTRIPLE=i686-pc-none-elf -G Ninja
ninja
cd ../pe
echo 'Hello, world!' > hello.txt
echo 'hello.txt' > image-list
cpio -o < image-list > initcpio
objcopy --add-section initcpio=initcpio ../elf/ntsvc ../images/ntos
