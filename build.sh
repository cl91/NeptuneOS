mkdir build
cd build
cmake ../private/ntsvc -DCMAKE_TOOLCHAIN_FILE=../sel4/llvm.cmake -DTRIPLE=i686-pc-none-elf -G Ninja
ninja
