set(LLVM_TOOLCHAIN ON)

set(CMAKE_AR "llvm-ar" CACHE FILEPATH "Archiver")

set(CMAKE_ASM_COMPILER "clang")
set(CMAKE_ASM_COMPILER_ID Clang)
set(CMAKE_ASM_COMPILER_TARGET ${TRIPLE})

string(APPEND asm_common_flags " -Wno-unused-command-line-argument")

set(CMAKE_C_COMPILER "clang")
set(CMAKE_C_COMPILER_ID Clang)
set(CMAKE_C_COMPILER_TARGET ${TRIPLE})

set(CMAKE_CXX_COMPILER "clang++")
set(CMAKE_CXX_COMPILER_ID Clang)
set(CMAKE_CXX_COMPILER_TARGET ${TRIPLE})

string(APPEND c_common_flags " -Qunused-arguments")
string(APPEND c_common_flags " -Wno-constant-logical-operand")

set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)

set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)