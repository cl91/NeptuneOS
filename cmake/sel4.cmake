cmake_minimum_required(VERSION 3.7.2)

enable_language(C)
enable_language(CXX)
enable_language(ASM)

# Hide cmake variables that will just confuse the user
mark_as_advanced(
    FORCE
    CMAKE_INSTALL_PREFIX
    CROSS_COMPILER_PREFIX
    EXECUTABLE_OUTPUT_PATH
    CMAKE_BACKWARDS_COMPATIBILITY
    LIBRARY_OUTPUT_PATH
    CMAKE_ASM_COMPILER
    CMAKE_C_COMPILER
)

find_file(KERNEL_PATH sel4 PATHS "${CMAKE_SOURCE_DIR}/.." NO_CMAKE_FIND_ROOT_PATH)
mark_as_advanced(FORCE KERNEL_PATH)
if("${KERNEL_PATH}" STREQUAL "KERNEL_PATH-NOTFOUND")
    message(FATAL_ERROR "Failed to find kernel. Consider cmake -DKERNEL_PATH=/path/to/kernel")
endif()

# Give an explicit build directory as there is no guarantee this is actually
# subdirectory from the root source hierarchy
add_subdirectory("${KERNEL_PATH}" sel4)
# Include helpers from the kernel
include(${KERNEL_HELPERS_PATH})

# Make build options a visible choice, default it to Debug
set(
    CMAKE_BUILD_TYPE "Debug"
    CACHE STRING "Set the user mode build type (kernel build ignores this)"
)
set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS "Debug;Release;RelWithDebInfo;MinSizeRel")
mark_as_advanced(CLEAR CMAKE_BUILD_TYPE)

# Now all platform compilation flags have been set, we can check the compiler against flags
#check_arch_compiler()

add_subdirectory("${KERNEL_PATH}/libsel4" libsel4)
