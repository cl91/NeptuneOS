# Kernel configuration
set(KernelVerificationBuild OFF CACHE BOOL "")
set(KernelOptimisation "-O2" CACHE STRING "")
set(KernelRetypeFanOutLimit "256" CACHE STRING "")
set(KernelBenchmarks "none" CACHE STRING "")
set(KernelDangerousCodeInjection OFF CACHE BOOL "")
set(KernelFastpath ON CACHE BOOL "")
if((${CMAKE_BUILD_TYPE} STREQUAL "Debug"))
    set(KernelDebugBuild ON CACHE BOOL "")
    set(KernelPrinting ON CACHE BOOL "")
    # This redirects kernel invocation errors to the IPC buffer. We
    # don't want this. The kernel invocation error messages will be
    # displayed on the serial console.
    set(KernelInvocationReportErrorIPC OFF CACHE BOOL "")
else()
    set(KernelDebugBuild OFF CACHE BOOL "")
    set(KernelPrinting OFF CACHE BOOL "")
endif()
set(KernelNumDomains 1 CACHE STRING "")

# For small memory systems, reduce the root cnode size.
# For large memory systems, increase the root cnode size.
# The numbers below are for a moderate system (256MB for x32, 4G for x64).
# On 32-bit systems each CNode slot costs 16 bytes. 2^18 slots cost 4M.
# On 64-bit systems each CNode slot costs 32 bytes. 2^20 slots cost 32M.
if(Arch STREQUAL "i386")
    set(KernelRootCNodeSizeBits 18 CACHE STRING "")
    set(KernelMaxNumBootinfoUntypedCaps 256 CACHE STRING "")
elseif("${Arch}" MATCHES "^(amd64|arm64)$")
    set(KernelRootCNodeSizeBits 20 CACHE STRING "")
    set(KernelMaxNumBootinfoUntypedCaps 230 CACHE STRING "")
else()
    message(FATAL_ERROR "Unsupported architecture: ${Arch}")
endif()

if("${Arch}" MATCHES "^(i386|arm64)$")
    set(KernelMaxNumNodes 32 CACHE STRING "")
elseif(Arch STREQUAL "amd64")
    set(KernelMaxNumNodes 64 CACHE STRING "")
else()
    message(FATAL_ERROR "Unsupported architecture: ${Arch}")
endif()

if ("${Arch}" MATCHES "^(i386|amd64)$")
    set(KernelSupportPCID OFF CACHE BOOL "")
    set(KernelIOMMU OFF CACHE BOOL "")
    set(KernelFPU FXSAVE CACHE STRING "")
    set(KernelHugePage OFF CACHE BOOL "")
    set(KernelIRQController "IOAPIC" CACHE STRING "")
endif()

if(Arch STREQUAL "i386")
    set(KernelFSGSBase gdt CACHE STRING "")
    set(KernelSetTLSBaseSelf ON CACHE BOOL "")
    set(KernelLAPICMode "XAPIC" CACHE STRING "")
    set(KernelMaxNumIOAPIC 4 CACHE STRING "")
elseif(Arch STREQUAL "amd64")
    set(KernelFSGSBase inst CACHE STRING "")
    set(KernelSetTLSBaseSelf OFF CACHE BOOL "")
    set(KernelLAPICMode "X2APIC" CACHE STRING "")
    set(KernelMaxNumIOAPIC 16 CACHE STRING "")
elseif(Arch STREQUAL "arm64")
else()
    message(FATAL_ERROR "Unsupported architecture: ${Arch}")
endif()

include(${KERNEL_PATH}/configs/seL4Config.cmake)

sel4_import_kernel()
sel4_import_libsel4()
