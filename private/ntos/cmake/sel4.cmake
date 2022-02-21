# Kernel configuration
set(KernelPlatform "pc99" CACHE STRING "")
set(KernelVerificationBuild OFF CACHE BOOL "")
set(KernelMaxNumNodes "1" CACHE STRING "")
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
set(KernelSupportPCID OFF CACHE BOOL "")
set(KernelIOMMU OFF CACHE BOOL "")
set(KernelFPU FXSAVE CACHE STRING "")
set(KernelHugePage OFF CACHE BOOL "")
set(KernelIRQController "PIC" CACHE STRING "")

# For small memory systems, reduce the root cnode size.
# For large memory systems, increase the root cnode size.
# The numbers below are for a moderate system (256MB for x32, 4G for x64).
# On x32 each CNode slot costs 16 bytes. 2^18 slots cost 4M.
# On x64 each CNode slot costs 32 bytes. 2^20 slots cost 32M.
if(KernelSel4Arch STREQUAL "ia32")
    set(Arch "i386" CACHE STRING "")
    set(KernelFSGSBase msr CACHE STRING "")
    set(KernelSetTLSBaseSelf ON CACHE BOOL "")
    set(KernelRootCNodeSizeBits 18 CACHE STRING "")
    set(KernelMaxNumBootinfoUntypedCaps 230 CACHE STRING "")
elseif(KernelSel4Arch STREQUAL "x86_64")
    set(Arch "amd64" CACHE STRING "")
    set(KernelFSGSBase inst CACHE STRING "")
    set(KernelSetTLSBaseSelf OFF CACHE BOOL "")
    set(KernelRootCNodeSizeBits 20 CACHE STRING "")
    set(KernelMaxNumBootinfoUntypedCaps 128 CACHE STRING "")
else()
    message(FATAL_ERROR "Unsupported architecture: ${KernelSel4Arch}")
endif()

include(${KERNEL_PATH}/configs/seL4Config.cmake)

sel4_import_kernel()
sel4_import_libsel4()
