# Now all platform compilation flags have been set, we can check the compiler against flags
#check_arch_compiler()

# Kernel configuration
set(KernelPlatform "pc99" CACHE STRING "")
set(KernelSel4Arch "x86_64" CACHE STRING "")
set(KernelVerificationBuild OFF CACHE BOOL "")
set(KernelMaxNumNodes "1" CACHE STRING "")
set(KernelOptimisation "-O2" CACHE STRING "")
set(KernelRetypeFanOutLimit "256" CACHE STRING "")
set(KernelBenchmarks "none" CACHE STRING "")
set(KernelDangerousCodeInjection OFF CACHE BOOL "")
set(KernelFastpath ON CACHE BOOL "")
set(KernelDebugBuild ON CACHE BOOL "")
set(KernelPrinting ON CACHE BOOL "")
set(KernelNumDomains 16 CACHE STRING "")
set(KernelRootCNodeSizeBits 19 CACHE STRING "")
set(KernelMaxNumBootinfoUntypedCaps 230 CACHE STRING "")
set(KernelSupportPCID OFF CACHE BOOL "")
set(KernelFSGSBase msr CACHE STRING "")
set(KernelIOMMU OFF CACHE BOOL "")
set(KernelFPU FXSAVE CACHE STRING "")

include(${KERNEL_PATH}/configs/seL4Config.cmake)

sel4_import_kernel()
sel4_import_libsel4()
