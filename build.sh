# Default architecture and build type
ARCH=i386
DEFAULT_PLATFORM=pc99
BUILD_TYPE=Debug
TOOLCHAIN=llvm

if [[ $TOOLCHAIN != "llvm" ]]; then
    echo "There is a GCC build profile but it is totally untested."
    echo "Use the LLVM toolchain unless you want to try to make GCC work."
    exit 1
fi

args=(${@,,})

if [[ ${args[@]} =~ "release" ]]; then
    BUILD_TYPE=Release
elif [[ ${args[@]} =~ "reldbginfo" ]]; then
    BUILD_TYPE=RelWithDebInfo
fi

if [[ ${args[@]} =~ "amd64" ]]; then
    ARCH=amd64
fi

if [[ ${args[@]} =~ "arm64" ]]; then
    ARCH=arm64
fi

if [[ ${ARCH} == "i386" ]]; then
    SEL4_ARCH=ia32
    RTLIB_ARCH=i386
    MC_COMPILER_ARCH=i686
    ELF_TRIPLE=i686-pc-linux-gnu
    PE_TRIPLE=i686-pc-windows-msvc
    OUTPUT_TARGET=elf32-i386
    LINKER_EMULATION=elf_i386
elif [[ ${ARCH} == "amd64" ]]; then
    SEL4_ARCH=x86_64
    RTLIB_ARCH=x86_64
    MC_COMPILER_ARCH=x86_64
    ELF_TRIPLE=x86_64-pc-linux-gnu
    PE_TRIPLE=x86_64-pc-windows-msvc
    OUTPUT_TARGET=elf64-x86-64
    LINKER_EMULATION=elf_x86_64
elif [[ ${ARCH} == "arm64" ]]; then
    SEL4_ARCH=aarch64
    RTLIB_ARCH=aarch64
    MC_COMPILER_ARCH=x86_64
    ELF_TRIPLE=aarch64-elf
    PE_TRIPLE=aarch64-pc-windows-msvc
    DEFAULT_PLATFORM=rockpro64
    OUTPUT_TARGET=elf64-aarch64
    LINKER_EMULATION=aarch64elf
else
    echo "Unsupported arch ${ARCH}"
    exit 1
fi

PLATFORM=${PLATFORM:=$DEFAULT_PLATFORM}

BUILDDIR="build-$ARCH-${BUILD_TYPE,,}"
IMAGEDIR="images-$ARCH-${BUILD_TYPE,,}"

function build_failed
{
    echo "#################################"
    echo "         Build failed."
    echo "#################################"
    exit 1
}

echo
echo "####################################################"
echo "     Building ${BUILD_TYPE} version for ${ARCH}"
echo "####################################################"

cd "$(dirname "$0")"
RTLIB=$(echo ${PWD}/compiler-rt/libclang_rt.builtins-${RTLIB_ARCH}.a)

mkdir -p $BUILDDIR/{host,elf,pe_inc,ntdll,wdm,ntlnxshim,base,drivers,initcpio,ndk_lib,ddk_lib,ldk_lib,$IMAGEDIR}

cd $BUILDDIR
PE_INC=$(echo ${PWD}/pe_inc)
SPEC2DEF_PATH=$(echo ${PWD}/host/spec2def/spec2def)
UTF16LE_PATH=$(echo ${PWD}/host/utf16le/utf16le)

# Build spec2def with the native toolchain
cd host
echo
echo "---- Building native targets ----"
echo
cmake ../../tools -G Ninja
ninja

# Build ntos with the ELF toolchain
cd ../elf
echo
echo "---- Building ELF targets ----"
echo
cmake ../../private/ntos \
      -DArch=${ARCH} \
      -DTRIPLE=${ELF_TRIPLE} \
      -DOUTPUT_TARGET=${OUTPUT_TARGET} \
      -DKernelPlatform=${PLATFORM} \
      -DKernelSel4Arch=${SEL4_ARCH} \
      -DCMAKE_TOOLCHAIN_FILE=../../sel4/${TOOLCHAIN}.cmake \
      -DCMAKE_BUILD_TYPE=${BUILD_TYPE} \
      -DSANITIZED_SEL4_INCLUDE_DIR="${PWD}/../../sel4/libsel4/include" \
      -DSANITIZED_SEL4_ARCH_INCLUDE_DIR="${PWD}/../../sel4/libsel4/sel4_arch_include/${SEL4_ARCH}" \
      -DSEL4_GENERATED_HEADERS_DIR=${PWD} \
      -DSTRUCTURES_GEN_H_ORIG=${PWD}/kernel/generated/arch/object/structures_gen.h \
      -DSTRUCTURES_GEN_DIR=${PWD} \
      -DGIT_HEAD_SHA_SHORT="$(git rev-parse --short HEAD)" \
      -DCMAKE_EXPORT_COMPILE_COMMANDS=1 \
      -G Ninja
ninja all-elf || build_failed
cp rtl/syssvc_gen.h ../pe_inc || build_failed
cp rtl/wdmsvc_gen.h ../pe_inc || build_failed

# For PE targets, we modify how libsel4 retrives the IPC buffer address
# so it does not rely on the thread-local variable __sel4_ipc_buffer. Also,
# for 64-bit PE targets, since the ELF toolchain assumes sizeof(long) == 8
# and the PE toolchain assumes sizeof(long) == 4, we need to modify the
# libsel4 sel4_arch headers to undefine the macro SEL4_INT64_IS_LONG and
# define SEL4_INT64_IS_LONG_LONG. So far this seems to work and produce
# valid seL4 system calls. However we need to be very careful.
cd ../pe_inc
echo
echo "---- Building private PE targets ----"
echo
mkdir -p {kernel,libsel4,sel4_include/sel4,sel4_arch_include/sel4/sel4_arch}
cp ../elf/structures_gen.h . || build_failed
cp -r ../../sel4/libsel4/include/sel4/* sel4_include/sel4 || build_failed
cp -r ../../sel4/libsel4/sel4_arch_include/$SEL4_ARCH/sel4/sel4_arch/* \
   sel4_arch_include/sel4/sel4_arch || build_failed
cp -r ../elf/kernel/gen_config kernel || build_failed
for i in gen_config autoconf include arch_include sel4_arch_include; do
    cp -r ../elf/libsel4/$i libsel4 || build_failed
done
cat <<EOF > sel4_get_ipc_buffer.h
LIBSEL4_INLINE_FUNC seL4_IPCBuffer *seL4_GetIPCBuffer(void)
{
    PCHAR NtTib = (PVOID)NtCurrentTib();
    return (PVOID)(NtTib - NT_TIB_OFFSET);
}
EOF
sed -i '/__sel4_ipc_buffer/d' sel4_include/sel4/functions.h
sed -i '/void seL4_SetIPCBuffer/,/\}/d' sel4_include/sel4/functions.h
sed -i '/LIBSEL4_INLINE_FUNC seL4_IPCBuffer \*seL4_GetIPCBuffer/,/\}/d' sel4_include/sel4/functions.h
sed -i '/CONFIG_KERNEL_INVOCATION_REPORT_ERROR_IPC/,/#endif/d' sel4_include/sel4/functions.h
sed -i '/#include <sel4\/syscalls.h>/r sel4_get_ipc_buffer.h' sel4_include/sel4/functions.h
cat <<EOF >> sel4_include/sel4/functions.h
LIBSEL4_INLINE_FUNC char seL4_CanPrintError(void)
{
    return 1;
}
EOF
if [[ $ARCH == "amd64" || $ARCH == "arm64" ]]; then
    cat <<EOF > sel4_arch_include/sel4/sel4_arch/simple_types.h
#pragma once

#define SEL4_WORD_IS_UINT64
#define SEL4_INT64_IS_LONG_LONG
EOF
    sed -i '/assert_size_correct(long/d' libsel4/include/interfaces/sel4_client.h || build_failed
    sed -i '/assert_size_correct(seL4_X86_VMAttributes,/d' libsel4/include/interfaces/sel4_client.h || build_failed
    sed -i '/assert_size_correct(seL4_ARM_VMAttributes,/d' libsel4/include/interfaces/sel4_client.h || build_failed
    sed -i '/assert_size_correct(seL4_VCPUReg,/d' libsel4/include/interfaces/sel4_client.h || build_failed
fi

# Build ntdll.dll with the PE toolchain
cd ../ntdll
cmake ../../private/ntdll \
      -DArch=${ARCH} \
      -DTRIPLE=${PE_TRIPLE} \
      -DKernelPlatform=${PLATFORM} \
      -DKernelSel4Arch=${SEL4_ARCH} \
      -DMC_COMPILER_ARCH=${MC_COMPILER_ARCH} \
      -DCMAKE_TOOLCHAIN_FILE=../../${TOOLCHAIN}-pe.cmake \
      -DCMAKE_BUILD_TYPE=${BUILD_TYPE} \
      -DSANITIZED_SEL4_INCLUDE_DIR="${PE_INC}/sel4_include" \
      -DSANITIZED_SEL4_ARCH_INCLUDE_DIR="${PE_INC}/sel4_arch_include" \
      -DSEL4_GENERATED_HEADERS_DIR="${PE_INC}" \
      -DSTRUCTURES_GEN_DIR="${PE_INC}" \
      -DSPEC2DEF_PATH=${SPEC2DEF_PATH} \
      -DUTF16LE_PATH=${UTF16LE_PATH} \
      -DGENINC_PATH=${PWD}/../host/geninc/geninc \
      -DGIT_HEAD_SHA_SHORT="$(git rev-parse --short HEAD)" \
      -DCMAKE_EXPORT_COMPILE_COMMANDS=1 \
      -DSVCGEN_TYPE="--client" \
      -G Ninja
ninja || build_failed
cp ntdll.lib ../ndk_lib || build_failed
cp ntdllp.lib ../ndk_lib || build_failed
echo

# Build wdm.dll with the PE toolchain
cd ../wdm
cmake ../../private/wdm \
      -DArch=${ARCH} \
      -DTRIPLE=${PE_TRIPLE} \
      -DKernelPlatform=${PLATFORM} \
      -DKernelSel4Arch=${SEL4_ARCH} \
      -DMC_COMPILER_ARCH=${MC_COMPILER_ARCH} \
      -DCMAKE_TOOLCHAIN_FILE=../../${TOOLCHAIN}-pe.cmake \
      -DCMAKE_BUILD_TYPE=${BUILD_TYPE} \
      -DSANITIZED_SEL4_INCLUDE_DIR="${PE_INC}/sel4_include" \
      -DSANITIZED_SEL4_ARCH_INCLUDE_DIR="${PE_INC}/sel4_arch_include" \
      -DSEL4_GENERATED_HEADERS_DIR="${PE_INC}" \
      -DSTRUCTURES_GEN_DIR="${PE_INC}" \
      -DSPEC2DEF_PATH=${SPEC2DEF_PATH} \
      -DUTF16LE_PATH=${UTF16LE_PATH} \
      -DGENINC_PATH=${PWD}/../host/geninc/geninc \
      -DNDK_LIB_PATH=${PWD}/../ndk_lib \
      -DGEN_INC_DIR=${PWD}/../ntdll \
      -DGIT_HEAD_SHA_SHORT="$(git rev-parse --short HEAD)" \
      -DCMAKE_EXPORT_COMPILE_COMMANDS=1 \
      -DSVCGEN_TYPE="--client" \
      -G Ninja
ninja || build_failed
cp wdm.lib ../ddk_lib || build_failed

# Build ntlnxshim.so with the ELF toolchain. Note for ntlnxshim, even though it is an
# ELF target, we use the modified sel4_include headers so the seL4 IPC buffer address
# is obtained from the NtCurrentTib() call, rather than from a thread-local variable.
cd ../ntlnxshim
cp ../elf/structures_gen.h . || build_failed
cp ../elf/rtl/syssvc_gen.h . || build_failed
cp ../elf/rtl/wdmsvc_gen.h . || build_failed
cmake ../../private/ntlnxshim \
      -DArch=${ARCH} \
      -DTRIPLE=${ELF_TRIPLE} \
      -DKernelPlatform=${PLATFORM} \
      -DKernelSel4Arch=${SEL4_ARCH} \
      -DCMAKE_TOOLCHAIN_FILE=../../sel4/${TOOLCHAIN}.cmake \
      -DCMAKE_BUILD_TYPE=${BUILD_TYPE} \
      -DSANITIZED_SEL4_INCLUDE_DIR="${PE_INC}/sel4_include" \
      -DSANITIZED_SEL4_ARCH_INCLUDE_DIR="${PWD}/../../sel4/libsel4/sel4_arch_include/${SEL4_ARCH}" \
      -DSEL4_GENERATED_HEADERS_DIR="${PWD}/../elf" \
      -DSTRUCTURES_GEN_DIR="${PWD}" \
      -DGIT_HEAD_SHA_SHORT="$(git rev-parse --short HEAD)" \
      -DCMAKE_EXPORT_COMPILE_COMMANDS=1 \
      -DSVCGEN_TYPE="--utf8_client" \
      -G Ninja
ninja || build_failed
cp libntlnxshimk.a ../ldk_lib || build_failed
cp libntlnxshimu.a ../ldk_lib || build_failed

# Build drivers with the PE toolchain
cd ../drivers
echo
echo "---- Building drivers ----"
echo
cmake ../../drivers \
      -DArch=${ARCH} \
      -DTRIPLE=${PE_TRIPLE} \
      -DMC_COMPILER_ARCH=${MC_COMPILER_ARCH} \
      -DCMAKE_TOOLCHAIN_FILE=../../${TOOLCHAIN}-pe.cmake \
      -DCMAKE_BUILD_TYPE=${BUILD_TYPE} \
      -DNDK_LIB_PATH=${PWD}/../ndk_lib \
      -DDDK_LIB_PATH=${PWD}/../ddk_lib \
      -DSPEC2DEF_PATH=${SPEC2DEF_PATH} \
      -DUTF16LE_PATH=${UTF16LE_PATH} \
      -DGIT_HEAD_SHA_SHORT="$(git rev-parse --short HEAD)" \
      -DCMAKE_EXPORT_COMPILE_COMMANDS=1 \
      -G Ninja
ninja || build_failed

# Build base NT clients with the PE toolchain
cd ../base
echo
echo "---- Building base NT clients ----"
echo
cmake ../../base \
      -DTRIPLE=${PE_TRIPLE} \
      -DMC_COMPILER_ARCH=${MC_COMPILER_ARCH} \
      -DCMAKE_TOOLCHAIN_FILE=../../${TOOLCHAIN}-pe.cmake \
      -DCMAKE_BUILD_TYPE=${BUILD_TYPE} \
      -DNDK_LIB_PATH=${PWD}/../ndk_lib \
      -DUTF16LE_PATH=${UTF16LE_PATH} \
      -DGIT_HEAD_SHA_SHORT="$(git rev-parse --short HEAD)" \
      -DCMAKE_EXPORT_COMPILE_COMMANDS=1 \
      -G Ninja
ninja || build_failed

# Build initcpio
echo
echo "---- Building INITCPIO ----"
echo
cd ../initcpio
PE_COPY_LIST='ntdll/ntdll.dll wdm/wdm.dll'
BASE_COPY_LIST='smss/smss.exe ntcmd/ntcmd.exe'
DRIVER_COPY_LIST='base/null/null.sys base/beep/beep.sys base/pnp/pnp.sys
bus/acpi/acpi.sys bus/pci/pci.sys input/kbdclass/kbdclass.sys filesystems/fatfs/fatfs.sys'
X86_DRIVER_COPY_LIST='input/i8042prt/i8042prt.sys storage/fdc/fdc.sys'
for i in ${PE_COPY_LIST}; do
    cp ../$i . || build_failed
done
for i in ${BASE_COPY_LIST}; do
    cp ../base/$i . || build_failed
done
for i in ${DRIVER_COPY_LIST}; do
    cp ../drivers/$i . || build_failed
done
if [[ "${ARCH}" == "i386" || "${ARCH}" == "amd64" ]]; then
    for i in ${X86_DRIVER_COPY_LIST}; do
	cp ../drivers/$i . || build_failed
    done
fi
{ for i in ${PE_COPY_LIST}; do echo $(basename $i); done } > image-list
{ for i in ${BASE_COPY_LIST}; do echo $(basename $i); done } >> image-list
{ for i in ${DRIVER_COPY_LIST}; do echo $(basename $i); done } >> image-list
if [[ "${ARCH}" == "i386" || "${ARCH}" == "amd64" ]]; then
    { for i in ${X86_DRIVER_COPY_LIST}; do echo $(basename $i); done } >> image-list
fi
cpio -H newc -o < image-list > initcpio || build_failed
llvm-objcopy -I binary -O ${OUTPUT_TARGET} \
	--rename-section .data=initcpio,CONTENTS,ALLOC,LOAD,READONLY,DATA \
	initcpio initcpio.o
if [[ $? == 0 ]]; then
    echo "Success."
else
    build_failed
fi

# Link ntos and initcpio into final ntos image
echo
echo "---- Linking NTOS image ----"
echo
cd ../$IMAGEDIR
cp ../elf/kernel-$SEL4_ARCH-$PLATFORM kernel || build_failed
if [[ ${BUILD_TYPE} == Release ]]; then
    LLD_OPTIONS="--gc-sections -O 3"
else
    LLD_OPTIONS=""
fi
ld.lld -m ${LINKER_EMULATION} ${LLD_OPTIONS} ${RTLIB} \
       --allow-multiple-definition \
       -z max-page-size=0x1000 \
       ../elf/libntos.a \
       ../elf/rtl/librtl.a \
       ../initcpio/initcpio.o \
       -T ../../private/ntos/ntos.lds \
       -o ntos
if [[ $? == 0 ]]; then
    echo "Success."
else
    build_failed
fi

echo
echo "---- Stripping symbols for ${BUILD_TYPE} build ----"
echo
STRIP=llvm-strip
if [[ ${BUILD_TYPE} == Release ]]; then
    cp kernel kernel-no-strip
    cp ntos ntos-no-strip
    $STRIP kernel && $STRIP ntos
    if [[ $? == 0 ]]; then
	echo "Success."
    fi
else
    $STRIP kernel -o kernel-stripped && $STRIP ntos -o ntos-stripped
    if [[ $? == 0 ]]; then
	echo "Success."
    fi
fi

if [[ ${ARCH} == "arm64" ]]; then
    echo
    echo "---- Generate the final ELF boot image ----"
    echo
    cd ..
    mkdir elfloader
    cd elfloader
    cmake -DKernelArch=arm \
	  -DKernelSel4Arch=${SEL4_ARCH} \
	  -DKernelPlatform=${PLATFORM} \
	  -DTRIPLE=${ELF_TRIPLE} \
	  -DCMAKE_TOOLCHAIN_FILE=../../sel4/${TOOLCHAIN}.cmake \
	  -DCMAKE_BUILD_TYPE=${BUILD_TYPE} \
	  -DPLATFORM=${PLATFORM} \
	  -DKernelDTBPath=$PWD/../elf/kernel/kernel.dtb \
	  -DHARDWARE_GEN_PATH=$PWD/../../sel4/tools/hardware_gen.py \
	  -DKERNEL_IMAGE=$PWD/../$IMAGEDIR/kernel \
	  -DNTOS_IMAGE=$PWD/../$IMAGEDIR/ntos \
	  -DKERNEL_GEN_CONFIG_DIR=$PWD/../elf/kernel/gen_config \
	  -DCMAKE_EXPORT_COMPILE_COMMANDS=1 \
	  -G Ninja ../../tools/elfloader || build_failed
    ninja bootimg || build_failed
    cp elfloader-bin ../$IMAGEDIR/bootimg-$SEL4_ARCH-$PLATFORM-${BUILD_TYPE,,}
    if [[ $? == 0 ]]; then
	echo "Success."
    else
	build_failed
    fi
fi

echo
echo "---- Merge compile_commands.json ----"
echo
if [[ $(which jq) ]]; then
    jq -s add ../*/*.json > ../compile_commands.json
    rm ../*/compile_commands.json
    echo "Done."
else
    echo "You'll need to install jq (https://jqlang.github.io/jq)."
fi

echo
echo "####################################"
echo "         Build successful!"
echo "####################################"
