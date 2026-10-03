cmake_minimum_required(VERSION 3.12.0)

project(win32)

set(CMAKE_SYSTEM_NAME Windows)
set(CMAKE_EXECUTABLE_SUFFIX ".exe")
set(CMAKE_SHARED_LIBRARY_SUFFIX ".dll")

add_compile_options(
    -Wall
    -nostdinc
    -Wno-incompatible-library-redeclaration
    -Wno-microsoft-anon-tag
    -fasync-exceptions
    --target=${TRIPLE}
    -ferror-limit=0
    -DGIT_HEAD_SHA_SHORT=\"${GIT_HEAD_SHA_SHORT}\"
)

include_directories(
    ${CMAKE_CURRENT_LIST_DIR}/../public/crt/inc
    ${CMAKE_CURRENT_LIST_DIR}/../public/sdk/inc
)

set(CMAKE_C_FLAGS_DEBUG "-g -Xclang -gcodeview -O0 -D_DEBUG")
set(CMAKE_C_FLAGS_MINSIZEREL "-Os -DNDEBUG")
set(CMAKE_C_FLAGS_RELEASE "-O3 -DNDEBUG")
set(CMAKE_C_FLAGS_RELWITHDEBINFO "-O2 -g -DNDEBUG -Xclang -gcodeview")

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -ftls-model=global-dynamic")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -nostdinc++")
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_LIBRARIES "")
set(CMAKE_CXX_STANDARD_LIBRARIES "")

include(${CMAKE_CURRENT_LIST_DIR}/../tools/cmake/spec2def.cmake)

list(APPEND VALID_MODULE_TYPES basedll win32cui win32gui win32dll win32ocx cpl)

function(set_module_type MODULE TYPE)
    cmake_parse_arguments(__module "UNICODE" "IMAGEBASE" "ENTRYPOINT" ${ARGN})

    if(__module_UNPARSED_ARGUMENTS)
        message(STATUS "set_module_type : unparsed arguments ${__module_UNPARSED_ARGUMENTS}, module : ${MODULE}")
    endif()

    # Check this is a type that we know
    if (NOT TYPE IN_LIST VALID_MODULE_TYPES)
        message(FATAL_ERROR "Unknown type ${TYPE} for module ${MODULE}")
    endif()

    # Set subsystem.
    if(${TYPE} STREQUAL basedll)
	target_include_directories(${MODULE} PRIVATE ${CMAKE_SOURCE_DIR}/../public/ndk/inc)
        # The base win32 dlls have WINDOWS_GUI as the PE subsystem
	target_link_options(${MODULE} PRIVATE "-Wl,-subsystem:windows -nostdlib")
	target_link_directories(${MODULE} PRIVATE ${NDK_LIB_PATH})
	target_link_libraries(${MODULE} ntdll ntdllp)
    elseif(${TYPE} STREQUAL win32cui)
	target_link_options(${MODULE} PRIVATE "-Wl,-subsystem:console")
    else()
	target_link_options(${MODULE} PRIVATE "-Wl,-subsystem:windows")
    endif()

    # Set unicode definitions
    if(__module_UNICODE)
        target_compile_definitions(${MODULE} PRIVATE UNICODE _UNICODE)
    endif()

    # Set entry point
    if(__module_ENTRYPOINT OR (__module_ENTRYPOINT STREQUAL "0"))
        set_entrypoint(${MODULE} ${__module_ENTRYPOINT})
    elseif(${TYPE} STREQUAL basedll)
        set_entrypoint(${MODULE} DllMain 12)
    elseif(${TYPE} STREQUAL win32cui)
        if(__module_UNICODE)
            set_entrypoint(${MODULE} wmainCRTStartup)
        else()
            set_entrypoint(${MODULE} mainCRTStartup)
        endif()
    elseif(${TYPE} STREQUAL win32gui)
        if(__module_UNICODE)
            set_entrypoint(${MODULE} wWinMainCRTStartup)
        else()
            set_entrypoint(${MODULE} WinMainCRTStartup)
        endif()
    else()
        set_entrypoint(${MODULE} DllMainCRTStartup 12)
    endif()

    # Set base address
    # Use 'IMAGEBASE default' to skip these set_image_base(), especially for win32dll test files
    if(__module_IMAGEBASE)
        if(NOT ${__module_IMAGEBASE} STREQUAL "default")
            set_image_base(${MODULE} ${__module_IMAGEBASE})
        endif()
    elseif((${TYPE} STREQUAL basedll) OR (${TYPE} STREQUAL win32dll))
        if(DEFINED baseaddress_${MODULE})
            set_image_base(${MODULE} ${baseaddress_${MODULE}})
        else()
            message(STATUS "${MODULE} has no base address")
        endif()
    endif()

    if(${TYPE} STREQUAL win32ocx)
        set_target_properties(${MODULE} PROPERTIES SUFFIX ".ocx")
    endif()

    if(${TYPE} STREQUAL cpl)
        set_target_properties(${MODULE} PROPERTIES SUFFIX ".cpl")
    endif()

    target_link_options(${MODULE} PRIVATE
        "--target=${TRIPLE} -fuse-ld=lld-link -Wl,-safeseh:no -Wl,-errorlimit:0")
endfunction()

add_subdirectory(base)
add_subdirectory(shell)