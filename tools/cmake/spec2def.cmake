function(spec2def _dllname _spec_file)
    cmake_parse_arguments(__spec2def "ADD_IMPORTLIB;NO_PRIVATE_WARNINGS;WITH_RELAY" "VERSION" "" ${ARGN})

    # _dllname is the basename of the dll file (ie. ntdll in ntdll.dll)
    if(${_dllname} MATCHES ".*\\.dll")
        message(FATAL_ERROR "_dllname is the basename of the dll file.")
    endif()

    # Error out on anything else than spec
    if(NOT ${_spec_file} MATCHES ".*\\.spec")
        message(FATAL_ERROR "spec2def only takes spec files as input.")
    endif()

    if(__spec2def_WITH_RELAY)
        set(__with_relay_arg "--with-tracing")
    endif()

    if(__spec2def_VERSION)
        set(__version_arg "--version=0x${__spec2def_VERSION}")
    endif()

    # Generate exports def and C stubs file for the DLL
    add_custom_target(
        spec2def_${_dllname} ALL
        COMMAND ${SPEC2DEF_PATH} --ms -n=${_dllname}.dll -a=${ARCH} -d=${CMAKE_CURRENT_BINARY_DIR}/${_dllname}.def -s=${CMAKE_CURRENT_BINARY_DIR}/${_dllname}_stubs.c ${__with_relay_arg} ${__version_arg} ${CMAKE_CURRENT_SOURCE_DIR}/${_spec_file}
        DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/${_spec_file}
    )

    add_dependencies(${_dllname} spec2def_${_dllname})
endfunction()