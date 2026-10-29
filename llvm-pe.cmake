include(${CMAKE_CURRENT_LIST_DIR}/public/ndk/cmake/llvm.cmake)

function(set_entrypoint _module _entrypoint)
    if(${_entrypoint} STREQUAL "0")
	set_property(TARGET ${_module} APPEND_STRING PROPERTY LINK_FLAGS " -Wl,-noentry")
    else()
	set_property(TARGET ${_module} APPEND_STRING PROPERTY LINK_FLAGS " -Wl,-entry:${_entrypoint}")
    endif()
endfunction()

function(set_dll_def _module _module_def)
    get_property(target_dir TARGET ${_module} PROPERTY BINARY_DIR)
    set_property(TARGET ${_module} APPEND_STRING PROPERTY LINK_FLAGS
		 " -Wl,/def:${target_dir}/${_module_def}")
endfunction()