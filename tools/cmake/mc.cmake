macro(macro_mc FLAG FILE)
    set(COMMAND_MC ${CMAKE_MC_COMPILER} -u ${FLAG} -b -h ${CMAKE_CURRENT_BINARY_DIR}/
    		   -r ${CMAKE_CURRENT_BINARY_DIR}/ ${FILE})
endmacro()

function(add_message_headers _type)
    if(${_type} STREQUAL UNICODE)
        set(_flag "-U")
    else()
        set(_flag "-A")
    endif()
    foreach(_file ${ARGN})
        get_filename_component(_file_name ${_file} NAME_WE)
        set(_converted_file ${CMAKE_CURRENT_BINARY_DIR}/${_file}) ## ${_file_name}.mc
        set(_source_file ${CMAKE_CURRENT_SOURCE_DIR}/${_file})    ## ${_file_name}.mc
        add_custom_command(
            OUTPUT "${_converted_file}"
            COMMAND ${UTF16LE_PATH} "${_source_file}" "${_converted_file}" nobom
            DEPENDS "${_source_file}")
        macro_mc(${_flag} ${_converted_file})
        add_custom_command(
            OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/${_file_name}.h
	    	   ${CMAKE_CURRENT_BINARY_DIR}/${_file_name}.rc
            COMMAND ${COMMAND_MC}
            DEPENDS "${_converted_file}")
        set_source_files_properties(
            ${CMAKE_CURRENT_BINARY_DIR}/${_file_name}.h
	    ${CMAKE_CURRENT_BINARY_DIR}/${_file_name}.rc
            PROPERTIES GENERATED TRUE)
        add_custom_target(${_file_name}
			  ALL DEPENDS
			  ${CMAKE_CURRENT_BINARY_DIR}/${_file_name}.h
			  ${CMAKE_CURRENT_BINARY_DIR}/${_file_name}.rc)
    endforeach()
endfunction()