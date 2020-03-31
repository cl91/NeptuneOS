set(RUNTIME_LIBRARY_DIR "${CMAKE_CURRENT_LIST_DIR}" CACHE STRING "")
mark_as_advanced(RUNTIME_LIBRARY_DIR)

function(rtl_import_project)
    add_subdirectory(${RUNTIME_LIBRARY_DIR} rtl)
endfunction()

include(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(rtl DEFAULT_MSG RUNTIME_LIBRARY_DIR)
