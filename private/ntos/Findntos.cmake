set(NTOS_LIBRARY_DIR "${CMAKE_CURRENT_LIST_DIR}" CACHE STRING "")
mark_as_advanced(NTOS_LIBRARY_DIR)

function(ntos_import_project)
    add_subdirectory(${NTOS_LIBRARY_DIR} ntos)
endfunction()

include(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(ntos DEFAULT_MSG NTOS_LIBRARY_DIR)
