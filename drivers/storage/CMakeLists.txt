# Floppy drives are only supported on i386 and amd64 architectures
if ("${Arch}" MATCHES "^(i386|amd64)$")
add_subdirectory(fdc)
endif()
