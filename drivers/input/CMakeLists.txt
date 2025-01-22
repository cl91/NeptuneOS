add_subdirectory(kbdclass)

# PS2 keyboard and mouse are only supported on i386 and amd64 architectures
if ("${Arch}" MATCHES "^(i386|amd64)$")
add_subdirectory(i8042prt)
endif()
