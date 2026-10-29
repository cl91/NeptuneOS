project(csrss C)

add_executable(csrss csrss.c csrss.rc)
set_module_type(csrss native ENTRYPOINT NtProcessStartup 4)
target_link_libraries(csrss csrsrv)
