project(csrss C)

add_executable(csrss csrss.c csrss.rc)
target_link_libraries(csrss csrsrv)
