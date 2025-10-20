project(dmilib C)

add_library(dmilib STATIC dmilib.c)
target_include_directories(dmilib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
