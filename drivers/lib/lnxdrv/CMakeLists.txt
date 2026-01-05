project(lnxdrv C)

file(GLOB SRC src/*.c)

add_library(lnxdrv STATIC ${SRC})
target_include_directories(lnxdrv PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/inc)
