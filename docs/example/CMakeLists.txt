# 3.15: no default /W3 to clash with the /W4 below
cmake_minimum_required(VERSION 3.15)

project(example-client C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED YES)

add_executable(example-client example-client.c)

# the API header lives at the top of the repository
target_include_directories(example-client PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../..)
target_compile_definitions(example-client PRIVATE UNICODE _UNICODE)
target_link_libraries(example-client PRIVATE setupapi cfgmgr32 ws2_32)

if(MSVC)
    target_compile_options(example-client PRIVATE /W4 /WX)
endif()
