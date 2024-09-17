cmake_minimum_required(VERSION 3.10)

project(gui)

set(CMAKE_CXX_STANDARD 17)            # Enable C++17
set(CMAKE_CXX_STANDARD_REQUIRED YES)   # Ensure the compiler strictly requires C++17

add_executable (gui WIN32 "gui.cpp")

add_definitions(-DUNICODE -D_UNICODE)
target_link_libraries(gui PRIVATE user32 gdi32 Ws2_32)
