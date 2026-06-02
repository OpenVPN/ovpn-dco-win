cmake_minimum_required(VERSION 3.14)

project(tests)

include(FetchContent)
FetchContent_Declare(
    googletest
    URL https://github.com/google/googletest/archive/03597a01ee50ed33e9dfd640b249b4be3799d395.zip
    DOWNLOAD_EXTRACT_TIMESTAMP true)

set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

enable_testing()

add_executable(
    tests
    tests.cpp
    ../crypto_epoch.cpp
)
target_link_libraries(
    tests
    GTest::gtest_main
    bcrypt
    ws2_32
)

include(GoogleTest)
gtest_discover_tests(tests)