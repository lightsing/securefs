cmake_minimum_required(VERSION 2.8.5 FATAL_ERROR)
project (securefs)

set (CMAKE_CXX_FLAGS "-std=c++11 -Wall -Wextra -pedantic -D_FILE_OFFSET_BITS=64")
set (CMAKE_BUILD_TYPE Release)

include_directories("${PROJECT_SOURCE_DIR}/sources")

file (GLOB SOURCES "${PROJECT_SOURCE_DIR}/sources/*.cpp")
file (GLOB TEST_SOURCES "${PROJECT_SOURCE_DIR}/test/*.cpp")
add_executable(securefs ${SOURCES} main.cpp)
add_executable(securefs_test ${SOURCES} ${TEST_SOURCES})

list(APPEND CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake")
find_package(FUSE REQUIRED)
include_directories("${FUSE_INCLUDE_DIR}")
target_link_libraries(securefs "${FUSE_LIBRARIES}")
target_link_libraries(securefs_test "${FUSE_LIBRARIES}")

find_package(Nettle REQUIRED)
include_directories("${NETTLE_INCLUDE_DIR}")
target_link_libraries(securefs "${NETTLE_LIBRARY}")
target_link_libraries(securefs_test "${NETTLE_LIBRARY}")

enable_testing()
add_test(NAME sec_test COMMAND securefs_test)
add_test(NAME simple_test COMMAND "${PROJECT_SOURCE_DIR}/test/simple_test.py")

install(TARGETS securefs DESTINATION bin)
