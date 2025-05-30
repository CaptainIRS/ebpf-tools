
cmake_minimum_required(VERSION 3.10)


set(CMAKE_TOOLCHAIN_FILE "conan_toolchain.cmake")

project(thread_visualizer C CXX)

set(CMAKE_C_COMPILER clang)
set(CMAKE_CXX_COMPILER clang++)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
find_package(LibBpf REQUIRED)
find_package(BpfObject REQUIRED)

include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/clang-format.cmake)

find_package(perfetto CONFIG REQUIRED)
if (NOT perfetto_FOUND)
    message(FATAL_ERROR "perfetto not found")
endif()
message(STATUS "perfetto INCLUDE_DIRS: ${perfetto_INCLUDE_DIRS}")
message(STATUS "perfetto LIBRARIES: ${perfetto_LIBRARIES}")

bpf_object(${PROJECT_NAME} src/${PROJECT_NAME}.bpf.c src/common.h)
add_executable(${PROJECT_NAME} src/${PROJECT_NAME}.cc)
target_include_directories(${PROJECT_NAME} PRIVATE ${perfetto_INCLUDE_DIRS})
target_link_libraries(${PROJECT_NAME} PRIVATE ${perfetto_LIBRARIES})
target_link_libraries(${PROJECT_NAME} PUBLIC ${PROJECT_NAME}_skel)
