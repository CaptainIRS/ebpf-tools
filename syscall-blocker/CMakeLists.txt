cmake_minimum_required(VERSION 3.10)
project(syscall_blocker C)

set(CMAKE_C_COMPILER clang)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
find_package(LibBpf REQUIRED)
find_package(BpfObject REQUIRED)
find_package(Python3 REQUIRED)

execute_process(
    COMMAND bash -c "echo -e '#include <sys/syscall.h>' | cpp -dM | grep \"#define __NR_.*[0-9]\$\" | cut -d' ' -f 2 | cut -c 6-"
    OUTPUT_FILE syscalls.txt
)

message("Python ${PYTHON_EXECUTABLE}")
add_custom_command(
    OUTPUT ${CMAKE_SOURCE_DIR}/src/generated/${PROJECT_NAME}_gen.bpf.c
    COMMAND bash -c "${PYTHON_EXECUTABLE} ${CMAKE_SOURCE_DIR}/src/generate.py \
        --input ${CMAKE_SOURCE_DIR}/src/${PROJECT_NAME}.bpf.c \
        --output ${CMAKE_SOURCE_DIR}/src/generated/${PROJECT_NAME}_gen.bpf.c \
        --syscalls ${CMAKE_BINARY_DIR}/syscalls.txt"
    DEPENDS ${CMAKE_SOURCE_DIR}/src/${PROJECT_NAME}.bpf.c
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    COMMENT "Generating ${PROJECT_NAME}_gen.bpf.c"
)
set_property(SOURCE ${CMAKE_SOURCE_DIR}/src/generated/${PROJECT_NAME}_gen.bpf.c PROPERTY GENERATED 1)
add_custom_target(generate_bpf_src ALL DEPENDS ${CMAKE_SOURCE_DIR}/src/generated/${PROJECT_NAME}_gen.bpf.c)

add_custom_command(
    OUTPUT ${CMAKE_SOURCE_DIR}/src/generated/${PROJECT_NAME}_gen.c
    COMMAND bash -c "${PYTHON_EXECUTABLE} ${CMAKE_SOURCE_DIR}/src/generate.py \
        --input ${CMAKE_SOURCE_DIR}/src/${PROJECT_NAME}.c \
        --output ${CMAKE_SOURCE_DIR}/src/generated/${PROJECT_NAME}_gen.c \
        --syscalls ${CMAKE_BINARY_DIR}/syscalls.txt"
    DEPENDS ${CMAKE_SOURCE_DIR}/src/${PROJECT_NAME}.c
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    COMMENT "Generating ${PROJECT_NAME}_gen.c"
)
set_property(SOURCE ${CMAKE_SOURCE_DIR}/src/generated/${PROJECT_NAME}_gen.c PROPERTY GENERATED 1)
add_custom_target(generate_src ALL DEPENDS ${CMAKE_SOURCE_DIR}/src/generated/${PROJECT_NAME}_gen.c)

# copy src/common.h to build directory
configure_file(src/common.h ${CMAKE_BINARY_DIR}/common.h COPYONLY)

bpf_object(${PROJECT_NAME} src/generated/${PROJECT_NAME}_gen.bpf.c src/common.h)
add_executable(${PROJECT_NAME} src/generated/${PROJECT_NAME}_gen.c)
target_link_libraries(${PROJECT_NAME} ${PROJECT_NAME}_skel)

# Dummy target to get the IDE to work with the non-generated source files
bpf_object(${PROJECT_NAME}_dummy src/${PROJECT_NAME}.bpf.c src/common.h)
add_executable(${PROJECT_NAME}_dummy src/${PROJECT_NAME}.c)
target_link_libraries(${PROJECT_NAME}_dummy ${PROJECT_NAME}_dummy_skel)
add_dependencies(${PROJECT_NAME}_dummy ${PROJECT_NAME})
