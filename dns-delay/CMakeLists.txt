
cmake_minimum_required(VERSION 3.10)
project(dns_delay_injector C)

set(CMAKE_C_COMPILER clang)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

execute_process(COMMAND uname -r OUTPUT_VARIABLE UNAME_RESULT OUTPUT_STRIP_TRAILING_WHITESPACE)
message(-- " Kernel version: " ${UNAME_RESULT})
string(REGEX MATCH "[0-9]+.[0-9]+" LINUX_KERNEL_VERSION ${UNAME_RESULT})

if (LINUX_KERNEL_VERSION VERSION_LESS 6.10)
    message(FATAL_ERROR "Linux kernel version should be greater than 6.10")
endif()

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
find_package(LibBpf REQUIRED)
find_package(BpfObject REQUIRED)

bpf_object(${PROJECT_NAME} src/${PROJECT_NAME}.bpf.c src/common.h)
bpf_object(proc_name_mapper src/proc_name_mapper.bpf.c src/common.h)
add_executable(${PROJECT_NAME} src/${PROJECT_NAME}.c)
target_link_libraries(${PROJECT_NAME} ${PROJECT_NAME}_skel proc_name_mapper_skel)
