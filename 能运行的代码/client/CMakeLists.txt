cmake_minimum_required(VERSION 3.25)
project(Client C)

set(CMAKE_C_STANDARD 90)
set(CMAKE_BUILD_TYPE Debug)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g")
include_directories(client common lib)

aux_source_directory(client SRC_LIST)
aux_source_directory(common SRC_LIST1)
aux_source_directory(lib SRC_LIST2)

add_executable(main ${SRC_LIST} ${SRC_LIST1} ${SRC_LIST2})

# 添加宏定义
target_compile_definitions(main PRIVATE
        HAVE_SYS_TYPES_H=1
        HAVE_ERRNO_H=1
        STDC_HEADERS=1
        HAVE_UNISTD_H=1
        HAVE_SYS_STAT_H=1
        HAVE_NETINET_IN_H=1
        HAVE_CTYPE_H=1
        HAVE_TIME_H=1
        VERSION=\"0.0.1\"
)
