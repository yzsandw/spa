cmake_minimum_required(VERSION 3.25)
project(Server C)

set(CMAKE_C_STANDARD 90)
set(CMAKE_BUILD_TYPE Debug)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g")

include_directories(server common lib)

aux_source_directory(server SRC_LIST)
aux_source_directory(common SRC_LIST1)
aux_source_directory(lib SRC_LIST2)

add_executable(main ${SRC_LIST} ${SRC_LIST1} ${SRC_LIST2})


target_link_libraries(main PRIVATE -lnfnetlink -lnetfilter_queue -lpcap)

# 添加宏定义及其注释
target_compile_definitions(main PRIVATE
        # 导入系统库
        HAVE_SYS_TYPES_H=1
        HAVE_ERRNO_H=1
        STDC_HEADERS=1
        HAVE_UNISTD_H=1
        HAVE_SYS_STAT_H=1
        HAVE_NETINET_IN_H=1
        HAVE_CTYPE_H=1
        HAVE_TIME_H=1
        HAVE_LOCALE_H=1
        VERSION="0.0.1"
        # 防火墙的执行文件？
        FIREWALL_EXE="iptables"
        # 引入LIBNETFILTER库
        USE_LIBNETFILTER_QUEUE=1
        # 使用文件进行缓存
        USE_FILE_CACHE=1
        # 选择iptables
        FIREWALL_FIREWALLD=0
        FIREWALL_IPTABLES=1
        FIREWALL_IPFW=0
        FIREWALL_PF=0
        FIREWALL_IPF=0
        # 配置文件的位置和执行文件的地址
        SYSCONFDIR="/home/catlee/fko_test"
        PACKAGE_NAME="myconfig"
        SYSRUNDIR="/home/catlee/fko_test"
        #使用pcap
        USE_LIBPCAP=1
)



