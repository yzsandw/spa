/* * */

/* Fwknop主要由文件“AUTHORS”中列出的人员开发。 */
#ifndef _COMMON_H
#define _COMMON_H

/* 常见的包括我们的其他fwknop客户端和服务器源文件。 */
#if HAVE_CONFIG_H
  #include "config.h"
#endif

#if HAVE_LIBFIU
  #include <fiu.h>
  #include <fiu-control.h>
#endif

/* 如果启用了c单元测试支持，则包括cunit标头。 */
#ifdef HAVE_C_UNIT_TESTS
    #include "CUnit/Basic.h"
    #include "cunit_common.h"
#endif

#include <stdio.h>

#if HAVE_SYS_TYPES_H
  #include <sys/types.h>
#endif

#if HAVE_ERRNO_H
  #include <errno.h>
#endif

#if STDC_HEADERS
  #include <stdlib.h>
  #include <string.h>
#elif HAVE_STRINGS_H
  #include <strings.h>
#endif /* STDC_HEADERS */

#if HAVE_UNISTD_H
  #include <unistd.h>
#endif

#ifdef HAVE_SYS_STAT_H
  #include <sys/stat.h>
#endif

#if HAVE_NETINET_IN_H
  #include <netinet/in.h>
#endif

#if HAVE_CTYPE_H
  #include <ctype.h>
#endif

#if HAVE_TIME_H
  #include <time.h>
#endif

/* 一些用于容纳Windows的箍带 */
#ifdef WIN32
  #include <io.h>
  #define strcasecmp	_stricmp
  #define strncasecmp	_strnicmp
  #define snprintf		_snprintf
  #define unlink		_unlink
  #define open			_open
  #define fdopen        _fdopen
  #define close			_close
  #define write			_write
  #define popen			_popen
  #define pclose		_pclose
  #define O_WRONLY		_O_WRONLY
  #define O_RDONLY		_O_RDONLY
  #define O_RDWR		_O_RDWR
  #define O_CREAT		_O_CREAT
  #define O_EXCL		_O_EXCL
  #define S_IRUSR		_S_IREAD
  #define S_IWUSR		_S_IWRITE
  #define PATH_SEP      '\\'
  // --DSS needed for VS versions before 2010
  #ifndef __MINGW32__
    typedef __int8 int8_t;
  #endif
  typedef unsigned __int8 uint8_t;
  typedef __int16 int16_t;
  typedef unsigned __int16 uint16_t;
  typedef __int32 int32_t;
  typedef unsigned __int32 uint32_t;
  typedef __int64 int64_t;
  typedef unsigned __int64 uint64_t;

#else
  #include <signal.h>
  #define PATH_SEP      '/'
#endif

#include "fko.h"
#include "fko_limits.h"
#include "fko_util.h"

/* 从version（在config.h中定义）获取我们的程序版本。 */
#define MY_VERSION VERSION

enum {
    FKO_PROTO_UDP,
    FKO_PROTO_UDP_RAW,
    FKO_PROTO_TCP,
    FKO_PROTO_TCP_RAW,
    FKO_PROTO_ICMP,
    FKO_PROTO_HTTP,
};

/* 其他常见定义 */
#define FKO_DEFAULT_PROTO   FKO_PROTO_UDP
#define FKO_DEFAULT_PORT    62201
#define DEFAULT_NAT_PORT    55000
#define MIN_HIGH_PORT       10000  /* SPA目标端口的合理最小值 */
#define ANY_PORT            0      /* 用作通配符 */
#define ANY_PROTO           0      /* 用作通配符 */
#define NAT_ANY_PORT        ANY_PORT
#define MAX_SERVER_STR_LEN  50
#define MAX_ICMP_TYPE       40
#define MAX_ICMP_CODE       15
#define RAW_SPA_TTL         255

#define MAX_LINE_LEN        1024
#define MAX_PATH_LEN        1024
#define MAX_GPG_KEY_ID      128
#define MAX_USERNAME_LEN    30

#define MAX_KEY_LEN                 128
#define MAX_B64_KEY_LEN             180

#if HAVE_LIBFIU
  #define MAX_FAULT_TAG_LEN 128
#endif

/* 一些方便的宏 */

/* 获取数组的元素数 */
#define ARRAY_SIZE(t)   (sizeof(t) / sizeof(t[0]))

/* 配置参数及其值之间允许有字符。 */
#define IS_CONFIG_PARAM_DELIMITER(x) (x == ' ' || x == '\t' || x == '=');

/* 行尾字符。 */
#define IS_LINE_END(x) (x == '\n' || x == '\r' || x == ';');

/* 行的第一个位置的字符使其被考虑 */
#define IS_EMPTY_LINE(x) ( \
    x == '#' || x == '\n' || x == '\r' || x == ';' || x == '\0' \
)

/* 解决没有strnlen的问题 */
#if !HAVE_STRNLEN
  #define strnlen(s, l) (strlen(s) < l ? strlen(s) : l)
#endif

#endif /* _COMMON_H */

/* **EOF** */
