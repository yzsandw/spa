
#ifndef FKO_COMMON_H
#define FKO_COMMON_H 1

#if HAVE_CONFIG_H
  #include "config.h"
#endif

#if HAVE_LIBFIU
  #include <fiu.h>
#endif

#include <stdio.h>
#include <sys/types.h>

#if STDC_HEADERS
  #include <stdlib.h>
  #include <string.h>
#elif HAVE_STRINGS_H
  #include <strings.h>
#endif /* STDC_HEADERS */

#if HAVE_UNISTD_H
  #include <unistd.h>
#endif

#if HAVE_CTYPE_H
  #include <ctype.h> /* 将此用于isdigit（） */
#else
  /* 回退不考虑区域设置 */
  #define isdigit(c) (c >= 48 && c <= 57)
#endif

#ifdef WIN32
  #include <io.h>
  #define strcasecmp  _stricmp
  #define strncasecmp _strnicmp
  #define snprintf    _snprintf
  #define strdup      _strdup
  #define unlink      _unlink
  #define open        _open
  #define close       _close
  #define write       _write
  #define O_WRONLY    _O_WRONLY
  #define O_RDONLY    _O_RDONLY
  #define O_RDWR      _O_RDWR
  #define O_CREAT     _O_CREAT
  #define O_EXCL      _O_EXCL
  #define S_IRUSR     _S_IREAD
  #define S_IWUSR     _S_IWRITE
  #define PATH_SEP    '\\'

  /* 这些是windows下的摘要代码所需要的。 */
  typedef unsigned __int8   uint8_t;
  typedef unsigned __int32	uint32_t;
  typedef unsigned __int64	uint64_t;
#else
  #if HAVE_STDINT_H
    #include <stdint.h>
  #endif
#endif

/* 计算结束时间 */
#ifdef HAVE_ENDIAN_H
  #include <endian.h>
  #if defined(BYTE_ORDER) /* POSIX提案 */
    #define BYTEORDER BYTE_ORDER
  #elif defined(__BYTE_ORDER) /* 旧系统？ */
    #define BYTEORDER __BYTE_ORDER
  #endif
#elif HAVE_SYS_ENDIAN_H /* FreeBSD有一个sys/endian.h */
  #include <sys/endian.h>
  #define BYTEORDER _BYTE_ORDER
#elif HAVE_SYS_BYTEORDER_H /* Solaris（至少是v10）似乎有这个 */
  #include <sys/byteorder.h>
  #if defined(_BIG_ENDIAN)
    #define BYTEORDER 4321
  #elif defined(_LITTLE_ENDIAN)
    #define BYTEORDER 1234
  #endif
#endif

#ifndef BYTEORDER
  #if defined(__BYTE_ORDER)
    #define BYTEORDER __BYTE_ORDER
  #elif defined(_BYTE_ORDER)
    #define BYTEORDER _BYTE_ORDER
  #elif defined(BYTE_ORDER)
    #define BYTEORDER BYTE_ORDER
  #endif
#endif

#ifndef BYTEORDER
  #if defined(_BIG_ENDIAN) || defined(__BIG_ENDIAN__)
    #define BYTEORDER 4321
  #elif defined(_LITTLE_ENDIAN) || defined(__LITTLE_ENDIAN__) || defined(WIN32)
    #define BYTEORDER 1234
  #endif
#endif

#ifndef BYTEORDER
  #error unable to determine BYTEORDER
#endif

#ifdef WIN32
  #include <time.h>
#else
  #ifdef HAVE_SYS_TIME_H
    #include <sys/time.h>
    #ifdef TIME_WITH_SYS_TIME
      #include <time.h>
    #endif
  #endif
#endif

/* 用于将节包装在'extern“C”｛'构造中的方便宏。 */
#ifdef __cplusplus
  #define BEGIN_C_DECLS extern "C" {
  #define END_C_DECLS   }
#else /* __cplusplus */
  #define BEGIN_C_DECLS
  #define END_C_DECLS
#endif /* __cplusplus */


#include "fko_util.h"
#include "fko_limits.h"
#include "fko_state.h"
#include "fko_context.h"
#include "fko_message.h"
#include "fko_user.h"

/* 试着为那些没有bzero的人做掩护。 */
#if !HAVE_BZERO && HAVE_MEMSET
 #define bzero(buf, bytes)      ((void) memset (buf, 0, bytes))
#endif

/* 解决没有strnlen的问题 */
#if !HAVE_STRNLEN
  #define strnlen(s, l) (strlen(s) < l ? strlen(s) : l)
#endif

/* 获取数组的元素数 */
#define ARRAY_SIZE(t)   (sizeof(t) / sizeof(t[0]))

#endif /* FKO_COMMON_H */

/* **EOF** */
