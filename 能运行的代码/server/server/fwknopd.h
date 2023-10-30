/**
 * \file server/fwknopd.h
 *
 * \brief fwknopd服务器程序的头文件。
 */

#ifndef FWKNOPD_H
#define FWKNOPD_H

#include "fwknopd_common.h"

#include <sys/file.h>
#include <sys/fcntl.h>

#if HAVE_LOCALE_H
  #include <locale.h>
#endif


#ifndef LOCK_SH
  /**
   * \def LOCK_SH
   *
   * \brief 共享文件锁定
   */
  #define   LOCK_SH        0x01
#endif
#ifndef LOCK_EX
  /**
   * \def LOCK_EX
   *
   * \brief 独占文件锁定
   */
  #define   LOCK_EX        0x02
#endif
#ifndef LOCK_NB
  /**
   * \def LOCK_NB
   *
   * \brief 锁定时不要阻塞
   */
  #define   LOCK_NB        0x04
#endif
#ifndef LOCK_UN
  /**
   * \def LOCK_UN
   *
   * \brief 解锁文件
   */
  #define   LOCK_UN        0x08
#endif

  /**
   * \def PID_BUFLEN
   *
   * \brief PID的缓冲区长度
   */
#define PID_BUFLEN 8

#endif  /* FWKNOPD_H */
