/**
 * \file server/log_msg.h
 *
 * \brief log_msg.c的头文件。
 */

#ifndef LOG_MSG_H
#define LOG_MSG_H

#include <syslog.h>
#include <stdarg.h>


#define LOG_SYSLOG_ONLY         0x0000
#define LOG_STDERR              0x1000
#define LOG_WITHOUT_SYSLOG      0x2000
#define LOG_STDERR_ONLY         (LOG_STDERR | LOG_WITHOUT_SYSLOG)
#define LOG_VERBOSITY_MASK      0x0FFF

#define LOG_DEFAULT_VERBOSITY   LOG_INFO    

void init_logging(fko_srv_options_t *opts);
void free_logging(void);
void set_log_facility(int fac);
void log_msg(int, char*, ...);
void log_set_verbosity(int level);

#endif /* LOG_MSG_H */

/***EOF***/
