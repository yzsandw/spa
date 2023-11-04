

#include "fwknop_common.h"
#include "log_msg.h"
#include <stdarg.h>

#define LOG_STREAM_STDERR   stderr                  /* ！<错误和警告消息被重定向到stderr */
#define LOG_STREAM_STDOUT   stdout                  /* ！<正常、信息和调试消息被重定向到stdout */

typedef struct
{
    int verbosity;//详细程度级别                                  /* ！<详细级别（LOG_Verbosity_DEBUG。。。 */
} log_ctx_t;

static log_ctx_t log_ctx;                           /* ！<用于存储模块上下文的结构 */

/* * */
void
log_new(void)
{
    log_ctx.verbosity = LOG_DEFAULT_VERBOSITY;
}


void
log_set_verbosity(int level)
{
    log_ctx.verbosity = level;
}


/* 2020年7月3日15:37:07 */


/* * */
void
log_msg(int level, char* msg, ...)
{
    va_list ap;

    if (level <= log_ctx.verbosity)
    {
        va_start(ap, msg);

        switch (level)
        {
            case LOG_VERBOSITY_ERROR:
            case LOG_VERBOSITY_WARNING:
                vfprintf(LOG_STREAM_STDERR, msg, ap);
                fprintf(LOG_STREAM_STDERR, "\n");
                break;
            case LOG_VERBOSITY_NORMAL:
            case LOG_VERBOSITY_INFO:
            case LOG_VERBOSITY_DEBUG:
            default :
                vfprintf(LOG_STREAM_STDOUT, msg, ap);
                fprintf(LOG_STREAM_STDOUT, "\n");
                break;
        }

        va_end(ap);
    }
    else;
}

/* **EOF** */
