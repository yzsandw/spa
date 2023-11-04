/* * */


#ifndef LOG_MSG_H
#define LOG_MSG_H
/* 这段代码定义了一个枚举类型，用于表示不同的日志级别。枚举类型是一种特殊的整数类型，它为一组相关的常量提供了有意义的名称。 */
enum
{
    LOG_FIRST_VERBOSITY = 0,
    LOG_VERBOSITY_ERROR = 0,    /* ！<用于定义ERROR消息的常量 */
    LOG_VERBOSITY_WARNING,      /* ！<用于定义警告消息的常量 */
    LOG_VERBOSITY_NORMAL,       /* ！<常量，用于定义NORMAL消息 */
    LOG_VERBOSITY_INFO,         /* ！<用于定义INFO消息的常量 */
    LOG_VERBOSITY_DEBUG,        /* ！<用于定义DEBUG消息的常量 */
    LOG_LAST_VERBOSITY
};

#define LOG_DEFAULT_VERBOSITY   LOG_VERBOSITY_NORMAL    /* ！<要使用的默认详细程度 */

void log_new(void);
void log_free(void);
void log_set_verbosity(int level);
void log_msg(int verbosity_level, char *msg, ...);

#endif /* 日志_MSG_H */

/* **EOF** */
