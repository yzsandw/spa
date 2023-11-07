#include "spad_common.h"
#include "utils.h"
#include "log_msg.h"

/* 默认的日志设施（可以通过配置文件指令进行覆盖）。
*/
static int syslog_fac = LOG_DAEMON;

/* 这个值会与所有日志调用上的日志级别进行或操作。这允许将日志强制发送到 stderr 而不是 syslog，只需将其设置为适当的值（这是在 init_logging() 中完成的）。
*/
static int static_log_flag = LOG_STDERR_ONLY;

/* 用于日志消息中的 ID 的名称。默认为 spad。
*/
static char *log_name = NULL;

/* 日志模块使用的默认详细程度值
*/
static int verbosity = LOG_DEFAULT_VERBOSITY;

/* 释放为日志分配的资源。
*/
void free_logging(void)
{
    if (log_name != NULL)
        free(log_name);
}

/* 初始化日志设置用于 syslog 的名称。
*/
void init_logging(ztn_srv_options_t *opts)
{
    char *my_name = NULL;
    int is_syslog = 0;

    /* 以防这是重新初始化。
    */
    free_logging();

    /* 为 log_name 分配内存，并将 my_name 设置为指向适当的名称。名称应该已经在配置结构中设置，但如果没有设置，就会回退到 'MY_NAME' 定义的默认值。
    */
    if (opts->config[CONF_SYSLOG_IDENTITY] != NULL
        && opts->config[CONF_SYSLOG_IDENTITY][0] != '\0')
    {
        my_name = opts->config[CONF_SYSLOG_IDENTITY];
        log_name = calloc(1, strlen(opts->config[CONF_SYSLOG_IDENTITY]) + 1);
        is_syslog = 1;
    }
    else
    {
        my_name = (char *) &MY_NAME;
        log_name = calloc(1, strlen(MY_NAME) + 1);
    }

    if (log_name == NULL)
    {
        fprintf(stderr, "设置 log_name 时的内存分配错误！\n");
        clean_exit(opts, NO_FW_CLEANUP, EXIT_FAILURE);
    }

    /* 设置我们的名称。
    */
    if (is_syslog)
        strlcpy(log_name, my_name, strlen(opts->config[CONF_SYSLOG_IDENTITY]) + 1);
    else
        strlcpy(log_name, my_name, strlen(MY_NAME) + 1);

    static_log_flag = LOG_SYSLOG_ONLY;

    /* 如果我们在前台运行或执行防火墙操作，所有日志将发送到 stderr。
    */
    if (opts->foreground != 0 || opts->fw_flush != 0 || opts->fw_list != 0 || opts->fw_list_all != 0)
        static_log_flag = LOG_STDERR_ONLY;

    /* 如果用户使用 --syslog-enable 强制使用 syslog，我们将移除 LOG_WITHOUT_SYSLOG 标志。这意味着所有消息将通过 syslog 发送*/
    if (opts->syslog_enable != 0)
        static_log_flag &= ~LOG_WITHOUT_SYSLOG;

    /* 解析配置结构中指定的日志设施。如果由于某种原因未设置，fac 将已设置为 LOG_DAEMON。
    */
    if (opts->config[CONF_SYSLOG_FACILITY] != NULL
        && opts->config[CONF_SYSLOG_FACILITY][0] != '\0')
    {
        if (!strcasecmp(opts->config[CONF_SYSLOG_FACILITY], "LOG_DAEMON"))
            syslog_fac = LOG_DAEMON;
        else if (!strcasecmp(opts->config[CONF_SYSLOG_FACILITY], "LOG_LOCAL0"))
            syslog_fac = LOG_LOCAL0;
        else if (!strcasecmp(opts->config[CONF_SYSLOG_FACILITY], "LOG_LOCAL1"))
            syslog_fac = LOG_LOCAL1;
        else if (!strcasecmp(opts->config[CONF_SYSLOG_FACILITY], "LOG_LOCAL2"))
            syslog_fac = LOG_LOCAL2;
        else if (!strcasecmp(opts->config[CONF_SYSLOG_FACILITY], "LOG_LOCAL3"))
            syslog_fac = LOG_LOCAL3;
        else if (!strcasecmp(opts->config[CONF_SYSLOG_FACILITY], "LOG_LOCAL4"))
            syslog_fac = LOG_LOCAL4;
        else if (!strcasecmp(opts->config[CONF_SYSLOG_FACILITY], "LOG_LOCAL5"))
            syslog_fac = LOG_LOCAL5;
        else if (!strcasecmp(opts->config[CONF_SYSLOG_FACILITY], "LOG_LOCAL6"))
            syslog_fac = LOG_LOCAL6;
        else if (!strcasecmp(opts->config[CONF_SYSLOG_FACILITY], "LOG_LOCAL7"))
            syslog_fac = LOG_LOCAL7;
        else
        {
            fprintf(stderr, "无效的 SYSLOG_FACILITY 设置 '%s'\n", opts->config[CONF_SYSLOG_FACILITY]);
            clean_exit(opts, NO_FW_CLEANUP, EXIT_FAILURE);
        }
    }

    verbosity = LOG_DEFAULT_VERBOSITY + opts->verbose;
}

/* syslog 消息函数。它使用在初始化时设置的默认值，还接受可变参数以适应类似 printf 的格式和扩展。
*/
void log_msg(int level, char *msg, ...)
{
    va_list ap, apse;

    /* 确保级别在正确的范围内
    */
    if ((level & LOG_VERBOSITY_MASK) > verbosity)
        return;

    va_start(ap, msg);

    level |= static_log_flag;

    /* 如果级别已与 LOG_STDERR 进行或操作，将消息打印到 stderr
    */
    if (LOG_STDERR & level)
    {
        /* 需要复制 va_list，以便在将其打印到 stderr 后不会破坏消息发送到 syslog 后的消息。
        */
        va_copy(apse, ap);

        vfprintf(stderr, msg, apse);
        fprintf(stderr, "\n");
        fflush(stderr);

        va_end(apse);
    }

    /* 如果消息不需要打印到 syslog，则返回
    */
    if (LOG_WITHOUT_SYSLOG & level)
    {
        va_end(ap);
        return;
    }

    /* 从级别中移除静态日志标志
    */
    level &= LOG_VERBOSITY_MASK;

    /* 将消息发送到 syslog。
    */
    openlog(log_name, LOG_PID, syslog_fac);

    vsyslog(level, msg, ap);

    va_end(ap);
}

/**
 * 设置日志模块当前上下文的详细程度级别。
 *
 * 模块使用的详细程度级别由 syslog 模块定义。
 *
 * @param level 要设置的详细程度级别（LOG_INFO、LOG
 * 设置的详细程度级别（LOG_INFO、LOG_NOTICE ...）
 */
void log_set_verbosity(int level)
{
    verbosity = level;
}

/***EOF***/
