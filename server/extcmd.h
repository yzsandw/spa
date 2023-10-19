/**
 * \file server/extcmd.h
 *
 * \brief Header file for extcmd.c.
 */

#ifndef EXTCMD_H
#define EXTCMD_H

#define IO_READ_BUF_LEN     256
#define EXTCMD_DEF_TIMEOUT  15
#define NO_TIMEOUT          0
#define WANT_STDERR         0x01
#define WANT_STDOUT_GETLINE 0x02
#define ALLOW_PARTIAL_LINES 0x04
#define NO_STDERR           0
#define ROOT_UID            0
#define ROOT_GID            0

/* 外部命令结果可能最终进入的各种返回状态。
*/
enum {
    EXTCMD_WRITE_ERROR              =   -9,
    EXTCMD_CHDIR_ERROR              =   -8,
    EXTCMD_OPEN_ERROR               =   -7,
    EXTCMD_ARGV_ERROR               =   -6,
    EXTCMD_SETGID_ERROR             =   -5,
    EXTCMD_SETUID_ERROR             =   -4,
    EXTCMD_SELECT_ERROR             =   -3,
    EXTCMD_PIPE_ERROR               =   -2,
    EXTCMD_FORK_ERROR               =   -1,
    EXTCMD_SUCCESS_ALL_OUTPUT       = 0x00,
    EXTCMD_SUCCESS_PARTIAL_STDOUT   = 0x01,
    EXTCMD_SUCCESS_PARTIAL_STDERR   = 0x02,
    EXTCMD_STDOUT_READ_ERROR        = 0x04,
    EXTCMD_STDERR_READ_ERROR        = 0x08,
    EXTCMD_EXECUTION_ERROR          = 0x10,
    EXTCMD_EXECUTION_TIMEOUT        = 0x20
};

/* 一些用于测试extcmd返回状态的方便宏。
*/
#define EXTCMD_IS_SUCCESS(x) (x == EXTCMD_SUCCESS_ALL_OUTPUT)
#define EXTCMD_IS_SUCCESS_PARTIAL_STDOUT(x) (x && EXTCMD_SUCCESS_PARTIAL_STDOUT)
#define EXTCMD_IS_SUCCESS_PARTIAL_STDERR(x) (x && EXTCMD_SUCCESS_PARTIAL_STDERR)
#define EXTCMD_IS_SUCCESS_PARTIAL_OUTPUT(x) \
    ((x && EXTCMD_SUCCESS_PARTIAL_STDOUT) \
        || x && EXTCMD_SUCCESS_PARTIAL_STDERR)
#define EXTCMD_STDOUT_READ_ERROR(x) (x && EXTCMD_STDOUT_READ_ERROR)
#define EXTCMD_STDERR_READ_ERROR(x) (x && EXTCMD_STDERR_READ_ERROR)
#define EXTCMD_READ_ERROR(x) \
    ((x && EXTCMD_STDOUT_READ_ERROR) \
        || x && EXTCMD_STDERR_READ_ERROR)
#define EXTCMD_EXECUTION_ERROR(x) (x && EXTCMD_EXECUTION_ERROR)

#define EXTCMD_NOERROR(x,y) ((y == 0) \
    && (EXTCMD_IS_SUCCESS(x) || EXTCMD_IS_SUCCESS_PARTIAL_OUTPUT(x))

/* 功能原型
*/



/**
 * \brief 运行外部命令
 *
 * 这个函数实际上是_run_extcmd（）的包装器。
 * 运行一个返回退出状态的外部命令，并可以选择用STDOUT输出填充提供的缓冲区，直到提供的大小为止。
 *
*\param cmd要运行的命令
*\param so_buf用于命令输出的缓冲区，或用于放弃输出的空指针
*\param so_buf_sz so-buf的长度
*\param want_sderr指示要保存stderr的标志
*\param timeout占位符，未使用超时
*\param pid_status存储命令状态的指针
*\param opts程序选项结构
 *
 */
int run_extcmd(const char *cmd, char *so_buf, const size_t so_buf_sz,
        const int want_stderr, const int timeout, int *pid_status,
        const fko_srv_options_t * const opts);

/**
 * \brief 以给定用户和组的身份运行外部命令
 *
 *这个函数实际上是_run_extcmd（）的包装器。
 *运行外部命令，返回退出状态，并可选择填充
 *所提供的具有STDOUT输出的缓冲器达到所提供的大小。
 *此函数在运行命令时使用用户ID和组ID。
 *
 *\param uid要作为运行的用户
 *\param gid要作为运行的组
 *\param cmd要运行的命令
 *\param so_buf命令输出的缓冲区
 *\param so_buf_sz so-buf的长度
 *\param want_sderr指示要保存stderr的标志
 *\param timeout占位符，未使用超时
 *\param pid_status存储命令状态的指针
 *\param opts程序选项结构
 *
 */
int run_extcmd_as(uid_t uid, gid_t gid, const char *cmd, char *so_buf,
        const size_t so_buf_sz, const int want_stderr, const int timeout,
        int *pid_status, const fko_srv_options_t * const opts);

/**
 * \brief 运行外部命令，搜索子字符串
 *
 *这个函数实际上是_run_extcmd（）的包装器。
 *运行外部命令，返回退出状态，并可选择填充
 *所提供的具有STDOUT输出的缓冲器达到所提供的大小。
 *
*\param cmd要运行的命令
*\param want_sderr指示要保存stderr的标志
*\param timeout占位符，未使用超时
*\param substra_search要搜索的子字符串
*\param pid_status存储命令状态的指针
*\param opts程序选项结构
 */
int search_extcmd(const char *cmd, const int want_stderr,
        const int timeout, const char *substr_search,
        int *pid_status, const fko_srv_options_t * const opts);

/**
 * \brief 运行外部命令，返回一行输出
 *
 *这个函数实际上是_run_extcmd（）的包装器。
 *运行外部命令，返回退出状态，并可选择填充
 *所提供的具有STDOUT输出的缓冲器达到所提供的大小。
 *此函数搜索第一个匹配的命令输出
 *提供的子字符串返回匹配的行号，
 *并用该行输出填充so-buf。
 *
 *\param cmd要运行的命令
 *\param so_buf命令输出的缓冲区
 *\param so_buf_sz so-buf的长度
 *\param timeout占位符，未使用超时
 *\param substra_search要搜索的子字符串
 *\param pid_status存储命令状态的指针
 *\param opts程序选项结构
 *
 * \return 返回匹配的行号，或0表示不匹配
 */
int search_extcmd_getline(const char *cmd, char *so_buf, const size_t so_buf_sz,
        const int timeout, const char *substr_search, int *pid_status,
        const fko_srv_options_t * const opts);

/**
 * \brief 运行一个外部命令，并将其输入stdin
 *
 *这个函数实际上是_run_extcmd_write（）的包装器。
 *运行一个需要stdin的外部命令。
 *
*\param cmd要运行的命令
*\param cmd_write要作为stdin发送的文本
*\param pid_status存储命令状态的指针
*\param opts程序选项结构
 *
 */
int run_extcmd_write(const char *cmd, const char *cmd_write, int *pid_status,
        const fko_srv_options_t * const opts);
#endif /* EXTCMD_H */

/***EOF***/
