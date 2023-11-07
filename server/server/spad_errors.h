/**
 * \file server/spad_errors.h
 *
 * \brief spad_errors.c的头文件。
 */

#ifndef SPAD_ERRORS_H
#define SPAD_ERRORS_H

/* SPA消息处理状态代码
*/
enum {
    SPA_MSG_SUCCESS = 0,
    SPA_MSG_BAD_DATA = 0x1000,
    SPA_MSG_LEN_TOO_SMALL,
    SPA_MSG_NOT_SPA_DATA,
    SPA_MSG_HTTP_NOT_ENABLED,
    SPA_MSG_ZTN_CTX_ERROR,
    SPA_MSG_DIGEST_ERROR,
    SPA_MSG_DIGEST_CACHE_ERROR,
    SPA_MSG_REPLAY,
    SPA_MSG_TOO_OLD,
    SPA_MSG_ACCESS_DENIED,
    SPA_MSG_COMMAND_ERROR,
    SPA_MSG_NOT_SUPPORTED,
    SPA_MSG_NAT_NOT_ENABLED,
    SPA_MSG_ERROR
};

/* 防火墙规则处理错误代码
*/
enum {
    FW_RULE_SUCCESS = 0,
    FW_RULE_ADD_ERROR = 0x2000,
    FW_RULE_DELETE_ERROR,
    FW_RULE_UNKNOWN_ERROR
};

/* 用于确定错误代码是spa_msg处理程序错误和/或防火墙规则处理错误的宏。
*/
#define IS_SPA_MSG_ERROR(x) (x & 0x1000)
#define IS_FW_RULE_ERROR(x) (x & 0x2000)
#define IS_SPAD_ERROR(x) (IS_SPA_MSG_ERROR(x) | IS_FW_RULE_ERROR(x))

/* 功能原型
*/

/**
*\brief 获取一个数字错误代码并返回可读字符串
*\param err_code要转换的整数错误代码
*\return 返回一个指向错误字符串的指针
 */
const char* get_errstr(const int err_code);

/**
 * \brief 将所有服务器错误（从server/spad_errors.c）打印到stdout
 */
void dump_server_errors(void);

#endif /* SPAD_ERRORS_H */

/***EOF***/
