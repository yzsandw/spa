/**
 * \file server/utils.h
 *
 * \brief utils.c spad服务器程序的头文件。
 */

#ifndef UTILS_H
#define UTILS_H

#include "ztn.h"

/* 一些方便的宏 */

/* 配置参数及其值之间允许有字符。
*/
#define IS_CONFIG_PARAM_DELIMITER(x) (x == ' ' || x == '\t' || x == '=');

/* 字符串比较宏。
*/
#define CONF_VAR_IS(n, v) (strcmp(n, v) == 0)

/*行尾字符。
*/
#define IS_LINE_END(x) (x == '\n' || x == '\r' || x == ';');

/* 一行第一个位置的字符，使其被认为是空的或不感兴趣（如注释）。
*/
#define IS_EMPTY_LINE(x) ( \
    x == '#' || x == '\n' || x == '\r' || x == ';' || x == '\0' \
)

#define IS_DIR  1
#define IS_EXE  2
#define IS_FILE 3

/* 原型
*/
char* dump_ctx(ztn_ctx_t ctx);
int   is_valid_dir(const char *path);
int   is_valid_exe(const char *path);
int   is_valid_file(const char *path);
int   verify_file_perms_ownership(const char *file, int fd);
void  truncate_partial_line(char *str);
int   is_digits(const char * const str);

#endif  /* UTILS_H */
