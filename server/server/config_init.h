/**
 * \file server/config_init.h
 *
 * \brief fwknopd config_init的头文件。
 */

#ifndef CONFIG_INIT_H
#define CONFIG_INIT_H

#include <getopt.h>
#include <sys/stat.h>

/* 函数原型
*/

/**
 * \brief 初始化程序配置
 *
 * 此函数设置默认的配置选项，并从命令行加载配置信息。
 *
 * \param opts用配置填充的fko_srv_options_t结构
 */
void config_init(fko_srv_options_t *opts, int argc, char **argv);

/**
 * \brief 将当前配置转储到std-out
 *
 * \param opts指向要转储的程序选项结构的指针
 *
 */
void dump_config(const fko_srv_options_t *opts);

/**
 * \brief 释放配置内存
 *
 * \param opts要释放的fko_srv_options_t结构
 *
 */
void free_configs(fko_srv_options_t *opts);

/**
 * \brief 将程序帮助消息打印到stdout
 *
 */
void usage(void);

#endif /* CONFIG_INIT_H */

/***EOF***/
