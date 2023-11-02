/**
 * \file server/cmd_cycle.h
 *
 * \brief 用于管理vi access.conf节（CMD_CYCLE_OPEN和CMD_CYCLE_CLOSE）中定义的命令周期的函数原型。
 */


#ifndef CMD_CYCLE_H
#define CMD_CYCLE_H

#define CMD_CYCLE_BUFSIZE 256

/**
 * \brief 打开/关闭命令循环的主驱动器
 *
 *
 * 当接收到与包含命令周期的节匹配的有效SPA数据包时，将调用此函数。
 * 
 * \param opts
 * \param acc
 * \param spadat
 * \param stanza_num
 * \param res
 *
 */
int cmd_cycle_open(fko_srv_options_t *opts, acc_stanza_t *acc,
        spa_data_t *spadat, const int stanza_num, int *res);

/**
 * \brief 启动命令循环关闭命令
 *
 *
 * \param opts
 *
 */
void cmd_cycle_close(fko_srv_options_t *opts);

/**
 * \brief 释放命令周期列表
 *
 *
 * \param opts
 *
 */
void free_cmd_cycle_list(fko_srv_options_t *opts);

#endif  /* CMD_CYCLE_H */
