/**
 * \file server/incoming_spa.h
 *
 * \brief incomig_spa.c的头文件。
 */

#ifndef INCOMING_SPA_H
#define INCOMING_SPA_H

/* 原型
*/

/**
 * \brief 处理SPA数据包
 *
 *这是处理传入SPA数据的中心功能。每个要处理的SPA数据包调用一次
 *
 * \param opts Main program data struct
 *
 */
void incoming_spa(ztn_srv_options_t *opts);

#endif  /* INCOMING_SPA_H */
