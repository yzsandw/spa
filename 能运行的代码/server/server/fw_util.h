/**
 * \file server/fw_util.h
 *
 * \brief fw_util.c的头文件
 */

#ifndef FW_UTIL_H
#define FW_UTIL_H

#define CMD_BUFSIZE                 256
#define MAX_FW_COMMAND_ARGS_LEN     256
#define CMD_LOOP_TRIES              10   /* 用于重复执行命令 */

#define STANDARD_CMD_OUT_BUFSIZE    4096

#define EXPIRE_COMMENT_PREFIX "_exp_"
#define TMP_COMMENT "__TMPCOMMENT__"
#define DUMMY_IP "127.0.0.2"

#if FIREWALL_FIREWALLD
  #include "fw_util_firewalld.h"
#elif FIREWALL_IPTABLES
  #include "fw_util_iptables.h"
#elif FIREWALL_IPFW
  #include "fw_util_ipfw.h"
#elif FIREWALL_PF
  #include "fw_util_pf.h"
#elif FIREWALL_IPF
  #include "fw_util_ipf.h"
#endif

#if HAVE_TIME_H
  #include <time.h>
#endif

/* 功能原型。
 *
*注意：这些是用于管理防火墙规则的公共功能。它们应该在每个相应的fw_util_<fw-type>.c文件中实现
*/
int fw_config_init(fko_srv_options_t * const opts);
int fw_initialize(const fko_srv_options_t * const opts);
int fw_cleanup(const fko_srv_options_t * const opts);
void check_firewall_rules(const fko_srv_options_t * const opts,
        const int chk_rm_all);
int fw_dump_rules(const fko_srv_options_t * const opts);
int process_spa_request(const fko_srv_options_t * const opts,
        const acc_stanza_t * const acc, spa_data_t * const spadat);

#endif /* FW_UTIL_H */

/***EOF***/
