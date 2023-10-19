/**
 * \file server/fw_util_firewalld.h
 *
 * \brief fw_util_firewalld.c的头文件。
 */

#ifndef FW_UTIL_FIREWALLD_H
#define FW_UTIL_FIREWALLD_H

#define SNAT_TARGET_BUFSIZE   64

#define FIREWD_CMD_FAIL_STR   "COMMAND_FAILED" /* returned by firewall-cmd */
#define FIREWD_CMD_PREFIX     "--direct --passthrough ipv4"

#if HAVE_EXECVP
  #define SH_REDIR "" /* execvp（）可用时不使用shell */
#else
  #define SH_REDIR " 2>&1"
#endif

/* firewalld command args
*/
#define FIREWD_CHK_RULE_ARGS       "-C %s %s" /* the other macros add SH_REDIR if necessary */
#define FIREWD_RULE_ARGS           "-t %s -p %i -s %s -d %s --dport %i -m comment --comment " EXPIRE_COMMENT_PREFIX "%u -j %s" SH_REDIR
#define FIREWD_OUT_RULE_ARGS       "-t %s -p %i -d %s -s %s --sport %i -m comment --comment " EXPIRE_COMMENT_PREFIX "%u -j %s" SH_REDIR
#define FIREWD_FWD_RULE_ARGS       "-t %s -p %i -s %s --dport %i -m comment --comment " EXPIRE_COMMENT_PREFIX "%u -j %s" SH_REDIR
#define FIREWD_FWD_ALL_RULE_ARGS   "-t %s -s %s -m comment --comment " EXPIRE_COMMENT_PREFIX "%u -j %s" SH_REDIR
#define FIREWD_DNAT_RULE_ARGS      "-t %s -p %i -s %s -d %s --dport %i -m comment --comment " EXPIRE_COMMENT_PREFIX "%u -j %s --to-destination %s:%i" SH_REDIR
#define FIREWD_DNAT_ALL_RULE_ARGS  "-t %s -s %s -d %s -m comment --comment " EXPIRE_COMMENT_PREFIX "%u -j %s --to-destination %s" SH_REDIR
#define FIREWD_SNAT_RULE_ARGS      "-t %s -p %i -d %s --dport %i -m comment --comment " EXPIRE_COMMENT_PREFIX "%u -j %s %s" SH_REDIR
#define FIREWD_SNAT_ALL_RULE_ARGS     "-t %s -s %s -m comment --comment " EXPIRE_COMMENT_PREFIX "%u -j %s %s" SH_REDIR
#define FIREWD_TMP_COMMENT_ARGS    "-t %s -I %s %i -s " DUMMY_IP " -m comment --comment " TMP_COMMENT " -j %s" SH_REDIR
#define FIREWD_TMP_CHK_RULE_ARGS   "-t %s -I %s %i -s " DUMMY_IP " -p udp -j %s" SH_REDIR
#define FIREWD_TMP_VERIFY_CHK_ARGS "-t %s -C %s -s " DUMMY_IP " -p udp -j %s" SH_REDIR
#define FIREWD_DEL_RULE_ARGS       "-t %s -D %s %i" SH_REDIR
#define FIREWD_NEW_CHAIN_ARGS      "-t %s -N %s" SH_REDIR
#define FIREWD_FLUSH_CHAIN_ARGS    "-t %s -F %s" SH_REDIR
#define FIREWD_CHAIN_EXISTS_ARGS   "-t %s -L %s -n" SH_REDIR
#define FIREWD_DEL_CHAIN_ARGS      "-t %s -X %s" SH_REDIR
#define FIREWD_CHK_JUMP_RULE_ARGS  "-t %s -j %s" SH_REDIR
#define FIREWD_ADD_JUMP_RULE_ARGS  "-t %s -I %s %i -j %s" SH_REDIR
#define FIREWD_DEL_JUMP_RULE_ARGS  "-t %s -D %s -j %s" SH_REDIR  /* let firewalld work out the rule number */
#define FIREWD_LIST_RULES_ARGS     "-t %s -L %s --line-numbers -n" SH_REDIR
#define FIREWD_LIST_ALL_RULES_ARGS "-t %s -v -n -L --line-numbers" SH_REDIR
#define FIREWD_ANY_IP              "0.0.0.0/0"

#if USE_LIBNETFILTER_QUEUE
  #define FIREWD_NFQ_ADD_ARGS "-t %s -A %s -p udp -m udp --dport %s -j NFQUEUE --queue-num %s"
  #define FIREWD_NFQ_ADD_ARGS_WITH_IF "-t %s -A %s -i %s -p udp -m udp --dport %s -j NFQUEUE --queue-num %s"
  #define FIREWD_NFQ_DEL_ARGS "-t %s -D %s -p udp -m udp --dport %s -j NFQUEUE --queue-num %s"
#endif

int validate_firewd_chain_conf(const char * const chain_str);

#endif /* FW_UTIL_FIREWALLD_H */

/***EOF***/
