/**
 * \file server/fw_util_ipfw.h
 *
 * \brief fw_util_ipfw.c的头文件。
 */

#ifndef FW_UTIL_IPFW_H
#define FW_UTIL_IPFW_H

enum {
    RULE_FREE = 0,
    RULE_ACTIVE,
    RULE_EXPIRED,
    RULE_TMP_MARKED
};

/* ipfw command args
*/
#define IPFW_ADD_RULE_ARGS           "add %u set %u pass %u from %s to %s dst-port %u setup keep-state // " EXPIRE_COMMENT_PREFIX "%u"
#define IPFW_ADD_CHECK_STATE_ARGS    "add %u set %u check-state"
#define IPFW_MOVE_RULE_ARGS          "set move rule %u to %u"
#define IPFW_MOVE_SET_ARGS           "set move %u to %u"
#define IPFW_DISABLE_SET_ARGS        "set disable %u"
#define IPFW_LIST_ALL_RULES_ARGS     "list"
#define IPFW_DEL_RULE_SET_ARGS       "delete set %u"
#define IPFW_ANY_IP                  "me"

#ifdef __APPLE__
    #define IPFW_DEL_RULE_ARGS           "delete %u" //--DSS diff args
    #define IPFW_LIST_RULES_ARGS         "-d -S -T list | grep 'set %u'"
    #define IPFW_LIST_SET_RULES_ARGS     "-S list | grep 'set %u'"
    #define IPFW_LIST_EXP_SET_RULES_ARGS "-S list | grep 'set %u'"
    #define IPFW_LIST_SET_DYN_RULES_ARGS "-d list | grep 'set %u'"
#else
  #define IPFW_DEL_RULE_ARGS           "set %u delete %u"
  #define IPFW_LIST_RULES_ARGS         "-d -S -T set %u list"
  #define IPFW_LIST_SET_RULES_ARGS     "set %u list"
  #define IPFW_LIST_EXP_SET_RULES_ARGS "-S set %u list"
  #define IPFW_LIST_SET_DYN_RULES_ARGS "-d set %u list"
#endif

void ipfw_purge_expired_rules(const fko_srv_options_t *opts);

#endif /* FW_UTIL_IPFW_H */

/***EOF***/
