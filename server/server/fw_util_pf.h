/**
 * \file server/fw_util_pf.h
 *
 * \brief fw_util_pf.c的头文件。
 */

#ifndef FW_UTIL_PF_H
#define FW_UTIL_PF_H

#define MAX_PF_ANCHOR_SEARCH_LEN    (MAX_PF_ANCHOR_LEN+11)   /* room for 'anchor "' string */
#define MAX_PF_NEW_RULE_LEN         140

#if HAVE_EXECVP
  #define SH_REDIR "" 
#else
  #define SH_REDIR " 2>&1"
#endif

/* pf command args
*/
#define PF_ADD_RULE_ARGS              "pass in quick proto %u from %s to %s port %u keep state label " EXPIRE_COMMENT_PREFIX "%u"
#define PF_WRITE_ANCHOR_RULES_ARGS    "-a %s -f -"
#if HAVE_EXECVP
  #define PF_LIST_ANCHOR_RULES_ARGS   "-a %s -s rules"
#else
  #define PF_LIST_ANCHOR_RULES_ARGS   "-a %s -s rules 2> /dev/null"
#endif
#define PF_ANCHOR_CHECK_ARGS          "-s Anchor" SH_REDIR  /* to check for spa anchor */
#define PF_DEL_ALL_ANCHOR_RULES       "-a %s -F all" SH_REDIR
#define PF_ANY_IP                     "any"

#endif /* FW_UTIL_PF_H */

/***EOF***/
