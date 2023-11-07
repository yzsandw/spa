/**
 * \file server/spad_common.h
 *
 * \brief spad源文件的头文件。
 */

#ifndef SPAD_COMMON_H
#define SPAD_COMMON_H

#include "common.h"

#if PLATFORM_OPENBSD
  #include <netinet/in.h>
#endif

#if HAVE_SYS_STAT_H
  #include <sys/stat.h>
#endif

#if USE_LIBPCAP
  #include <pcap.h>
#endif


#define MY_NAME     "spad"
#define MY_DESC     "Single Packet Authorization server"

/* 从version获取程序版本。（在config.h中定义）
*/
#define MY_VERSION VERSION

/* 某些程序默认设置。
*/
#ifndef DEF_CONF_DIR
  /* 我们的默认配置目录基于配置脚本设置的SYSCONFDIR。
  */
  #define DEF_CONF_DIR      SYSCONFDIR"/"PACKAGE_NAME
#endif

#define DEF_CONFIG_FILE     DEF_CONF_DIR"/"MY_NAME".conf"
#define DEF_ACCESS_FILE     DEF_CONF_DIR"/access.conf"

#ifndef DEF_RUN_DIR
  /* 我们的默认运行目录基于configure脚本设置的LOCALSTATEDIR。这是我们放置PID和摘要缓存文件的地方。
  */
  #define DEF_RUN_DIR       SYSRUNDIR"/"PACKAGE_NAME
#endif

/* More Conf defaults
*/
#define DEF_PID_FILENAME                MY_NAME".pid"
#if USE_FILE_CACHE
  #define DEF_DIGEST_CACHE_FILENAME       "digest.cache"
#else
  #define DEF_DIGEST_CACHE_DB_FILENAME    "digest_db.cache"
#endif

#define DEF_INTERFACE                   "eth0"
#define DEF_ENABLE_PCAP_PROMISC         "N"
#define DEF_PCAP_FILTER                 "udp port 62201"
#define DEF_PCAP_DISPATCH_COUNT         "100"
#define DEF_PCAP_LOOP_SLEEP             "100000" /* a tenth of a second (in microseconds) */
#define DEF_ENABLE_PCAP_ANY_DIRECTION   "N"
#define DEF_EXIT_AT_INTF_DOWN           "Y"
#define DEF_ENABLE_SPA_PACKET_AGING     "Y"
#define DEF_MAX_SPA_PACKET_AGE          "120"
#define DEF_ENABLE_DIGEST_PERSISTENCE   "Y"
#define DEF_RULES_CHECK_THRESHOLD       "20"
#define DEF_MAX_SNIFF_BYTES             "1500"
#define DEF_GPG_HOME_DIR                "/root/.gnupg"
#define DEF_ENABLE_X_FORWARDED_FOR      "N"
#define DEF_ENABLE_RULE_PREPEND         "N"
#define DEF_ENABLE_NAT_DNS              "Y"
#ifdef  GPG_EXE
  #define DEF_GPG_EXE                   GPG_EXE
#else
  #define DEF_GPG_EXE                   "/usr/bin/gpg"
#endif
#ifdef  SUDO_EXE
  #define DEF_SUDO_EXE                   SUDO_EXE
#else
  #define DEF_SUDO_EXE                   "/usr/bin/sudo"
#endif
#define DEF_ENABLE_SPA_OVER_HTTP        "N"
#define DEF_ALLOW_ANY_USER_AGENT        "N"
#define DEF_ENABLE_TCP_SERVER           "N"
#define DEF_TCPSERV_PORT                "62201"
#if USE_LIBPCAP
  #define DEF_ENABLE_UDP_SERVER           "N"
#else
  #define DEF_ENABLE_UDP_SERVER           "Y"
#endif
#if USE_LIBNETFILTER_QUEUE
  #define DEF_ENABLE_NFQ_CAPTURE          "N"
  #define DEF_NFQ_INTERFACE               ""
  #define DEF_NFQ_PORT                    "62201"
  #define DEF_NFQ_TABLE                   "mangle"
  #define DEF_NFQ_CHAIN                   "SPA_NFQ"
  #define DEF_NFQ_QUEUE_NUMBER            "1"
  #define DEF_CONF_NFQ_LOOP_SLEEP         "500000" /* 半秒（以微秒为单位） */

#endif
#define DEF_UDPSERV_PORT                "62201"
#define DEF_UDPSERV_SELECT_TIMEOUT      "500000" /* 半秒（以微秒为单位） */
#define DEF_SYSLOG_IDENTITY             MY_NAME
#define DEF_SYSLOG_FACILITY             "LOG_DAEMON"
#define DEF_ENABLE_DESTINATION_RULE     "N"

#define DEF_FW_ACCESS_TIMEOUT           30
#define DEF_MAX_FW_TIMEOUT              300

/* For integer variable range checking
*/
#define RCHK_MAX_PCAP_LOOP_SLEEP        (2 << 22)
#define RCHK_MAX_SPA_PACKET_AGE         100000  /* 秒，可以禁用*/
#define RCHK_MAX_SNIFF_BYTES            (2 << 14)
#define RCHK_MAX_TCPSERV_PORT           ((2 << 16) - 1)
#define RCHK_MAX_UDPSERV_PORT           ((2 << 16) - 1)
#define RCHK_MAX_UDPSERV_SELECT_TIMEOUT (2 << 22)
#define RCHK_MAX_PCAP_DISPATCH_COUNT    (2 << 22)
#define RCHK_MAX_FW_TIMEOUT             (2 << 22) /* seconds */
#define RCHK_MAX_CMD_CYCLE_TIMER        (2 << 22) /* seconds */
#define RCHK_MIN_CMD_CYCLE_TIMER        1
#define RCHK_MAX_RULES_CHECK_THRESHOLD  ((2 << 16) - 1)

/* FirewallD-specific defines
*/
#if FIREWALL_FIREWALLD

  #define DEF_FLUSH_FIREWD_AT_INIT         "Y"
  #define DEF_FLUSH_FIREWD_AT_EXIT         "Y"
  #define DEF_ENABLE_FIREWD_FORWARDING     "N"
  #define DEF_ENABLE_FIREWD_LOCAL_NAT      "N"
  #define DEF_ENABLE_FIREWD_SNAT           "N"
  #define DEF_ENABLE_FIREWD_OUTPUT         "N"
  #define DEF_ENABLE_FIREWD_COMMENT_CHECK  "Y"
  #define DEF_FIREWD_INPUT_ACCESS          "ACCEPT, filter, INPUT, 1, SPA_INPUT, 1"
  #define DEF_FIREWD_OUTPUT_ACCESS         "ACCEPT, filter, OUTPUT, 1, SPA_OUTPUT, 1"
  #define DEF_FIREWD_FORWARD_ACCESS        "ACCEPT, filter, FORWARD, 1, SPA_FORWARD, 1"
  #define DEF_FIREWD_DNAT_ACCESS           "DNAT, nat, PREROUTING, 1, SPA_PREROUTING, 1"
  #define DEF_FIREWD_SNAT_ACCESS           "SNAT, nat, POSTROUTING, 1, SPA_POSTROUTING, 1"
  #define DEF_FIREWD_MASQUERADE_ACCESS     "MASQUERADE, nat, POSTROUTING, 1, SPA_MASQUERADE, 1"

  #define RCHK_MAX_FIREWD_RULE_NUM         (2 << 15)

/* Iptables-specific defines
*/
#elif FIREWALL_IPTABLES

  #define DEF_FLUSH_IPT_AT_INIT         "Y"
  #define DEF_FLUSH_IPT_AT_EXIT         "Y"
  #define DEF_ENABLE_IPT_FORWARDING     "N"
  #define DEF_ENABLE_IPT_LOCAL_NAT      "N"
  #define DEF_ENABLE_IPT_SNAT           "N"
  #define DEF_ENABLE_IPT_OUTPUT         "N"
  #define DEF_ENABLE_IPT_COMMENT_CHECK  "Y"
  #define DEF_IPT_INPUT_ACCESS          "ACCEPT, filter, INPUT, 1, SPA_INPUT, 1"
  #define DEF_IPT_OUTPUT_ACCESS         "ACCEPT, filter, OUTPUT, 1, SPA_OUTPUT, 1"
  #define DEF_IPT_FORWARD_ACCESS        "ACCEPT, filter, FORWARD, 1, SPA_FORWARD, 1"
  #define DEF_IPT_DNAT_ACCESS           "DNAT, nat, PREROUTING, 1, SPA_PREROUTING, 1"
  #define DEF_IPT_SNAT_ACCESS           "SNAT, nat, POSTROUTING, 1, SPA_POSTROUTING, 1"
  #define DEF_IPT_MASQUERADE_ACCESS     "MASQUERADE, nat, POSTROUTING, 1, SPA_MASQUERADE, 1"

  #define RCHK_MAX_IPT_RULE_NUM         (2 << 15)

/* Ipfw-specific defines
*/
#elif FIREWALL_IPFW

  #define DEF_FLUSH_IPFW_AT_INIT         "Y"
  #define DEF_FLUSH_IPFW_AT_EXIT         "Y"
  #define DEF_IPFW_START_RULE_NUM        "10000"
  #define DEF_IPFW_MAX_RULES             "65535"
  #define DEF_IPFW_ACTIVE_SET_NUM        "1"
  #define DEF_IPFW_EXPIRE_SET_NUM        "2"
  #define DEF_IPFW_EXPIRE_PURGE_INTERVAL "30"
  #define DEF_IPFW_ADD_CHECK_STATE       "N"

  #define RCHK_MAX_IPFW_START_RULE_NUM   ((2 << 16) - 1)
  #define RCHK_MAX_IPFW_MAX_RULES        ((2 << 16) - 1)
  #define RCHK_MAX_IPFW_SET_NUM          ((2 << 5) - 1)
  #define RCHK_MAX_IPFW_PURGE_INTERVAL   ((2 << 16) - 1)

#elif FIREWALL_PF

  #define DEF_PF_ANCHOR_NAME             "spa"
  #define DEF_PF_EXPIRE_INTERVAL         "30"

  #define RCHK_MAX_PF_EXPIRE_INTERVAL    ((2 << 16) - 1)

#elif FIREWALL_IPF

    /* --DSS Place-holder */

#endif /* FIREWALL Type */

/* spad特定限值
*/
#define MAX_PCAP_FILTER_LEN     1024
#define MAX_IFNAME_LEN          128
#define MAX_SPA_PACKET_LEN      1500 /* --DSS check this? */
#define MAX_DECRYPTED_SPA_LEN   1024

/* 可能的最小有效SPA数据大小。
*/
#define MIN_SPA_DATA_SIZE   140

/* 配置文件参数标记。这将对应于配置参数数组中的条目。
*/
enum {
    CONF_CONFIG_FILE = 0,
    CONF_OVERRIDE_CONFIG,
    //CONF_FIREWALL_TYPE,
    CONF_PCAP_INTF,
    CONF_PCAP_FILE,
    CONF_ENABLE_PCAP_PROMISC,
    CONF_PCAP_FILTER,
    CONF_PCAP_DISPATCH_COUNT,
    CONF_PCAP_LOOP_SLEEP,
    CONF_ENABLE_PCAP_ANY_DIRECTION,
    CONF_EXIT_AT_INTF_DOWN,
    CONF_MAX_SNIFF_BYTES,
    CONF_ENABLE_SPA_PACKET_AGING,
    CONF_MAX_SPA_PACKET_AGE,
    CONF_ENABLE_DIGEST_PERSISTENCE,
    CONF_RULES_CHECK_THRESHOLD,
    CONF_CMD_EXEC_TIMEOUT,
    //CONF_BLACKLIST,
    CONF_ENABLE_SPA_OVER_HTTP,
    CONF_ALLOW_ANY_USER_AGENT,
    CONF_ENABLE_TCP_SERVER,
    CONF_TCPSERV_PORT,
    CONF_ENABLE_UDP_SERVER,
    CONF_UDPSERV_PORT,
    CONF_UDPSERV_SELECT_TIMEOUT,
#if USE_LIBNETFILTER_QUEUE
    CONF_ENABLE_NFQ_CAPTURE,
    CONF_NFQ_INTERFACE,
    CONF_NFQ_PORT,
    CONF_NFQ_TABLE,
    CONF_NFQ_CHAIN,
    CONF_NFQ_QUEUE_NUMBER,
    CONF_NFQ_LOOP_SLEEP,
#endif
    CONF_LOCALE,
    CONF_SYSLOG_IDENTITY,
    CONF_SYSLOG_FACILITY,
    //CONF_IPT_EXEC_TRIES,
    //CONF_ENABLE_EXTERNAL_CMDS,
    //CONF_EXTERNAL_CMD_OPEN,
    //CONF_EXTERNAL_CMD_CLOSE,
    //CONF_EXTERNAL_CMD_ALARM,
    //CONF_ENABLE_EXT_CMD_PREFIX,
    //CONF_EXT_CMD_PREFIX,
    CONF_ENABLE_X_FORWARDED_FOR,
    CONF_ENABLE_DESTINATION_RULE,
    CONF_ENABLE_RULE_PREPEND,
    CONF_ENABLE_NAT_DNS,
#if FIREWALL_FIREWALLD
    CONF_ENABLE_FIREWD_FORWARDING,
    CONF_ENABLE_FIREWD_LOCAL_NAT,
    CONF_ENABLE_FIREWD_SNAT,
    CONF_SNAT_TRANSLATE_IP,
    CONF_ENABLE_FIREWD_OUTPUT,
    CONF_FLUSH_FIREWD_AT_INIT,
    CONF_FLUSH_FIREWD_AT_EXIT,
    CONF_FIREWD_INPUT_ACCESS,
    CONF_FIREWD_OUTPUT_ACCESS,
    CONF_FIREWD_FORWARD_ACCESS,
    CONF_FIREWD_DNAT_ACCESS,
    CONF_FIREWD_SNAT_ACCESS,
    CONF_FIREWD_MASQUERADE_ACCESS,
    CONF_ENABLE_FIREWD_COMMENT_CHECK,
#elif FIREWALL_IPTABLES
    CONF_ENABLE_IPT_FORWARDING,
    CONF_ENABLE_IPT_LOCAL_NAT,
    CONF_ENABLE_IPT_SNAT,
    CONF_SNAT_TRANSLATE_IP,
    CONF_ENABLE_IPT_OUTPUT,
    CONF_FLUSH_IPT_AT_INIT,
    CONF_FLUSH_IPT_AT_EXIT,
    CONF_IPT_INPUT_ACCESS,
    CONF_IPT_OUTPUT_ACCESS,
    CONF_IPT_FORWARD_ACCESS,
    CONF_IPT_DNAT_ACCESS,
    CONF_IPT_SNAT_ACCESS,
    CONF_IPT_MASQUERADE_ACCESS,
    CONF_ENABLE_IPT_COMMENT_CHECK,
#elif FIREWALL_IPFW
    CONF_FLUSH_IPFW_AT_INIT,
    CONF_FLUSH_IPFW_AT_EXIT,
    CONF_IPFW_START_RULE_NUM,
    CONF_IPFW_MAX_RULES,
    CONF_IPFW_ACTIVE_SET_NUM,
    CONF_IPFW_EXPIRE_SET_NUM,
    CONF_IPFW_EXPIRE_PURGE_INTERVAL,
    CONF_IPFW_ADD_CHECK_STATE,
#elif FIREWALL_PF
    CONF_PF_ANCHOR_NAME,
    CONF_PF_EXPIRE_INTERVAL,
#elif FIREWALL_IPF
    /* --DSS Place-holder */
#endif /* FIREWALL type */
    CONF_SPA_RUN_DIR,
    CONF_SPA_CONF_DIR,
    CONF_ACCESS_FILE,
    CONF_ACCESS_FOLDER,
    CONF_SPA_PID_FILE,
#if USE_FILE_CACHE
    CONF_DIGEST_FILE,
#else
    CONF_DIGEST_DB_FILE,
#endif
    CONF_GPG_HOME_DIR,
    CONF_GPG_EXE,
    CONF_SUDO_EXE,
    CONF_FIREWALL_EXE,
    CONF_VERBOSE,
#if AFL_FUZZING
    CONF_AFL_PKT_FILE,
#endif
    CONF_FAULT_INJECTION_TAG,

    NUMBER_OF_CONFIG_ENTRIES  /* Marks the end and number of entries */
};

/* 访问节项的uint的简单链接列表，允许使用多个逗号分隔的条目
*/
typedef struct acc_int_list
{
    unsigned int        maddr;
    unsigned int        mask;
    struct acc_int_list *next;
} acc_int_list_t;

/* 访问节项的proto和端口的简单链表，允许多个逗号分隔的条目。
*/
typedef struct acc_port_list
{
    unsigned int            proto;
    unsigned int            port;
    struct acc_port_list    *next;
} acc_port_list_t;

/* 访问节项的字符串的简单链表，允许使用多个逗号分隔的条目。
*/
typedef struct acc_string_list
{
    char                    *str;
    struct acc_string_list  *next;
} acc_string_list_t;

/*访问节列表结构。
*/
typedef struct acc_stanza
{
    char                *source;
    acc_int_list_t      *source_list;
    char                *destination;
    acc_int_list_t      *destination_list;
    char                *open_ports;
    acc_port_list_t     *oport_list;
    char                *restrict_ports;
    acc_port_list_t     *rport_list;
    char                *key;
    int                  key_len;
    char                *key_base64;
    char                *hmac_key;
    int                  hmac_key_len;
    char                *hmac_key_base64;
    int                  hmac_type;
    unsigned char        use_rijndael;
    int                  fw_access_timeout;
    int                  max_fw_timeout;
    unsigned char        enable_cmd_exec;
    unsigned char        enable_cmd_sudo_exec;
    char                *cmd_sudo_exec_user;
    char                *cmd_sudo_exec_group;
    uid_t                cmd_sudo_exec_uid;
    gid_t                cmd_sudo_exec_gid;
    char                *cmd_exec_user;
    char                *cmd_exec_group;
    char                *cmd_cycle_open;
    char                *cmd_cycle_close;
    unsigned char        cmd_cycle_do_close;
    int                  cmd_cycle_timer;
    uid_t                cmd_exec_uid;
    gid_t                cmd_exec_gid;
    char                *require_username;
    unsigned char        require_source_address;
    char                *gpg_home_dir;
    char                *gpg_exe;
    char                *gpg_decrypt_id;
    char                *gpg_decrypt_pw;
    unsigned char        gpg_require_sig;
    unsigned char        gpg_disable_sig;
    unsigned char        gpg_ignore_sig_error;
    unsigned char        use_gpg;
    unsigned char        gpg_allow_no_pw;
    char                *gpg_remote_id;
    acc_string_list_t   *gpg_remote_id_list;
    char                *gpg_remote_fpr;
    acc_string_list_t   *gpg_remote_fpr_list;
    time_t               access_expire_time;
    int                  expired;
    int                  encryption_mode;

    /* NAT参数
    */
    unsigned char        force_nat;
    char                *force_nat_ip;
    char                *force_nat_proto;
    unsigned int         force_nat_port;
    unsigned char        forward_all;
    unsigned char        disable_dnat;
    unsigned char        force_snat;
    char                *force_snat_ip;
    unsigned char        force_masquerade;

    struct acc_stanza   *next;
} acc_stanza_t;

/* 用于命令打开/关闭周期的字符串的简单链表
*/
typedef struct cmd_cycle_list
{
    char                    src_ip[MAX_IPV4_STR_LEN];
    char                   *close_cmd;
    time_t                  expire;
    int                     stanza_num;
    struct cmd_cycle_list  *next;
} cmd_cycle_list_t;

/* 防火墙相关数据和类型. */

#if FIREWALL_FIREWALLD

  #define MAX_TABLE_NAME_LEN      64
  #define MAX_CHAIN_NAME_LEN      64
  #define MAX_TARGET_NAME_LEN     64

  /* Spa自定义链类型
  */
  enum {
      FIREWD_INPUT_ACCESS,
      FIREWD_OUTPUT_ACCESS,
      FIREWD_FORWARD_ACCESS,
      FIREWD_DNAT_ACCESS,
      FIREWD_SNAT_ACCESS,
      FIREWD_MASQUERADE_ACCESS,
      NUM_SPA_ACCESS_TYPES
  };

  /* 结构来定义spa防火墙链配置。
  */
  struct fw_chain {
      int     type;
      char    target[MAX_TARGET_NAME_LEN];
      char    table[MAX_TABLE_NAME_LEN];
      char    from_chain[MAX_CHAIN_NAME_LEN];
      int     jump_rule_pos;
      char    to_chain[MAX_CHAIN_NAME_LEN];
      int     rule_pos;
      int     active_rules;
      time_t  next_expire;
  };

  /* 基于fw_chain字段（不计算类型）
  */
  #define FW_NUM_CHAIN_FIELDS 6

  struct fw_config {
      struct fw_chain chain[NUM_SPA_ACCESS_TYPES];
      char            fw_command[MAX_PATH_LEN];

      /* 用于在规则中设置目标字段的标志
      */
      unsigned char   use_destination;
  };

#elif FIREWALL_IPTABLES

  #define MAX_TABLE_NAME_LEN      64
  #define MAX_CHAIN_NAME_LEN      64
  #define MAX_TARGET_NAME_LEN     64

  /* Spa自定义链类型
  */
  enum {
      IPT_INPUT_ACCESS,
      IPT_OUTPUT_ACCESS,
      IPT_FORWARD_ACCESS,
      IPT_DNAT_ACCESS,
      IPT_SNAT_ACCESS,
      IPT_MASQUERADE_ACCESS,
      NUM_SPA_ACCESS_TYPES
  };

  /* 结构来定义spa防火墙链配置。
  */
  struct fw_chain {
      int     type;
      char    target[MAX_TARGET_NAME_LEN];
      char    table[MAX_TABLE_NAME_LEN];
      char    from_chain[MAX_CHAIN_NAME_LEN];
      int     jump_rule_pos;
      char    to_chain[MAX_CHAIN_NAME_LEN];
      int     rule_pos;
      int     active_rules;
      time_t  next_expire;
  };


  #define FW_NUM_CHAIN_FIELDS 6

  struct fw_config {
      struct fw_chain chain[NUM_SPA_ACCESS_TYPES];
      char            fw_command[MAX_PATH_LEN];


      unsigned char   use_destination;
  };

#elif FIREWALL_IPFW

  struct fw_config {
      unsigned short    start_rule_num;
      unsigned short    max_rules;
      unsigned short    active_rules;
      unsigned short    total_rules;
      unsigned short    active_set_num;
      unsigned short    expire_set_num;
      unsigned short    purge_interval;
      unsigned char    *rule_map;
      time_t            next_expire;
      time_t            last_purge;
      char              fw_command[MAX_PATH_LEN];
      unsigned char     use_destination;
  };

#elif FIREWALL_PF

  #define MAX_PF_ANCHOR_LEN 64

  struct fw_config {
      unsigned short    active_rules;
      time_t            next_expire;
      char              anchor[MAX_PF_ANCHOR_LEN];
      char              fw_command[MAX_PATH_LEN];
      unsigned char     use_destination;
  };

#elif FIREWALL_IPF


#endif /* FIREWALL type */

/* SPA数据包信息结构。
*/
typedef struct spa_pkt_info
{
    unsigned int    packet_data_len;
    unsigned int    packet_proto;
    unsigned int    packet_src_ip;
    unsigned int    packet_dst_ip;
    unsigned short  packet_src_port;
    unsigned short  packet_dst_port;
    unsigned char   packet_data[MAX_SPA_PACKET_LEN+1];
} spa_pkt_info_t;

/* 服务器使用的（已处理和验证的）SPA数据的结构。*/
typedef struct spa_data
{
    char           *username;
    time_t          timestamp;
    char           *version;
    short           message_type;
    char           *spa_message;
    char            spa_message_src_ip[MAX_IPV4_STR_LEN];
    char            pkt_source_ip[MAX_IPV4_STR_LEN];
    char            pkt_source_xff_ip[MAX_IPV4_STR_LEN];
    char            pkt_destination_ip[MAX_IPV4_STR_LEN];
    char            spa_message_remain[1024]; /* --DSS FIXME: arbitrary bounds */
    char           *nat_access;
    char           *server_auth;
    unsigned int    client_timeout;
    unsigned int    fw_access_timeout;
    char            *use_src_ip;
} spa_data_t;

/* spad服务器配置参数和值
*/
typedef struct ztn_srv_options
{
    /* 调用即时响应的命令行选项或标志然后退出。
    */
    unsigned char   dump_config;        /*转储当前配置标志*/
    unsigned char   foreground;        /*在前台运行标志*/
    unsigned char   kill;               /*启动终止spad的标志*/
    unsigned char   rotate_digest_cache;/*强制摘要旋转的标志*/
    unsigned char   restart;            /*重新启动spad标志*/
    unsigned char   status;            /*获取spad状态标志*/
    unsigned char   fw_list;            /*列出当前防火墙规则*/
    unsigned char   fw_list_all;        /*列出所有当前防火墙规则*/
    unsigned char   fw_flush;          /*刷新当前防火墙规则*/
    unsigned char   key_gen;            /*生成密钥并退出*/
    unsigned char   exit_after_parse_config; /*分析配置并退出*/
    unsigned char   exit_parse_digest_cache; /*分析摘要缓存并退出*/

    /* 操作标志
    */
    unsigned char   test;               /*测试模式标志*/
    unsigned char   afl_fuzzing;        /*用于AFL模糊化的来自stdin的SPA pkts*/
    unsigned char   verbose;           /*详细模式标志*/
    unsigned char   enable_udp_server;  /*启用UDP服务器模式*/
    unsigned char   enable_nfq_capture; /*启用Netfilter队列捕获模式*/
    unsigned char   enable_fw;          /*命令模式本身不需要防火墙支持*/

    unsigned char   firewd_disable_check_support; /* 不使用 firewall-cmd ... -C */
    unsigned char   ipt_disable_check_support;    /*不使用 iptables -C */


    unsigned char   pcap_any_direction;

    int             data_link_offset;
    int             tcp_server_pid;
    int             lock_fd;

    /* 仅在--key gen模式中使用的值
    */
    char key_gen_file[MAX_PATH_LEN];
    int  key_len;
    int  hmac_key_len;
    int  hmac_type;

#if USE_FILE_CACHE
    struct digest_cache_list *digest_cache;   /* 内存摘要缓存列表*/
#endif

    spa_pkt_info_t  spa_pkt;            /* The current SPA packet */

    /* 计数器，从命令行设置为在处理指定数量的SPA数据包后退出。
    */
    unsigned int    packet_ctr_limit;
    unsigned int    packet_ctr;  /* counts packets with >0 payload bytes */

    /* 此数组将所有配置文件条目值保存为按其标记名进行索引的字符串。
    */
    char           *config[NUMBER_OF_CONFIG_ENTRIES];

    /* 从配置项派生的数据元素-避免在解析配置后调用strtol_wrapper（）。
    */
    unsigned short tcpserv_port;
    unsigned short udpserv_port;
    int            udpserv_select_timeout;
    int            rules_chk_threshold;
    int            pcap_loop_sleep;
    int            pcap_dispatch_count;
    int            max_sniff_bytes;
    int            max_spa_packet_age;

    acc_stanza_t   *acc_stanzas;       /* 访问节列表 */

    /* 防火墙配置信息。
    */
    struct fw_config *fw_config;

    /* 规则检查计数器-这是用于垃圾清理模式的，
    * 用于删除任何计时器过期的规则（即使是那些可能由第三方程序添加的规则）。
    */
    unsigned int check_rules_ctr;

    cmd_cycle_list_t *cmd_cycle_list;


    unsigned char   syslog_enable;

} ztn_srv_options_t;

/* 用于在退出前清理内存
*/
#define FW_CLEANUP          1
#define NO_FW_CLEANUP       0

/**
 * \brief 释放所有内存并退出
 *
*\param选择程序选项
*\param fw_cleanup_flag标志表示防火墙是否需要清理
*\param exit_status关闭程序时返回的退出状态
 *
 */
void clean_exit(ztn_srv_options_t *opts,
        unsigned int fw_cleanup_flag, unsigned int exit_status);

#endif /* SPAD_COMMON_H */

/***EOF***/
