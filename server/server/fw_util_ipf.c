/**
 * \file server/fw_util_ipf.c
 *
 * \brief 用于管理ipf防火墙规则的Spa例程。
 */

#include "spad_common.h"

#if FIREWALL_IPF

#include "fw_util.h"
#include "utils.h"
#include "log_msg.h"
#include "extcmd.h"
#include "access.h"

static struct fw_config fwc;
static char   cmd_buf[CMD_BUFSIZE];
static char   err_buf[CMD_BUFSIZE];
static char   cmd_out[STANDARD_CMD_OUT_BUFSIZE];

/* 将正在运行的spad守护程序当前实例化的所有防火墙规则打印到stdout。
*/
int
fw_dump_rules(const ztn_srv_options_t *opts)
{
    int     i;
    int     res, got_err = 0;

    fprintf(stdout, "Listing spad ipf rules...\n");
    fflush(stdout);

    zero_cmd_buffers();


    return(got_err);
}

void
fw_config_init(ztn_srv_options_t *opts)
{

    memset(&fwc, 0x0, sizeof(struct fw_config));

    /* 设置防火墙exe命令路径（大多数情况下为iptables）。
    */
    strlcpy(fwc.fw_command, opts->config[CONF_FIREWALL_EXE], sizeof(fwc.fw_command));
    
    if(strncasecmp(opts->config[CONF_ENABLE_DESTINATION_RULE], "Y", 1)==0)
    {
        fwc.use_destination = 1;
    }

    /* 通过opts结构来找到它。
    */
    opts->fw_config = &fwc;

    return 1;
}

void
fw_initialize(const ztn_srv_options_t *opts)
{
    int res = 0;


    if(res != 0)
    {
        log_msg(LOG_WARNING,
                "Warning: Errors detected during fw_initialize().");
        return 0;
    }
    return 1;
}

int
fw_cleanup(void)
{

    return(0);
}

/****************************************************************************/

/* 规则处理-创建访问请求
*/
int
process_spa_request(const ztn_srv_options_t *opts, const acc_stanza_t *acc, spa_data_t *spadat)
{
    

    char             nat_ip[MAX_IPV4_STR_LEN] = {0};
    char            *ndx;

    unsigned int     nat_port = 0;;

    acc_port_list_t *port_list = NULL;
    acc_port_list_t *ple;

    int             res = 0;
    time_t          now;
    unsigned int    exp_ts;

    /* 解析并扩展我们的访问消息。
    */
    expand_acc_port_list(&port_list, spadat->spa_message_remain);

    /* 从协议端口列表的顶部开始
    */
    ple = port_list;

    /* 设置过期时间值。
    */
    time(&now);
    exp_ts = now + spadat->fw_access_timeout;

  

    return(res);
}

/* 遍历配置防火墙访问链并清除过期的防火墙规则。
*/
void
check_firewall_rules(const ztn_srv_options_t *opts,
        const int chk_rm_all)
{

  

    char             exp_str[12]     = {0};
    char             rule_num_str[6] = {0};
    char            *ndx, *rn_start, *rn_end, *tmp_mark;

    int             i, res, rn_offset;
    time_t          now, rule_exp, min_exp = 0;

    time(&now);

    zero_cmd_buffers();
}

#endif /* FIREWALL_IPF */

/***EOF***/
