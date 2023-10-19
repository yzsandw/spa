#include "fwknopd_common.h"

#if FIREWALL_IPFW

#include "fw_util.h"
#include "utils.h"
#include "log_msg.h"
#include "extcmd.h"
#include "access.h"

static struct fw_config fwc;
static char   cmd_buf[CMD_BUFSIZE];
static char   err_buf[CMD_BUFSIZE];
static char   cmd_out[STANDARD_CMD_OUT_BUFSIZE];

static unsigned short
get_next_rule_num(void)
{
    unsigned short i;

    for(i=0; i < fwc.max_rules; i++)
    {
        if(fwc.rule_map[i] == RULE_FREE)
            return(fwc.start_rule_num + i);
    }

    return(0);
}

static void
zero_cmd_buffers(void)
{
    memset(cmd_buf, 0x0, CMD_BUFSIZE);
    memset(err_buf, 0x0, CMD_BUFSIZE);
    memset(cmd_out, 0x0, STANDARD_CMD_OUT_BUFSIZE);
}

static int pid_status = 0;

static int
ipfw_set_exists(const fko_srv_options_t *opts,
    const char *fw_command, const unsigned short set_num)
{
    int res = 0;

    zero_cmd_buffers();

    snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " IPFW_LIST_SET_RULES_ARGS,
        fw_command,
        set_num
    );

    res = run_extcmd(cmd_buf, cmd_out, STANDARD_CMD_OUT_BUFSIZE,
            WANT_STDERR, NO_TIMEOUT, &pid_status, opts);

    log_msg(LOG_DEBUG, "ipfw_set_exists() CMD: '%s' (res: %d)",
        cmd_buf, res);

    if(!EXTCMD_IS_SUCCESS(res))
        return(0);

    if(cmd_out[0] == '\0')
        return(0);

    return(1);
}

/* 打印当前由运行的 fwknopd 守护进程实例化的所有防火墙规则到标准输出。*/
int
fw_dump_rules(const fko_srv_options_t * const opts)
{
    int     res, got_err = 0;

    if (opts->fw_list_all)
    {
        fprintf(stdout, "列出所有 ipfw 规则...\n");
        fflush(stdout);

        zero_cmd_buffers();

        /* 创建用于列出所有规则的命令*/
        snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " IPFW_LIST_ALL_RULES_ARGS,
            opts->fw_config->fw_command
        );

        res = run_extcmd(cmd_buf, NULL, 0, NO_STDERR,
                        NO_TIMEOUT, &pid_status, opts);

        log_msg(LOG_DEBUG, "fw_dump_rules() CMD: '%s' (res: %d)",
            cmd_buf, res);

        /* 预期完全成功 */
        if(!EXTCMD_IS_SUCCESS(res))
        {
            log_msg(LOG_ERR, "来自命令的错误 %i: '%s': %s", res, cmd_buf, err_buf);
            got_err++;
        }
    }
    else
    {
        fprintf(stdout, "列出 fwknopd ipfw 规则...\n");
        fflush(stdout);

        zero_cmd_buffers();

        /* 创建用于列出活动规则的命令*/
        snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " IPFW_LIST_RULES_ARGS,
            opts->fw_config->fw_command,
            opts->fw_config->active_set_num
        );

        printf("\n活动规则:\n");
        res = run_extcmd(cmd_buf, NULL, 0, NO_STDERR,
                    NO_TIMEOUT, &pid_status, opts);

        log_msg(LOG_DEBUG, "fw_dump_rules() CMD: '%s' (res: %d)",
            cmd_buf, res);

        /* 预期完全成功 */
        if(!EXTCMD_IS_SUCCESS(res))
        {
            log_msg(LOG_ERR, "来自命令的错误 %i: '%s': %s", res, cmd_buf, err_buf);
            got_err++;
        }

        /* 创建用于列出过期规则的命令*/
        snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " IPFW_LIST_RULES_ARGS,
            opts->fw_config->fw_command,
            opts->fw_config->expire_set_num
        );

        printf("\n过期规则:\n");
        res = run_extcmd(cmd_buf, NULL, 0, NO_STDERR,
                    NO_TIMEOUT, &pid_status, opts);

        log_msg(LOG_DEBUG, "fw_dump_rules() CMD: '%s' (res: %d)",
            cmd_buf, res);

        /* 预期完全成功 */
        if(!EXTCMD_IS_SUCCESS(res))
        {
            log_msg(LOG_ERR, "来自命令的错误 %i: '%s': %s", res, cmd_buf, err_buf);
            got_err++;
        }
    }

    return(got_err);
}

int
fw_config_init(fko_srv_options_t * const opts)
{
    int         is_err;

    memset(&fwc, 0x0, sizeof(struct fw_config));

    /* 设置防火墙执行命令路径（在大多数情况下为iptables）。*/
    strlcpy(fwc.fw_command, opts->config[CONF_FIREWALL_EXE], sizeof(fwc.fw_command));

    fwc.start_rule_num = strtol_wrapper(opts->config[CONF_IPFW_START_RULE_NUM],
            0, RCHK_MAX_IPFW_MAX_RULES, NO_EXIT_UPON_ERR, &is_err);
    if(is_err != FKO_SUCCESS)
    {
        log_msg(LOG_ERR, "[*] IPFW_START_RULE_NUM '%s' 超出范围 [%d-%d]。",
                opts->config[CONF_IPFW_START_RULE_NUM], 0, RCHK_MAX_IPFW_MAX_RULES);
        return 0;
    }

    fwc.max_rules = strtol_wrapper(opts->config[CONF_IPFW_MAX_RULES],
            0, RCHK_MAX_IPFW_MAX_RULES, NO_EXIT_UPON_ERR, &is_err);
    if(is_err != FKO_SUCCESS)
    {
        log_msg(LOG_ERR, "[*] IPFW_MAX_RULES_INT '%s' 超出范围 [%d-%d]。",
                opts->config[CONF_IPFW_MAX_RULES], 0, RCHK_MAX_IPFW_MAX_RULES);
        return 0;
    }

    fwc.active_set_num = strtol_wrapper(opts->config[CONF_IPFW_ACTIVE_SET_NUM],
            0, RCHK_MAX_IPFW_SET_NUM, NO_EXIT_UPON_ERR, &is_err);
    if(is_err != FKO_SUCCESS)
    {
        log_msg(LOG_ERR, "[*] IPFW_ACTIVE_SET_NUM '%s' 超出范围 [%d-%d]。",
                opts->config[CONF_IPFW_ACTIVE_SET_NUM], 0, RCHK_MAX_IPFW_SET_NUM);
        return 0;
    }

 
    fwc.expire_set_num = strtol_wrapper(opts->config[CONF_IPFW_EXPIRE_SET_NUM],
            0, RCHK_MAX_IPFW_SET_NUM, NO_EXIT_UPON_ERR, &is_err);
    if(is_err != FKO_SUCCESS)
    {
        log_msg(LOG_ERR, "[*] IPFW_MAX_EXPIRE_SET_NUM '%s' 超出范围 [%d-%d]。",
                opts->config[CONF_IPFW_EXPIRE_SET_NUM], 0, RCHK_MAX_IPFW_SET_NUM);
        return 0;
    }

    fwc.purge_interval = strtol_wrapper(opts->config[CONF_IPFW_EXPIRE_PURGE_INTERVAL],
            0, RCHK_MAX_IPFW_PURGE_INTERVAL, NO_EXIT_UPON_ERR, &is_err);
    if(is_err != FKO_SUCCESS)
    {
        log_msg(LOG_ERR, "[*] IPFW_EXPIRE_PURGE_INTERVAL '%s' 超出范围 [%d-%d]。",
                opts->config[CONF_IPFW_EXPIRE_PURGE_INTERVAL], 0, RCHK_MAX_IPFW_PURGE_INTERVAL);
        return 0;
    }
    
    if(strncasecmp(opts->config[CONF_ENABLE_DESTINATION_RULE], "Y", 1) == 0)
    {
        fwc.use_destination = 1;
    }

    /* 通过 opts 结构体也可以找到它。*/
    opts->fw_config = &fwc;

    return 1;
}

int
fw_initialize(const fko_srv_options_t * const opts)
{
    int             res = 0, is_err;
    unsigned short  curr_rule;
    char           *ndx;

    /* 暂时，我们只调用 fw_cleanup 来开始一个干净的状态。*/
    if (strncasecmp(opts->config[CONF_FLUSH_IPFW_AT_INIT], "Y", 1) == 0)
        res = fw_cleanup(opts);

    if (res != 0)
    {
        log_msg(LOG_ERR, "[*] 致命错误：在初始化 ipfw 规则时检测到错误。");
        return 0;
    }

    /* 为跟踪活动（和已过期）规则分配 rule_map 数组。*/
    fwc.rule_map = calloc(fwc.max_rules, sizeof(char));

    if (fwc.rule_map == NULL)
    {
        log_msg(LOG_ERR, "[*] 致命错误：在 fw_initialize() 中的内存分配错误。");
        return 0;
    }

    /* 如果必要，创建一个 check-state 规则。*/
    if (strncasecmp(opts->config[CONF_IPFW_ADD_CHECK_STATE], "Y", 1) == 0)
    {
        zero_cmd_buffers();

        snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " IPFW_ADD_CHECK_STATE_ARGS,
            fwc.fw_command,
            fwc.start_rule_num,
            fwc.active_set_num
        );

        res = run_extcmd(cmd_buf, err_buf, CMD_BUFSIZE,
                    WANT_STDERR, NO_TIMEOUT, &pid_status, opts);

        log_msg(LOG_DEBUG, "fw_initialize() CMD: '%s' (res: %d, err: %s)",
            cmd_buf, res, err_buf);

        if (EXTCMD_IS_SUCCESS(res))
        {
            log_msg(LOG_INFO, "将检查状态规则 %u 添加到集合 %u",
                fwc.start_rule_num,
                fwc.active_set_num
            );

            fwc.rule_map[0] = RULE_ACTIVE;
        }
        else
            log_msg(LOG_ERR, "来自命令的错误 %i: '%s': %s", res, cmd_buf, err_buf);
    }

    if (fwc.expire_set_num > 0
            && (strncasecmp(opts->config[CONF_FLUSH_IPFW_AT_INIT], "Y", 1) == 0))
    {
        /* 确保我们的过期集合已禁用。*/
        zero_cmd_buffers();

        snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " IPFW_DISABLE_SET_ARGS,
            fwc.fw_command,
            fwc.expire_set_num
        );

        res = run_extcmd(cmd_buf, err_buf, CMD_BUFSIZE,
                    WANT_STDERR, NO_TIMEOUT, &pid_status, opts);

        log_msg(LOG_DEBUG, "fw_initialize() CMD: '%s' (res: %d, err: %s)",
            cmd_buf, res, err_buf);

        if (EXTCMD_IS_SUCCESS(res))
            log_msg(LOG_INFO, "将 ipfw 过期集合 %u 设置为已禁用。",
                fwc.expire_set_num);
        else
            log_msg(LOG_ERR, "来自命令的错误 %i: '%s': %s", res, cmd_buf, err_buf);
    }

    /* 现在读取过期集合以跟踪可能的现有规则。*/
    zero_cmd_buffers();

    snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " IPFW_LIST_EXP_SET_RULES_ARGS,
        opts->fw_config->fw_command,
        fwc.expire_set_num
    );

    res = run_extcmd(cmd_buf, cmd_out, STANDARD_CMD_OUT_BUFSIZE,
                WANT_STDERR, NO_TIMEOUT, &pid_status, opts);

    log_msg(LOG_DEBUG, "fw_initialize() CMD: '%s' (res: %d)",
        cmd_buf, res);

    if (!EXTCMD_IS_SUCCESS(res))
    {
        log_msg(LOG_ERR, "来自命令的错误 %i: '%s': %s", res, cmd_buf, cmd_out);
        return 0;
    }

    log_msg(LOG_DEBUG, "规则列表：%s", cmd_out);

    /* 找到第一个 "# DISABLED" 字符串（如果有的话）。*/
    ndx = strstr(cmd_out, "# DISABLED ");

    /* 如果没有看到字符串，假设没有禁用的规则。*/
    if (ndx == NULL)
        return 1;

    /* 否则，我们遍历每一行以获取规则号并设置相应的规则映射条目。*/
    while (ndx != NULL)
    {
        /* 跳过 DISABLED 字符串以到达规则编号。*/
        ndx += 11;

        if (isdigit(*ndx))
        {
            curr_rule = strtol_wrapper(ndx, 0, -1, NO_EXIT_UPON_ERR, &is_err);

            if (is_err == FKO_SUCCESS)
            {
                if (curr_rule >= fwc.start_rule_num
                  && curr_rule < fwc.start_rule_num + fwc.max_rules)
                {
                    fwc.rule_map[curr_rule - fwc.start_rule_num] = RULE_EXPIRED;
                    fwc.total_rules++;
                }
            }
        }
        else
            log_msg(LOG_WARNING,
                    "fw_initialize: 在预期位置未找到规则编号。");

        /* 找到下一个 "# DISABLED" 字符串（如果有的话）。*/
        ndx = strstr(ndx, "# DISABLED ");
    }

    return 1;
}

int
fw_cleanup(const fko_srv_options_t * const opts)
{
    int     res, got_err = 0;

    if (strncasecmp(opts->config[CONF_FLUSH_IPFW_AT_EXIT], "N", 1) == 0)
    {
        if (fwc.rule_map != NULL)
            free(fwc.rule_map);
        return(0);
    }

    zero_cmd_buffers();

    if (fwc.active_set_num > 0
        && ipfw_set_exists(opts, fwc.fw_command, fwc.active_set_num))
    {
        /* 为活动规则创建集合删除命令*/
        snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " IPFW_DEL_RULE_SET_ARGS,
            fwc.fw_command,
            fwc.active_set_num
        );

        res = run_extcmd(cmd_buf, NULL, 0, NO_STDERR,
                    NO_TIMEOUT, &pid_status, opts);

        log_msg(LOG_DEBUG, "fw_cleanup() CMD: '%s' (res: %d)",
            cmd_buf, res);

        /* 预期完全成功 */
        if (!EXTCMD_IS_SUCCESS(res))
        {
            log_msg(LOG_ERR, "来自命令的错误 %i: '%s': %s", res, cmd_buf, err_buf);
         
            got_err++;
        }
    }

    /* --DSS 保留已过期规则列表，以防丢失任何现有已建立的规则 */
#if 0
    if (fwc.expire_set_num > 0)
    {
        /* 为已过期规则创建集合删除命令*/
        snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " IPFW_DEL_RULE_SET_ARGS,
            fwc.fw_command,
            fwc.expire_set_num
        );

        //printf("CMD: '%s'\n", cmd_buf);
        res = system(cmd_buf);

        /* 预期完全成功 */
        if (!EXTCMD_IS_SUCCESS(res))
        {
            log_msg(LOG_ERR, "来自命令的错误 %i: '%s': %s", res, cmd_buf, err_buf);
            got_err++;
        }
    }
#endif

    /* 释放规则映射。*/
    if (fwc.rule_map != NULL)
        free(fwc.rule_map);

    return got_err;
}

/****************************************************************************/

/* 规则处理 - 创建一个访问请求...
*/
int
process_spa_request(const fko_srv_options_t * const opts,
        const acc_stanza_t * const acc, spa_data_t * const spadat)
{
    unsigned short   rule_num;

    acc_port_list_t *port_list = NULL;
    acc_port_list_t *ple;

    int             res = 0;
    time_t          now;
    unsigned int    exp_ts;

    /* 解析并扩展我们的访问消息。
    */
    expand_acc_port_list(&port_list, spadat->spa_message_remain);

    /* 从协议/端口列表的顶部开始...
    */
    ple = port_list;

    /* 设置我们的到期时间值。
    */
    time(&now);
    exp_ts = now + spadat->fw_access_timeout;

    /* 对于直接访问请求，我们当前支持多个协议/端口请求。
    */
    if (spadat->message_type == FKO_ACCESS_MSG
      || spadat->message_type == FKO_CLIENT_TIMEOUT_ACCESS_MSG)
    {
        /* 获取下一个可用的规则编号。
        */
        rule_num = get_next_rule_num();

        /* 如果 rule_num 返回为 0，表示我们已经达到了允许的最大活动规则数，因此我们在此处拒绝并退出。
        */
        if (rule_num == 0)
        {
            log_msg(LOG_WARNING,
                    "访问请求被拒绝：已达到允许的最大规则数。");
            free_acc_port_list(port_list);
            return(-1);
        }

        /* 为源 IP 的每个协议/端口创建一个访问命令。
        */
        while (ple != NULL)
        {
            zero_cmd_buffers();

            snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " IPFW_ADD_RULE_ARGS,
                fwc.fw_command,
                rule_num,
                fwc.active_set_num,
                ple->proto,
                spadat->use_src_ip,
                (fwc.use_destination ? spadat->pkt_destination_ip : IPFW_ANY_IP),
                ple->port,
                exp_ts
            );

            res = run_extcmd(cmd_buf, err_buf, CMD_BUFSIZE,
                            WANT_STDERR, NO_TIMEOUT, &pid_status, opts);

            log_msg(LOG_DEBUG, "process_spa_request() CMD: '%s' (res: %d, err: %s)",
                cmd_buf, res, err_buf);

            if (EXTCMD_IS_SUCCESS(res))
            {
                log_msg(LOG_INFO, "添加规则 %u，用于 %s，%s 到期时间：%u",
                    rule_num,
                    spadat->use_src_ip,
                    spadat->spa_message_remain, exp_ts
                );

                fwc.rule_map[rule_num - fwc.start_rule_num] = RULE_ACTIVE;

                fwc.active_rules++;
                fwc.total_rules++;

                /* 如果合理，重新设置该链的下一个预期到期时间。
                */
                if (fwc.next_expire < now || exp_ts < fwc.next_expire)
                    fwc.next_expire = exp_ts;
            }
            else
                log_msg(LOG_ERR, "来自命令的错误 %i: '%s': %s", res, cmd_buf, err_buf);

            ple = ple->next;
        }

    }
    else
    {
        /* 目前不支持其他 SPA 请求模式。
        */
        if (spadat->message_type == FKO_LOCAL_NAT_ACCESS_MSG
          || spadat->message_type == FKO_CLIENT_TIMEOUT_LOCAL_NAT_ACCESS_MSG)
        {
            log_msg(LOG_WARNING, "当前不支持本地 NAT 请求。");
        }
        else if (spadat->message_type == FKO_NAT_ACCESS_MSG
          || spadat->message_type == FKO_CLIENT_TIMEOUT_NAT_ACCESS_MSG)
        {
            log_msg(LOG_WARNING, "当前不支持转发/NAT 请求。");
        }

        free_acc_port_list(port_list);
        return(-1);
    }

    free_acc_port_list(port_list);
    return(res);
}



void
check_firewall_rules(const fko_srv_options_t * const opts,
        const int chk_rm_all)
{
    char            exp_str[12]     = {0};
    char            rule_num_str[6] = {0};
    char           *ndx, *rn_start, *rn_end, *tmp_mark;

    int             i=0, res=0, is_err;
    time_t          now, rule_exp, min_exp = 0;
    unsigned short  curr_rule;

   /* Just in case we somehow lose track and fall out-of-whack.
*/
/* 以防万一我们不小心丢失跟踪并出现不匹配的情况。
如果已经存在的活动规则数大于规定的最大规则数，将活动规则数重置为0。*/
if(fwc.active_rules > fwc.max_rules)
    fwc.active_rules = 0;

/* If there are no active rules or we have not yet
 * reached our expected next expire time, continue.
*/
/* 如果没有活动规则，或者尚未达到预期的下一个到期时间，继续。*/
if(fwc.active_rules == 0)
    return;

/* 获取当前时间。*/
time(&now);

/* 如果下一个到期时间大于当前时间，也继续。*/
if (fwc.next_expire > now)
    return;

/* 清空命令缓冲区。*/
zero_cmd_buffers();

/* 应该有规则需要删除。获取当前链中的规则列表，并删除已过期的规则。*/
snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " IPFW_LIST_SET_RULES_ARGS,
    opts->fw_config->fw_command,
    fwc.active_set_num
);

/* 运行外部命令来获取规则列表。*/
res = run_extcmd(cmd_buf, cmd_out, STANDARD_CMD_OUT_BUFSIZE,
            WANT_STDERR, NO_TIMEOUT, &pid_status, opts);
chop_newline(cmd_out);

log_msg(LOG_DEBUG, "check_firewall_rules() CMD: '%s' (res: %d)",
    cmd_buf, res);

if(!EXTCMD_IS_SUCCESS(res))
{
    log_msg(LOG_ERR, "来自命令的错误 %i: '%s': %s", res, cmd_buf, cmd_out);
    return;
}

log_msg(LOG_DEBUG, "RULES LIST: %s", cmd_out);

/* 查找第一个 _exp_ 字符串（如果存在）。*/
ndx = strstr(cmd_out, EXPIRE_COMMENT_PREFIX);

if(ndx == NULL)
{
    /* 我们没有找到预期的规则。*/
    log_msg(LOG_ERR,
        "在规则列表 %i 中未找到到期注释。");

    /* 如果已存在的活动规则数大于0，则减少它。*/
    if (fwc.active_rules > 0)
        fwc.active_rules--;

    return;
}

/* 遍历列表并根据需要处理规则。*/

   while (ndx != NULL) {
    /* Jump forward and extract the timestamp
    */
    /* 向前移动并提取时间戳。*/
    ndx += strlen(EXPIRE_COMMENT_PREFIX);

    /* 记住此位置，以便在查找下一个规则时使用。*/
    tmp_mark = ndx;

    /* 复制时间戳字符串并去除空格。*/
    strlcpy(exp_str, ndx, sizeof(exp_str));
    chop_spaces(exp_str);

    /* 检查时间戳字符串是否包含数字。*/
    if (!is_digits(exp_str)) {
        /* 如果不是数字，继续查找下一个规则。*/
        ndx = strstr(tmp_mark, EXPIRE_COMMENT_PREFIX);
        continue;
    }

    /* 将时间戳字符串转换为时间戳值。*/
    rule_exp = (time_t)atoll(exp_str);

    if (rule_exp <= now) {
        /* 如果规则已经过期，回溯并获取规则编号并删除它。*/
        rn_start = ndx;
        while (--rn_start > cmd_out) {
            if (*rn_start == '\n')
                break;
        }

        if (*rn_start == '\n') {
            rn_start++;
        } else if (rn_start > cmd_out) {
            /* 这不应该发生。但如果发生了，记录错误，
             * 减少活动规则数量，然后继续。
            */
            log_msg(LOG_ERR,
                "查找规则行起始时出现规则解析错误。");

            if (fwc.active_rules > 0)
                fwc.active_rules--;

            break;
        }

        rn_end = strchr(rn_start, ' ');

        if (rn_end == NULL) {
            /* 这不应该发生。但如果发生了，记录错误，
             * 减少活动规则数量，然后继续。
            */
            log_msg(LOG_ERR,
                "查找规则编号时出现规则解析错误。");

            if (fwc.active_rules > 0)
                fwc.active_rules--;

            break;
        }

        /* 复制规则编号字符串。*/
        strlcpy(rule_num_str, rn_start, (rn_end - rn_start) + 1);

        /* 将规则编号字符串转换为整数。*/
        curr_rule = strtol_wrapper(rule_num_str, 0, -1, NO_EXIT_UPON_ERR, &is_err);

        if (is_err == FKO_SUCCESS) {
            zero_cmd_buffers();

            /* 将规则移动到已过期规则集合。*/
            snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " IPFW_MOVE_RULE_ARGS,
                opts->fw_config->fw_command,
                curr_rule,
                fwc.expire_set_num
            );

            res = run_extcmd(cmd_buf, err_buf, CMD_BUFSIZE,
                        WANT_STDERR, NO_TIMEOUT, &pid_status, opts);

            log_msg(LOG_DEBUG, "check_firewall_rules() CMD: '%s' (res: %d, err: %s)",
                cmd_buf, res, err_buf);

            if (EXTCMD_IS_SUCCESS(res)) {
                log_msg(LOG_INFO, "将规则 %s（到期时间：%u）移动到集合 %u。",
                    rule_num_str, rule_exp, fwc.expire_set_num
                );

                if (fwc.active_rules > 0)
                    fwc.active_rules--;

                fwc.rule_map[curr_rule - fwc.start_rule_num] = RULE_EXPIRED;
            } else {
                log_msg(LOG_ERR, "来自命令的错误 %i: '%s': %s", res, cmd_buf, err_buf);
            }
        } else {
            log_msg(LOG_ERR, "来自命令的错误 %i: '%s': %s", res, cmd_buf, err_buf);
        }
    } else {
        /* 跟踪未来规则的最小到期时间。*/
        if (rule_exp > now)
            min_exp = (min_exp < rule_exp) ? min_exp : rule_exp;
    }

    /* 推进我们的跟踪索引，超过（刚刚处理的）_exp_字符串，
     * 以便我们可以继续处理列表中的下一个规则。
    */
    ndx = strstr(tmp_mark, EXPIRE_COMMENT_PREFIX);
}


    
   // 根据需要设置下一个挂起的到期时间。如果没有更多规则，则为0，或者下一个预期的（min_exp）时间。
    if(fwc.active_rules < 1)
        fwc.next_expire = 0;
    else if(min_exp)
        fwc.next_expire = min_exp;
}
void
ipfw_purge_expired_rules(const fko_srv_options_t *opts)
{
    char *ndx, *co_end;
    int i, res, is_err;
    unsigned short curr_rule;

    /* 首先，获取已过期规则集合的当前活动动态规则。
     * 然后将其与规则映射中的已过期规则进行比较。任何
     * 映射中没有动态规则的规则都可以被删除。
    */
    zero_cmd_buffers();

    snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " IPFW_LIST_SET_DYN_RULES_ARGS,
        opts->fw_config->fw_command,
        fwc.expire_set_num
    );

    res = run_extcmd(cmd_buf, cmd_out, STANDARD_CMD_OUT_BUFSIZE,
            WANT_STDERR, NO_TIMEOUT, &pid_status, opts);

    log_msg(LOG_DEBUG, "ipfw_purge_expired_rules() CMD: '%s' (res: %d)",
        cmd_buf, res);

    if (!EXTCMD_IS_SUCCESS(res)) {
        log_msg(LOG_ERR, "来自命令的错误 %i: '%s': %s", res, cmd_buf, cmd_out);
        return;
    }

    /* 我们可能根本没有任何动态规则 - 有人可能没有
     * 初始化连接（例如）
    */
    if (cmd_out[0] != '\0') {
        co_end = cmd_out + strlen(cmd_out);

        log_msg(LOG_DEBUG, "EXP RULES LIST: %s", cmd_out);

        /* 找到 "## Dynamic rules" 字符串。
        */
        ndx = strcasestr(cmd_out, "## Dynamic rules");

        if (ndx == NULL) {
            log_msg(LOG_ERR,
                "意外错误：在列表输出中未找到 'Dynamic rules' 字符串。"
            );
            return;
        }

        /* 跳到下一个换行字符。
        */
        ndx = strchr(ndx, '\n');

        if (ndx == NULL) {
            log_msg(LOG_ERR,
                "意外错误：未找到 'Dynamic rules' 行终止的换行符。"
            );
            return;
        }

        /* 遍历动态规则列表（如果有的话）。
        */
        while (ndx != NULL) {
            ndx++;

            while (!isdigit(*ndx) && ndx < co_end)
                ndx++;

            if (ndx >= co_end)
                break;

            /* 如果我们位于数字处，假定它是规则编号，提取它，
             * 如果它在正确的范围内，则标记它（以便在下一步中不被删除）。
            */
            if (isdigit(*ndx)) {
                curr_rule = strtol_wrapper(ndx, 0, -1, NO_EXIT_UPON_ERR, &is_err);

                if (is_err == FKO_SUCCESS) {
                    if (curr_rule >= fwc.start_rule_num
                      && curr_rule < fwc.start_rule_num + fwc.max_rules)
                        fwc.rule_map[curr_rule - fwc.start_rule_num] = RULE_TMP_MARKED;
                }
            }

            ndx = strchr(ndx, '\n');
        }
    }

    /* 现在，遍历规则映射并删除仍然标记为已过期的规则。
    */
    for (i = 0; i < fwc.max_rules; i++) {
        /* 如果它是TMP_MARKED，将其设置回EXPIRED并继续。
        */
        if (fwc.rule_map[i] == RULE_TMP_MARKED) {
            fwc.rule_map[i] = RULE_EXPIRED;
            continue;
        }

        /* 如果它没有过期，继续。
        */
        if (fwc.rule_map[i] != RULE_EXPIRED)
            continue;

        /* 这个规则准备好要删除了。
        */
        zero_cmd_buffers();

        curr_rule = fwc.start_rule_num + i;

        snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " IPFW_DEL_RULE_ARGS,
            opts->fw_config->fw_command,
#ifndef __APPLE__
            fwc.expire_set_num,
#endif
            curr_rule
        );

        res = run_extcmd(cmd_buf, cmd_out, STANDARD_CMD_OUT_BUFSIZE,
                    WANT_STDERR, NO_TIMEOUT, &pid_status, opts);

        log_msg(LOG_DEBUG, "ipfw_purge_expired_rules() CMD: '%s' (res: %d)",
            cmd_buf, res);

        if (!EXTCMD_IS_SUCCESS(res)) {
            log_msg(LOG_ERR, "来自命令的错误 %i: '%s': %s", res, cmd_buf, cmd_out);
            continue;
        }

        log_msg(LOG_INFO, "从集合 %u 中清除规则 %u", curr_rule, fwc.expire_set_num);

        fwc.rule_map[curr_rule - fwc.start_rule_num] = RULE_FREE;

        fwc.total_rules--;
    }
}
