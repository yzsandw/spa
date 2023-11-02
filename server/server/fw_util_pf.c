/**
 * \file server/fw_util_pf.c
 *
 * \brief 用于管理pf防火墙规则的Fwknop例程。
 */

#include "fwknopd_common.h"

#if FIREWALL_PF

#include "fw_util.h"
#include "utils.h"
#include "log_msg.h"
#include "extcmd.h"
#include "access.h"

static struct fw_config fwc;
static char   cmd_buf[CMD_BUFSIZE];
static char   err_buf[CMD_BUFSIZE];
static char   cmd_out[STANDARD_CMD_OUT_BUFSIZE];

static void
zero_cmd_buffers(void)
{
    memset(cmd_buf, 0x0, CMD_BUFSIZE);
    memset(err_buf, 0x0, CMD_BUFSIZE);
    memset(cmd_out, 0x0, STANDARD_CMD_OUT_BUFSIZE);
}

/* 将正在运行的fwknopd守护程序当前实例化的所有防火墙规则打印到stdout。
*/
int
fw_dump_rules(const fko_srv_options_t * const opts)
{
    int     res, got_err = 0, pid_status = 0;

    fprintf(stdout, "Listing fwknopd pf rules...\n");
    fflush(stdout);

    zero_cmd_buffers();

    /* 为活动规则创建列表命令
    */
    snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " PF_LIST_ANCHOR_RULES_ARGS,
        opts->fw_config->fw_command,
        opts->fw_config->anchor
    );

    fprintf(stdout, "\nActive Rules in PF anchor '%s':\n", opts->fw_config->anchor);
    fflush(stdout);

    /* 排除stderr，因为ALTQ可能不可用
    */
    res = run_extcmd(cmd_buf, NULL, 0, NO_STDERR, NO_TIMEOUT, &pid_status, opts);

    if(! EXTCMD_IS_SUCCESS(res))
    {
        log_msg(LOG_ERR, "Error %i from cmd:'%s': %s", res, cmd_buf, err_buf);
        got_err++;
    }

    return(got_err);
}

/* 检查fwknop锚是否链接到主策略。如果不是，
* fwknopd添加/删除的任何规则都不会影响实际流量。
*/
static int
anchor_active(const fko_srv_options_t *opts)
{
    int    pid_status = 0;
    char   anchor_search_str[MAX_PF_ANCHOR_SEARCH_LEN] = {0};

    /* 构建锚定搜索字符串
    */
    snprintf(anchor_search_str, MAX_PF_ANCHOR_SEARCH_LEN-1, "%s\n",
        opts->fw_config->anchor);

    zero_cmd_buffers();

    snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " PF_ANCHOR_CHECK_ARGS,
        opts->fw_config->fw_command
    );

    /* 检查锚点是否存在并链接到主策略
    */
    if(search_extcmd(cmd_buf, WANT_STDERR, NO_TIMEOUT,
            anchor_search_str, &pid_status, opts) > 0)
        return 1;

    return 0;
}

static void
delete_all_anchor_rules(const fko_srv_options_t *opts)
{
    int res = 0, pid_status = 0;

    zero_cmd_buffers();

    snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " PF_DEL_ALL_ANCHOR_RULES,
        fwc.fw_command,
        fwc.anchor
    );

    res = run_extcmd(cmd_buf, err_buf, CMD_BUFSIZE,
                WANT_STDERR, NO_TIMEOUT, &pid_status, opts);

    if(! EXTCMD_IS_SUCCESS(res))
        log_msg(LOG_ERR, "Error %i from cmd:'%s': %s", res, cmd_buf, err_buf);

    return;
}

int
fw_config_init(fko_srv_options_t * const opts)
{
    memset(&fwc, 0x0, sizeof(struct fw_config));

    /* 设置防火墙exe命令路径
    */
    strlcpy(fwc.fw_command, opts->config[CONF_FIREWALL_EXE], sizeof(fwc.fw_command));

    /* 设置PF锚点名称
    */
    strlcpy(fwc.anchor, opts->config[CONF_PF_ANCHOR_NAME], sizeof(fwc.anchor));
    
    if(strncasecmp(opts->config[CONF_ENABLE_DESTINATION_RULE], "Y", 1)==0)
    {
        fwc.use_destination = 1;
    }

    /* 通过opts结构来找到它。
    */
    opts->fw_config = &fwc;

    return 1;
}

int
fw_initialize(const fko_srv_options_t * const opts)
{

    if (! anchor_active(opts))
    {
        log_msg(LOG_WARNING,
                "Warning: the fwknop anchor is not active in the pf policy");
        return 0;
    }

    /* 删除fwknop锚定中的任何现有规则
    */
    delete_all_anchor_rules(opts);

    return 1;
}

int
fw_cleanup(const fko_srv_options_t * const opts)
{
    delete_all_anchor_rules(opts);
    return(0);
}

/****************************************************************************/

/* 规则处理-创建访问请求
*/
int
process_spa_request(const fko_srv_options_t * const opts,
        const acc_stanza_t * const acc, spa_data_t * const spadat)
{
    char             new_rule[MAX_PF_NEW_RULE_LEN] = {0};
    char             write_cmd[CMD_BUFSIZE] = {0};

    acc_port_list_t *port_list = NULL;
    acc_port_list_t *ple;

    int             res = 0, pid_status = 0;
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

    /* 对于直接访问请求，我们目前支持多协议/端口请求。
    */
    if(spadat->message_type == FKO_ACCESS_MSG
      || spadat->message_type == FKO_CLIENT_TIMEOUT_ACCESS_MSG)
    {
        /* 为源ip的每个协议/端口创建访问命令。
        */
        while(ple != NULL)
        {
            zero_cmd_buffers();

            snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " PF_LIST_ANCHOR_RULES_ARGS,
                opts->fw_config->fw_command,
                opts->fw_config->anchor
            );

            /* 缓存当前定位点规则集
            */
            res = run_extcmd(cmd_buf, cmd_out, STANDARD_CMD_OUT_BUFSIZE,
                        WANT_STDERR, NO_TIMEOUT, &pid_status, opts);

            /* 生成新的规则字符串
            */
            memset(new_rule, 0x0, MAX_PF_NEW_RULE_LEN);
            snprintf(new_rule, MAX_PF_NEW_RULE_LEN-1, PF_ADD_RULE_ARGS "\n",
                ple->proto,
                spadat->use_src_ip,
                (fwc.use_destination ? spadat->pkt_destination_ip : PF_ANY_IP),
                ple->port,
                exp_ts
            );

            if (strlen(cmd_out) + strlen(new_rule) < STANDARD_CMD_OUT_BUFSIZE)
            {
                /* 我们将规则添加到正在运行的策略中
                */
                strlcat(cmd_out, new_rule, STANDARD_CMD_OUT_BUFSIZE);

                memset(write_cmd, 0x0, CMD_BUFSIZE);

                snprintf(write_cmd, CMD_BUFSIZE-1, "%s " PF_WRITE_ANCHOR_RULES_ARGS,
                    opts->fw_config->fw_command,
                    opts->fw_config->anchor
                );

                res = run_extcmd_write(write_cmd, cmd_out, &pid_status, opts);

                if(EXTCMD_IS_SUCCESS(res))
                {
                    log_msg(LOG_INFO, "Added Rule for %s, %s expires at %u",
                        spadat->use_src_ip,
                        spadat->spa_message_remain,
                        exp_ts
                    );

                    fwc.active_rules++;

                    /* 如果有保证，请重置此链的下一个预期过期时间。
                    */
                    if(fwc.next_expire < now || exp_ts < fwc.next_expire)
                        fwc.next_expire = exp_ts;
                }
                else
                {
                    log_msg(LOG_WARNING, "Could not write rule to pf anchor");
                    free_acc_port_list(port_list);
                    return(-1);
                }
            }
            else
            {
                /*我们没有足够的空间添加新的防火墙规则，因此发出警告并释放。
                * 一旦某些现有规则过期，用户将再次能够获得访问权限。请注意，我们并不期望真正做到这一点
                * 由于STANDARD_CMD_OUT_BUFSIZE的限制是相当多的锚定规则。
                */
                log_msg(LOG_WARNING, "Max anchor rules reached, try again later.");
                free_acc_port_list(port_list);
                return 0;
            }

            ple = ple->next;
        }

    }
    else
    {
        /* 尚不支持其他SPA请求模式。
        */
        if(spadat->message_type == FKO_LOCAL_NAT_ACCESS_MSG
          || spadat->message_type == FKO_CLIENT_TIMEOUT_LOCAL_NAT_ACCESS_MSG)
        {
            log_msg(LOG_WARNING, "Local NAT requests are not currently supported.");
        }
        else if(spadat->message_type == FKO_NAT_ACCESS_MSG
          || spadat->message_type == FKO_CLIENT_TIMEOUT_NAT_ACCESS_MSG)
        {
            log_msg(LOG_WARNING, "Forwarding/NAT requests are not currently supported.");
        }

        free_acc_port_list(port_list);
        return(-1);
    }

    free_acc_port_list(port_list);
    return(res);
}

/* 遍历配置防火墙访问链并清除过期的防火墙规则。
*/
void
check_firewall_rules(const fko_srv_options_t * const opts,
        const int chk_rm_all)
{
    char            exp_str[12] = {0};
    char            anchor_rules_copy[STANDARD_CMD_OUT_BUFSIZE] = {0};
    char            write_cmd[CMD_BUFSIZE] = {0};
    char           *ndx, *tmp_mark, *tmp_ndx, *newline_tmp_ndx;

    time_t          now, rule_exp, min_exp=0;
    int             i=0, res=0, anchor_ndx=0, is_delete=0, pid_status=0;

    /* 如果尚未达到预期的下一个到期时间，请继续。
    */
    if(fwc.next_expire == 0)
        return;

    time(&now);

    if (fwc.next_expire > now)
        return;

    zero_cmd_buffers();

    /* 应该有一个要删除的规则。获取当前规则列表并删除过期的规则。
    */
    snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " PF_LIST_ANCHOR_RULES_ARGS,
        opts->fw_config->fw_command,
        opts->fw_config->anchor
    );

    res = run_extcmd(cmd_buf, cmd_out, STANDARD_CMD_OUT_BUFSIZE,
                WANT_STDERR, NO_TIMEOUT, &pid_status, opts);
    chop_newline(cmd_out);

    if(!EXTCMD_IS_SUCCESS(res))
    {
        log_msg(LOG_ERR, "Error %i from cmd:'%s': %s", res, cmd_buf, cmd_out);
        return;
    }

    /* 找到first _exp_ string (如果有).
    */
    ndx = strstr(cmd_out, EXPIRE_COMMENT_PREFIX);

    if(ndx == NULL)
    {
        /* 我们没有找到预期的规则。
        */
        log_msg(LOG_ERR,
            "Did not find expire comment in rules list %i.", i);

        return;
    }

    memset(anchor_rules_copy, 0x0, STANDARD_CMD_OUT_BUFSIZE);

    /* 根据需要浏览列表和处理规则。
    */
    while (ndx != NULL)
    {
        /* 向前跳并提取时间戳
        */
        ndx += strlen(EXPIRE_COMMENT_PREFIX);

        /* 标记这个地方，当我们寻找下一条规则时。
        */
        tmp_mark = ndx;

        strlcpy(exp_str, ndx, sizeof(exp_str));
        chop_spaces(exp_str);
        chop_char(exp_str, 0x22); /* 后面有一个引号 */
        if(!is_digits(exp_str))
        {
            /* 转到下一个规则（如果存在）
            */
            ndx = strstr(tmp_mark, EXPIRE_COMMENT_PREFIX);
            continue;
        }

        rule_exp = (time_t)atoll(exp_str);

        if(rule_exp <= now)
        {
            /*我们将删除此规则，因为我们重新构建PF锚以包含所有未过期的规则，所以要删除此规则我们只需跳到下一个规则。
            */
            log_msg(LOG_INFO, "Deleting rule with expire time of %u.", rule_exp);

            if (fwc.active_rules > 0)
                fwc.active_rules--;

            is_delete = 1;
        }
        else
        {
            /* 规则尚未过期，因此请将其复制到列出当前规则的定位点字符串中并将用于送到“pfctl-a<anchor>-f-”
            */

            /* 备份到上一个换行符或规则输出字符串的开头。
            */
            tmp_ndx = ndx;
            while(--tmp_ndx > cmd_out)
            {
                if(*tmp_ndx == '\n')
                    break;
            }

            if(*tmp_ndx == '\n')
                tmp_ndx++;

            /* 可以确保规则以字符串“pass”开头，并确保以换行符结尾。如果其中一个测试失败，则释放。
            */
            if (strlen(tmp_ndx) <= strlen("pass")
                    || strncmp(tmp_ndx, "pass", strlen("pass")) != 0)
                break;

            newline_tmp_ndx = tmp_ndx;

            while (*newline_tmp_ndx != '\n' && *newline_tmp_ndx != '\0')
                newline_tmp_ndx++;

            /* 将整个规则复制到下一个新行（包括过期时间）
            */
            while (*tmp_ndx != '\n' && *tmp_ndx != '\0'
                && anchor_ndx < STANDARD_CMD_OUT_BUFSIZE)
            {
                anchor_rules_copy[anchor_ndx] = *tmp_ndx;
                tmp_ndx++;
                anchor_ndx++;
            }
            anchor_rules_copy[anchor_ndx] = '\n';
            anchor_ndx++;

            /* 跟踪未来规则的最短过期时间。
            */
            if(rule_exp > now)
	         min_exp = (min_exp && (min_exp < rule_exp)) ? min_exp : rule_exp;
        }

        /* 将跟踪索引向前推到（刚刚处理的）_exp_string之外，以便继续列表中的下一个规则。
        */
        ndx = strstr(tmp_mark, EXPIRE_COMMENT_PREFIX);
    }

    if (is_delete)
    {
        /* 我们使用删除了规则的新规则字符串重新实例化锚定规则。如果没有至少一个“通过”规则，那么我们只需刷新锚点。
        */
        if (strlen(anchor_rules_copy) > strlen("pass")
            && strncmp(anchor_rules_copy, "pass", strlen("pass")) == 0)
        {
            memset(write_cmd, 0x0, CMD_BUFSIZE);

            snprintf(write_cmd, CMD_BUFSIZE-1, "%s " PF_WRITE_ANCHOR_RULES_ARGS,
                opts->fw_config->fw_command,
                opts->fw_config->anchor
            );

            res = run_extcmd_write(write_cmd, anchor_rules_copy, &pid_status, opts);
            if(! EXTCMD_IS_SUCCESS(res))
            {
                log_msg(LOG_WARNING, "Could not execute command: %s",
                        write_cmd);
                return;
            }
        }
        else
        {
            delete_all_anchor_rules(opts);
        }
    }

    /* 相应地设置下一个挂起过期时间
    */
    if(fwc.active_rules < 1)
        fwc.next_expire = 0;
    else if(min_exp)
        fwc.next_expire = min_exp;

    return;
}

#endif /* FIREWALL_PF */

/***EOF***/
