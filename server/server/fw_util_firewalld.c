/**
 * \file server/fw_util_firewalld.c
 *
 * \brief 用于管理firewalld防火墙规则
 */


#include "spad_common.h"

#if FIREWALL_FIREWALLD

#include "fw_util.h"
#include "utils.h"
#include "log_msg.h"
#include "extcmd.h"
#include "access.h"

static struct fw_config fwc;
static char   cmd_buf[CMD_BUFSIZE];
static char   err_buf[CMD_BUFSIZE];
static char   cmd_out[STANDARD_CMD_OUT_BUFSIZE];

/* 假定提供了'firewall-cmd --direct --passthrough ipv4 -C'（请参见firewd_chk_support())。
*/
static int have_firewd_chk_support = 1;

static void
zero_cmd_buffers(void)
{
    memset(cmd_buf, 0x0, CMD_BUFSIZE);
    memset(err_buf, 0x0, CMD_BUFSIZE);
    memset(cmd_out, 0x0, STANDARD_CMD_OUT_BUFSIZE);
}

static int pid_status = 0;

static int
rule_exists_no_chk_support(const ztn_srv_options_t * const opts,
        const struct fw_chain * const fwc,
        const unsigned int proto,
        const char * const srcip,
        const char * const dstip,
        const unsigned int port,
        const char * const natip,
        const unsigned int nat_port,
        const unsigned int exp_ts)
{
    int     rule_exists=0;
    char    fw_line_buf[CMD_BUFSIZE]     = {0};
    char    target_search[CMD_BUFSIZE]   = {0};
    char    proto_search[CMD_BUFSIZE]    = {0};
    char    srcip_search[CMD_BUFSIZE]    = {0};
    char    dstip_search[CMD_BUFSIZE]    = {0};
    char    natip_search[CMD_BUFSIZE]    = {0};
    char    port_search[CMD_BUFSIZE]     = {0};
    char    nat_port_search[CMD_BUFSIZE] = {0};
    char    exp_ts_search[CMD_BUFSIZE]   = {0};
    char    *ndx = NULL;

    snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " FIREWD_LIST_RULES_ARGS,
        opts->fw_config->fw_command,
        fwc->table,
        fwc->to_chain
    );

#if CODE_COVERAGE
    /* 如果我们正在最大化代码覆盖率，那么使用run_extcmd_write()函数，通常只用于PF防火墙。
    * 这是为了与测试套件一起最大化代码覆盖率，永远不会编译为spa的生产发布
    */
    if(run_extcmd_write("/bin/grep -v test", "/bin/echo test", &pid_status, opts) == 0)
        log_msg(LOG_WARNING, "[ignore] Code coverage: Executed command");
#endif

    if(proto == IPPROTO_TCP)
        snprintf(proto_search, CMD_BUFSIZE-1, " tcp ");
    else if(proto == IPPROTO_UDP)
        snprintf(proto_search, CMD_BUFSIZE-1, " udp ");
    else if(proto == IPPROTO_ICMP)
        snprintf(proto_search, CMD_BUFSIZE-1, " icmp ");
    else
        snprintf(proto_search, CMD_BUFSIZE-1, " %u ", proto);

    snprintf(port_search, CMD_BUFSIZE-1, "dpt:%u ", port);
    snprintf(nat_port_search, CMD_BUFSIZE-1, ":%u", nat_port);
    snprintf(target_search, CMD_BUFSIZE-1, " %s ", fwc->target);

    if (srcip != NULL)
        snprintf(srcip_search, CMD_BUFSIZE-1, " %s ", srcip);

    if (dstip != NULL)
        snprintf(dstip_search, CMD_BUFSIZE-1, " %s ", dstip);

    if (natip != NULL)
        snprintf(natip_search, CMD_BUFSIZE-1, " to:%s", natip);

    snprintf(exp_ts_search, CMD_BUFSIZE-1, "%u ", exp_ts);

    /* 对于每个子字符串，搜索规则到期时间是主要的搜索方法。
    */
    if(search_extcmd_getline(cmd_buf, fw_line_buf,
                CMD_BUFSIZE, NO_TIMEOUT, exp_ts_search, &pid_status, opts))
    {
        chop_newline(fw_line_buf);
        /* 我们有一个匹配到期时间的iptables策略规则，因此确保此规则还匹配其他字段。
        * 如果不匹配，那么它可能是由另一个SPA数据包请求的不同访问。
        */
        if(((proto == ANY_PROTO) ? 1 : (strstr(fw_line_buf, proto_search) != NULL))
            && ((srcip == NULL) ? 1 : (strstr(fw_line_buf, srcip_search) != NULL))
            && ((dstip == NULL) ? 1 : (strstr(fw_line_buf, dstip_search) != NULL))
            && ((natip == NULL) ? 1 : (strstr(fw_line_buf, natip_search) != NULL))
            && (strstr(fw_line_buf, target_search) != NULL)
            && ((port == ANY_PORT) ? 1 : (strstr(fw_line_buf, port_search) != NULL)))
        {
            rule_exists = 1;
        }
    }

    /* 如果有NAT端口，我们必须将其作为规则中的'to:<ip>:<port>'部分（在末尾）的一部分来标识。
    */
    if(rule_exists && nat_port != NAT_ANY_PORT)
    {
        ndx = strstr(fw_line_buf, " to:");
        /* 确保没有重复的 "to:" 字符串（即，如果有人试图通过iptables注释匹配来捣乱）
        */
        if(ndx != NULL && (strstr((ndx+strlen(" to:")), " to:") == NULL))
        {
            ndx = strstr((ndx+strlen(" to:")), nat_port_search);
            if (ndx == NULL)
            {
                rule_exists = 0;
            }
            else if((*(ndx+strlen(nat_port_search)) != '\0')
                    && (*(ndx+strlen(nat_port_search)) != ' '))
            {
                rule_exists = 0;
            }
        }
        else
        {
            rule_exists = 0;
        }
    }

    if(rule_exists)
        log_msg(LOG_DEBUG,
                "rule_exists_no_chk_support() %s %u -> %s expires: %u rule already exists",
                proto_search, port, srcip, exp_ts);
    else
        log_msg(LOG_DEBUG,
                "rule_exists_no_chk_support() %s %u -> %s expires: %u rule does not exist",
                proto_search, port, srcip, exp_ts);

   return(rule_exists);
}

static int
rule_exists_chk_support(const ztn_srv_options_t * const opts,
        const char * const chain, const char * const rule)
{
    int     rule_exists = 0;
    int     res = 0;

    zero_cmd_buffers();

    snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " FIREWD_CHK_RULE_ARGS,
            opts->fw_config->fw_command, chain, rule);

    res = run_extcmd(cmd_buf, err_buf, CMD_BUFSIZE,
            WANT_STDERR, NO_TIMEOUT, &pid_status, opts);
    chop_newline(err_buf);

    log_msg(LOG_DEBUG,
            "rule_exists_chk_support() CMD: '%s' (res: %d, err: %s)",
            cmd_buf, res, err_buf);

    if(strncmp(err_buf, "success", strlen("success")) == 0)
    {
        rule_exists = 1;
        log_msg(LOG_DEBUG,
                "rule_exists_chk_support() Rule : '%s' in %s already exists",
                rule, chain);
    }
    else
    {
        log_msg(LOG_DEBUG,
                "rule_exists_chk_support() Rule : '%s' in %s does not exist",
                rule, chain);
    }

    return(rule_exists);
}

static int
rule_exists(const ztn_srv_options_t * const opts,
        const struct fw_chain * const fwc,
        const char * const rule,
        const unsigned int proto,
        const char * const srcip,
        const char * const dstip,
        const unsigned int port,
        const char * const nat_ip,
        const unsigned int nat_port,
        const unsigned int exp_ts)
{
    int rule_exists = 0;

    if(have_firewd_chk_support == 1)
        rule_exists = rule_exists_chk_support(opts, fwc->to_chain, rule);
    else
        rule_exists = rule_exists_no_chk_support(opts, fwc, proto, srcip,
                (opts->fw_config->use_destination ? dstip : NULL), port,
                nat_ip, nat_port, exp_ts);

    if(rule_exists == 1)
        log_msg(LOG_DEBUG, "rule_exists() Rule : '%s' in %s already exists",
                rule, fwc->to_chain);
    else
        log_msg(LOG_DEBUG, "rule_exists() Rule : '%s' in %s does not exist",
                rule, fwc->to_chain);

    return(rule_exists);
}

static void
firewd_chk_support(const ztn_srv_options_t * const opts)
{
    int               res = 1;
    struct fw_chain  *in_chain = &(opts->fw_config->chain[FIREWD_INPUT_ACCESS]);

    zero_cmd_buffers();

    /* 向firewalld的INPUT链中添加一个无害的规则，然后查看firewalld是否支持'-C'来检查它。
    * 相应地设置"have_firewd_chk_support"，删除规则，然后返回。
    */
    snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " FIREWD_TMP_CHK_RULE_ARGS,
        opts->fw_config->fw_command,
        in_chain->table,
        in_chain->from_chain,
        1,   /* first rule */
        in_chain->target
    );

    res = run_extcmd(cmd_buf, err_buf, CMD_BUFSIZE,
            WANT_STDERR, NO_TIMEOUT, &pid_status, opts);
    chop_newline(err_buf);

    log_msg(LOG_DEBUG, "firewd_chk_support() CMD: '%s' (res: %d, err: %s)",
        cmd_buf, res, err_buf);

    zero_cmd_buffers();

    /* 现在查看是否'-C'起作用。
    */
    snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " FIREWD_TMP_VERIFY_CHK_ARGS,
        opts->fw_config->fw_command,
        in_chain->table,
        in_chain->from_chain,
        in_chain->target
    );

    res = run_extcmd(cmd_buf, err_buf, CMD_BUFSIZE,
            WANT_STDERR, NO_TIMEOUT, &pid_status, opts);
    chop_newline(err_buf);

    log_msg(LOG_DEBUG, "firewd_chk_support() CMD: '%s' (res: %d, err: %s)",
        cmd_buf, res, err_buf);

    if(strncmp(err_buf, "success", strlen("success")) == 0)
    {
        log_msg(LOG_DEBUG, "firewd_chk_support() -C supported");
        have_firewd_chk_support = 1;
    }
    else
    {
        log_msg(LOG_DEBUG, "firewd_chk_support() -C not supported");
        have_firewd_chk_support = 0;
    }

    /* 删除临时规则
    */
    zero_cmd_buffers();

    snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " FIREWD_DEL_RULE_ARGS,
        opts->fw_config->fw_command,
        in_chain->table,
        in_chain->from_chain,
        1
    );
    run_extcmd(cmd_buf, err_buf, CMD_BUFSIZE,
            WANT_STDERR, NO_TIMEOUT, &pid_status, opts);

    return;
}

static int
comment_match_exists(const ztn_srv_options_t * const opts)
{
    int               res = 1;
    char             *ndx = NULL;
    struct fw_chain  *in_chain  = &(opts->fw_config->chain[FIREWD_INPUT_ACCESS]);

    zero_cmd_buffers();

    /*向firewalld的INPUT链中添加一个无害的规则，该规则使用注释匹配，并确保它存在。
    * 如果不存在，返回零。否则，删除规则并返回true。
    */
    snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " FIREWD_TMP_COMMENT_ARGS,
        opts->fw_config->fw_command,
        in_chain->table,
        in_chain->from_chain,
        1,   /* first rule */
        in_chain->target
    );

    res = run_extcmd(cmd_buf, err_buf, CMD_BUFSIZE,
            WANT_STDERR, NO_TIMEOUT, &pid_status, opts);
    chop_newline(err_buf);
    if((!EXTCMD_IS_SUCCESS(res)) || (pid_status != 0)) {
        log_msg(LOG_ERR, "comment_match_exists() Error %i from cmd:'%s': %s",
                res, cmd_buf, cmd_out);
        return 0; /* Errored out*/
    }

    log_msg(LOG_DEBUG, "comment_match_exists() CMD: '%s' (res: %d, err: %s)",
            cmd_buf, res, err_buf);

    zero_cmd_buffers();

    snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " FIREWD_LIST_RULES_ARGS,
        opts->fw_config->fw_command,
        in_chain->table,
        in_chain->from_chain
    );

    res = run_extcmd(cmd_buf, cmd_out, STANDARD_CMD_OUT_BUFSIZE,
            WANT_STDERR, NO_TIMEOUT, &pid_status, opts);
    chop_newline(cmd_out);

    if(!EXTCMD_IS_SUCCESS(res))
        log_msg(LOG_ERR, "comment_match_exists() Error %i from cmd:'%s': %s",
                res, cmd_buf, cmd_out);

    ndx = strstr(cmd_out, TMP_COMMENT);
    if(ndx == NULL)
        res = 0;  /* 没有找到临时注释。 */
    else
        res = 1;

    if(res == 1)
    {
        /* 删除临时注释规则。
        */
        zero_cmd_buffers();

        snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " FIREWD_DEL_RULE_ARGS,
            opts->fw_config->fw_command,
            in_chain->table,
            in_chain->from_chain,
            1
        );
        run_extcmd(cmd_buf, err_buf, CMD_BUFSIZE,
                WANT_STDERR, NO_TIMEOUT, &pid_status, opts);
    }

    return res;
}

static int
add_jump_rule(const ztn_srv_options_t * const opts, const int chain_num)
{
    int res = 0, rv = 0;

    zero_cmd_buffers();

    snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " FIREWD_ADD_JUMP_RULE_ARGS,
        fwc.fw_command,
        fwc.chain[chain_num].table,
        fwc.chain[chain_num].from_chain,
        fwc.chain[chain_num].jump_rule_pos,
        fwc.chain[chain_num].to_chain
    );

    res = run_extcmd(cmd_buf, err_buf, CMD_BUFSIZE,
            WANT_STDERR, NO_TIMEOUT, &pid_status, opts);

    log_msg(LOG_DEBUG, "add_jump_rule() CMD: '%s' (res: %d, err: %s)",
        cmd_buf, res, err_buf);

    if(EXTCMD_IS_SUCCESS(res))
    {
        log_msg(LOG_INFO, "Added jump rule from chain: %s to chain: %s",
            fwc.chain[chain_num].from_chain,
            fwc.chain[chain_num].to_chain);
        rv = 1;
    }
    else
        log_msg(LOG_ERR, "add_jump_rule() Error %i from cmd:'%s': %s",
                res, cmd_buf, err_buf);

    return rv;
}

static int
chain_exists(const ztn_srv_options_t * const opts, const int chain_num)
{
    int res = 0, rv = 0;

    zero_cmd_buffers();

    snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " FIREWD_CHAIN_EXISTS_ARGS,
        fwc.fw_command,
        fwc.chain[chain_num].table,
        fwc.chain[chain_num].to_chain
    );

    res = run_extcmd(cmd_buf, err_buf, CMD_BUFSIZE,
            WANT_STDERR, NO_TIMEOUT, &pid_status, opts);
    chop_newline(err_buf);

    log_msg(LOG_DEBUG, "chain_exists() CMD: '%s' (res: %d, err: %s)",
        cmd_buf, res, err_buf);

    if(strstr(err_buf, FIREWD_CMD_FAIL_STR) == NULL)
    {
        log_msg(LOG_DEBUG, "'%s' table '%s' chain exists",
            fwc.chain[chain_num].table,
            fwc.chain[chain_num].to_chain);
        rv = 1;
    }
    else
        log_msg(LOG_DEBUG,
                "chain_exists() Error %i from cmd:'%s': %s",
                res, cmd_buf, err_buf);

    return rv;
}

static int
jump_rule_exists_chk_support(const ztn_srv_options_t * const opts, const int chain_num)
{
    int    exists = 0;
    char   rule_buf[CMD_BUFSIZE] = {0};

    snprintf(rule_buf, CMD_BUFSIZE-1, FIREWD_CHK_JUMP_RULE_ARGS,
        fwc.chain[chain_num].table,
        fwc.chain[chain_num].to_chain
    );

    if(rule_exists_chk_support(opts, fwc.chain[chain_num].from_chain, rule_buf) == 1)
    {
        log_msg(LOG_DEBUG, "jump_rule_exists_chk_support() jump rule found");
        exists = 1;
    }
    else
        log_msg(LOG_DEBUG, "jump_rule_exists_chk_support() jump rule not found");

    return exists;
}

static int
jump_rule_exists_no_chk_support(const ztn_srv_options_t * const opts,
        const int chain_num)
{
    int     exists = 0;
    char    chain_search[CMD_BUFSIZE] = {0};

    snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " FIREWD_LIST_RULES_ARGS,
        fwc.fw_command,
        fwc.chain[chain_num].table,
        fwc.chain[chain_num].from_chain
    );

    /* 在删除时包括由'firewalld -L'输出产生的两侧的空格。
    */
    snprintf(chain_search, CMD_BUFSIZE-1, " %s ",
        fwc.chain[chain_num].to_chain);

    if(search_extcmd(cmd_buf, WANT_STDERR,
                NO_TIMEOUT, chain_search, &pid_status, opts) > 0)
        exists = 1;

    if(exists)
        log_msg(LOG_DEBUG,
                "jump_rule_exists_no_chk_support() jump rule found");
    else
        log_msg(LOG_DEBUG,
                "jump_rule_exists_no_chk_support() jump rule not found");

   return(exists);
}

static int
jump_rule_exists(const ztn_srv_options_t * const opts, const int chain_num)
{
    int    exists = 0;

    if(have_firewd_chk_support == 1)
        exists = jump_rule_exists_chk_support(opts, chain_num);
    else
        exists = jump_rule_exists_no_chk_support(opts, chain_num);

    return exists;
}

/* 打印当前正在运行的spad守护进程实例化的所有防火墙规则到标准输出。 */
int
fw_dump_rules(const ztn_srv_options_t * const opts)
{
    int     i;
    int     res, got_err = 0;

    struct fw_chain *ch = opts->fw_config->chain;

    if (opts->fw_list_all == 1)
    {
        fprintf(stdout, "Listing all firewalld rules in applicable tables...\n");
        fflush(stdout);

        for(i=0; i < NUM_SPA_ACCESS_TYPES; i++)
        {
            if(fwc.chain[i].target[0] == '\0')
                continue;

            zero_cmd_buffers();

            /* 创建列表命令 */
            snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " FIREWD_LIST_ALL_RULES_ARGS,
                opts->fw_config->fw_command,
                ch[i].table
            );

            res = run_extcmd(cmd_buf, NULL, 0, NO_STDERR,
                        NO_TIMEOUT, &pid_status, opts);

            log_msg(LOG_DEBUG, "fw_dump_rules() CMD: '%s' (res: %d)",
                cmd_buf, res);

            /* 预期完全成功 */
            if(! EXTCMD_IS_SUCCESS(res))
            {
                log_msg(LOG_ERR, "fw_dump_rules() Error %i from cmd:'%s': %s",
                        res, cmd_buf, err_buf);
                got_err++;
            }
        }
    }
    else
    {
        fprintf(stdout, "Listing rules in spad firewalld chains...\n");
        fflush(stdout);

        for(i=0; i < NUM_SPA_ACCESS_TYPES; i++)
        {
            if(fwc.chain[i].target[0] == '\0')
                continue;

            zero_cmd_buffers();

            /* 创建列表命令 */
            snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " FIREWD_LIST_RULES_ARGS,
                opts->fw_config->fw_command,
                ch[i].table,
                ch[i].to_chain
            );

            fprintf(stdout, "\n");
            fflush(stdout);

            res = run_extcmd(cmd_buf, NULL, 0, NO_STDERR,
                        NO_TIMEOUT, &pid_status, opts);

            log_msg(LOG_DEBUG, "fw_dump_rules() CMD: '%s' (res: %d)",
                cmd_buf, res);

            /* 预期此操作完全成功 */
            if(! EXTCMD_IS_SUCCESS(res))
            {
                log_msg(LOG_ERR, "fw_dump_rules() Error %i from cmd:'%s': %s",
                        res, cmd_buf, err_buf);
                got_err++;
            }
        }
    }

    return(got_err);
}

/* 静默清空并删除所有 spa 自定义链。 */
static void
delete_all_chains(const ztn_srv_options_t * const opts)
{
    int     i, res, cmd_ctr = 0;

    for(i=0; i < NUM_SPA_ACCESS_TYPES; i++)
    {
        if(fwc.chain[i].target[0] == '\0')
            continue;

        /* 首先查找跳转到此链的规则，如果存在则移除它。 */
        cmd_ctr = 0;
        while(cmd_ctr < CMD_LOOP_TRIES && (jump_rule_exists(opts, i) == 1))
        {
            zero_cmd_buffers();

            snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " FIREWD_DEL_JUMP_RULE_ARGS,
                fwc.fw_command,
                fwc.chain[i].table,
                fwc.chain[i].from_chain,
                fwc.chain[i].to_chain
            );

            res = run_extcmd(cmd_buf, err_buf, CMD_BUFSIZE,
                    WANT_STDERR, NO_TIMEOUT, &pid_status, opts);
            chop_newline(err_buf);

            log_msg(LOG_DEBUG, "delete_all_chains() CMD: '%s' (res: %d, err: %s)",
                cmd_buf, res, err_buf);

            /* 预期此操作完全成功 */
            if(! EXTCMD_IS_SUCCESS(res))
                log_msg(LOG_ERR, "delete_all_chains() Error %i from cmd:'%s': %s",
                        res, cmd_buf, err_buf);

            cmd_ctr++;
        }

        zero_cmd_buffers();

        /* 现在清空并移除该链
        */
        snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " FIREWD_FLUSH_CHAIN_ARGS,
            fwc.fw_command,
            fwc.chain[i].table,
            fwc.chain[i].to_chain
        );

        res = run_extcmd(cmd_buf, err_buf, CMD_BUFSIZE, WANT_STDERR,
                NO_TIMEOUT, &pid_status, opts);
        chop_newline(err_buf);

        log_msg(LOG_DEBUG, "delete_all_chains() CMD: '%s' (res: %d, err: %s)",
            cmd_buf, res, err_buf);

        /* 预期此操作完全成功。 */
        if(! EXTCMD_IS_SUCCESS(res))
            log_msg(LOG_ERR, "delete_all_chains() Error %i from cmd:'%s': %s",
                    res, cmd_buf, err_buf);

        zero_cmd_buffers();

        snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " FIREWD_DEL_CHAIN_ARGS,
            fwc.fw_command,
            fwc.chain[i].table,
            fwc.chain[i].to_chain
        );

        res = run_extcmd(cmd_buf, err_buf, CMD_BUFSIZE, WANT_STDERR,
                NO_TIMEOUT, &pid_status, opts);
        chop_newline(err_buf);

        log_msg(LOG_DEBUG, "delete_all_chains() CMD: '%s' (res: %d, err: %s)",
            cmd_buf, res, err_buf);

        /* 预期此操作完全成功。 */
        if(! EXTCMD_IS_SUCCESS(res))
            log_msg(LOG_ERR, "delete_all_chains() Error %i from cmd:'%s': %s",
                    res, cmd_buf, err_buf);

#if USE_LIBNETFILTER_QUEUE
        if(opts->enable_nfq_capture)
        {
            zero_cmd_buffers();

            /* 删除用于将流量定向到 NFQ 链的规则。
            */
            snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " FIREWD_DEL_RULE_ARGS,
                fwc.fw_command,
                opts->config[CONF_NFQ_TABLE],
                "INPUT",
                1
            );
            res = run_extcmd(cmd_buf, err_buf, CMD_BUFSIZE, WANT_STDERR,
                NO_TIMEOUT, &pid_status, opts);

            if (opts->verbose)
                log_msg(LOG_INFO, "delete_all_chains() CMD: '%s' (res: %d, err: %s)",
                        cmd_buf, res, err_buf);

            /* 预期完全成功 */
            if(! EXTCMD_IS_SUCCESS(res))
                log_msg(LOG_ERR, "Error %i from cmd:'%s': %s", res, cmd_buf, err_buf);

            zero_cmd_buffers();

            /* 清空 NFQ 链
            */
            snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " FIREWD_FLUSH_CHAIN_ARGS,
                fwc.fw_command,
                opts->config[CONF_NFQ_TABLE],
                opts->config[CONF_NFQ_CHAIN]
            );
            res = run_extcmd(cmd_buf, err_buf, CMD_BUFSIZE, WANT_STDERR,
                NO_TIMEOUT, &pid_status, opts);

            if (opts->verbose)
                log_msg(LOG_INFO, "delete_all_chains() CMD: '%s' (res: %d, err: %s)",
                    cmd_buf, res, err_buf);

            /* 预期此操作完全成功  */
            if(! EXTCMD_IS_SUCCESS(res))
                log_msg(LOG_ERR, "Error %i from cmd:'%s': %s", res, cmd_buf, err_buf);

            zero_cmd_buffers();

            /* 删除 NF_QUEUE 链和规则
            */
            snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " FIREWD_DEL_CHAIN_ARGS,
                fwc.fw_command,
                opts->config[CONF_NFQ_TABLE],
                opts->config[CONF_NFQ_CHAIN]
            );
            res = run_extcmd(cmd_buf, err_buf, CMD_BUFSIZE, WANT_STDERR,
                NO_TIMEOUT, &pid_status, opts);

            if (opts->verbose)
                log_msg(LOG_INFO, "delete_all_chains() CMD: '%s' (res: %d, err: %s)",
                    cmd_buf, res, err_buf);

            /* 预期完全成功 */
            if(! EXTCMD_IS_SUCCESS(res))
                log_msg(LOG_ERR, "Error %i from cmd:'%s': %s", res, cmd_buf, err_buf);
        }
#endif
    }
    return;
}

static int
create_chain(const ztn_srv_options_t * const opts, const int chain_num)
{
    int res = 0, rv = 0;

    zero_cmd_buffers();

    /* 创建自定义链
    */
    snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " FIREWD_NEW_CHAIN_ARGS,
        fwc.fw_command,
        fwc.chain[chain_num].table,
        fwc.chain[chain_num].to_chain
    );

    res = run_extcmd(cmd_buf, err_buf, CMD_BUFSIZE, WANT_STDERR,
                NO_TIMEOUT, &pid_status, opts);
    chop_newline(err_buf);

    log_msg(LOG_DEBUG, "create_chain() CMD: '%s' (res: %d, err: %s)",
        cmd_buf, res, err_buf);

    /* 预期完全成功 */
    if(EXTCMD_IS_SUCCESS(res))
        rv = 1;
    else
        log_msg(LOG_ERR, "create_chain() Error %i from cmd:'%s': %s",
                res, cmd_buf, err_buf);

    return rv;
}

static int
mk_chain(const ztn_srv_options_t * const opts, const int chain_num)
{
    int err = 0;

    /* 确保所需的链和跳转规则存在
    */
    if(! chain_exists(opts, chain_num))
        if(! create_chain(opts, chain_num))
            err++;

    if (! jump_rule_exists(opts, chain_num))
        if(! add_jump_rule(opts, chain_num))
            err++;

    return err;
}

/* 创建 spa 自定义链（至少创建已配置的链）
*/
static int
create_fw_chains(const ztn_srv_options_t * const opts)
{
    int     i, got_err = 0;
#if USE_LIBNETFILTER_QUEUE
    int     res = 0;
#endif

    for(i=0; i < NUM_SPA_ACCESS_TYPES; i++)
    {
        if(fwc.chain[i].target[0] == '\0')
            continue;

        got_err += mk_chain(opts, i);
    }
#if USE_LIBNETFILTER_QUEUE
    if(opts->enable_nfq_capture)
    {
        zero_cmd_buffers();

        /* 创建 NF_QUEUE 链和规则
        */
        snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " FIREWD_NEW_CHAIN_ARGS,
            fwc.fw_command,
            opts->config[CONF_NFQ_TABLE],
            opts->config[CONF_NFQ_CHAIN]
        );
        res = run_extcmd(cmd_buf, err_buf, CMD_BUFSIZE, WANT_STDERR,
                         NO_TIMEOUT, &pid_status, opts);

        if (opts->verbose)
            log_msg(LOG_INFO, "create_fw_chains() CMD: '%s' (res: %d, err: %s)",
                cmd_buf, res, err_buf);

        /* 预期完全成功 */
        if(! EXTCMD_IS_SUCCESS(res))
        {
            log_msg(LOG_ERR, "Error %i from cmd:'%s': %s", res, cmd_buf, err_buf);
            got_err++;
        }

        zero_cmd_buffers();

        /* 创建规则以将流量定向到 NFQ 链
        */
        snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " FIREWD_ADD_JUMP_RULE_ARGS,
            fwc.fw_command,
            opts->config[CONF_NFQ_TABLE],
            "INPUT",
            1,
            opts->config[CONF_NFQ_CHAIN]
        );
        res = run_extcmd(cmd_buf, err_buf, CMD_BUFSIZE, WANT_STDERR,
                         NO_TIMEOUT, &pid_status, opts);

        if (opts->verbose)
            log_msg(LOG_INFO, "create_fw_chains() CMD: '%s' (res: %d, err: %s)",
                cmd_buf, res, err_buf);

        /* 预期完全成功 */
        if(! EXTCMD_IS_SUCCESS(res))
        {
            log_msg(LOG_ERR, "Error %i from cmd:'%s': %s", res, cmd_buf, err_buf);
            got_err++;
        }

        zero_cmd_buffers();

        /* 创建规则以将 SPA 数据包定向到队列。
        *  如果指定了接口，请使用命令的 "_WITH_IF" 版本。
        */
        if(strlen(opts->config[CONF_NFQ_INTERFACE]) > 0)
        {
            snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " FIREWD_NFQ_ADD_ARGS_WITH_IF,
                fwc.fw_command,
                opts->config[CONF_NFQ_TABLE],
                opts->config[CONF_NFQ_CHAIN],
                opts->config[CONF_NFQ_INTERFACE],
                opts->config[CONF_NFQ_PORT],
                opts->config[CONF_NFQ_QUEUE_NUMBER]
            );
        }
        else
        {
            snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " FIREWD_NFQ_ADD_ARGS,
                fwc.fw_command,
                opts->config[CONF_NFQ_TABLE],
                opts->config[CONF_NFQ_CHAIN],
                opts->config[CONF_NFQ_PORT],
                opts->config[CONF_NFQ_QUEUE_NUMBER]
            );
        }
        res = run_extcmd(cmd_buf, err_buf, CMD_BUFSIZE, WANT_STDERR,
                         NO_TIMEOUT, &pid_status, opts);

        if (opts->verbose)
            log_msg(LOG_INFO, "create_fw_chains() CMD: '%s' (res: %d, err: %s)",
                cmd_buf, res, err_buf);

        /* 预期完全成功 */
        if(! EXTCMD_IS_SUCCESS(res))
        {
            log_msg(LOG_ERR, "Error %i from cmd:'%s': %s", res, cmd_buf, err_buf);
            got_err++;
        }
    }
#endif
    return(got_err);
}

static int
set_fw_chain_conf(const int type, const char * const conf_str)
{
    int i, j, is_err;
    char tbuf[MAX_LINE_LEN]  = {0};
    const char *ndx          = conf_str;

    char *chain_fields[FW_NUM_CHAIN_FIELDS];

    struct fw_chain *chain = &(fwc.chain[type]);

    if(conf_str == NULL)
    {
        log_msg(LOG_ERR, "[*] NULL conf_str");
        return 0;
    }

    chain->type = type;

    if(ndx != NULL)
        chain_fields[0] = tbuf;

    i = 0;
    j = 1;
    while(*ndx != '\0')
    {
        if(*ndx != ' ')
        {
            if(*ndx == ',')
            {
                tbuf[i] = '\0';
                chain_fields[j++] = &(tbuf[++i]);
            }
            else
                tbuf[i++] = *ndx;
        }
        if(*ndx != '\0'
                && *ndx != ' '
                && *ndx != ','
                && *ndx != '_'
                && isalnum(*ndx) == 0)
        {
            log_msg(LOG_ERR, "[*] Custom chain config parse error: "
                "invalid character '%c' for chain type %i, "
                "line: %s", *ndx, type, conf_str);
            return 0;
        }
        ndx++;
    }

    /* 健全性检查 - j 应该是链字段的数量（不包括类型）。
    */
    if(j != FW_NUM_CHAIN_FIELDS)
    {
        log_msg(LOG_ERR, "[*] Custom chain config parse error: "
            "wrong number of fields for chain type %i, "
            "line: %s", type, conf_str);
        return 0;
    }

    /*  提取并设置目标 */
    strlcpy(chain->target, chain_fields[0], sizeof(chain->target));

    /* 提取并设置表格 */
    strlcpy(chain->table, chain_fields[1], sizeof(chain->table));

    /* 提取并设置来源链 */
    strlcpy(chain->from_chain, chain_fields[2], sizeof(chain->from_chain));

    /* 提取并设置跳转规则位置 */
    chain->jump_rule_pos = strtol_wrapper(chain_fields[3],
            0, RCHK_MAX_FIREWD_RULE_NUM, NO_EXIT_UPON_ERR, &is_err);
    if(is_err != ZTN_SUCCESS)
    {
        log_msg(LOG_ERR, "[*] invalid jump rule position in Line: %s",
            conf_str);
        return 0;
    }

    /* 提取并设置目标链 */
    strlcpy(chain->to_chain, chain_fields[4], sizeof(chain->to_chain));

    /* 提取并设置到达链的规则位置 */
    chain->rule_pos = strtol_wrapper(chain_fields[5],
            0, RCHK_MAX_FIREWD_RULE_NUM, NO_EXIT_UPON_ERR, &is_err);
    if(is_err != ZTN_SUCCESS)
    {
        log_msg(LOG_ERR, "[*] invalid to_chain rule position in Line: %s",
            conf_str);
        return 0;
    }
    return 1;
}

int
fw_config_init(ztn_srv_options_t * const opts)
{
    memset(&fwc, 0x0, sizeof(struct fw_config));

    /* 设置我们的防火墙执行命令路径（在大多数情况下为 firewall-cmd 或 iptables）.
    */
#if FIREWALL_FIREWALLD
    char cmd_passthru[512];
    snprintf(cmd_passthru, sizeof cmd_passthru, "%s %s ",
        opts->config[CONF_FIREWALL_EXE], FIREWD_CMD_PREFIX);
    strlcpy(fwc.fw_command, cmd_passthru, sizeof(fwc.fw_command));
#else
    strlcpy(fwc.fw_command, opts->config[CONF_FIREWALL_EXE], sizeof(fwc.fw_command));
#endif

#if HAVE_LIBFIU
    fiu_return_on("fw_config_init", 0);
#endif

    /* 提取 spa 链配置信息并设置我们的内部配置结构。
    *FIREWD_INPUT 是唯一必需的，其余是可选的
    */
    if(set_fw_chain_conf(FIREWD_INPUT_ACCESS, opts->config[CONF_FIREWD_INPUT_ACCESS]) != 1)
        return 0;

    /* SPA_OUTPUT_ACCESS 需要启用 ENABLE_FIREWD_OUTPUT_ACCESS == Y。
    */
    if(strncasecmp(opts->config[CONF_ENABLE_FIREWD_OUTPUT], "Y", 1)==0)
        if(set_fw_chain_conf(FIREWD_OUTPUT_ACCESS, opts->config[CONF_FIREWD_OUTPUT_ACCESS]) != 1)
            return 0;

    /* 剩余的访问链需要启用 ENABLE_FIREWD_FORWARDING 或 ENABLE_FIREWD_LOCAL_NAT
    */
    if(strncasecmp(opts->config[CONF_ENABLE_FIREWD_FORWARDING], "Y", 1)==0
            || strncasecmp(opts->config[CONF_ENABLE_FIREWD_LOCAL_NAT], "Y", 1)==0)
    {
        if(set_fw_chain_conf(FIREWD_FORWARD_ACCESS, opts->config[CONF_FIREWD_FORWARD_ACCESS]) != 1)
            return 0;

        if(set_fw_chain_conf(FIREWD_DNAT_ACCESS, opts->config[CONF_FIREWD_DNAT_ACCESS]) != 1)
            return 0;

        /* 需要启用 ENABLE_FIREWD_SNAT = Y
        */
        if(strncasecmp(opts->config[CONF_ENABLE_FIREWD_SNAT], "Y", 1)==0)
        {
            /* 同时支持 SNAT 和 MASQUERADE - 这将通过 individual rules 的 access.conf 配置来控制。
            */
            if(set_fw_chain_conf(FIREWD_MASQUERADE_ACCESS,
                        opts->config[CONF_FIREWD_MASQUERADE_ACCESS]) != 1)
                return 0;

            if(set_fw_chain_conf(FIREWD_SNAT_ACCESS,
                        opts->config[CONF_FIREWD_SNAT_ACCESS]) != 1)
                return 0;
        }
    }

    if(strncasecmp(opts->config[CONF_ENABLE_DESTINATION_RULE], "Y", 1)==0)
    {
        fwc.use_destination = 1;
    }

    /* 让我们也通过我们的 opts 结构找到它。
    */
    opts->fw_config = &fwc;

    return 1;
}

int
fw_initialize(const ztn_srv_options_t * const opts)
{
    int res = 1;

    /* 查看 firewalld 是否提供 '-C' 参数（较旧版本没有）。
     *如果没有，那么切换到解析 firewalld -L 输出以查找规则。
    */
    if(opts->firewd_disable_check_support)
        have_firewd_chk_support = 0;
    else
        firewd_chk_support(opts);

    /* 清空链（以防万一），以便我们可以重新开始。
    */
    if(strncasecmp(opts->config[CONF_FLUSH_FIREWD_AT_INIT], "Y", 1) == 0)
        delete_all_chains(opts);

    /* 现在创建任何配置的链。
    */
    if(create_fw_chains(opts) != 0)
    {
        log_msg(LOG_WARNING,
                "fw_initialize() Warning: Errors detected during spa custom chain creation");
        res = 0;
    }

    /* 确保 'comment' 匹配可用
    */
    if(strncasecmp(opts->config[CONF_ENABLE_FIREWD_COMMENT_CHECK], "Y", 1) == 0)
    {
        if(comment_match_exists(opts) == 1)
        {
            log_msg(LOG_INFO, "firewalld 'comment' match is available");
        }
        else
        {
            log_msg(LOG_WARNING, "Warning: Could not use the 'comment' match");
            res = 0;
        }
    }

    return(res);
}

int
fw_cleanup(const ztn_srv_options_t * const opts)
{
    if(strncasecmp(opts->config[CONF_FLUSH_FIREWD_AT_EXIT], "N", 1) == 0
            && opts->fw_flush == 0)
        return(0);

    delete_all_chains(opts);
    return(0);
}

static int
create_rule(const ztn_srv_options_t * const opts,
        const char * const fw_chain, const char * const fw_rule)
{
    int res = 0;

    zero_cmd_buffers();

    if (strncasecmp(opts->config[CONF_ENABLE_RULE_PREPEND], "Y", 1) == 0) {
        snprintf(cmd_buf, CMD_BUFSIZE-1, "%s -I %s %s",
                opts->fw_config->fw_command, fw_chain, fw_rule);
    } else {
        snprintf(cmd_buf, CMD_BUFSIZE-1, "%s -A %s %s",
                opts->fw_config->fw_command, fw_chain, fw_rule);
    }

    res = run_extcmd(cmd_buf, err_buf, CMD_BUFSIZE, WANT_STDERR,
                NO_TIMEOUT, &pid_status, opts);
    chop_newline(err_buf);

    log_msg(LOG_DEBUG, "create_rule() CMD: '%s' (res: %d, err: %s)",
        cmd_buf, res, err_buf);

    if(EXTCMD_IS_SUCCESS(res))
    {
        log_msg(LOG_DEBUG, "create_rule() Rule: '%s' added to %s", fw_rule, fw_chain);
        res = 1;
    }
    else
        log_msg(LOG_ERR, "create_rule() Error %i from cmd:'%s': %s",
                res, cmd_buf, err_buf);

    return res;
}

static void
firewd_rule(const ztn_srv_options_t * const opts,
        const char * const complete_rule_buf,
        const char * const fw_rule_macro,
        const char * const srcip,
        const char * const dstip,
        const unsigned int proto,
        const unsigned int port,
        const char * const nat_ip,
        const unsigned int nat_port,
        struct fw_chain * const chain,
        const unsigned int exp_ts,
        const time_t now,
        const char * const msg,
        const char * const access_msg)
{
    char rule_buf[CMD_BUFSIZE] = {0};

    if(complete_rule_buf != NULL && complete_rule_buf[0] != 0x0)
    {
        strlcpy(rule_buf, complete_rule_buf, CMD_BUFSIZE-1);
    }
    else
    {
        memset(rule_buf, 0, CMD_BUFSIZE);

        snprintf(rule_buf, CMD_BUFSIZE-1, fw_rule_macro,
            chain->table,
            proto,
            srcip,
            dstip,
            port,
            exp_ts,
            chain->target
        );
    }

    /* 检查确保链和跳转规则存在
    */
    mk_chain(opts, chain->type);

    if(rule_exists(opts, chain, rule_buf, proto, srcip,
                dstip, port, nat_ip, nat_port, exp_ts) == 0)
    {
        if(create_rule(opts, chain->to_chain, rule_buf))
        {
            log_msg(LOG_INFO, "Added %s rule to %s for %s -> %s %s, expires at %u",
                msg, chain->to_chain, srcip, (dstip == NULL) ? FIREWD_ANY_IP : dstip,
                access_msg, exp_ts
            );

            chain->active_rules++;

            /* 如果有必要，重置此链的下一个预期过期时间
            */
            if(chain->next_expire < now || exp_ts < chain->next_expire)
                chain->next_expire = exp_ts;
        }
    }

    return;
}

static void forward_access_rule(const ztn_srv_options_t * const opts,
        const acc_stanza_t * const acc,
        struct fw_chain * const fwd_chain,
        const char * const nat_ip,
        const unsigned int nat_port,
        const unsigned int fst_proto,
        const unsigned int fst_port,
        spa_data_t * const spadat,
        const unsigned int exp_ts,
        const time_t now)
{
    char   rule_buf[CMD_BUFSIZE] = {0};

    log_msg(LOG_DEBUG,
            "forward_access_rule() forward_all: %d, nat_ip: %s, nat_port: %d",
            acc->forward_all, nat_ip, nat_port);

    memset(rule_buf, 0, CMD_BUFSIZE);
    if(acc->forward_all)
    {

        snprintf(rule_buf, CMD_BUFSIZE-1, FIREWD_FWD_ALL_RULE_ARGS,
            fwd_chain->table,
            spadat->use_src_ip,
            exp_ts,
            fwd_chain->target
        );

        /* 创建一个全局的接受规则，用于所有端口和协议
        */
        firewd_rule(opts, rule_buf, NULL, spadat->use_src_ip,
            NULL, ANY_PROTO, ANY_PORT, NULL, NAT_ANY_PORT,
            fwd_chain, exp_ts, now, "FORWARD ALL", "*/*");
    }
    else
    {
        /* 创建转发访问规则
        */
        snprintf(rule_buf, CMD_BUFSIZE-1, FIREWD_FWD_RULE_ARGS,
            fwd_chain->table,
            fst_proto,
            spadat->use_src_ip,
            nat_port,
            exp_ts,
            fwd_chain->target
        );
        firewd_rule(opts, rule_buf, NULL, spadat->use_src_ip,
            NULL, fst_proto, nat_port, NULL, NAT_ANY_PORT,
            fwd_chain, exp_ts, now, "FORWARD", spadat->spa_message_remain);
    }
    return;
}

static void dnat_rule(const ztn_srv_options_t * const opts,
        const acc_stanza_t * const acc,
        struct fw_chain * const dnat_chain,
        const char * const nat_ip,
        const unsigned int nat_port,
        const unsigned int fst_proto,
        const unsigned int fst_port,
        spa_data_t * const spadat,
        const unsigned int exp_ts,
        const time_t now)
{
    char   rule_buf[CMD_BUFSIZE] = {0};

    log_msg(LOG_DEBUG, "dnat_rule() forward_all: %d, nat_ip: %s, nat_port: %d",
            acc->forward_all, nat_ip, nat_port);

    if(acc->forward_all)
    {
        memset(rule_buf, 0, CMD_BUFSIZE);

        snprintf(rule_buf, CMD_BUFSIZE-1, FIREWD_DNAT_ALL_RULE_ARGS,
            dnat_chain->table,
            spadat->use_src_ip,
            (fwc.use_destination ? spadat->pkt_destination_ip : FIREWD_ANY_IP),
            exp_ts,
            dnat_chain->target,
            nat_ip
        );

        /* 创建一个全局的 DNAT 规则，用于所有端口和协议
        */
        firewd_rule(opts, rule_buf, NULL, spadat->use_src_ip,
            NULL, ANY_PROTO, ANY_PORT, NULL, NAT_ANY_PORT,
            dnat_chain, exp_ts, now, "DNAT ALL", "*/*");
    }
    else
    {
        memset(rule_buf, 0, CMD_BUFSIZE);

        snprintf(rule_buf, CMD_BUFSIZE-1, FIREWD_DNAT_RULE_ARGS,
            dnat_chain->table,
            fst_proto,
            spadat->use_src_ip,
            (fwc.use_destination ? spadat->pkt_destination_ip : FIREWD_ANY_IP),
            fst_port,
            exp_ts,
            dnat_chain->target,
            nat_ip,
            nat_port
        );

        firewd_rule(opts, rule_buf, NULL, spadat->use_src_ip,
            (fwc.use_destination ? spadat->pkt_destination_ip : FIREWD_ANY_IP),
            fst_proto, fst_port, nat_ip, nat_port, dnat_chain, exp_ts, now,
            "DNAT", spadat->spa_message_remain);
    }
    return;
}

static void snat_rule(const ztn_srv_options_t * const opts,
        const acc_stanza_t * const acc,
        const char * const nat_ip,
        const unsigned int nat_port,
        const unsigned int fst_proto,
        const unsigned int fst_port,
        spa_data_t * const spadat,
        const unsigned int exp_ts,
        const time_t now)
{
    char     rule_buf[CMD_BUFSIZE] = {0};
    char     snat_target[SNAT_TARGET_BUFSIZE] = {0};
    struct   fw_chain *snat_chain = NULL;

    log_msg(LOG_DEBUG,
            "snat_rule() forward_all: %d, nat_ip: %s, nat_port: %d, force_snat: %d, force_snat_ip: %s, force_masq: %d",
            acc->forward_all, nat_ip, nat_port, acc->force_snat,
            (acc->force_snat_ip == NULL) ? "(NONE)" : acc->force_snat_ip,
            acc->force_masquerade);

    if(acc->forward_all)
    {
        /* 默认使用 MASQUERADE */
        snat_chain = &(opts->fw_config->chain[FIREWD_MASQUERADE_ACCESS]);
        snprintf(snat_target, SNAT_TARGET_BUFSIZE-1, " ");

        /* 添加 SNAT 或 MASQUERADE 规则.
        */
        if(acc->force_snat && acc->force_snat_ip != NULL && is_valid_ipv4_addr(acc->force_snat_ip, strlen(acc->force_snat_ip)))
        {
            /* 使用静态 SNAT */
            snat_chain = &(opts->fw_config->chain[FIREWD_SNAT_ACCESS]);
            snprintf(snat_target, SNAT_TARGET_BUFSIZE-1,
                "--to-source %s", acc->force_snat_ip);
        }
        else if((opts->config[CONF_SNAT_TRANSLATE_IP] != NULL)
            && is_valid_ipv4_addr(opts->config[CONF_SNAT_TRANSLATE_IP], strlen(opts->config[CONF_SNAT_TRANSLATE_IP])))
        {
            /* 使用静态 SNAT */
            snat_chain = &(opts->fw_config->chain[FIREWD_SNAT_ACCESS]);
            snprintf(snat_target, SNAT_TARGET_BUFSIZE-1,
                "--to-source %s", opts->config[CONF_SNAT_TRANSLATE_IP]);
        }

        memset(rule_buf, 0, CMD_BUFSIZE);

        snprintf(rule_buf, CMD_BUFSIZE-1, FIREWD_SNAT_ALL_RULE_ARGS,
            snat_chain->table,
            spadat->use_src_ip,
            exp_ts,
            snat_chain->target,
            snat_target
        );

        firewd_rule(opts, rule_buf, NULL, spadat->use_src_ip,
            NULL, ANY_PROTO, ANY_PORT, NULL, NAT_ANY_PORT,
            snat_chain, exp_ts, now, "SNAT ALL", "*/*");
    }
    else
    {
        /* 添加 SNAT 或 MASQUERADE 规则.
        */
        if(acc->force_snat && acc->force_snat_ip != NULL && is_valid_ipv4_addr(acc->force_snat_ip, strlen(acc->force_snat_ip)))
        {
            /* 使用静态 SNAT */
            snat_chain = &(opts->fw_config->chain[FIREWD_SNAT_ACCESS]);
            snprintf(snat_target, SNAT_TARGET_BUFSIZE-1,
                "--to-source %s", acc->force_snat_ip);
        }
        else if(acc->force_snat && acc->force_masquerade)
        {
            /* 使用 MASQUERADE */
            snat_chain = &(opts->fw_config->chain[FIREWD_MASQUERADE_ACCESS]);
            snprintf(snat_target, SNAT_TARGET_BUFSIZE-1,
                "--to-ports %i", fst_port);
        }
        else if((opts->config[CONF_SNAT_TRANSLATE_IP] != NULL)
            && is_valid_ipv4_addr(opts->config[CONF_SNAT_TRANSLATE_IP], strlen(opts->config[CONF_SNAT_TRANSLATE_IP])))
        {
            /* 使用静态 SNAT */
            snat_chain = &(opts->fw_config->chain[FIREWD_SNAT_ACCESS]);
            snprintf(snat_target, SNAT_TARGET_BUFSIZE-1,
                "--to-source %s", opts->config[CONF_SNAT_TRANSLATE_IP]);
        }
        else
        {
            /* 使用 MASQUERADE */
            snat_chain = &(opts->fw_config->chain[FIREWD_MASQUERADE_ACCESS]);
            snprintf(snat_target, SNAT_TARGET_BUFSIZE-1,
                "--to-ports %i", fst_port);
        }

        memset(rule_buf, 0, CMD_BUFSIZE);

        snprintf(rule_buf, CMD_BUFSIZE-1, FIREWD_SNAT_RULE_ARGS,
            snat_chain->table,
            fst_proto,
            nat_ip,
            nat_port,
            exp_ts,
            snat_chain->target,
            snat_target
        );

        firewd_rule(opts, rule_buf, NULL, spadat->use_src_ip,
                NULL, fst_proto, nat_port, nat_ip, nat_port,
                snat_chain, exp_ts, now, "SNAT",
                spadat->spa_message_remain);
    }
    return;
}

/****************************************************************************/

/* 规则处理 - 创建一个访问请求...
*/
int
process_spa_request(const ztn_srv_options_t * const opts,
        const acc_stanza_t * const acc, spa_data_t * const spadat)
{
    char            nat_ip[MAX_IPV4_STR_LEN] = {0};
    char            nat_dst[MAX_HOSTNAME_LEN] = {0};
    unsigned int    nat_port = 0;
    unsigned int    fst_proto;
    unsigned int    fst_port;

    struct fw_chain * const in_chain   = &(opts->fw_config->chain[FIREWD_INPUT_ACCESS]);
    struct fw_chain * const out_chain  = &(opts->fw_config->chain[FIREWD_OUTPUT_ACCESS]);
    struct fw_chain * const fwd_chain  = &(opts->fw_config->chain[FIREWD_FORWARD_ACCESS]);
    struct fw_chain * const dnat_chain = &(opts->fw_config->chain[FIREWD_DNAT_ACCESS]);

    acc_port_list_t *port_list = NULL;
    acc_port_list_t *ple = NULL;

    char            *ndx = NULL;
    int             res = 0, is_err;
    int             str_len;
    time_t          now;
    unsigned int    exp_ts;

    /*解析和展开我们的访问消息。
    */
    if(expand_acc_port_list(&port_list, spadat->spa_message_remain) != 1)
    {
        /* 在技术上，如果有任何内存分配错误（请参见 add_port_list() 函数），
        * 我们将已经退出并显示错误，但为了完整性...
        */
        free_acc_port_list(port_list);
        return res;
    }

    /* 从协议端口列表的顶部开始...
    */
    ple = port_list;

    /* 记住第一个协议/端口组合，以备在需要时用于 NAT 访问请求.
    */
    fst_proto = ple->proto;
    fst_port  = ple->port;

    /* 设置我们的过期时间值。
    */
    time(&now);
    exp_ts = now + spadat->fw_access_timeout;

    /* 处理自身请求 NAT 操作的 SPA 数据包。
    */
    if(spadat->message_type == ZTN_LOCAL_NAT_ACCESS_MSG
      || spadat->message_type == ZTN_CLIENT_TIMEOUT_LOCAL_NAT_ACCESS_MSG
      || spadat->message_type == ZTN_NAT_ACCESS_MSG
      || spadat->message_type == ZTN_CLIENT_TIMEOUT_NAT_ACCESS_MSG
      || acc->force_nat)
    {
        if(acc->force_nat)
        {
            strlcpy(nat_ip, acc->force_nat_ip, sizeof(nat_ip));
            nat_port = acc->force_nat_port;
        }
        else
        {
            ndx = strchr(spadat->nat_access, ',');
            str_len = strcspn(spadat->nat_access, ",");
            if((ndx != NULL) && (str_len <= MAX_HOSTNAME_LEN))
            {
                strlcpy(nat_dst, spadat->nat_access, str_len+1);
                if(! is_valid_ipv4_addr(nat_dst, str_len))
                {
                    if(strncasecmp(opts->config[CONF_ENABLE_NAT_DNS], "Y", 1) == 0)
                    {
                        if (!is_valid_hostname(nat_dst, str_len))
                        {
                            log_msg(LOG_INFO, "Invalid Hostname in NAT SPA message");
                            free_acc_port_list(port_list);
                            return res;
                        }
                        if (ipv4_resolve(nat_dst, nat_ip) == 0)
                        {
                            log_msg(LOG_INFO, "Resolved NAT IP in SPA message");
                        }
                        else
                        {
                            log_msg(LOG_INFO, "Unable to resolve Hostname in NAT SPA message");
                            free_acc_port_list(port_list);
                            return res;
                        }
                    }
                    else
                    {
                        log_msg(LOG_INFO, "Received Hostname in NAT SPA message, but hostname is disabled.");
                        free_acc_port_list(port_list);
                        return res;

                    }
                }
                else
                {
                    strlcpy(nat_ip, nat_dst, MAX_IPV4_STR_LEN);
                }

                nat_port = strtol_wrapper(ndx+1, 0, MAX_PORT,
                        NO_EXIT_UPON_ERR, &is_err);
                if(is_err != ZTN_SUCCESS)
                {
                    log_msg(LOG_INFO, "Invalid NAT port in SPA message");
                    free_acc_port_list(port_list);
                    res = is_err;
                    return res;
                }
            }
            else
            {
                log_msg(LOG_INFO, "Invalid NAT IP in SPA message");
                free_acc_port_list(port_list);
                return res;
            }
        }

        if(spadat->message_type == ZTN_LOCAL_NAT_ACCESS_MSG
                || spadat->message_type == ZTN_CLIENT_TIMEOUT_LOCAL_NAT_ACCESS_MSG)
        {
            firewd_rule(opts, NULL, FIREWD_RULE_ARGS, spadat->use_src_ip,
                (fwc.use_destination ? spadat->pkt_destination_ip : FIREWD_ANY_IP),
                fst_proto, nat_port, nat_ip, nat_port, in_chain, exp_ts,
                now, "local NAT", spadat->spa_message_remain);
        }
        else if(strlen(fwd_chain->to_chain))
        {
            /* FORWARD 访问规则。
            */
            forward_access_rule(opts, acc, fwd_chain, nat_ip,
                    nat_port, fst_proto, fst_port, spadat, exp_ts, now);
        }

        /* DNAT 规则
        */
        if(strlen(dnat_chain->to_chain) && !acc->disable_dnat)
            dnat_rule(opts, acc, dnat_chain, nat_ip,
                    nat_port, fst_proto, fst_port, spadat, exp_ts, now);

        /* SNAT 规则
        */
        if(acc->force_snat || strncasecmp(opts->config[CONF_ENABLE_FIREWD_SNAT], "Y", 1) == 0)
            snat_rule(opts, acc, nat_ip, nat_port,
                    fst_proto, fst_port, spadat, exp_ts, now);
    }
    else /* 非 NAT 请求 - 这是典型情况。*/

        /* 为源 IP 的每个协议/端口创建一个访问命令
        */
        while(ple != NULL)
        {
            firewd_rule(opts, NULL, FIREWD_RULE_ARGS, spadat->use_src_ip,
                (fwc.use_destination ? spadat->pkt_destination_ip : FIREWD_ANY_IP),
                ple->proto, ple->port, NULL, NAT_ANY_PORT,
                in_chain, exp_ts, now, "access", spadat->spa_message_remain);

            /* 如果 out_chain 目标不为 NULL，我们需要创建相应的 OUTPUT 规则。
            */
            if(strlen(out_chain->to_chain))
            {
                firewd_rule(opts, NULL, FIREWD_OUT_RULE_ARGS, spadat->use_src_ip,
                    (fwc.use_destination ? spadat->pkt_destination_ip : FIREWD_ANY_IP),
                    ple->proto, ple->port, NULL, NAT_ANY_PORT,
                    out_chain, exp_ts, now, "OUTPUT", spadat->spa_message_remain);
            }
            ple = ple->next;
        }
    }

    /* 完成访问规则的端口列表。 */
    free_acc_port_list(port_list);

    return(res);
}

static void
rm_expired_rules(const ztn_srv_options_t * const opts,
        const char * const fw_output_buf,
        char *ndx, struct fw_chain *ch, int cpos, time_t now)
{
    char        exp_str[12]     = {0};
    char        rule_num_str[6] = {0};
    char        *rn_start, *rn_end, *tmp_mark;

    int         res, is_err, rn_offset=0, rule_num;
    time_t      rule_exp, min_exp = 0;

    /* 遍历列表并根据需要处理规则。 */
    while (ndx != NULL) {
       /* 跳转前进并提取时间戳 */
        ndx += strlen(EXPIRE_COMMENT_PREFIX);

        /* 为查找下一个规则记住这个位置。 */
        tmp_mark = ndx;

        strlcpy(exp_str, ndx, sizeof(exp_str));
        if (strchr(exp_str, '*') != NULL)
            strchr(exp_str, '*')[0] = '\0';

        chop_spaces(exp_str);
        if(!is_digits(exp_str))
        {
            /* 转到下一个规则，如果存在的话 */
            ndx = strstr(tmp_mark, EXPIRE_COMMENT_PREFIX);
            continue;
        }

        rule_exp = (time_t)atoll(exp_str);

        if(rule_exp <= now)
        {
            /* 转到下一个规则，如果存在的话 */
            rn_start = ndx;
            while(--rn_start > fw_output_buf)
            {
                if(*rn_start == '\n')
                    break;
            }

            if(*rn_start != '\n')
            {
                /* 这不应该发生，但如果发生了，请提出投诉，减少活动规则值，然后继续。 */
                log_msg(LOG_ERR,
                    "Rule parse error while finding rule line start in chain %i",
                    cpos);

                if (ch[cpos].active_rules > 0)
                    ch[cpos].active_rules--;

                break;
            }
            rn_start++;

            rn_end = strchr(rn_start, ' ');
            if(rn_end == NULL)
            {
                /* 这不应该发生，但如果发生了，请报告问题，减少活动规则值，然后继续。 */
                log_msg(LOG_ERR,
                    "Rule parse error while finding rule number in chain %i",
                    cpos);

                if (ch[cpos].active_rules > 0)
                    ch[cpos].active_rules--;

                break;
            }

            strlcpy(rule_num_str, rn_start, (rn_end - rn_start)+1);

            rule_num = strtol_wrapper(rule_num_str, rn_offset, RCHK_MAX_FIREWD_RULE_NUM,
                    NO_EXIT_UPON_ERR, &is_err);
            if(is_err != ZTN_SUCCESS)
            {
                log_msg(LOG_ERR,
                    "Rule parse error while finding rule number in chain %i",
                    cpos);

                if (ch[cpos].active_rules > 0)
                    ch[cpos].active_rules--;

                break;
            }

            zero_cmd_buffers();

            snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " FIREWD_DEL_RULE_ARGS,
                opts->fw_config->fw_command,
                ch[cpos].table,
                ch[cpos].to_chain,
                rule_num - rn_offset /* 考虑先前删除的规则的位置，带有 rn_offset 偏移量 */
            );

            res = run_extcmd(cmd_buf, err_buf, CMD_BUFSIZE,
                    WANT_STDERR, NO_TIMEOUT, &pid_status, opts);
            chop_newline(err_buf);

            log_msg(LOG_DEBUG, "check_firewall_rules() CMD: '%s' (res: %d, err: %s)",
                cmd_buf, res, err_buf);

            if(EXTCMD_IS_SUCCESS(res))
            {
                log_msg(LOG_INFO, "Removed rule %s from %s with expire time of %u",
                    rule_num_str, ch[cpos].to_chain, rule_exp
                );

                rn_offset++;

                if (ch[cpos].active_rules > 0)
                    ch[cpos].active_rules--;
            }
            else
                log_msg(LOG_ERR, "rm_expired_rules() Error %i from cmd:'%s': %s",
                        res, cmd_buf, err_buf);

        }
        else
        {
            /* Track the minimum future rule expire time.
            */
            min_exp = (min_exp < rule_exp) ? min_exp : rule_exp;
        }

        /* 将我们的跟踪索引推向 exp 字符串之外，
         * 以便我们可以继续处理列表中的下一个规则。
        */
        ndx = strstr(tmp_mark, EXPIRE_COMMENT_PREFIX);
    }

    /* 根据情况设置下一个待处理的过期时间。如果没有更多规则，则为0，
     * 否则为下一个预期的（最小的）时间。
    */
    if(ch[cpos].active_rules < 1)
        ch[cpos].next_expire = 0;
    else if(min_exp)
        ch[cpos].next_expire = min_exp;

    return;
}

/* 迭代配置的防火墙访问链并清除过期的防火墙规则
*/
void
check_firewall_rules(const ztn_srv_options_t * const opts,
        const int chk_rm_all)
{
    char            *ndx;
    char            fw_output_buf[STANDARD_CMD_OUT_BUFSIZE] = {0};

    int             i, res;
    time_t          now;

    struct fw_chain *ch = opts->fw_config->chain;

    time(&now);

    /* 迭代每个链并查找要删除的活动规则。
    */
    for(i=0; i < NUM_SPA_ACCESS_TYPES; i++)
    {
        /* 如果没有活动规则或者我们还没有达到预期的下一个过期时间，请继续。
        */
        if(!chk_rm_all && (ch[i].active_rules == 0 || ch[i].next_expire > now))
            continue;

        if(ch[i].table[0] == '\0' || ch[i].to_chain[i] == '\0')
            continue;

        zero_cmd_buffers();
        memset(fw_output_buf, 0x0, STANDARD_CMD_OUT_BUFSIZE);

        /* 获取该链的当前规则列表并删除任何已过期的规则。请注意，
         * chk_rm_all 使我们处于垃圾收集模式，并允许任何已手动添加的规则
         * （可能是由 spad 以外的程序添加的）利用 spad 的超时机制
         * 
        */
        snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " FIREWD_LIST_RULES_ARGS,
            opts->fw_config->fw_command,
            ch[i].table,
            ch[i].to_chain
        );

        res = run_extcmd(cmd_buf, fw_output_buf, STANDARD_CMD_OUT_BUFSIZE,
                WANT_STDERR, NO_TIMEOUT, &pid_status, opts);
        chop_newline(fw_output_buf);

        log_msg(LOG_DEBUG,
            "check_firewall_rules() CMD: '%s' (res: %d, fw_output_buf: %s)",
            cmd_buf, res, fw_output_buf);

        if(!EXTCMD_IS_SUCCESS(res))
        {
            log_msg(LOG_ERR,
                    "check_firewall_rules() Error %i from cmd:'%s': %s",
                    res, cmd_buf, fw_output_buf);
            continue;
        }

        log_msg(LOG_DEBUG, "RES=%i, CMD_BUF: %s\nRULES LIST: %s",
                res, cmd_buf, fw_output_buf);

        ndx = strstr(fw_output_buf, EXPIRE_COMMENT_PREFIX);
        if(ndx == NULL)
        {
            
            /* 我们没有找到要过期的候选规则 */
            log_msg(LOG_DEBUG,
                "Did not find expire comment in rules list %i", i);

            if (ch[i].active_rules > 0)
                ch[i].active_rules--;

            continue;
        }
        rm_expired_rules(opts, fw_output_buf, ndx, ch, i, now);
    }

    return;
}

int
validate_firewd_chain_conf(const char * const chain_str)
{
    int         j, rv  = 1;
    const char   *ndx  = chain_str;

    j = 1;
    while(*ndx != '\0')
    {
        if(*ndx == ',')
            j++;

        if(*ndx != '\0'
                && *ndx != ' '
                && *ndx != ','
                && *ndx != '_'
                && isalnum(*ndx) == 0)
        {
            rv = 0;
            break;
        }
        ndx++;
    }

    /* 健全性检查 - j 应该是链字段的数量（不包括类型）。 */
    if(j != FW_NUM_CHAIN_FIELDS)
        rv = 0;

    return rv;
}

#endif /* FIREWALL_FIREWALLD */

/***EOF***/
