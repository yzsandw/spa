/**
 * \file server/cmd_cycle.c
 *
 * \brief Fwknop例程，用于管理通过access.conf节（CMD_CYCLE_OPEN和CMD_CYCLE_CLOSE）定义的命令周期。
 */


#include "fwknopd_common.h"
#include "log_msg.h"
#include "extcmd.h"
#include "cmd_cycle.h"
#include "access.h"

static char cmd_buf[CMD_CYCLE_BUFSIZE];
static char err_buf[CMD_CYCLE_BUFSIZE];

static void
zero_cmd_buffers(void)
{
    memset(cmd_buf, 0x0, CMD_CYCLE_BUFSIZE);
    memset(err_buf, 0x0, CMD_CYCLE_BUFSIZE);
    return;
}

static int pid_status = 0;

static int
is_var(const char * const var, const char * const cmd_str)
{
    int i;
    for(i=0; i < strlen(var); i++)
    {
        if(cmd_str[i] != var[i])
            return 0;
    }
    return 1;
}

static int
build_cmd(spa_data_t *spadat, const char * const cmd_cycle_str, int timer)
{
    char             port_str[MAX_PORT_STR_LEN+1]   = {0};
    char             proto_str[MAX_PROTO_STR_LEN+1] = {0};
    char             timestamp_str[20] = {0};
    char             client_timeout_str[10] = {0};
    acc_port_list_t *port_list = NULL;
    int              i=0, buf_idx=0;

#if HAVE_LIBFIU
    fiu_return_on("cmd_cycle_build_err", 0);
#endif

    if(expand_acc_port_list(&port_list, spadat->spa_message_remain) != 1)
    {
        free_acc_port_list(port_list);
        return 0;
    }

    /* 即使SPA消息设置了多个端口和协议，我们也只查看命令打开/关闭周期的第一个端口/原型组合。
    */
    snprintf(port_str, MAX_PORT_STR_LEN+1, "%d", port_list->port);
    snprintf(proto_str, MAX_PROTO_STR_LEN+1, "%d", port_list->proto);

    zero_cmd_buffers();

    /* 查找以下替换变量：IP、SRC、PKT_SRC、DST、PORT和PROTO
    */
    for(i=0; i < strnlen(cmd_cycle_str, CMD_CYCLE_BUFSIZE); i++)
    {
        if(cmd_cycle_str[i] == '$')
        {
            /* 找到了一个变量的开头，现在验证它并在IP/port/proto中交换。
            */
            if(is_var("IP", (cmd_cycle_str+i+1)))
            {
                strlcat(cmd_buf, spadat->use_src_ip,
                        CMD_CYCLE_BUFSIZE);
                i += strlen("IP");
                buf_idx += strlen(spadat->use_src_ip);
            }
            /* SRC是IP的同义词
            */
            else if(is_var("SRC", (cmd_cycle_str+i+1)))
            {
                strlcat(cmd_buf, spadat->use_src_ip,
                        CMD_CYCLE_BUFSIZE);
                i += strlen("SRC");
                buf_idx += strlen(spadat->use_src_ip);
            }
            /* 特殊情况下，如果用户真的想这样做，SPA包源IP在IP报头(即不是从解密SPA有效载荷)。
            */
            else if(is_var("PKT_SRC", (cmd_cycle_str+i+1)))
            {
                strlcat(cmd_buf, spadat->pkt_source_ip,
                        CMD_CYCLE_BUFSIZE);
                i += strlen("PKT_SRC");
                buf_idx += strlen(spadat->pkt_source_ip);
            }
            else if(is_var("DST", (cmd_cycle_str+i+1)))
            {
                strlcat(cmd_buf, spadat->pkt_destination_ip,
                        CMD_CYCLE_BUFSIZE);
                i += strlen("DST");
                buf_idx += strlen(spadat->pkt_destination_ip);
            }
            else if (is_var("PORT", (cmd_cycle_str+i+1)))
            {
                strlcat(cmd_buf, port_str, CMD_CYCLE_BUFSIZE);
                i += strlen("PORT");
                buf_idx += strlen(port_str);
            }
            else if (is_var("PROTO", (cmd_cycle_str+i+1)))
            {
                strlcat(cmd_buf, proto_str, CMD_CYCLE_BUFSIZE);
                i += strlen("PROTO");
                buf_idx += strlen(proto_str);
            }
            else if (is_var("TIMEOUT", (cmd_cycle_str+i+1)))
            {
                snprintf(timestamp_str, sizeof(timestamp_str), "%lli",
                        (long long)spadat->timestamp +
                        (spadat->client_timeout == 0 ? timer :
                        spadat->client_timeout));
                strlcat(cmd_buf, timestamp_str, CMD_CYCLE_BUFSIZE);
                i += strlen("TIMEOUT");
                buf_idx += strlen(timestamp_str);
            }
            else if (is_var("CLIENT_TIMEOUT", (cmd_cycle_str+i+1)))
            {
                snprintf(client_timeout_str, sizeof(client_timeout_str), "%u",
                         spadat->client_timeout == 0 ? timer :
                         spadat->client_timeout);
                strlcat(cmd_buf, client_timeout_str, CMD_CYCLE_BUFSIZE);
                i += strlen("CLIENT_TIMEOUT");
                buf_idx += strlen(client_timeout_str);
            }
            continue;
        }
        if(cmd_cycle_str[i] != '\0')
            cmd_buf[buf_idx++] = cmd_cycle_str[i];
        if(buf_idx == CMD_CYCLE_BUFSIZE)
        {
            free_acc_port_list(port_list);
            return 0;
        }
    }

    free_acc_port_list(port_list);
    return 1;
}

static int
cmd_open(fko_srv_options_t *opts, acc_stanza_t *acc,
        spa_data_t *spadat, const int stanza_num)
{
    /* CMD_CYCLE_OPEN：必要时通过变量替换来构建打开命令
    */
    if(build_cmd(spadat, acc->cmd_cycle_open, acc->cmd_cycle_timer))
    {
        log_msg(LOG_INFO, "[%s] (stanza #%d) Running CMD_CYCLE_OPEN command: %s",
                spadat->pkt_source_ip, stanza_num, cmd_buf);

        /* 运行open命令
        */
        run_extcmd(cmd_buf, err_buf, CMD_CYCLE_BUFSIZE,
                WANT_STDERR, NO_TIMEOUT, &pid_status, opts);
    }
    else
    {
        log_msg(LOG_ERR,
            "[%s] (stanza #%d) Could not build CMD_CYCLE_OPEN command.",
            spadat->pkt_source_ip, stanza_num
        );
        return 0;
    }
    return 1;
}

static int
add_cmd_close(fko_srv_options_t *opts, acc_stanza_t *acc,
        spa_data_t *spadat, const int stanza_num)
{
    cmd_cycle_list_t   *last_clist=NULL, *new_clist=NULL, *tmp_clist=NULL;
    time_t              now;
    int                 cmd_close_len = 0;

    /* CMD_CYCLE_CLOSE：生成关闭命令，但在过期计时器过去之前不要执行它。
    */
    if(build_cmd(spadat, acc->cmd_cycle_close, acc->cmd_cycle_timer))
    {
        /* 现在，相应的关闭命令现在位于cmd_buf中，以便在计时器到期时稍后执行
        */
        cmd_close_len = strnlen(cmd_buf, CMD_CYCLE_BUFSIZE-1)+1;
        log_msg(LOG_INFO,
                "[%s] (stanza #%d) Running CMD_CYCLE_CLOSE command in %d seconds: %s",
                spadat->pkt_source_ip, stanza_num,
                (spadat->client_timeout == 0 ? acc->cmd_cycle_timer :
                spadat->client_timeout), cmd_buf);
    }
    else
    {
        log_msg(LOG_ERR,
            "[%s] (stanza #%d) Could not build CMD_CYCLE_CLOSE command.",
            spadat->pkt_source_ip, stanza_num
        );
        return 0;
    }

    /* 添加相应的关闭命令-在指定计时器到期后执行。
    */
    if((new_clist = calloc(1, sizeof(cmd_cycle_list_t))) == NULL)
    {
        log_msg(LOG_ERR,
            "[*] Fatal memory allocation error creating string list entry"
        );
        clean_exit(opts, FW_CLEANUP, EXIT_FAILURE);
    }

    if(opts->cmd_cycle_list == NULL)
    {
        opts->cmd_cycle_list = new_clist;
    }
    else
    {
        tmp_clist = opts->cmd_cycle_list;

        do {
            last_clist = tmp_clist;
        } while((tmp_clist = tmp_clist->next));

        last_clist->next = new_clist;
    }

    /* 设置源IP
    */
    strlcpy(new_clist->src_ip, spadat->use_src_ip,
            sizeof(new_clist->src_ip));

    /* 设置过期计时器
    */
    time(&now);
    new_clist->expire = now + (spadat->client_timeout == 0 ?
            acc->cmd_cycle_timer : spadat->client_timeout);

    /* 设置关闭命令
    */
    if((new_clist->close_cmd = calloc(1, cmd_close_len)) == NULL)
    {
        log_msg(LOG_ERR,
            "[*] Fatal memory allocation error creating command close string"
        );
        clean_exit(opts, FW_CLEANUP, EXIT_FAILURE);
    }
    strlcpy(new_clist->close_cmd, cmd_buf, cmd_close_len);

    /* 设置access.conf节编号
    */
    new_clist->stanza_num = stanza_num;

    return 1;
}

/* 这是打开/关闭命令循环的主要驱动程序
*/
int
cmd_cycle_open(fko_srv_options_t *opts, acc_stanza_t *acc,
        spa_data_t *spadat, const int stanza_num, int *res)
{
    if(! cmd_open(opts, acc, spadat, stanza_num))
        return 0;

    if(acc->cmd_cycle_do_close)
        if(! add_cmd_close(opts, acc, spadat, stanza_num))
            return 0;

     return 1;
}

static void
free_cycle_list_node(cmd_cycle_list_t *list_node)
{
    if(list_node != NULL)
    {
        if(list_node->close_cmd != NULL)
            free(list_node->close_cmd);
        free(list_node);
    }
    return;
}

/* 根据过期计时器运行所有关闭命令
*/
void
cmd_cycle_close(fko_srv_options_t *opts)
{
    cmd_cycle_list_t   *curr=NULL, *prev=NULL;
    int                 do_delete=1;
    time_t              now;

    time(&now);

    if(opts->cmd_cycle_list == NULL)
    {
        return; /*没有激活的命令周期 */
    }
    else
    {
        while(do_delete)
        {
            do_delete = 0;

            /* 只要有要执行（和过期）的命令，就一直浏览命令列表。
            */
            for(curr = opts->cmd_cycle_list;
                    curr != NULL;
                    prev = curr, curr=curr->next)
            {
                if(curr->expire <= now)
                {
                    log_msg(LOG_INFO,
                            "[%s] (stanza #%d) Timer expired, running CMD_CYCLE_CLOSE command: %s",
                            curr->src_ip, curr->stanza_num,
                            curr->close_cmd);

                    zero_cmd_buffers();

                    /* 运行关闭命令
                    */
                    run_extcmd(curr->close_cmd, err_buf, CMD_CYCLE_BUFSIZE,
                            WANT_STDERR, NO_TIMEOUT, &pid_status, opts);

                    if(prev == NULL)
                        opts->cmd_cycle_list = curr->next;
                    else
                        prev->next = curr->next;

                    free_cycle_list_node(curr);
                    do_delete = 1;
                    break;
                }
            }
        }
    }

    return;
}

void
free_cmd_cycle_list(fko_srv_options_t *opts)
{
    cmd_cycle_list_t   *tmp_clist=NULL, *clist=NULL;

    clist = opts->cmd_cycle_list;

    while(clist != NULL)
    {
        tmp_clist = clist->next;
        free_cycle_list_node(clist);
        clist = tmp_clist;
    }
    return;
}
