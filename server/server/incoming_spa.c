
#include "spad_common.h"
#include "netinet_common.h"

#if HAVE_SYS_WAIT_H
  #include <sys/wait.h>
#endif

#include "incoming_spa.h"
#include "access.h"
#include "extcmd.h"
#include "cmd_cycle.h"
#include "log_msg.h"
#include "utils.h"
#include "fw_util.h"
#include "spad_errors.h"
#include "replay_cache.h"

#define CTX_DUMP_BUFSIZE            4096                /*!< Maximum size allocated to a ZTN context dump */

/* 
 * 验证并在某些情况下预处理/重新格式化SPA数据。如果存在任何指示数据不是有效的SPA数据的迹象，则返回错误代码值。
*/
static int
preprocess_spa_data(const ztn_srv_options_t *opts, spa_pkt_info_t *spa_pkt, spa_data_t *spadat)
{

    char    *ndx = (char *)&(spa_pkt->packet_data);
    char    *xff;
    int      i, pkt_data_len = 0;

    pkt_data_len = spa_pkt->packet_data_len;

   /* 在这一点上，我们可以将数据包数据长度重置为0。这是我们程序的其余部分的指示，表明我们没有当前的 SPA 数据包要处理（除了当前这一个）。
 * 
 */

spa_pkt->packet_data_len = 0;

/* 这两个检查已经在 process_packet() 中完成，但这是一个防御性措施，以便在这里再次运行它们
 * 
 */

if(pkt_data_len < MIN_SPA_DATA_SIZE)
    return(SPA_MSG_BAD_DATA);

if(pkt_data_len > MAX_SPA_PACKET_LEN)
    return(SPA_MSG_BAD_DATA);

/* 忽略包含 Rijndael 或 GnuPG 前缀的任何 SPA 数据包，因为攻击者可能将它们附加到以前见过的 SPA 数据包中，以试图通过重放检查。而且，我们不会更糟糕，因为合法的 SPA 数据包，如果包含外部前缀之后的前缀，则会被删除，无论如何都不会正确解密，因为 libztn 不会添加新的前缀。
 * TODO:?
 * 
 */

   
   if (constant_runtime_cmp(ndx, B64_RIJNDAEL_SALT, B64_RIJNDAEL_SALT_STR_LEN) == 0)
    return(SPA_MSG_BAD_DATA);

if (pkt_data_len > MIN_GNUPG_MSG_SIZE
        && constant_runtime_cmp(ndx, B64_GPG_PREFIX, B64_GPG_PREFIX_STR_LEN) == 0)
    return(SPA_MSG_BAD_DATA);

/* 初始化 X-Forwarded-For 字段 */
spadat->pkt_source_xff_ip[0] = '\0';

/* 检测并解析来自 HTTP 请求的 SPA 数据。如果 SPA 数据以 "GET /" 开头，而用户代理以 "Spa" 开头，那么假定这是一个通过 HTTP 请求的 SPA。
*/
if (strncasecmp(opts->config[CONF_ENABLE_SPA_OVER_HTTP], "Y", 1) == 0
  && strncasecmp(ndx, "GET /", 5) == 0)
{
    /* 这看起来像一个 HTTP 请求，因此让我们看看是否配置为接受这种请求，如果是的话，找到 SPA 数据。
    */

    /* 首先看看我们是否需要 User-Agent 以 'Spa' 开头
    */
    if (strncasecmp(opts->config[CONF_ALLOW_ANY_USER_AGENT], "N", 1) == 0
      && strstr(ndx, "User-Agent: Spa") == NULL)
    {
        return(SPA_MSG_BAD_DATA);
    }

    /* 处理 X-Forwarded-For 标头 */

    xff = strcasestr(ndx, "X-Forwarded-For: ");

    if (xff != NULL && strncasecmp(opts->config[CONF_ENABLE_X_FORWARDED_FOR], "Y", 1) == 0) {
        xff += 17;

        for (i = 0; *xff != '\0'; i++)
            if (isspace((int)(unsigned char)*xff))
               *xff = '\0';
            else
               xff++;

        xff -= i - 1;

        if (!is_valid_ipv4_addr(xff, strlen(xff)))
            log_msg(LOG_WARNING,
            "解析 X-Forwarded-For 标头时出错：值 '%s' 不是 IP 地址",
            xff);
        else
            strlcpy(spadat->pkt_source_xff_ip, xff, i);
    }

    /* 现在提取、调整（将由 spa 客户端转换的字符转换回来）并重置 SPA 消息本身。
    */
    strlcpy((char *)spa_pkt->packet_data, ndx+5, pkt_data_len);
    pkt_data_len -= 5;

    for(i=0; i<pkt_data_len; i++)
    {
        if(isspace((int)(unsigned char)*ndx)) /* 第一个空格标记着请求的结束 */
        {
            *ndx = '\0';
            break;
        }
        else if(*ndx == '-') /* 将 '-' 转换为 '+' */
            *ndx = '+';
        else if(*ndx == '_') /* 将 '_' 转换为 '/' */
            *ndx = '/';

        ndx++;
    }

    if(i < MIN_SPA_DATA_SIZE)
        return(SPA_MSG_BAD_DATA);

    spa_pkt->packet_data_len = pkt_data_len = i;
}


    
   // 要求 base64 编码的数据
    if(! is_base64(spa_pkt->packet_data, pkt_data_len))
        return(SPA_MSG_NOT_SPA_DATA);


    
   // 如果我们到达这里，我们没有理由认为这不是 SPA 数据。最终的测试将是 SPA 数据是否通过 HMAC 进行身份验证。
    return(ZTN_SUCCESS);
}

/* For replay attack detection
*/
static int
get_raw_digest(char **digest, char *pkt_data)
{
    ztn_ctx_t    ctx = NULL;
    char        *tmp_digest = NULL;
    int          res = ZTN_SUCCESS;
    short        raw_digest_type = -1;

    
   // 初始化一个没有解密密钥的 ZTN 上下文，以便我们可以获得外部消息摘要
    res = ztn_new_with_data(&ctx, (char *)pkt_data, NULL, 0,
            ZTN_DEFAULT_ENC_MODE, NULL, 0, 0);

    if(res != ZTN_SUCCESS)
    {
        log_msg(LOG_WARNING, "Error initializing ZTN context from SPA data: %s",
            ztn_errstr(res));
        ztn_destroy(ctx);
        ctx = NULL;
        return(SPA_MSG_ZTN_CTX_ERROR);
    }

    res = ztn_set_raw_spa_digest_type(ctx, ZTN_DEFAULT_DIGEST);
    if(res != ZTN_SUCCESS)
    {
        log_msg(LOG_WARNING, "Error setting digest type for SPA data: %s",
            ztn_errstr(res));
        ztn_destroy(ctx);
        ctx = NULL;
        return(SPA_MSG_DIGEST_ERROR);
    }

    res = ztn_get_raw_spa_digest_type(ctx, &raw_digest_type);
    if(res != ZTN_SUCCESS)
    {
        log_msg(LOG_WARNING, "Error getting digest type for SPA data: %s",
            ztn_errstr(res));
        ztn_destroy(ctx);
        ctx = NULL;
        return(SPA_MSG_DIGEST_ERROR);
    }

   // 保证摘要类型是我们期望的
    if(raw_digest_type != ZTN_DEFAULT_DIGEST)
    {
        log_msg(LOG_WARNING, "Error setting digest type for SPA data: %s",
            ztn_errstr(res));
        ztn_destroy(ctx);
        ctx = NULL;
        return(SPA_MSG_DIGEST_ERROR);
    }

    res = ztn_set_raw_spa_digest(ctx);
    if(res != ZTN_SUCCESS)
    {
        log_msg(LOG_WARNING, "Error setting digest for SPA data: %s",
            ztn_errstr(res));
        ztn_destroy(ctx);
        ctx = NULL;
        return(SPA_MSG_DIGEST_ERROR);
    }

    res = ztn_get_raw_spa_digest(ctx, &tmp_digest);
    if(res != ZTN_SUCCESS)
    {
        log_msg(LOG_WARNING, "Error getting digest from SPA data: %s",
            ztn_errstr(res));
        ztn_destroy(ctx);
        ctx = NULL;
        return(SPA_MSG_DIGEST_ERROR);
    }

    *digest = strdup(tmp_digest);

    if (*digest == NULL)
        res = SPA_MSG_ERROR;   // 真的是一个 strdup() 内存分配问题

    ztn_destroy(ctx);
    ctx = NULL;

    return res;
}
/*从初始化（并填充）的ZTN上下文中弹出spa_data结构。

*/

static int
get_spa_data_fields(ztn_ctx_t ctx, spa_data_t *spdat)
{
    int res = ZTN_SUCCESS;

    res = ztn_get_username(ctx, &(spdat->username));
    if(res != ZTN_SUCCESS)
        return(res);

    res = ztn_get_timestamp(ctx, &(spdat->timestamp));
    if(res != ZTN_SUCCESS)
        return(res);

    res = ztn_get_version(ctx, &(spdat->version));
    if(res != ZTN_SUCCESS)
        return(res);

    res = ztn_get_spa_message_type(ctx, &(spdat->message_type));
    if(res != ZTN_SUCCESS)
        return(res);

    res = ztn_get_spa_message(ctx, &(spdat->spa_message));
    if(res != ZTN_SUCCESS)
        return(res);

    res = ztn_get_spa_nat_access(ctx, &(spdat->nat_access));
    if(res != ZTN_SUCCESS)
        return(res);

    res = ztn_get_spa_server_auth(ctx, &(spdat->server_auth));
    if(res != ZTN_SUCCESS)
        return(res);

    res = ztn_get_spa_client_timeout(ctx, (int *)&(spdat->client_timeout));
    if(res != ZTN_SUCCESS)
        return(res);

    return(res);
}

static int
check_pkt_age(const ztn_srv_options_t *opts, spa_data_t *spadat,
        const int stanza_num)
{
    int         ts_diff;
    time_t      now_ts;

    if(strncasecmp(opts->config[CONF_ENABLE_SPA_PACKET_AGING], "Y", 1) == 0)
    {
        time(&now_ts);

        ts_diff = labs(now_ts - spadat->timestamp);

        if(ts_diff > opts->max_spa_packet_age)
        {
            log_msg(LOG_WARNING, "[%s] (stanza #%d) SPA data time difference is too great (%i seconds).",
                spadat->pkt_source_ip, stanza_num, ts_diff);
            return 0;
        }
    }
    return 1;
}

static int
check_stanza_expiration(acc_stanza_t *acc, spa_data_t *spadat,
        const int stanza_num)
{
    if(acc->access_expire_time > 0)
    {
        if(acc->expired)
        {
            return 0;
        }
        else
        {
            if(time(NULL) > acc->access_expire_time)
            {
                log_msg(LOG_INFO, "[%s] (stanza #%d) Access stanza has expired",
                    spadat->pkt_source_ip, stanza_num);
                acc->expired = 1;
                return 0;
            }
        }
    }
    return 1;
}


// 检查基于SPA数据包源IP的access.conf段源匹配
static int
is_src_match(acc_stanza_t *acc, const uint32_t ip)
{
    while (acc)
    {
        if(compare_addr_list(acc->source_list, ip))
            return 1;

        acc = acc->next;
    }
    return 0;
}

static int
src_check(ztn_srv_options_t *opts, spa_pkt_info_t *spa_pkt,
        spa_data_t *spadat, char **raw_digest)
{
    if (is_src_match(opts->acc_stanzas, ntohl(spa_pkt->packet_src_ip)))
    {
        if(strncasecmp(opts->config[CONF_ENABLE_DIGEST_PERSISTENCE], "Y", 1) == 0)
        {
            
           // 检查重放攻击
            if(get_raw_digest(raw_digest, (char *)spa_pkt->packet_data) != ZTN_SUCCESS)
            {
                if (*raw_digest != NULL)
                    free(*raw_digest);
                return 0;
            }
            if (*raw_digest == NULL)
                return 0;

            if (is_replay(opts, *raw_digest) != SPA_MSG_SUCCESS)
            {
                free(*raw_digest);
                return 0;
            }
        }
    }
    else
    {
        log_msg(LOG_WARNING,
            "No access data found for source IP: %s", spadat->pkt_source_ip
        );
        return 0;
    }
    return 1;
}

static int
precheck_pkt(ztn_srv_options_t *opts, spa_pkt_info_t *spa_pkt,
        spa_data_t *spadat, char **raw_digest)
{
    int res = 0, packet_data_len = 0;

    packet_data_len = spa_pkt->packet_data_len;

    res = preprocess_spa_data(opts, spa_pkt, spadat);
    if(res != ZTN_SUCCESS)
    {
        log_msg(LOG_DEBUG, "[%s] preprocess_spa_data() returned error %i: '%s' for incoming packet.",
            spadat->pkt_source_ip, res, get_errstr(res));
        return 0;
    }

    if(opts->foreground == 1 && opts->verbose > 2)
    {
        printf("[+] candidate SPA packet payload:\n");
        hex_dump(spa_pkt->packet_data, packet_data_len);
    }

    if(! src_check(opts, spa_pkt, spadat, raw_digest))
        return 0;

    return 1;
}

static int
src_dst_check(acc_stanza_t *acc, spa_pkt_info_t *spa_pkt,
        spa_data_t *spadat, const int stanza_num)
{
    if(! compare_addr_list(acc->source_list, ntohl(spa_pkt->packet_src_ip)) ||
       (acc->destination_list != NULL
        && ! compare_addr_list(acc->destination_list, ntohl(spa_pkt->packet_dst_ip))))
    {
        log_msg(LOG_DEBUG,
                "(stanza #%d) SPA packet (%s -> %s) filtered by SOURCE and/or DESTINATION criteria",
                stanza_num, spadat->pkt_source_ip, spadat->pkt_destination_ip);
        return 0;
    }
    return 1;
}


// 处理命令消息
static int
process_cmd_msg(ztn_srv_options_t *opts, acc_stanza_t *acc,
        spa_data_t *spadat, const int stanza_num, int *res)
{
    int             pid_status=0;
    char            cmd_buf[MAX_SPA_CMD_LEN] = {0};

    if(!acc->enable_cmd_exec)
    {
        log_msg(LOG_WARNING,
            "[%s] (stanza #%d) SPA Command messages are not allowed in the current configuration.",
            spadat->pkt_source_ip, stanza_num
        );
        return 0;
    }
    else if(opts->test)
    {
        log_msg(LOG_WARNING,
            "[%s] (stanza #%d) --test mode enabled, skipping command execution.",
            spadat->pkt_source_ip, stanza_num
        );
        return 0;
    }
    else
    {
        log_msg(LOG_INFO,
            "[%s] (stanza #%d) Processing SPA Command message: command='%s'.",
            spadat->pkt_source_ip, stanza_num, spadat->spa_message_remain
        );

        memset(cmd_buf, 0x0, sizeof(cmd_buf));
        if(acc->enable_cmd_sudo_exec)
        {
            

           // 如果我们有一个 sudo 用户，那么我们将使用它来执行命令
            strlcpy(cmd_buf, opts->config[CONF_SUDO_EXE],
                    sizeof(cmd_buf));
            if(acc->cmd_sudo_exec_user != NULL
                    && strncasecmp(acc->cmd_sudo_exec_user, "root", 4) != 0)
            {
                strlcat(cmd_buf, " -u ", sizeof(cmd_buf));
                strlcat(cmd_buf, acc->cmd_sudo_exec_user, sizeof(cmd_buf));
            }
            if(acc->cmd_exec_group != NULL
                    && strncasecmp(acc->cmd_sudo_exec_group, "root", 4) != 0)
            {
                strlcat(cmd_buf, " -g ", sizeof(cmd_buf));
                strlcat(cmd_buf,
                        acc->cmd_sudo_exec_group, sizeof(cmd_buf));
            }
            strlcat(cmd_buf, " ",  sizeof(cmd_buf));
            strlcat(cmd_buf, spadat->spa_message_remain, sizeof(cmd_buf));
        }
        else
            strlcpy(cmd_buf, spadat->spa_message_remain, sizeof(cmd_buf));

        if(acc->cmd_exec_user != NULL
                && strncasecmp(acc->cmd_exec_user, "root", 4) != 0)
        {
            log_msg(LOG_INFO,
                    "[%s] (stanza #%d) Running command '%s' setuid/setgid user/group to %s/%s (UID=%i,GID=%i)",
                spadat->pkt_source_ip, stanza_num, cmd_buf, acc->cmd_exec_user,
                acc->cmd_exec_group == NULL ? acc->cmd_exec_user : acc->cmd_exec_group,
                acc->cmd_exec_uid, acc->cmd_exec_gid);

            *res = run_extcmd_as(acc->cmd_exec_uid, acc->cmd_exec_gid,
                    cmd_buf, NULL, 0, WANT_STDERR, NO_TIMEOUT,
                    &pid_status, opts);
        }
        else // 以 root 身份运行
        {
            log_msg(LOG_INFO,
                    "[%s] (stanza #%d) Running command '%s'",
                spadat->pkt_source_ip, stanza_num, cmd_buf);
            *res = run_extcmd(cmd_buf, NULL, 0, WANT_STDERR,
                    5, &pid_status, opts);
        }

       

       // 如果WIFEXITED()命令成功执行，则将结果设置为 SPA_MSG_COMMAND_SUCCESS
        log_msg(LOG_INFO,
            "[%s] (stanza #%d) CMD_EXEC: command returned %i, pid_status: %d",
            spadat->pkt_source_ip, stanza_num, *res,
            WIFEXITED(pid_status) ? WEXITSTATUS(pid_status) : pid_status);

        if(WIFEXITED(pid_status))
        {
            if(WEXITSTATUS(pid_status) != 0)
                *res = SPA_MSG_COMMAND_ERROR;
        }
        else
            *res = SPA_MSG_COMMAND_ERROR;
    }
    return 1;
}

static int
check_mode_ctx(spa_data_t *spadat, ztn_ctx_t *ctx, int attempted_decrypt,
        const int enc_type, const int stanza_num, const int res)
{
    if(attempted_decrypt == 0)
    {
        log_msg(LOG_ERR,
            "[%s] (stanza #%d) No stanza encryption mode match for encryption type: %i.",
            spadat->pkt_source_ip, stanza_num, enc_type);
        return 0;
    }

    
    if(res != ZTN_SUCCESS)
    {
        log_msg(LOG_WARNING, "[%s] (stanza #%d) Error creating ztn context: %s",
            spadat->pkt_source_ip, stanza_num, ztn_errstr(res));

        if(IS_GPG_ERROR(res))
            log_msg(LOG_WARNING, "[%s] (stanza #%d) - GPG ERROR: %s",
                spadat->pkt_source_ip, stanza_num, ztn_gpg_errstr(*ctx));
        return 0;
    }

    return 1;
}

static void
handle_rijndael_enc(acc_stanza_t *acc, spa_pkt_info_t *spa_pkt,
        spa_data_t *spadat, ztn_ctx_t *ctx, int *attempted_decrypt,
        int *cmd_exec_success, const int enc_type, const int stanza_num,
        int *res)
{
    if(enc_type == ZTN_ENCRYPTION_RIJNDAEL || acc->enable_cmd_exec)
    {
        *res = ztn_new_with_data(ctx, (char *)spa_pkt->packet_data,
            acc->key, acc->key_len, acc->encryption_mode, acc->hmac_key,
            acc->hmac_key_len, acc->hmac_type);
        *attempted_decrypt = 1;
        if(*res == ZTN_SUCCESS)
            *cmd_exec_success = 1;
    }
    return;
}

static int
handle_gpg_enc(acc_stanza_t *acc, spa_pkt_info_t *spa_pkt,
        spa_data_t *spadat, ztn_ctx_t *ctx, int *attempted_decrypt,
        const int cmd_exec_success, const int enc_type,
        const int stanza_num, int *res)
{
    if(acc->use_gpg && enc_type == ZTN_ENCRYPTION_GPG && cmd_exec_success == 0)
    {
        
        // 如果我们有一个 GPG 密码，或者允许没有密码，则创建一个新的 ZTN 上下文
        if(acc->gpg_decrypt_pw != NULL || acc->gpg_allow_no_pw)
        {
            *res = ztn_new_with_data(ctx, (char *)spa_pkt->packet_data, NULL,
                    0, ZTN_ENC_MODE_ASYMMETRIC, acc->hmac_key,
                    acc->hmac_key_len, acc->hmac_type);

            if(*res != ZTN_SUCCESS)
            {
                log_msg(LOG_WARNING,
                    "[%s] (stanza #%d) Error creating ztn context (before decryption): %s",
                    spadat->pkt_source_ip, stanza_num, ztn_errstr(*res)
                );
                return 0;
            }

         
           // 如果我们有一个 GPG 可执行文件路径，则设置它
            if(acc->gpg_exe != NULL)
            {
                *res = ztn_set_gpg_exe(*ctx, acc->gpg_exe);
                if(*res != ZTN_SUCCESS)
                {
                    log_msg(LOG_WARNING,
                        "[%s] (stanza #%d) Error setting GPG path %s: %s",
                        spadat->pkt_source_ip, stanza_num, acc->gpg_exe,
                        ztn_errstr(*res)
                    );
                    return 0;
                }
            }

            if(acc->gpg_home_dir != NULL)
            {
                *res = ztn_set_gpg_home_dir(*ctx, acc->gpg_home_dir);
                if(*res != ZTN_SUCCESS)
                {
                    log_msg(LOG_WARNING,
                        "[%s] (stanza #%d) Error setting GPG keyring path to %s: %s",
                        spadat->pkt_source_ip, stanza_num, acc->gpg_home_dir,
                        ztn_errstr(*res)
                    );
                    return 0;
                }
            }

            if(acc->gpg_decrypt_id != NULL)
                ztn_set_gpg_recipient(*ctx, acc->gpg_decrypt_id);

           /* 如果为此 acc stanza 设置了 GPG_REQUIRE_SIG，则相应地设置 ZTN 上下文并检查其他与 GPG 签名相关的参数。当设置了 REMOTE_ID 时，也适用。
*/

if (acc->gpg_require_sig)
{
    ztn_set_gpg_signature_verify(*ctx, 1);

    /* 设置是否忽略签名验证错误。
    */
    ztn_set_gpg_ignore_verify_error(*ctx, acc->gpg_ignore_sig_error);
}
else
{
    ztn_set_gpg_signature_verify(*ctx, 0);
    ztn_set_gpg_ignore_verify_error(*ctx, 1);
}

/* 现在解密数据。
*/

            *res = ztn_decrypt_spa_data(*ctx, acc->gpg_decrypt_pw, 0);
            *attempted_decrypt = 1;
        }
    }
    return 1;
}

static int
handle_gpg_sigs(acc_stanza_t *acc, spa_data_t *spadat,
        ztn_ctx_t *ctx, const int enc_type, const int stanza_num, int *res)
{
    char                *gpg_id, *gpg_fpr;
    acc_string_list_t   *gpg_id_ndx;
    acc_string_list_t   *gpg_fpr_ndx;
    unsigned char        is_gpg_match = 0;

    if(enc_type == ZTN_ENCRYPTION_GPG && acc->gpg_require_sig)
    {
        *res = ztn_get_gpg_signature_id(*ctx, &gpg_id);
        if(*res != ZTN_SUCCESS)
        {
            log_msg(LOG_WARNING,
                "[%s] (stanza #%d) Error pulling the GPG signature ID from the context: %s",
                spadat->pkt_source_ip, stanza_num, ztn_gpg_errstr(*ctx));
            return 0;
        }

        *res = ztn_get_gpg_signature_fpr(*ctx, &gpg_fpr);
        if(*res != ZTN_SUCCESS)
        {
            log_msg(LOG_WARNING,
                "[%s] (stanza #%d) Error pulling the GPG fingerprint from the context: %s",
                spadat->pkt_source_ip, stanza_num, ztn_gpg_errstr(*ctx));
            return 0;
        }

        log_msg(LOG_INFO,
                "[%s] (stanza #%d) Incoming SPA data signed by '%s' (fingerprint '%s').",
                spadat->pkt_source_ip, stanza_num, gpg_id, gpg_fpr);

       /* 如果已配置，优先使用 GnuPG 指纹匹配*/

        if(acc->gpg_remote_fpr != NULL)
        {
            is_gpg_match = 0;
            for(gpg_fpr_ndx = acc->gpg_remote_fpr_list;
                    gpg_fpr_ndx != NULL; gpg_fpr_ndx=gpg_fpr_ndx->next)
            {
                *res = ztn_gpg_signature_fpr_match(*ctx,
                        gpg_fpr_ndx->str, &is_gpg_match);
                if(*res != ZTN_SUCCESS)
                {
                    log_msg(LOG_WARNING,
                        "[%s] (stanza #%d) Error in GPG signature comparison: %s",
                        spadat->pkt_source_ip, stanza_num, ztn_gpg_errstr(*ctx));
                    return 0;
                }
                if(is_gpg_match)
                    break;
            }
            if(! is_gpg_match)
            {
                log_msg(LOG_WARNING,
                    "[%s] (stanza #%d) Incoming SPA packet signed by: %s, but that fingerprint is not in the GPG_FINGERPRINT_ID list.",
                    spadat->pkt_source_ip, stanza_num, gpg_fpr);
                return 0;
            }
        }

        if(acc->gpg_remote_id != NULL)
        {
            is_gpg_match = 0;
            for(gpg_id_ndx = acc->gpg_remote_id_list;
                    gpg_id_ndx != NULL; gpg_id_ndx=gpg_id_ndx->next)
            {
                *res = ztn_gpg_signature_id_match(*ctx,
                        gpg_id_ndx->str, &is_gpg_match);
                if(*res != ZTN_SUCCESS)
                {
                    log_msg(LOG_WARNING,
                        "[%s] (stanza #%d) Error in GPG signature comparison: %s",
                        spadat->pkt_source_ip, stanza_num, ztn_gpg_errstr(*ctx));
                    return 0;
                }
                if(is_gpg_match)
                    break;
            }

            if(! is_gpg_match)
            {
                log_msg(LOG_WARNING,
                    "[%s] (stanza #%d) Incoming SPA packet signed by ID: %s, but that ID is not in the GPG_REMOTE_ID list.",
                    spadat->pkt_source_ip, stanza_num, gpg_id);
                return 0;
            }
        }
    }
    return 1;
}

static int
check_src_access(acc_stanza_t *acc, spa_data_t *spadat, const int stanza_num)
{
    if(strcmp(spadat->spa_message_src_ip, "0.0.0.0") == 0)
    {
        if(acc->require_source_address)
        {
            log_msg(LOG_WARNING,
                "[%s] (stanza #%d) Got 0.0.0.0 when valid source IP was required.",
                spadat->pkt_source_ip, stanza_num
            );
            return 0;
        }

        if (spadat->pkt_source_xff_ip[0] != '\0')
            spadat->use_src_ip = spadat->pkt_source_xff_ip;
        else
            spadat->use_src_ip = spadat->pkt_source_ip;
    }
    else
        spadat->use_src_ip = spadat->spa_message_src_ip;

    return 1;
}

static int
check_username(acc_stanza_t *acc, spa_data_t *spadat, const int stanza_num)
{
    if(acc->require_username != NULL)
    {
        if(strcmp(spadat->username, acc->require_username) != 0)
        {
            log_msg(LOG_WARNING,
                "[%s] (stanza #%d) Username in SPA data (%s) does not match required username: %s",
                spadat->pkt_source_ip, stanza_num, spadat->username, acc->require_username
            );
            return 0;
        }
    }
    return 1;
}

static int
check_nat_access_types(ztn_srv_options_t *opts, acc_stanza_t *acc,
        spa_data_t *spadat, const int stanza_num)
{
    int      not_enabled=0;

    if(spadat->message_type == ZTN_NAT_ACCESS_MSG
          || spadat->message_type == ZTN_CLIENT_TIMEOUT_NAT_ACCESS_MSG)
    {
#if FIREWALL_FIREWALLD
        if(strncasecmp(opts->config[CONF_ENABLE_FIREWD_FORWARDING], "Y", 1)!=0)
            not_enabled = 1;
#elif FIREWALL_IPTABLES
        if(strncasecmp(opts->config[CONF_ENABLE_IPT_FORWARDING], "Y", 1)!=0)
            not_enabled = 1;
#endif
    }
    else if(spadat->message_type == ZTN_LOCAL_NAT_ACCESS_MSG
          || spadat->message_type == ZTN_CLIENT_TIMEOUT_LOCAL_NAT_ACCESS_MSG)
    {
#if FIREWALL_FIREWALLD
        if(strncasecmp(opts->config[CONF_ENABLE_FIREWD_LOCAL_NAT], "Y", 1)!=0)
            not_enabled = 1;
#elif FIREWALL_IPTABLES
        if(strncasecmp(opts->config[CONF_ENABLE_IPT_LOCAL_NAT], "Y", 1)!=0)
            not_enabled = 1;
#endif
    }

    if(not_enabled)
    {
        log_msg(LOG_WARNING,
            "(stanza #%d) SPA packet from %s requested NAT access, but is not enabled/supported",
            stanza_num, spadat->pkt_source_ip
        );
        return 0;
    }
    return 1;
}

static int
add_replay_cache(ztn_srv_options_t *opts, acc_stanza_t *acc,
        spa_data_t *spadat, char *raw_digest, int *added_replay_digest,
        const int stanza_num, int *res)
{
    if (!opts->test && *added_replay_digest == 0
            && strncasecmp(opts->config[CONF_ENABLE_DIGEST_PERSISTENCE], "Y", 1) == 0)
    {

        *res = add_replay(opts, raw_digest);
        if (*res != SPA_MSG_SUCCESS)
        {
            log_msg(LOG_WARNING, "[%s] (stanza #%d) Could not add digest to replay cache",
                spadat->pkt_source_ip, stanza_num);
            return 0;
        }
        *added_replay_digest = 1;
    }

    return 1;
}

static void
set_timeout(acc_stanza_t *acc, spa_data_t *spadat)
{
    spadat->fw_access_timeout = DEF_FW_ACCESS_TIMEOUT;

    if(spadat->client_timeout > 0)
        if(acc->max_fw_timeout < spadat->client_timeout)
        {
            /* 
             * 不允许客户端请求超过最大允许的时间。
            */
            spadat->fw_access_timeout = acc->max_fw_timeout;
        }
        else
        {
            spadat->fw_access_timeout = spadat->client_timeout;
        }
    else if(acc->fw_access_timeout > 0)
        spadat->fw_access_timeout = acc->fw_access_timeout;

    return;
}

static int
check_port_proto(acc_stanza_t *acc, spa_data_t *spadat, const int stanza_num)
{
    if(! acc_check_port_access(acc, spadat->spa_message_remain))
    {
        log_msg(LOG_WARNING,
            "[%s] (stanza #%d) One or more requested protocol/ports was denied per access.conf.",
            spadat->pkt_source_ip, stanza_num
        );
        return 0;
    }
    return 1;
}


//处理spa数据包
void
incoming_spa(ztn_srv_options_t *opts)
{   
    //初始化总是一个好主意，如果它将被使用
    //重复（特别是使用ztn_new_with_data（））。
    
   
    ztn_ctx_t       ctx = NULL;

    char            *spa_ip_demark, *raw_digest = NULL;
    int             res, enc_type, stanza_num=0;
    int             added_replay_digest = 0;
    int             cmd_exec_success = 0, attempted_decrypt = 0;
    char            dump_buf[CTX_DUMP_BUFSIZE];

    spa_pkt_info_t *spa_pkt = &(opts->spa_pkt);

   
   //这将保存我们的相关SPA数据
    spa_data_t spadat;

    
   //循环遍历所有访问部分，寻找匹配
    acc_stanza_t        *acc = opts->acc_stanzas;

    //将网络地址从二进制转换为可读字符串形式的函数
    inet_ntop(AF_INET, &(spa_pkt->packet_src_ip),
        spadat.pkt_source_ip, sizeof(spadat.pkt_source_ip));

    inet_ntop(AF_INET, &(spa_pkt->packet_dst_ip),
        spadat.pkt_destination_ip, sizeof(spadat.pkt_destination_ip));

    
   //在这一点上，我们想要验证并（如果需要）预处理SPA数据和/或合理地确定我们是否有一个SPA数据包
//    （即尝试消除明显的非spa数据包）
    if(!precheck_pkt(opts, spa_pkt, &spadat, &raw_digest))
        return;

   //现在我们知道有一个匹配的access.conf部分和传入的SPA数据包不是重播，看看我们是否应该授予任何访问
    while(acc)
    {
        res = ZTN_SUCCESS;
        cmd_exec_success  = 0;
        attempted_decrypt = 0;
        stanza_num++;

        /* 
         * 使用一个干净的ZTN上下文开始访问循环
        */
        if(ctx != NULL)
        {
            if(ztn_destroy(ctx) == ZTN_ERROR_ZERO_OUT_DATA)
                log_msg(LOG_WARNING,
                    "[%s] (stanza #%d) ztn_destroy() could not zero out sensitive data buffer.",
                    spadat.pkt_source_ip, stanza_num
                );
            ctx = NULL;
        }

        /* 
         * 检查SPA源IP和目标IP以及访问段落的匹配情况。
        */
        if(! src_dst_check(acc, spa_pkt, &spadat, stanza_num))
        {
            acc = acc->next;
            continue;
        }

        log_msg(LOG_INFO,
            "(stanza #%d) SPA Packet from IP: %s received with access source match",
            stanza_num, spadat.pkt_source_ip);

        log_msg(LOG_DEBUG, "SPA Packet: '%s'", spa_pkt->packet_data);

        /* 
        */
       //保证这个访问部分没有过期
        if(! check_stanza_expiration(acc, &spadat, stanza_num))
        {
            acc = acc->next;
            continue;
        }

        /* 
         * 获取加密类型并首先尝试其解码例程（如果已设置该类型的密钥）
        */
        enc_type = ztn_encryption_type((char *)spa_pkt->packet_data);

        if(acc->use_rijndael)
            handle_rijndael_enc(acc, spa_pkt, &spadat, &ctx,
                        &attempted_decrypt, &cmd_exec_success, enc_type,
                        stanza_num, &res);

        if(! handle_gpg_enc(acc, spa_pkt, &spadat, &ctx, &attempted_decrypt,
                    cmd_exec_success, enc_type, stanza_num, &res))
        {
            acc = acc->next;
            continue;
        }

        if(! check_mode_ctx(&spadat, &ctx, attempted_decrypt,
                    enc_type, stanza_num, res))
        {
            acc = acc->next;
            continue;
        }

        
       // 如果我们没有在测试模式下运行，而且我们还没有添加这个摘要，那么就添加它。
        if(! add_replay_cache(opts, acc, &spadat, raw_digest,
                    &added_replay_digest, stanza_num, &res))
        {
            acc = acc->next;
            continue;
        }

        /* .
         * 在这一点上，SPA数据已通过HMAC（如果使用）进行身份验证。
         * 接下来，我们需要检查它是否满足我们的访问标准，这是服务器无论SPA数据包的内容都会强制执行的。
        */
        log_msg(LOG_DEBUG, "[%s] (stanza #%d) SPA Decode (res=%i):",
            spadat.pkt_source_ip, stanza_num, res);

        res = dump_ctx_to_buffer(ctx, dump_buf, sizeof(dump_buf));
        if (res == ZTN_SUCCESS)
            log_msg(LOG_DEBUG, "%s", dump_buf);
        else
            log_msg(LOG_WARNING, "Unable to dump ZTN context: %s", ztn_errstr(res));

        /* 
         * 首先，如果这是一条GPG消息，并且GPG_REMOTE_ID列表不为空，
         * 那么我们需要确保传入的消息签名者ID与列表中的某个条目匹配。
        */

        if(! handle_gpg_sigs(acc, &spadat, &ctx, enc_type, stanza_num, &res))
        {
            acc = acc->next;
            continue;
        }

        /* 
        * 为将来的参考，填充我们的spa数据结构。
        */
        res = get_spa_data_fields(ctx, &spadat);

        if(res != ZTN_SUCCESS)
        {
            log_msg(LOG_ERR,
                "[%s] (stanza #%d) Unexpected error pulling SPA data from the context: %s",
                spadat.pkt_source_ip, stanza_num, ztn_errstr(res));

            acc = acc->next;
            continue;
        }

        /* 
         * 确定我们的超时时间将会是多少。如果在SPA数据中指定了超时时间，那么使用该值。
         * 如果没有指定，尝试使用access.conf文件中的FW_ACCESS_TIMEOUT（如果存在）。
         * 否则，使用默认超时时间。
        */
        set_timeout(acc, &spadat);

        /* 
         * 如果已配置，则检查数据包的年龄。
        */
        if(! check_pkt_age(opts, &spadat, stanza_num))
        {
            acc = acc->next;
            continue;
        }

        /* 
         * 此时，我们已经具备足够的信息来检查嵌入（或数据包源）的IP地址是否符合定义的访问权限。
         * 我们首先从消息中分离SPA消息源IP地址和其余部分。
        */
        spa_ip_demark = strchr(spadat.spa_message, ',');
        if(spa_ip_demark == NULL)
        {
            log_msg(LOG_WARNING,
                "[%s] (stanza #%d) Error parsing SPA message string: %s",
                spadat.pkt_source_ip, stanza_num, ztn_errstr(res));

            acc = acc->next;
            continue;
        }

        if((spa_ip_demark-spadat.spa_message) < MIN_IPV4_STR_LEN-1
                || (spa_ip_demark-spadat.spa_message) > MAX_IPV4_STR_LEN)
        {
            log_msg(LOG_WARNING,
                "[%s] (stanza #%d) Invalid source IP in SPA message, ignoring SPA packet",
                spadat.pkt_source_ip, stanza_num);
            break;
        }

        strlcpy(spadat.spa_message_src_ip,
            spadat.spa_message, (spa_ip_demark-spadat.spa_message)+1);

        if(! is_valid_ipv4_addr(spadat.spa_message_src_ip, strlen(spadat.spa_message_src_ip)))
        {
            log_msg(LOG_WARNING,
                "[%s] (stanza #%d) Invalid source IP in SPA message, ignoring SPA packet",
                spadat.pkt_source_ip, stanza_num, ztn_errstr(res));
            break;
        }

        strlcpy(spadat.spa_message_remain, spa_ip_demark+1, MAX_DECRYPTED_SPA_LEN);

        /* 
         * 如果请求使用源IP地址（嵌入IP地址为0.0.0.0），确保它是被允许的。
        */
        if(! check_src_access(acc, &spadat, stanza_num))
        {
            acc = acc->next;
            continue;
        }

        /* 
         * 如果设置了REQUIRE_USERNAME，请确保此SPA数据中的用户名匹配。
        */
        if(! check_username(acc, &spadat, stanza_num))
        {
            acc = acc->next;
            continue;
        }

       /* 根据 SPA 消息类型采取行动。
*/
if (!check_nat_access_types(opts, acc, &spadat, stanza_num))
{
    acc = acc->next;
    continue;
}

/* 命令消息。
*/
if (acc->cmd_cycle_open != NULL)
{
    if (cmd_cycle_open(opts, acc, &spadat, stanza_num, &res))
        break; /* 成功处理了匹配的访问部分。*/
    else
    {
        acc = acc->next;
        continue;
   }
}

        else if(spadat.message_type == ZTN_COMMAND_MSG)
        {
            if(process_cmd_msg(opts, acc, &spadat, stanza_num, &res))
            {
                /* 
                 * 我们已经在匹配的访问部分上处理了命令，因此不需要再查找与此SPA数据包有关的其他操作。
                */
                break;
            }
            else
            {
                acc = acc->next;
                continue;
            }
        }
        /*
         * 从这一点开始，我们有某种类型的访问消息。
         * 因此，我们首先通过检查访问权限来查看是否允许访问，
         * 这是通过与restrict_ports和open_ports进行比较来完成的。
         *
         *  --DSS TODO: We should add BLACKLIST support here as well.
        */
        if(! check_port_proto(acc, &spadat, stanza_num))
        {
            acc = acc->next;
            continue;
        }

        /* 
         * 在这一点上，我们处理SPA请求并跳出访问部分循环（第一个有效的访问部分停止我们查找其他的）。
        */
        if(opts->test)   //在测试模式下没有防火墙更改
        {
            log_msg(LOG_WARNING,
                "[%s] (stanza #%d) --test mode enabled, skipping firewall manipulation.",
                spadat.pkt_source_ip, stanza_num
            );
            acc = acc->next;
            continue;
        }
        else
        {
            if(acc->cmd_cycle_open != NULL)
            {
                if(cmd_cycle_open(opts, acc, &spadat, stanza_num, &res))
                    break; // 成功处理了匹配的访问部分。
                else
                {
                    acc = acc->next;
                    continue;
                }
            }
            else
            {
                process_spa_request(opts, acc, &spadat);
            }
        }

        /* 
         * 如果我们执行到了这一步，那么SPA数据包已根据匹配的access.conf访问部分进行处理，因此我们已完成了对这个数据包的处理。
        */
        break;
    }

    if (raw_digest != NULL)
        free(raw_digest);

    if(ctx != NULL)
    {
        if(ztn_destroy(ctx) == ZTN_ERROR_ZERO_OUT_DATA)
            log_msg(LOG_WARNING,
                "[%s] (stanza #%d) ztn_destroy() could not zero out sensitive data buffer.",
                spadat.pkt_source_ip, stanza_num
            );
        ctx = NULL;
    }

    return;
}

/***EOF***/
