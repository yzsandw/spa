/**
 * \file server/access.c
 *
 * \brief fwknop服务的Access.conf文件处理
 */

#if HAVE_SYS_SOCKET_H
  #include <sys/socket.h>
#endif

#include "fwknopd_common.h"
#include <arpa/inet.h>
#include "pwd.h"
#include "access.h"
#include "utils.h"
#include "log_msg.h"
#include "cmd_cycle.h"
#include <dirent.h>

#define FATAL_ERR -1

#ifndef SUCCESS
  #define SUCCESS    1
#endif

#ifdef HAVE_C_UNIT_TESTS /* LCOV_EXCL_START */
  #include "cunit_common.h"
  DECLARE_TEST_SUITE(access, "Access test suite");
#endif /* LCOV_EXCL_STOP */

/**
 * \brief 包含密钥文件
 *
 * 此函数仅从给定文件加载加密密钥。
 * 它将这些键插入到活动访问节中。
 *
 * \param curr_acc 指向当前访问节的指针
 * \param access_filename 指向包含密钥的文件的指针
 * \param opts fko_srv_options_t 服务器选项结构
 *
 */
int
include_keys_file(acc_stanza_t *, const char *, fko_srv_options_t *);

static int do_acc_stanza_init = 1;

void enable_acc_stanzas_init(void)
{
    do_acc_stanza_init = 1;
    return;
}

/* 添加一个访问字符串条目
*/
static void
add_acc_string(char **var, const char *val, FILE *file_ptr,
        fko_srv_options_t *opts)
{
    if(var == NULL)
    {
        log_msg(LOG_ERR, "[*] add_acc_string() called with NULL variable");
        if(file_ptr != NULL)
            fclose(file_ptr);
        clean_exit(opts, NO_FW_CLEANUP, EXIT_FAILURE);
    }

    if(*var != NULL)
        free(*var);

    if((*var = strdup(val)) == NULL)
    {
        log_msg(LOG_ERR,
            "[*] Fatal memory allocation error adding access list entry: %s", *var
        );
        if(file_ptr != NULL)
            fclose(file_ptr);
        clean_exit(opts, NO_FW_CLEANUP, EXIT_FAILURE);
    }
    return;
}

/* 添加一个访问用户表项
*/
static void
add_acc_user(char **user_var, uid_t *uid_var, struct passwd **upw,
        const char *val, const char *var_name, FILE *file_ptr,
        fko_srv_options_t *opts)
{
    struct passwd  *pw = NULL;

    add_acc_string(user_var, val, file_ptr, opts);

    errno = 0;
    *upw = pw = getpwnam(val);

    if(*upw == NULL || pw == NULL)
    {
        log_msg(LOG_ERR, "[*] Unable to determine UID for %s: %s.",
                var_name, errno ? strerror(errno) : "Not a user on this system");
        fclose(file_ptr);
        clean_exit(opts, NO_FW_CLEANUP, EXIT_FAILURE);
    }

    *uid_var = pw->pw_uid;

    return;
}

/* 添加访问组项
*/
static void
add_acc_group(char **group_var, gid_t *gid_var,
        const char *val, const char *var_name, FILE *file_ptr,
        fko_srv_options_t *opts)
{
    struct passwd  *pw = NULL;

    add_acc_string(group_var, val, file_ptr, opts);

    errno = 0;
    pw = getpwnam(val);

    if(pw == NULL)
    {
        log_msg(LOG_ERR, "[*] Unable to determine GID for %s: %s.",
                var_name, errno ? strerror(errno) : "Not a group on this system");
        fclose(file_ptr);
        clean_exit(opts, NO_FW_CLEANUP, EXIT_FAILURE);
    }

    *gid_var = pw->pw_gid;

    return;
}

/* 将 Base64 编码字符串解码为访问条目
*/
static void
add_acc_b64_string(char **var, int *len, const char *val, FILE *file_ptr,
        fko_srv_options_t *opts)
{
    if(var == NULL)
    {
        log_msg(LOG_ERR, "[*] add_acc_b64_string() called with NULL variable");
        if(file_ptr != NULL)
            fclose(file_ptr);
        clean_exit(opts, NO_FW_CLEANUP, EXIT_FAILURE);
    }

    if(*var != NULL)
        free(*var);

    if((*var = strdup(val)) == NULL)
    {
        log_msg(LOG_ERR,
            "[*] Fatal memory allocation error adding access list entry: %s", *var
        );
        if(file_ptr != NULL)
            fclose(file_ptr);
        clean_exit(opts, NO_FW_CLEANUP, EXIT_FAILURE);
    }
    memset(*var, 0x0, strlen(val));
    *len = fko_base64_decode(val, (unsigned char *) *var);

    if (*len < 0)
    {
        log_msg(LOG_ERR,
            "[*] base64 decoding returned error for: %s", *var
        );
        if(file_ptr != NULL)
            fclose(file_ptr);
        clean_exit(opts, NO_FW_CLEANUP, EXIT_FAILURE);
    }
    return;
}

/* 添加访问布尔项（1或0的无符号字符）
*/
static unsigned char
add_acc_bool(unsigned char *var, const char *val)
{
    return(*var = (strncasecmp(val, "Y", 1) == 0) ? 1 : 0);
}

/* 添加过期时间-将日期转换为epoch seconds
*/
static int
add_acc_expire_time(fko_srv_options_t *opts, time_t *access_expire_time, const char *val)
{
    struct tm tm;

    memset(&tm, 0, sizeof(struct tm));

    if (sscanf(val, "%2d/%2d/%4d", &tm.tm_mon, &tm.tm_mday, &tm.tm_year) != 3)
    {

        log_msg(LOG_ERR,
            "[*] Fatal: invalid date value '%s' (need MM/DD/YYYY) for access stanza expiration time",
            val
        );
        return FATAL_ERR;
    }

    if(tm.tm_mon > 0)
        tm.tm_mon -= 1;  /* 0-11 */

    /* number of years since 1900
    */
    if(tm.tm_year > 1900)
        tm.tm_year -= 1900;
    else
        if(tm.tm_year < 100)
            tm.tm_year += 100;

    *access_expire_time = mktime(&tm);

    return 1;
}

/* 通过access.conf中定义的epoch seconds添加过期时间
*/
static void
add_acc_expire_time_epoch(fko_srv_options_t *opts,
        time_t *access_expire_time, const char *val, FILE *file_ptr)
{
    char *endptr;
    unsigned long expire_time = 0;

    errno = 0;

    expire_time = (time_t) strtoul(val, &endptr, 10);

    if (errno == ERANGE || (errno != 0 && expire_time == 0))
    {
        log_msg(LOG_ERR,
            "[*] Fatal: invalid epoch seconds value '%s' for access stanza expiration time",
            val
        );
        fclose(file_ptr);
        clean_exit(opts, NO_FW_CLEANUP, EXIT_FAILURE);
    }

    *access_expire_time = (time_t) expire_time;

    return;
}

#if defined(FIREWALL_FIREWALLD) || defined(FIREWALL_IPTABLES)
static void
add_acc_force_nat(fko_srv_options_t *opts, acc_stanza_t *curr_acc,
        const char *val, FILE *file_ptr)
{
    char      ip_str[MAX_IPV4_STR_LEN] = {0};

    if (sscanf(val, "%15s %5u", ip_str, &curr_acc->force_nat_port) != 2)
    {
        log_msg(LOG_ERR,
            "[*] Fatal: invalid FORCE_NAT arg '%s', need <IP> <PORT>",
            val
        );
        if(file_ptr != NULL)
            fclose(file_ptr);
        clean_exit(opts, NO_FW_CLEANUP, EXIT_FAILURE);
    }

    if (curr_acc->force_nat_port > MAX_PORT)
    {
        log_msg(LOG_ERR,
            "[*] Fatal: invalid FORCE_NAT port '%d'", curr_acc->force_nat_port);
        if(file_ptr != NULL)
            fclose(file_ptr);
        clean_exit(opts, NO_FW_CLEANUP, EXIT_FAILURE);
    }

    if(! is_valid_ipv4_addr(ip_str, strlen(ip_str)))
    {
        log_msg(LOG_ERR,
            "[*] Fatal: invalid FORCE_NAT IP '%s'", ip_str);
        if(file_ptr != NULL)
            fclose(file_ptr);
        clean_exit(opts, NO_FW_CLEANUP, EXIT_FAILURE);
    }

    curr_acc->force_nat = 1;

    add_acc_string(&(curr_acc->force_nat_ip), ip_str, file_ptr, opts);
    return;
}

static void
add_acc_force_snat(fko_srv_options_t *opts, acc_stanza_t *curr_acc,
        const char *val, FILE *file_ptr)
{
    char      ip_str[MAX_IPV4_STR_LEN] = {0};

    if (sscanf(val, "%15s", ip_str) != 1)
    {
        log_msg(LOG_ERR,
                "[*] Fatal: invalid FORCE_SNAT arg '%s', need <IP>", val);
        if(file_ptr != NULL)
            fclose(file_ptr);
        clean_exit(opts, NO_FW_CLEANUP, EXIT_FAILURE);
    }

    if(! is_valid_ipv4_addr(ip_str, strlen(ip_str)))
    {
        log_msg(LOG_ERR,
            "[*] Fatal: invalid FORCE_SNAT IP '%s'", ip_str);
        if(file_ptr != NULL)
            fclose(file_ptr);
        clean_exit(opts, NO_FW_CLEANUP, EXIT_FAILURE);
    }

    curr_acc->force_snat = 1;

    add_acc_string(&(curr_acc->force_snat_ip), ip_str, file_ptr, opts);
    return;
}

#endif

/* 获取IP或子网/掩码，并将其转换为掩码供以后使。
 * 传入源IP与此掩码的比较。
*/
static int
add_int_ent(acc_int_list_t **ilist, const char *ip)
{
    char                *ndx;
    char                ip_str[MAX_IPV4_STR_LEN] = {0};
    char                ip_mask_str[MAX_IPV4_STR_LEN] = {0};
    uint32_t            mask;
    int                 is_err, mask_len = 0, need_shift = 1;

    struct in_addr      in;
    struct in_addr      mask_in;

    acc_int_list_t      *last_sle, *new_sle, *tmp_sle;

    if((new_sle = calloc(1, sizeof(acc_int_list_t))) == NULL)
    {
        log_msg(LOG_ERR,
            "[*] Fatal memory allocation error adding stanza source_list entry"
        );
        exit(EXIT_FAILURE);
    }

    /* 将IP数据转换为适当的IP+（可选）掩码
    */
    if(strcasecmp(ip, "ANY") == 0)
    {
        new_sle->maddr = 0x0;
        new_sle->mask = 0x0;
    }
    else
    {
        /* 看看我们是否有子网组件。如果是这样，则拉出IP和掩码值，然后创建最终的掩码值
        */
        if((ndx = strchr(ip, '/')) != NULL)
        {
            if(((ndx-ip)) >= MAX_IPV4_STR_LEN)
            {
                log_msg(LOG_ERR, "[*] Error parsing string to IP");
                free(new_sle);
                new_sle = NULL;
                return 0;
            }

            mask_len = strlen(ip) - (ndx-ip+1);

            if(mask_len > 2)
            {
                if(mask_len >= MIN_IPV4_STR_LEN && mask_len < MAX_IPV4_STR_LEN)
                {
                    /* IP formatted mask
                    */
                    strlcpy(ip_mask_str, (ip + (ndx-ip) + 1), mask_len+1);
                    if(inet_aton(ip_mask_str, &mask_in) == 0)
                    {
                        log_msg(LOG_ERR,
                            "[*] Fatal error parsing IP mask to int for: %s", ip_mask_str
                        );
                        free(new_sle);
                        new_sle = NULL;
                        return 0;
                    }
                    mask = ntohl(mask_in.s_addr);
                    need_shift = 0;
                }
                else
                {
                    log_msg(LOG_ERR, "[*] Invalid IP mask str '%s'.", ndx+1);
                    free(new_sle);
                    new_sle = NULL;
                    return 0;
                }
            }
            else
            {
                if(mask_len > 0)
                {
                    /* CIDR mask
                    */
                    mask = strtol_wrapper(ndx+1, 1, 32, NO_EXIT_UPON_ERR, &is_err);
                    if(is_err != FKO_SUCCESS)
                    {
                        log_msg(LOG_ERR, "[*] Invalid IP mask str '%s'.", ndx+1);
                        free(new_sle);
                        new_sle = NULL;
                        return 0;
                    }
                }
                else
                {
                    log_msg(LOG_ERR, "[*] Missing mask value.");
                    free(new_sle);
                    new_sle = NULL;
                    return 0;
                }
            }

            strlcpy(ip_str, ip, (ndx-ip)+1);
        }
        else
        {
            mask = 32;
            if(strnlen(ip, MAX_IPV4_STR_LEN+1) >= MAX_IPV4_STR_LEN)
            {
                log_msg(LOG_ERR, "[*] Error parsing string to IP");
                free(new_sle);
                new_sle = NULL;
                return 0;
            }
            strlcpy(ip_str, ip, sizeof(ip_str));
        }

        if(inet_aton(ip_str, &in) == 0)
        {
            log_msg(LOG_ERR,
                "[*] Fatal error parsing IP to int for: %s", ip_str
            );

            free(new_sle);
            new_sle = NULL;

            return 0;
        }

        /* 将 CIDR（Classless Inter-Domain Routing）转换为一个32位的数值，并存储起来
        */
        if(mask == 32)
            new_sle->mask = 0xFFFFFFFF;
        else if(need_shift && (mask > 0 && mask < 32))
            new_sle->mask = (0xFFFFFFFF << (32 - mask));
        else
            new_sle->mask = mask;

        /* 存储我们的屏蔽地址，以便与以后传入的数据包进行比较
        */
        new_sle->maddr = ntohl(in.s_addr) & new_sle->mask;
    }

    /* 如果这不是第一个条目，则将指针移到列表的末尾
    */
    if(*ilist == NULL)
    {
        *ilist = new_sle;
    }
    else
    {
        tmp_sle = *ilist;

        do {
            last_sle = tmp_sle;
        } while((tmp_sle = tmp_sle->next));

        last_sle->next = new_sle;
    }

    return 1;
}

/* 将访问源字符串展开为掩码列表
*/
static int
expand_acc_int_list(acc_int_list_t **ilist, char *ip)
{
    char           *ndx, *start;
    char            buf[ACCESS_BUF_LEN] = {0};
    int             res = 1;

    start = ip;

    for(ndx = start; *ndx; ndx++)
    {
        if(*ndx == ',')
        {
            /* Skip over any leading whitespace.
            */
            while(isspace((int)(unsigned char)*start))
                start++;

            if(((ndx-start)+1) >= ACCESS_BUF_LEN)
                return 0;

            strlcpy(buf, start, (ndx-start)+1);

            res = add_int_ent(ilist, buf);
            if(res == 0)
                return res;

            start = ndx+1;
        }
    }

    /* 跳过任何前导空格（再次为列表中的最后一个）
    */
    while(isspace((int)(unsigned char)*start))
        start++;

    if(((ndx-start)+1) >= ACCESS_BUF_LEN)
        return 0;

    strlcpy(buf, start, (ndx-start)+1);

    res = add_int_ent(ilist, buf);

    return res;
}

static int
parse_proto_and_port(char *pstr, int *proto, int *port)
{
    char    *ndx;
    char    proto_str[ACCESS_BUF_LEN] = {0};
    int     is_err;

    /* 将字符串解析为其组件
    */
    if((ndx = strchr(pstr, '/')) == NULL)
    {
        log_msg(LOG_ERR,
            "[*] Parse error on access port entry: %s", pstr);

        return(-1);
    }

    if(((ndx - pstr)+1) >= ACCESS_BUF_LEN)
    {
        log_msg(LOG_ERR,
            "[*] Parse error on access port entry: %s", pstr);
        return(-1);
    }

    strlcpy(proto_str, pstr, (ndx - pstr)+1);

    *port = strtol_wrapper(ndx+1, 0, MAX_PORT, NO_EXIT_UPON_ERR, &is_err);
    if(is_err != FKO_SUCCESS)
    {
        log_msg(LOG_ERR,
            "[*] Invalid port '%s' in access request, must be in [%d,%d]",
            pstr, 0, MAX_PORT);
        return(-1);
    }

    if(strcasecmp(proto_str, "tcp") == 0)
        *proto = PROTO_TCP;
    else if(strcasecmp(proto_str, "udp") == 0)
        *proto = PROTO_UDP;
    else
    {
        log_msg(LOG_ERR,
            "[*] Invalid protocol in access port entry: %s", pstr);
        return(-1);
    }

    return(0);
}

/* 获取proto/port字符串并将其转换为适当的整数值
 *用于比较传入的SPA请求。
*/
static int
add_port_list_ent(acc_port_list_t **plist, char *port_str)
{
    int                 proto_int, port;

    acc_port_list_t     *last_plist, *new_plist, *tmp_plist;

    /* 将字符串解析为其组件，并仅在传入字符串没有问题时继续
    */
    if(parse_proto_and_port(port_str, &proto_int, &port) != 0)
        return 0;

    if((new_plist = calloc(1, sizeof(acc_port_list_t))) == NULL)
    {
        log_msg(LOG_ERR,
            "[*] Fatal memory allocation error adding stanza port_list entry"
        );
        exit(EXIT_FAILURE);
    }

    /* 如果这不是第一个条目，则将指针移到列表的末尾。
    */
    if(*plist == NULL)
    {
        *plist = new_plist;
    }
    else
    {
        tmp_plist = *plist;

        do {
            last_plist = tmp_plist;
        } while((tmp_plist = tmp_plist->next));

        last_plist->next = new_plist;
    }

    new_plist->proto = proto_int;
    new_plist->port  = port;

    return 1;
}

/* 将字符串列表条目添加到给定的acc_string_list
*/
static int
add_string_list_ent(acc_string_list_t **stlist, const char *str_str)
{
    acc_string_list_t   *last_stlist, *new_stlist, *tmp_stlist;

    if((new_stlist = calloc(1, sizeof(acc_string_list_t))) == NULL)
    {
        log_msg(LOG_ERR,
            "[*] Fatal memory allocation error creating string list entry"
        );
        return FATAL_ERR;
    }

    /* 如果这不是第一个条目，则将指针移到列表的末尾。
    */
    if(*stlist == NULL)
    {
        *stlist = new_stlist;
    }
    else
    {
        tmp_stlist = *stlist;

        do {
            last_stlist = tmp_stlist;
        } while((tmp_stlist = tmp_stlist->next));

        last_stlist->next = new_stlist;
    }

    if(new_stlist->str != NULL)
        free(new_stlist->str);

    new_stlist->str = strdup(str_str);

    if(new_stlist->str == NULL)
    {
        log_msg(LOG_ERR,
            "[*] Fatal memory allocation error adding string list entry item"
        );
        return FATAL_ERR;
    }
    return SUCCESS;
}

/* 将协议/端口访问字符串展开为访问协议端口结构的列表
*/
int
expand_acc_port_list(acc_port_list_t **plist, char *plist_str)
{
    char           *ndx, *start;
    char            buf[ACCESS_BUF_LEN] = {0};

    start = plist_str;

    for(ndx = start; *ndx != '\0'; ndx++)
    {
        if(*ndx == ',')
        {
            /* 跳过任何前导空格
            */
            while(isspace((int)(unsigned char)*start))
                start++;

            if(((ndx-start)+1) >= ACCESS_BUF_LEN)
                return 0;

            strlcpy(buf, start, (ndx-start)+1);

            if(add_port_list_ent(plist, buf) == 0)
                return 0;

            start = ndx+1;
        }
    }

    /* 跳过任何前导空格（再次为列表中的最后一个）
    */
    while(isspace((int)(unsigned char)*start))
        start++;

    if(((ndx-start)+1) >= ACCESS_BUF_LEN)
        return 0;

    strlcpy(buf, start, (ndx-start)+1);

    if(add_port_list_ent(plist, buf) == 0)
        return 0;

    return 1;
}

/* 将逗号分隔的字符串展开为简单的acc_string_list。
*/
static int
expand_acc_string_list(acc_string_list_t **stlist, char *stlist_str)
{
    char           *ndx, *start;
    char            buf[MAX_LINE_LEN] = {0};

    start = stlist_str;

    for(ndx = start; *ndx; ndx++)
    {
        if(*ndx == ',')
        {
            /* 跳过任何前导空格
            */
            while(isspace((int)(unsigned char)*start))
                start++;

            if(((ndx-start)+1) >= MAX_LINE_LEN)
                return FATAL_ERR;

            strlcpy(buf, start, (ndx-start)+1);
            if(add_string_list_ent(stlist, buf) != SUCCESS)
                return FATAL_ERR;

            start = ndx+1;
        }
    }

    /* 跳过任何前导空格（再次为列表中的最后一个）
    */
    while(isspace((int)(unsigned char)*start))
        start++;

    if(((ndx-start)+1) >= MAX_LINE_LEN)
        return FATAL_ERR;

    strlcpy(buf, start, (ndx-start)+1);

    if(add_string_list_ent(stlist, buf) != SUCCESS)
        return FATAL_ERR;

    return SUCCESS;
}

/* 释放acc source_list
*/
static void
free_acc_int_list(acc_int_list_t *sle)
{
    acc_int_list_t    *last_sle;

    while(sle != NULL)
    {
        last_sle = sle;
        sle = last_sle->next;

        free(last_sle);
    }
}

/* 释放port_list
*/
void
free_acc_port_list(acc_port_list_t *ple)
{
    acc_port_list_t    *last_ple;

    while(ple != NULL)
    {
        last_ple = ple;
        ple = last_ple->next;

        free(last_ple);
    }
}

/* 释放一个string_list
*/
static void
free_acc_string_list(acc_string_list_t *stl)
{
    acc_string_list_t    *last_stl;

    while(stl != NULL)
    {
        last_stl = stl;
        stl = last_stl->next;

        free(last_stl->str);
        free(last_stl);
    }
}

static void
zero_buf_wrapper(char *buf, int len)
{

    if(zero_buf(buf, len) != FKO_SUCCESS)
        log_msg(LOG_ERR,
                "[*] Could not zero out sensitive data buffer.");

    return;
}

/* 释放访问节的任何已分配的内容
 * 注意：如果创建了新的access.conf参数，并且它是一个字符串值，则还需要将其添加到项目列表中以在下面进行检查和释放
*/
static void
free_acc_stanza_data(acc_stanza_t *acc)
{

    if(acc->source != NULL)
    {
        free(acc->source);
        free_acc_int_list(acc->source_list);
    }

    if(acc->destination != NULL)
    {
        free(acc->destination);
        free_acc_int_list(acc->destination_list);
    }

    if(acc->open_ports != NULL)
    {
        free(acc->open_ports);
        free_acc_port_list(acc->oport_list);
    }

    if(acc->restrict_ports != NULL)
    {
        free(acc->restrict_ports);
        free_acc_port_list(acc->rport_list);
    }

    if(acc->force_nat_ip != NULL)
        free(acc->force_nat_ip);

    if(acc->force_snat_ip != NULL)
        free(acc->force_snat_ip);

    if(acc->key != NULL)
    {
        zero_buf_wrapper(acc->key, acc->key_len);
        free(acc->key);
    }

    if(acc->key_base64 != NULL)
    {
        zero_buf_wrapper(acc->key_base64, strlen(acc->key_base64));
        free(acc->key_base64);
    }

    if(acc->hmac_key != NULL)
    {
        zero_buf_wrapper(acc->hmac_key, acc->hmac_key_len);
        free(acc->hmac_key);
    }

    if(acc->hmac_key_base64 != NULL)
    {
        zero_buf_wrapper(acc->hmac_key_base64, strlen(acc->hmac_key_base64));
        free(acc->hmac_key_base64);
    }

    if(acc->cmd_sudo_exec_user != NULL)
        free(acc->cmd_sudo_exec_user);

    if(acc->cmd_sudo_exec_group != NULL)
        free(acc->cmd_sudo_exec_group);

    if(acc->cmd_exec_user != NULL)
        free(acc->cmd_exec_user);

    if(acc->cmd_exec_group != NULL)
        free(acc->cmd_exec_group);

    if(acc->require_username != NULL)
        free(acc->require_username);

    if(acc->cmd_cycle_open != NULL)
        free(acc->cmd_cycle_open);

    if(acc->cmd_cycle_close != NULL)
        free(acc->cmd_cycle_close);

    if(acc->gpg_home_dir != NULL)
        free(acc->gpg_home_dir);

    if(acc->gpg_exe != NULL)
        free(acc->gpg_exe);

    if(acc->gpg_decrypt_id != NULL)
        free(acc->gpg_decrypt_id);

    if(acc->gpg_decrypt_pw != NULL)
        free(acc->gpg_decrypt_pw);

    if(acc->gpg_remote_id != NULL)
    {
        free(acc->gpg_remote_id);
        free_acc_string_list(acc->gpg_remote_id_list);
    }
    if(acc->gpg_remote_fpr != NULL)
    {
        free(acc->gpg_remote_fpr);
        free_acc_string_list(acc->gpg_remote_fpr_list);
    }
    return;
}

/* 展开可能是多值的任何访问条目
*/
static void
expand_acc_ent_lists(fko_srv_options_t *opts)
{
    acc_stanza_t   *acc = opts->acc_stanzas;

    /* 需要每个小节都这样做
    */
    while(acc)
    {
        /* 将源字符串扩展为每个条目的32位整数IP+掩码
        */
        if(expand_acc_int_list(&(acc->source_list), acc->source) == 0)
        {
            log_msg(LOG_ERR, "[*] Fatal invalid SOURCE in access stanza");
            clean_exit(opts, NO_FW_CLEANUP, EXIT_FAILURE);
        }

        if(acc->destination != NULL && strlen(acc->destination))
        {
            if(expand_acc_int_list(&(acc->destination_list), acc->destination) == 0)
            {
                log_msg(LOG_ERR, "[*] Fatal invalid DESTINATION in access stanza");
                clean_exit(opts, NO_FW_CLEANUP, EXIT_FAILURE);
            }
        }

        /* 现在展开open_ports字符串
        */
        if(acc->open_ports != NULL && strlen(acc->open_ports))
        {
            if(expand_acc_port_list(&(acc->oport_list), acc->open_ports) == 0)
            {
                log_msg(LOG_ERR, "[*] Fatal invalid OPEN_PORTS in access stanza");
                clean_exit(opts, NO_FW_CLEANUP, EXIT_FAILURE);
            }
        }

        if(acc->restrict_ports != NULL && strlen(acc->restrict_ports))
        {
            if(expand_acc_port_list(&(acc->rport_list), acc->restrict_ports) == 0)
            {
                log_msg(LOG_ERR, "[*] Fatal invalid RESTRICT_PORTS in access stanza");
                clean_exit(opts, NO_FW_CLEANUP, EXIT_FAILURE);
            }
        }

        /* 展开GPG_REMOTE_ID字符串
        */
        if(acc->gpg_remote_id != NULL && strlen(acc->gpg_remote_id))
        {
            if(expand_acc_string_list(&(acc->gpg_remote_id_list),
                        acc->gpg_remote_id) != SUCCESS)
            {
                log_msg(LOG_ERR, "[*] Fatal invalid GPG_REMOTE_ID list in access stanza");
                clean_exit(opts, NO_FW_CLEANUP, EXIT_FAILURE);
            }
        }

        /* 展开GPG_FINGERPRINT_ID字符串
        */
        if(acc->gpg_remote_fpr != NULL && strlen(acc->gpg_remote_fpr))
        {
            if(expand_acc_string_list(&(acc->gpg_remote_fpr_list),
                        acc->gpg_remote_fpr) != SUCCESS)
            {
                log_msg(LOG_ERR, "[*] Fatal invalid GPG_FINGERPRINT_ID list in access stanza");
                clean_exit(opts, NO_FW_CLEANUP, EXIT_FAILURE);
            }
        }

        acc = acc->next;
    }
    return;
}

void
free_acc_stanzas(fko_srv_options_t *opts)
{
    acc_stanza_t    *acc, *last_acc;

    /* 首先释放所有资源（在重新配置的情况下）。假设需要释放非NULL条目
    */
    acc = opts->acc_stanzas;

    while(acc != NULL)
    {
        last_acc = acc;
        acc = last_acc->next;

        free_acc_stanza_data(last_acc);
        free(last_acc);
    }

    return;
}

/**
 * \brief 释放最终访问节
 *
 * 该函数遍历访问节列表并释放最后一个成员
 *
 * \param opts 指向服务器选项结构的指针
 *
 */

void
free_last_acc_stanza(fko_srv_options_t *opts)
{
    acc_stanza_t *tmp_root = opts->acc_stanzas;

    //首先处理边缘情况，如空列表
    if (tmp_root == NULL)
        return;

    //仅检查一个元素
    if (tmp_root->next == NULL)
    {
        free_acc_stanza_data(tmp_root);
        free(tmp_root);
        opts->acc_stanzas = NULL;
        return;
    }

    //当是多个元素时使用一般情况
    while (tmp_root->next->next != NULL)
    {
        tmp_root = tmp_root->next;
    }

    free_acc_stanza_data(tmp_root->next);
    free(tmp_root->next);
    tmp_root->next = NULL;
    return;
}

/* free_acc_stanzas（）的包装器，可以在这里放置额外的初始化代码。
*/
static void
acc_stanza_init(fko_srv_options_t *opts)
{
    if(do_acc_stanza_init)
    {
        log_msg(LOG_DEBUG, "Initialize access stanzas");

        /* 首先释放所有资源（在重新配置的情况下）。假设需要释放非NULL条目
        */
        free_acc_stanzas(opts);

        /* 确保仅初始化访问节一次。
        */
        do_acc_stanza_init = 0;
    }

    return;
}

/* 添加一个新的节区，在所需的位置分配所需的内存地点
*/
static acc_stanza_t*
acc_stanza_add(fko_srv_options_t *opts)
{
    acc_stanza_t    *acc     = opts->acc_stanzas;
    acc_stanza_t    *new_acc = calloc(1, sizeof(acc_stanza_t));
    acc_stanza_t    *last_acc;

    if(new_acc == NULL)
    {
        log_msg(LOG_ERR,
            "[*] Fatal memory allocation error adding access stanza"
        );
        clean_exit(opts, NO_FW_CLEANUP, EXIT_FAILURE);
    }

    /* 如果这不是第一个acc条目，则将acc指针移到现有列表的末尾
    */
    if(acc == NULL)
    {
        opts->acc_stanzas = new_acc;
    }
    else
    {
        do {
            last_acc = acc;
        } while((acc = acc->next));

        last_acc->next = new_acc;
    }

    return(new_acc);
}

/* 扫描尚未设置但需要默认值的条目的访问选项。
*/
static void
set_acc_defaults(fko_srv_options_t *opts)
{
    acc_stanza_t    *acc = opts->acc_stanzas;
    int              i=1;

    if(!acc)
        return;

    while(acc)
    {
        /* 必要时设置默认fw_access_timeout
        */
        if(acc->fw_access_timeout < 1)
            acc->fw_access_timeout = DEF_FW_ACCESS_TIMEOUT;

        /*必要时设置默认max_fw_timeout
        */
        if(acc->max_fw_timeout < 1)
            acc->max_fw_timeout = DEF_MAX_FW_TIMEOUT;

        if(acc->max_fw_timeout < acc->fw_access_timeout)
            log_msg(LOG_INFO,
                "Warning: MAX_FW_TIMEOUT < FW_ACCESS_TIMEOUT, honoring MAX_FW_TIMEOUT for stanza source: '%s' (#%d)",
                acc->source, i
            );

        /* 必要时设置默认gpg密钥环路径
        */
        if(acc->gpg_decrypt_pw != NULL)
        {
            if(acc->gpg_home_dir == NULL)
                add_acc_string(&(acc->gpg_home_dir),
                        opts->config[CONF_GPG_HOME_DIR], NULL, opts);

            if(! acc->gpg_require_sig)
            {
                if (acc->gpg_disable_sig)
                {
                    log_msg(LOG_INFO,
                        "Warning: GPG_REQUIRE_SIG should really be enabled for stanza source: '%s' (#%d)",
                        acc->source, i
                    );
                }
                else
                {
                    /* 除非明确禁用，否则将其设为默认值
                    */
                    acc->gpg_require_sig = 1;
                }
            }
            else
            {
                if (acc->gpg_disable_sig)
                {
                    log_msg(LOG_INFO,
                        "Warning: GPG_REQUIRE_SIG and GPG_DISABLE_SIG are both set, will check sigs (stanza source: '%s' #%d)",
                        acc->source, i
                    );
                }
            }

            /* 如果启用了签名检查，请确保我们有要检查的sig ID或指纹ID
            */
            if(! acc->gpg_disable_sig
                    && (acc->gpg_remote_id == NULL && acc->gpg_remote_fpr == NULL))
            {
                log_msg(LOG_INFO,
                    "Warning: Must have either sig ID's or fingerprints to check via GPG_REMOTE_ID or GPG_FINGERPRINT_ID (stanza source: '%s' #%d)",
                    acc->source, i
                );
                clean_exit(opts, NO_FW_CLEANUP, EXIT_FAILURE);
            }
        }

        if(acc->encryption_mode == FKO_ENC_MODE_UNKNOWN)
            acc->encryption_mode = FKO_DEFAULT_ENC_MODE;

        /* 如果我们正在使用HMAC键，并且没有为HMAC_digest_type设置HMAC摘要类型，则假设它是SHA256
        */

        if(acc->hmac_type == FKO_HMAC_UNKNOWN
                && acc->hmac_key_len > 0 && acc->hmac_key != NULL)
        {
            acc->hmac_type = FKO_DEFAULT_HMAC_MODE;
        }

        acc = acc->next;
        i++;
    }
    return;
}

/* 对acc节数据执行健全性检查。
*/
static int
acc_data_is_valid(fko_srv_options_t *opts,
        struct passwd *user_pw, struct passwd *sudo_user_pw,
        acc_stanza_t * const acc)
{
    if(acc == NULL)
    {
        log_msg(LOG_ERR,
            "[*] acc_data_is_valid() called with NULL acc stanza");
        return(0);
    }

    if(((acc->key == NULL || acc->key_len == 0)
      && ((acc->gpg_decrypt_pw == NULL || !strlen(acc->gpg_decrypt_pw))
          && acc->gpg_allow_no_pw == 0))
      || (acc->use_rijndael == 0 && acc->use_gpg == 0 && acc->gpg_allow_no_pw == 0))
    {
        log_msg(LOG_ERR,
            "[*] No keys found for access stanza source: '%s'", acc->source
        );
        return(0);
    }

    if(acc->use_rijndael && acc->key != NULL)
    {
        if((acc->encryption_mode == FKO_ENC_MODE_CBC_LEGACY_IV)
                && (acc->key_len > 16))
        {
            log_msg(LOG_INFO,
                "Warning: truncating encryption key in legacy mode to 16 bytes for access stanza source: '%s'",
                acc->source
            );
            acc->key_len = 16;
        }
    }

    if((acc->hmac_key_len) != 0 && (acc->hmac_key != NULL))
    {
        if((acc->key != NULL) && (acc->key_len != 0)
                && (acc->key_len == acc->hmac_key_len))
        {
            if(memcmp(acc->key, acc->hmac_key, acc->hmac_key_len) == 0)
            {
                log_msg(LOG_ERR,
                    "[*] The encryption passphrase and HMAC key should not be identical for access stanza source: '%s'",
                    acc->source
                );
                return(0);
            }
        }
        else if((acc->gpg_allow_no_pw == 0)
                && acc->gpg_decrypt_pw != NULL
                && (strlen(acc->gpg_decrypt_pw) == acc->hmac_key_len))
        {
            if(memcmp(acc->gpg_decrypt_pw, acc->hmac_key, acc->hmac_key_len) == 0)
            {
                log_msg(LOG_ERR,
                    "[*] The encryption passphrase and HMAC key should not be identical for access stanza source: '%s'",
                    acc->source
                );
                return(0);
            }
        }
    }

#if defined(FIREWALL_FIREWALLD) || defined(FIREWALL_IPTABLES)
    if((acc->force_snat == 1 || acc->force_masquerade == 1)
            && acc->force_nat == 0)
    {
        if(acc->forward_all == 1)
        {
            add_acc_force_nat(opts, acc, "0.0.0.0 0", NULL);
        }
        else
        {
            log_msg(LOG_ERR,
                    "[*] FORCE_SNAT/FORCE_MASQUERADE requires either FORCE_NAT or FORWARD_ALL: '%s'",
                    acc->source
            );
            return(0);
        }
    }
#endif

    if(acc->require_source_address == 0)
    {
        log_msg(LOG_INFO,
            "Warning: REQUIRE_SOURCE_ADDRESS not enabled for access stanza source: '%s'",
            acc->source
        );
    }

    if(user_pw != NULL && acc->cmd_exec_uid != 0 && acc->cmd_exec_gid == 0)
    {
        log_msg(LOG_INFO,
            "Setting gid to group associated with CMD_EXEC_USER '%s' for setgid() execution in stanza source: '%s'",
            acc->cmd_exec_user,
            acc->source
        );
        acc->cmd_exec_gid = user_pw->pw_gid;
    }

    if(sudo_user_pw != NULL
            && acc->cmd_sudo_exec_uid != 0 && acc->cmd_sudo_exec_gid == 0)
    {
        log_msg(LOG_INFO,
            "Setting gid to group associated with CMD_SUDO_EXEC_USER '%s' in stanza source: '%s'",
            acc->cmd_sudo_exec_user,
            acc->source
        );
        acc->cmd_sudo_exec_gid = sudo_user_pw->pw_gid;
    }

    if(acc->cmd_cycle_open != NULL)
    {
        if(acc->cmd_cycle_close == NULL)
        {
            log_msg(LOG_ERR,
                "[*] Cannot set CMD_CYCLE_OPEN without also setting CMD_CYCLE_CLOSE: '%s'",
                acc->source
            );
            return(0);
        }

        /* 允许字符串“NONE”使关闭命令执行短路。
        */
        if(strncmp(acc->cmd_cycle_close, "NONE", 4) == 0)
            acc->cmd_cycle_do_close = 0;

        if(acc->cmd_cycle_timer == 0 && acc->cmd_cycle_do_close)
        {
            log_msg(LOG_ERR,
                "[*] Must set the CMD_CYCLE_TIMER for command cycle functionality: '%s'",
                acc->source
            );
            return(0);
        }
        if(strlen(acc->cmd_cycle_open) >= CMD_CYCLE_BUFSIZE)
        {
            log_msg(LOG_ERR,
                "[*] CMD_CYCLE_OPEN command is too long: '%s'",
                acc->source
            );
            return(0);
        }
    }

    if(acc->cmd_cycle_close != NULL)
    {
        if(acc->cmd_cycle_open == NULL)
        {
            log_msg(LOG_ERR,
                "[*] Cannot set CMD_CYCLE_CLOSE without also setting CMD_CYCLE_OPEN: '%s'",
                acc->source
            );
            return(0);
        }
        if(strlen(acc->cmd_cycle_close) >= CMD_CYCLE_BUFSIZE)
        {
            log_msg(LOG_ERR,
                "[*] CMD_CYCLE_CLOSE command is too long: '%s'",
                acc->source
            );
            return(0);
        }
    }

    /* 对于任何非命令周期节，我们都启用全局防火墙处理
    */
    if(acc->cmd_cycle_open == NULL)
        opts->enable_fw = 1;

    return(1);
}

int
parse_access_folder(fko_srv_options_t *opts, char *access_folder, int *depth)
{
    char            *extension;
    DIR             *dir_ptr;

    char            include_file[MAX_PATH_LEN] = {0};
    struct dirent  *dp;

    chop_char(access_folder, PATH_SEP);

    dir_ptr = opendir(access_folder);

    //获取目录中的文件名并循环它们
    if (dir_ptr == NULL)
    {
        log_msg(LOG_ERR, "[*] Access folder: '%s' could not be opened.", access_folder);
        return EXIT_FAILURE;
    }
    while ((dp = readdir(dir_ptr)) != NULL) {
        extension = (strrchr(dp->d_name, '.')); // 仅捕获扩展名
        if (extension && !strncmp(extension, ".conf", 5))
        {
            if (strlen(access_folder) + 1 + strlen(dp->d_name) > MAX_PATH_LEN - 1) //退出，而不是写入超过include_file结尾的内容
            {
                closedir(dir_ptr);
                return EXIT_FAILURE;
            }
            strlcpy(include_file, access_folder, sizeof(include_file)); //构造完整路径
            strlcat(include_file, "/", sizeof(include_file));
            strlcat(include_file, dp->d_name, sizeof(include_file));
            if (parse_access_file(opts, include_file, depth) == EXIT_FAILURE)
            {
                closedir(dir_ptr);
                return EXIT_FAILURE;
            }
        }
    }
    closedir(dir_ptr);
    return EXIT_SUCCESS;
}

/* 读取并解析访问文件，在执行过程中填充访问数据。
*/
int
parse_access_file(fko_srv_options_t *opts, char *access_filename, int *depth)
{
    FILE           *file_ptr;
    char           *ndx;
    int             is_err;
    unsigned int    num_lines = 0;

    char            access_line_buf[MAX_LINE_LEN] = {0};
    char            var[MAX_LINE_LEN] = {0};
    char            val[MAX_LINE_LEN] = {0};

    struct passwd  *user_pw = NULL;
    struct passwd  *sudo_user_pw = NULL;

    acc_stanza_t   *curr_acc = NULL;

    /* 限制包含深度，并在返回到根access.conf文件时跟踪。
    */
    (*depth)++;

    if ((file_ptr = fopen(access_filename, "r")) == NULL)
    {
        log_msg(LOG_ERR, "[*] Could not open access file: %s",
            access_filename);
        perror(NULL);

        return EXIT_FAILURE;
    }

#if HAVE_FILENO
    if(verify_file_perms_ownership(access_filename, fileno(file_ptr)) != 1)
#else
    if(verify_file_perms_ownership(access_filename, -1) != 1)
#endif
    {
        fclose(file_ptr);
        return EXIT_FAILURE;
    }

    log_msg(LOG_DEBUG, "Opened access file: %s", access_filename);

    /* 初始化访问列表
    */
    acc_stanza_init(opts);

    /* 现在遍历访问文件，将访问条目拉入当前节。
    */
    while ((fgets(access_line_buf, MAX_LINE_LEN, file_ptr)) != NULL)
    {
        num_lines++;
        access_line_buf[MAX_LINE_LEN-1] = '\0';

        /* 获取过去的注释和空行（注意：只查看第一个字符。）
        */
        if(IS_EMPTY_LINE(access_line_buf[0]))
            continue;

        if(sscanf(access_line_buf, "%s %[^;\n\r]", var, val) != 2)
        {
            log_msg(LOG_ERR,
                "[*] Invalid access file entry in %s at line %i.\n - '%s'",
                access_filename, num_lines, access_line_buf
            );
            fclose(file_ptr);
            return EXIT_FAILURE;
        }

        /* 删除可能位于var末尾的任何冒号
        */
        if((ndx = strrchr(var, ':')) != NULL)
            *ndx = '\0';

        /* 尽管sscanf应该自动添加一个终止NULL字节，
         * 但假设输入数组足够大，因此我们将强制使用一个终止的NULL字节
        */
        var[MAX_LINE_LEN-1] = 0x0;
        val[MAX_LINE_LEN-1] = 0x0;

        /* 从值中删除任何尾随空格
        */
        chop_whitespace(val);

        if (opts->verbose > 3)
            log_msg(LOG_DEBUG,
                "ACCESS FILE: %s, LINE: %s\tVar: %s, Val: '%s'",
                access_filename, access_line_buf, var, val
            );

        /* 处理条目。
         *
         * 注意：如果创建了新的access.conf参数。在下面的if/if-else构造中也需要考虑它。
        */
        if(CONF_VAR_IS(var, "%include"))
        {
            if ((*depth) < MAX_DEPTH)
            {
                log_msg(LOG_DEBUG, "[+] Processing include directive for file: '%s'", val);
                if (parse_access_file(opts, val, depth) == EXIT_FAILURE)
                {
                    fclose(file_ptr);
                    return EXIT_FAILURE;
                }
            }
            else
            {
                log_msg(LOG_ERR, "[*] Refusing to go deeper than 3 levels. Lost in Limbo: '%s'",
                        access_filename);
                fclose(file_ptr);
                return EXIT_FAILURE;
            }
        }
        else if(CONF_VAR_IS(var, "%include_folder"))
        {
            log_msg(LOG_DEBUG, "[+] Processing include_folder directive for: '%s'", val);
            if (parse_access_folder(opts, val, depth) == EXIT_FAILURE)
            {
                fclose(file_ptr);
                return EXIT_FAILURE;
            }
        }
        else if(CONF_VAR_IS(var, "SOURCE"))
        {
            /* 如果这不是第一节，则完整性检查前一节中所需的最小数据。
            */
            if(curr_acc != NULL) {
                if(!acc_data_is_valid(opts, user_pw, sudo_user_pw, curr_acc))
                {
                    log_msg(LOG_ERR, "[*] Data error in access file: '%s'",
                        access_filename);
                    fclose(file_ptr);
                    return EXIT_FAILURE;
                }
            }

            /* 开始新的一节。
            */
            curr_acc = acc_stanza_add(opts);
            add_acc_string(&(curr_acc->source), val, file_ptr, opts);
        }
        else if (curr_acc == NULL)
        {
            /*节必须以“SOURCE”变量开头
            */
            continue;
        }
        else if(CONF_VAR_IS(var, "%include_keys")) //只有该文件中的有效选项才是定义键的选项。
        {
          // 此指令仅在SOURCE节中有效
            log_msg(LOG_DEBUG, "[+] Processing include_keys directive for: '%s'", val);
            include_keys_file(curr_acc, val, opts);
            if(!acc_data_is_valid(opts, user_pw, sudo_user_pw, curr_acc))
            {
                log_msg(LOG_DEBUG, "[*] Data error in included keyfile: '%s', skipping stanza.", val);
                free_last_acc_stanza(opts);
                curr_acc = NULL;
            }
        }
        else if(CONF_VAR_IS(var, "DESTINATION"))
            add_acc_string(&(curr_acc->destination), val, file_ptr, opts);
        else if(CONF_VAR_IS(var, "OPEN_PORTS"))
            add_acc_string(&(curr_acc->open_ports), val, file_ptr, opts);
        else if(CONF_VAR_IS(var, "RESTRICT_PORTS"))
            add_acc_string(&(curr_acc->restrict_ports), val, file_ptr, opts);
        else if(CONF_VAR_IS(var, "KEY"))
        {
            if(strcasecmp(val, "__CHANGEME__") == 0)
            {
                log_msg(LOG_ERR,
                    "[*] KEY value is not properly set in stanza source '%s' in access file: '%s'",
                    curr_acc->source, access_filename);
                fclose(file_ptr);
                return EXIT_FAILURE;
            }
            add_acc_string(&(curr_acc->key), val, file_ptr, opts);
            curr_acc->key_len = strlen(curr_acc->key);
            add_acc_bool(&(curr_acc->use_rijndael), "Y");
        }
        else if(CONF_VAR_IS(var, "KEY_BASE64"))
        {
            if(strcasecmp(val, "__CHANGEME__") == 0)
            {
                log_msg(LOG_ERR,
                    "[*] KEY_BASE64 value is not properly set in stanza source '%s' in access file: '%s'",
                    curr_acc->source, access_filename);
                fclose(file_ptr);
                return EXIT_FAILURE;
            }
            if (! is_base64((unsigned char *) val, strlen(val)))
            {
                log_msg(LOG_ERR,
                    "[*] KEY_BASE64 argument '%s' doesn't look like base64-encoded data.",
                    val);
                fclose(file_ptr);
                return EXIT_FAILURE;
            }
            add_acc_string(&(curr_acc->key_base64), val, file_ptr, opts);
            add_acc_b64_string(&(curr_acc->key), &(curr_acc->key_len),
                    curr_acc->key_base64, file_ptr, opts);
            add_acc_bool(&(curr_acc->use_rijndael), "Y");
        }
        /* HMAC digest type */
        else if(CONF_VAR_IS(var, "HMAC_DIGEST_TYPE"))
        {
            curr_acc->hmac_type = hmac_digest_strtoint(val);
            if(curr_acc->hmac_type < 0)
            {
                log_msg(LOG_ERR,
                    "[*] HMAC_DIGEST_TYPE argument '%s' must be one of {md5,sha1,sha256,sha384,sha512,sha3_256,sha3_512}",
                    val);
                fclose(file_ptr);
                return EXIT_FAILURE;
            }
        }
        else if(CONF_VAR_IS(var, "HMAC_KEY_BASE64"))
        {
            if(strcasecmp(val, "__CHANGEME__") == 0)
            {
                log_msg(LOG_ERR,
                    "[*] HMAC_KEY_BASE64 value is not properly set in stanza source '%s' in access file: '%s'",
                    curr_acc->source, opts->config[CONF_ACCESS_FILE]);
                fclose(file_ptr);
                return EXIT_FAILURE;
            }
            if (! is_base64((unsigned char *) val, strlen(val)))
            {
                log_msg(LOG_ERR,
                    "[*] HMAC_KEY_BASE64 argument '%s' doesn't look like base64-encoded data.",
                    val);
                fclose(file_ptr);
                return EXIT_FAILURE;
            }
            add_acc_string(&(curr_acc->hmac_key_base64), val, file_ptr, opts);
            add_acc_b64_string(&(curr_acc->hmac_key), &(curr_acc->hmac_key_len),
                    curr_acc->hmac_key_base64, file_ptr, opts);
        }
        else if(CONF_VAR_IS(var, "HMAC_KEY"))
        {
            if(strcasecmp(val, "__CHANGEME__") == 0)
            {
                log_msg(LOG_ERR,
                    "[*] HMAC_KEY value is not properly set in stanza source '%s' in access file: '%s'",
                    curr_acc->source, opts->config[CONF_ACCESS_FILE]);
                fclose(file_ptr);
                return EXIT_FAILURE;
            }
            add_acc_string(&(curr_acc->hmac_key), val, file_ptr, opts);
            curr_acc->hmac_key_len = strlen(curr_acc->hmac_key);
        }
        else if(CONF_VAR_IS(var, "FW_ACCESS_TIMEOUT"))
        {
            curr_acc->fw_access_timeout = strtol_wrapper(val, 0,
                    RCHK_MAX_FW_TIMEOUT, NO_EXIT_UPON_ERR, &is_err);
            if(is_err != FKO_SUCCESS)
            {
                log_msg(LOG_ERR,
                    "[*] FW_ACCESS_TIMEOUT value not in range.");
                fclose(file_ptr);
                return EXIT_FAILURE;
            }
        }
        else if(CONF_VAR_IS(var, "MAX_FW_TIMEOUT"))
        {
            curr_acc->max_fw_timeout = strtol_wrapper(val, 0,
                    RCHK_MAX_FW_TIMEOUT, NO_EXIT_UPON_ERR, &is_err);
            if(is_err != FKO_SUCCESS)
            {
                log_msg(LOG_ERR,
                    "[*] MAX_FW_TIMEOUT value not in range.");
                fclose(file_ptr);
                return EXIT_FAILURE;
            }
        }
        else if(CONF_VAR_IS(var, "ENCRYPTION_MODE"))
        {
            if((curr_acc->encryption_mode = enc_mode_strtoint(val)) < 0)
            {
                log_msg(LOG_ERR,
                    "[*] Unrecognized ENCRYPTION_MODE '%s', use {CBC,CTR,legacy,Asymmetric}",
                    val);
                fclose(file_ptr);
                return EXIT_FAILURE;
            }
        }
        else if(CONF_VAR_IS(var, "ENABLE_CMD_EXEC"))
        {
            add_acc_bool(&(curr_acc->enable_cmd_exec), val);
        }
        else if(CONF_VAR_IS(var, "ENABLE_CMD_SUDO_EXEC"))
        {
            add_acc_bool(&(curr_acc->enable_cmd_sudo_exec), val);
        }
        else if(CONF_VAR_IS(var, "CMD_SUDO_EXEC_USER"))
            add_acc_user(&(curr_acc->cmd_sudo_exec_user),
                        &(curr_acc->cmd_sudo_exec_uid), &sudo_user_pw,
                        val, "CMD_SUDO_EXEC_USER", file_ptr, opts);
        else if(CONF_VAR_IS(var, "CMD_SUDO_EXEC_GROUP"))
            add_acc_group(&(curr_acc->cmd_sudo_exec_group),
                        &(curr_acc->cmd_sudo_exec_gid), val,
                        "CMD_SUDO_EXEC_GROUP", file_ptr, opts);
        else if(CONF_VAR_IS(var, "CMD_EXEC_USER"))
            add_acc_user(&(curr_acc->cmd_exec_user),
                        &(curr_acc->cmd_exec_uid), &user_pw,
                        val, "CMD_EXEC_USER", file_ptr, opts);
        else if(CONF_VAR_IS(var, "CMD_EXEC_GROUP"))
            add_acc_group(&(curr_acc->cmd_exec_group),
                        &(curr_acc->cmd_exec_gid), val,
                        "CMD_EXEC_GROUP", file_ptr, opts);
        else if(CONF_VAR_IS(var, "CMD_CYCLE_OPEN"))
        {
            add_acc_string(&(curr_acc->cmd_cycle_open), val, file_ptr, opts);
            curr_acc->cmd_cycle_do_close = 1; /* default, will be validated */
        }
        else if(CONF_VAR_IS(var, "CMD_CYCLE_CLOSE"))
            add_acc_string(&(curr_acc->cmd_cycle_close), val, file_ptr, opts);
        else if(CONF_VAR_IS(var, "CMD_CYCLE_TIMER"))
        {
            curr_acc->cmd_cycle_timer = strtol_wrapper(val,
                    RCHK_MIN_CMD_CYCLE_TIMER, RCHK_MAX_CMD_CYCLE_TIMER,
                    NO_EXIT_UPON_ERR, &is_err);
            if(is_err != FKO_SUCCESS)
            {
                log_msg(LOG_ERR,
                    "[*] CMD_CYCLE_TIMER value not in range [1,%d].",
                    RCHK_MAX_CMD_CYCLE_TIMER);
                fclose(file_ptr);
                return EXIT_FAILURE;
            }
        }
        else if(CONF_VAR_IS(var, "REQUIRE_USERNAME"))
            add_acc_string(&(curr_acc->require_username), val, file_ptr, opts);
        else if(CONF_VAR_IS(var, "REQUIRE_SOURCE_ADDRESS"))
            add_acc_bool(&(curr_acc->require_source_address), val);
        else if(CONF_VAR_IS(var, "REQUIRE_SOURCE"))  /* synonym for REQUIRE_SOURCE_ADDRESS */
            add_acc_bool(&(curr_acc->require_source_address), val);
        else if(CONF_VAR_IS(var, "GPG_HOME_DIR"))
        {
            if (is_valid_dir(val))
            {
                add_acc_string(&(curr_acc->gpg_home_dir), val, file_ptr, opts);
            }
            else
            {
                log_msg(LOG_ERR,
                    "[*] GPG_HOME_DIR directory '%s' stat()/existence problem in stanza source '%s' in access file: '%s'",
                    val, curr_acc->source, access_filename);
                fclose(file_ptr);
                return EXIT_FAILURE;
            }
        }
        else if(CONF_VAR_IS(var, "GPG_EXE"))
            add_acc_string(&(curr_acc->gpg_exe), val, file_ptr, opts);
        else if(CONF_VAR_IS(var, "GPG_DECRYPT_ID"))
            add_acc_string(&(curr_acc->gpg_decrypt_id), val, file_ptr, opts);
        else if(CONF_VAR_IS(var, "GPG_DECRYPT_PW"))
        {
            if(strcasecmp(val, "__CHANGEME__") == 0)
            {
                log_msg(LOG_ERR,
                    "[*] GPG_DECRYPT_PW value is not properly set in stanza source '%s' in access file: '%s'",
                    curr_acc->source, access_filename);
                fclose(file_ptr);
                return EXIT_FAILURE;
            }
            add_acc_string(&(curr_acc->gpg_decrypt_pw), val, file_ptr, opts);
            add_acc_bool(&(curr_acc->use_gpg), "Y");
        }
        else if(CONF_VAR_IS(var, "GPG_ALLOW_NO_PW"))
        {
            add_acc_bool(&(curr_acc->gpg_allow_no_pw), val);
            if(curr_acc->gpg_allow_no_pw == 1)
            {
                add_acc_bool(&(curr_acc->use_gpg), "Y");
                add_acc_string(&(curr_acc->gpg_decrypt_pw), "", file_ptr, opts);
            }
        }
        else if(CONF_VAR_IS(var, "GPG_REQUIRE_SIG"))
        {
            add_acc_bool(&(curr_acc->gpg_require_sig), val);
        }
        else if(CONF_VAR_IS(var, "GPG_DISABLE_SIG"))
        {
            add_acc_bool(&(curr_acc->gpg_disable_sig), val);
        }
        else if(CONF_VAR_IS(var, "GPG_IGNORE_SIG_VERIFY_ERROR"))
        {
            add_acc_bool(&(curr_acc->gpg_ignore_sig_error), val);
        }
        else if(CONF_VAR_IS(var, "GPG_REMOTE_ID"))
            add_acc_string(&(curr_acc->gpg_remote_id), val, file_ptr, opts);
        else if(CONF_VAR_IS(var, "GPG_FINGERPRINT_ID"))
            add_acc_string(&(curr_acc->gpg_remote_fpr), val, file_ptr, opts);
        else if(CONF_VAR_IS(var, "ACCESS_EXPIRE"))
        {
            if (add_acc_expire_time(opts, &(curr_acc->access_expire_time), val) != 1)
            {
                fclose(file_ptr);
                return EXIT_FAILURE;
            }
        }
        else if(CONF_VAR_IS(var, "ACCESS_EXPIRE_EPOCH"))
            add_acc_expire_time_epoch(opts,
                    &(curr_acc->access_expire_time), val, file_ptr);
        else if(CONF_VAR_IS(var, "FORCE_NAT"))
        {
#if FIREWALL_FIREWALLD
            if(strncasecmp(opts->config[CONF_ENABLE_FIREWD_FORWARDING], "Y", 1) !=0
                && (strncasecmp(opts->config[CONF_ENABLE_FIREWD_LOCAL_NAT], "Y", 1) !=0 ))
            {
                log_msg(LOG_ERR,
                    "[*] FORCE_NAT requires either ENABLE_FIREWD_FORWARDING or ENABLE_FIREWD_LOCAL_NAT in fwknopd.conf");
                fclose(file_ptr);
                return EXIT_FAILURE;
            }
            add_acc_force_nat(opts, curr_acc, val, file_ptr);
#elif FIREWALL_IPTABLES
            if(strncasecmp(opts->config[CONF_ENABLE_IPT_FORWARDING], "Y", 1) !=0
                && (strncasecmp(opts->config[CONF_ENABLE_IPT_LOCAL_NAT], "Y", 1) !=0 ))
            {
                log_msg(LOG_ERR,
                    "[*] FORCE_NAT requires either ENABLE_IPT_FORWARDING or ENABLE_IPT_LOCAL_NAT in fwknopd.conf");
                fclose(file_ptr);
                return EXIT_FAILURE;
            }
            add_acc_force_nat(opts, curr_acc, val, file_ptr);
#else
            log_msg(LOG_ERR,
                "[*] FORCE_NAT not supported.");
            fclose(file_ptr);
            return EXIT_FAILURE;
#endif
        }
        else if(CONF_VAR_IS(var, "FORCE_SNAT"))
        {
#if FIREWALL_FIREWALLD
            if(strncasecmp(opts->config[CONF_ENABLE_FIREWD_FORWARDING], "Y", 1) !=0
                && (strncasecmp(opts->config[CONF_ENABLE_FIREWD_LOCAL_NAT], "Y", 1) !=0 ))
            {
                log_msg(LOG_ERR,
                    "[*] FORCE_SNAT requires either ENABLE_FIREWD_FORWARDING or ENABLE_FIREWD_LOCAL_NAT in fwknopd.conf");
                fclose(file_ptr);
                return EXIT_FAILURE;
            }
            add_acc_force_snat(opts, curr_acc, val, file_ptr);
#elif FIREWALL_IPTABLES
            if(strncasecmp(opts->config[CONF_ENABLE_IPT_FORWARDING], "Y", 1) !=0
                && (strncasecmp(opts->config[CONF_ENABLE_IPT_LOCAL_NAT], "Y", 1) !=0 ))
            {
                log_msg(LOG_ERR,
                    "[*] FORCE_SNAT requires either ENABLE_IPT_FORWARDING or ENABLE_IPT_LOCAL_NAT in fwknopd.conf");
                fclose(file_ptr);
                return EXIT_FAILURE;
            }
            add_acc_force_snat(opts, curr_acc, val, file_ptr);
#else
            log_msg(LOG_ERR,
                "[*] FORCE_SNAT not supported.");
            fclose(file_ptr);
            return EXIT_FAILURE;
#endif
        }
        else if(CONF_VAR_IS(var, "FORCE_MASQUERADE"))
        {
            add_acc_bool(&(curr_acc->force_masquerade), val);
            add_acc_bool(&(curr_acc->force_snat), val);
        }
        else if(CONF_VAR_IS(var, "DISABLE_DNAT"))
        {
            add_acc_bool(&(curr_acc->disable_dnat), val);
        }
        else if(CONF_VAR_IS(var, "FORWARD_ALL"))
        {
            add_acc_bool(&(curr_acc->forward_all), val);
        }
        else
        {
            log_msg(LOG_ERR,
                "[*] Ignoring unknown access parameter: '%s' in %s",
                var, access_filename
            );
        }
    }

    fclose(file_ptr);
    if(*depth > 0)
        (*depth)--;

    if(*depth == 0) //意味着我们刚刚关闭了根access.conf
    {
        if(curr_acc != NULL)
        {
            if(!acc_data_is_valid(opts, user_pw, sudo_user_pw, curr_acc))
            {
                log_msg(LOG_ERR,
                    "[*] Data error in access file: '%s'",
                    access_filename);
                return EXIT_FAILURE;
            }
        }
        else if (opts->acc_stanzas == NULL)
        {
            log_msg(LOG_ERR,
                "[*] Could not find valid SOURCE stanza in access file: '%s'",
                opts->config[CONF_ACCESS_FILE]);
            return EXIT_FAILURE;
        }

        /*将我们的可扩展字段扩展到各自的数据桶中。
        */
        expand_acc_ent_lists(opts);

        /* 确保在需要的地方设置了默认值。
        */
        set_acc_defaults(opts);
    }
    else // 这是一个包含%的文件
    {
        /* 如果这个文件有一个节，请检查最后一个节。
         *
         *
        */
        if(curr_acc != NULL)
        {
            if(!acc_data_is_valid(opts, user_pw, sudo_user_pw, curr_acc))
            {
                log_msg(LOG_ERR,
                    "[*] Data error in access file: '%s'",
                    access_filename);
                return EXIT_FAILURE;
            }
        }
    }

    return EXIT_SUCCESS;
}

int valid_access_stanzas(acc_stanza_t *acc)
{
    if(acc == NULL)
        return 0;

    /* 这是一个基本检查，以确保至少有一个填充了“source”变量的访问节，
     * 并且只有在处理完所有access.conf文件后才会调用此函数。 
     * 这允许%include_folder处理对包含非access.conf文件的文件的目录进行处理。 
     * Aacc_data_is_valid（）中进行了其他更强的验证，但只有在从文件中解析出“SOURCE”变量时才会调用此函数
    */
    while(acc)
    {
        if(acc->source == NULL || acc->source[0] == '\0')
            return 0;
        acc = acc->next;
    }
    return 1;
}

int
compare_addr_list(acc_int_list_t *ip_list, const uint32_t ip)
{
    int match = 0;

    while(ip_list)
    {
        if((ip & ip_list->mask) == (ip_list->maddr & ip_list->mask))
        {
            match = 1;
            break;
        }

        ip_list = ip_list->next;
    }

    return(match);
}

/**
 * \brief 比较端口列表
 *
 * 比较2个端口列表的内容  当两者匹配时返回true。
 * 匹配依赖于match_any标志.  如果match_any为1，那么传入数据中的任何条目只需要匹配一个项即可返回true。
 * 否则，传入数据中的所有条目在访问port_list中都必须具有相应的匹配项。
 *
 * \param acc 指向保存访问节的acc_stanza_t结构的指针
 *
 * \return 匹配时返回true
 *
 */
static int
compare_port_list(acc_port_list_t *in, acc_port_list_t *ac, const int match_any)
{
    int a_cnt = 0;
    int i_cnt = 0;

    acc_port_list_t *tlist;
    while(in)
    {
        i_cnt++;

        tlist = ac;
        while(tlist)
        {
            if(in->proto == tlist->proto && in->port == tlist->port)
            {
                a_cnt++;
                if(match_any == 1)
                    return(1);
            }
            tlist = tlist->next;
        }
        in = in->next;
    }

    return(i_cnt == a_cnt);
}

/* 获取一个proto/port字符串（或多个逗号分隔的字符串），并将它们与给定访问节的列表进行核对。
 *
 * 如果允许，返回1
*/
int
acc_check_port_access(acc_stanza_t *acc, char *port_str)
{
    int             res = 1, ctr = 0;

    char            buf[ACCESS_BUF_LEN] = {0};
    char           *ndx, *start;

    acc_port_list_t *o_pl   = acc->oport_list;
    acc_port_list_t *r_pl   = acc->rport_list;

    acc_port_list_t *in_pl  = NULL;

    start = port_str;

    /* 根据传入的SPA数据创建我们自己的内部port_list以进行比较。
    */
    for(ndx = start; *ndx != '\0'; ndx++)
    {
        if(*ndx == ',')
        {
            if((ctr >= ACCESS_BUF_LEN)
                    || (((ndx-start)+1) >= ACCESS_BUF_LEN))
            {
                log_msg(LOG_ERR,
                    "[*] Unable to create acc_port_list from incoming data: %s",
                    port_str
                );
                free_acc_port_list(in_pl);
                return(0);
            }
            strlcpy(buf, start, (ndx-start)+1);
            if(add_port_list_ent(&in_pl, buf) == 0)
            {
                log_msg(LOG_ERR, "[*] Invalid proto/port string");
                free_acc_port_list(in_pl);
                return(0);
            }

            start = ndx+1;
            ctr = 0;
        }
        ctr++;
    }
    if((ctr >= ACCESS_BUF_LEN)
            || (((ndx-start)+1) >= ACCESS_BUF_LEN))
    {
        log_msg(LOG_ERR,
            "[*] Unable to create acc_port_list from incoming data: %s",
            port_str
        );
        free_acc_port_list(in_pl);
        return(0);
    }
    strlcpy(buf, start, (ndx-start)+1);
    if(add_port_list_ent(&in_pl, buf) == 0)
    {
        log_msg(LOG_ERR, "[*] Invalid proto/port string");
        free_acc_port_list(in_pl);
        return 0;
    }

    if(in_pl == NULL)
    {
        log_msg(LOG_ERR,
            "[*] Unable to create acc_port_list from incoming data: %s", port_str
        );
        return(0);
    }

    /* 从受限端口（如果有）开始。任何匹配（即使只有一个条目）都表示不允许。
    */
    if((acc->rport_list != NULL) && (compare_port_list(in_pl, r_pl, 1)))
    {
        res = 0;
        goto cleanup_and_bail;
    }

    /* 对于打开的端口列表，所有端口都必须匹配。
    */
    if((acc->oport_list != NULL) && (!compare_port_list(in_pl, o_pl, 0)))
            res = 0;

cleanup_and_bail:
    free_acc_port_list(in_pl);
    return(res);
}

/* 转储配置
*/
void
dump_access_list(const fko_srv_options_t *opts)
{
    int             i = 0;

    acc_stanza_t    *acc = opts->acc_stanzas;

    fprintf(stdout, "Current fwknopd access settings:\n");

    if(!acc)
    {
        fprintf(stderr, "\n    ** No Access Settings Defined **\n\n");
        return;
    }

    while(acc)
    {
        fprintf(stdout,
            "SOURCE (%i):  %s\n"
            "==============================================================\n"
            "                DESTINATION:  %s\n"
            "                 OPEN_PORTS:  %s\n"
            "             RESTRICT_PORTS:  %s\n"
            "                        KEY:  %s\n"
            "                 KEY_BASE64:  %s\n"
            "                    KEY_LEN:  %d\n"
            "                   HMAC_KEY:  %s\n"
            "            HMAC_KEY_BASE64:  %s\n"
            "               HMAC_KEY_LEN:  %d\n"
            "           HMAC_DIGEST_TYPE:  %d\n"
            "          FW_ACCESS_TIMEOUT:  %i\n"
            "             MAX_FW_TIMEOUT:  %i\n"
            "            ENABLE_CMD_EXEC:  %s\n"
            "       ENABLE_CMD_SUDO_EXEC:  %s\n"
            "         CMD_SUDO_EXEC_USER:  %s\n"
            "        CMD_SUDO_EXEC_GROUP:  %s\n"
            "              CMD_EXEC_USER:  %s\n"
            "             CMD_EXEC_GROUP:  %s\n"
            "             CMD_CYCLE_OPEN:  %s\n"
            "            CMD_CYCLE_CLOSE:  %s\n"
            "            CMD_CYCLE_TIMER:  %i\n"
            "           REQUIRE_USERNAME:  %s\n"
            "     REQUIRE_SOURCE_ADDRESS:  %s\n"
            "             FORCE_NAT (ip):  %s\n"
            "          FORCE_NAT (proto):  %s\n"
            "           FORCE_NAT (port):  %d\n"
            "            FORCE_SNAT (ip):  %s\n"
            "           FORCE_MASQUERADE:  %s\n"
            "               DISABLE_DNAT:  %s\n"
            "                FORWARD_ALL:  %s\n"
            "              ACCESS_EXPIRE:  %s"  /* asctime（）添加新行 */
            "               GPG_HOME_DIR:  %s\n"
            "                    GPG_EXE:  %s\n"
            "             GPG_DECRYPT_ID:  %s\n"
            "             GPG_DECRYPT_PW:  %s\n"
            "            GPG_REQUIRE_SIG:  %s\n"
            "GPG_IGNORE_SIG_VERIFY_ERROR:  %s\n"
            "              GPG_REMOTE_ID:  %s\n"
            "         GPG_FINGERPRINT_ID:  %s\n",
            ++i,
            acc->source,
            (acc->destination == NULL) ? "<not set>" : acc->destination,
            (acc->open_ports == NULL) ? "<not set>" : acc->open_ports,
            (acc->restrict_ports == NULL) ? "<not set>" : acc->restrict_ports,
            (acc->key == NULL) ? "<not set>" : "<see the access.conf file>",
            (acc->key_base64 == NULL) ? "<not set>" : "<see the access.conf file>",
            acc->key_len ? acc->key_len : 0,
            (acc->hmac_key == NULL) ? "<not set>" : "<see the access.conf file>",
            (acc->hmac_key_base64 == NULL) ? "<not set>" : "<see the access.conf file>",
            acc->hmac_key_len ? acc->hmac_key_len : 0,
            acc->hmac_type,
            acc->fw_access_timeout,
            acc->max_fw_timeout,
            acc->enable_cmd_exec ? "Yes" : "No",
            acc->enable_cmd_sudo_exec ? "Yes" : "No",
            (acc->cmd_sudo_exec_user == NULL) ? "<not set>" : acc->cmd_sudo_exec_user,
            (acc->cmd_sudo_exec_group == NULL) ? "<not set>" : acc->cmd_sudo_exec_group,
            (acc->cmd_exec_user == NULL) ? "<not set>" : acc->cmd_exec_user,
            (acc->cmd_exec_group == NULL) ? "<not set>" : acc->cmd_exec_group,
            (acc->cmd_cycle_open == NULL) ? "<not set>" : acc->cmd_cycle_open,
            (acc->cmd_cycle_close == NULL) ? "<not set>" : acc->cmd_cycle_close,
            acc->cmd_cycle_timer,
            (acc->require_username == NULL) ? "<not set>" : acc->require_username,
            acc->require_source_address ? "Yes" : "No",
            acc->force_nat ? acc->force_nat_ip : "<not set>",
            acc->force_nat && acc->force_nat_proto != NULL ? acc->force_nat_proto : "<not set>",
            acc->force_nat ? acc->force_nat_port : 0,
            acc->force_snat ? acc->force_snat_ip : "<not set>",
            acc->force_masquerade ? "Yes" : "No",
            acc->disable_dnat ? "Yes" : "No",
            acc->forward_all ? "Yes" : "No",
            (acc->access_expire_time > 0) ? asctime(localtime(&acc->access_expire_time)) : "<not set>\n",
            (acc->gpg_home_dir == NULL) ? "<not set>" : acc->gpg_home_dir,
            (acc->gpg_exe == NULL) ? "<not set>" : acc->gpg_exe,
            (acc->gpg_decrypt_id == NULL) ? "<not set>" : acc->gpg_decrypt_id,
            (acc->gpg_decrypt_pw == NULL) ? "<not set>" : "<see the access.conf file>",
            acc->gpg_require_sig ? "Yes" : "No",
            acc->gpg_ignore_sig_error  ? "Yes" : "No",
            (acc->gpg_remote_id == NULL) ? "<not set>" : acc->gpg_remote_id,
            (acc->gpg_remote_fpr == NULL) ? "<not set>" : acc->gpg_remote_fpr
        );

        fprintf(stdout, "\n");

        acc = acc->next;
    }

    fprintf(stdout, "\n");
    fflush(stdout);
}

int
include_keys_file(acc_stanza_t *curr_acc, const char *access_filename, fko_srv_options_t *opts)
{
    FILE           *file_ptr;
    unsigned int    num_lines = 0;

    char            access_line_buf[MAX_LINE_LEN] = {0};
    char            var[MAX_LINE_LEN] = {0};
    char            val[MAX_LINE_LEN] = {0};
    char           *ndx;

    log_msg(LOG_INFO, "Including key file: '%s'", access_filename);

    if ((file_ptr = fopen(access_filename, "r")) == NULL)
    {
        log_msg(LOG_ERR, "[*] Could not open access file: %s",
            access_filename);
        perror(NULL);

        return EXIT_FAILURE;
    }

    while ((fgets(access_line_buf, MAX_LINE_LEN, file_ptr)) != NULL)
    {
        num_lines++;
        access_line_buf[MAX_LINE_LEN-1] = '\0';

        /* 获取过去的注释和空行（注意：我们只看第一个字符。
        */
        if(IS_EMPTY_LINE(access_line_buf[0]))
            continue;

        if(sscanf(access_line_buf, "%s %[^;\n\r]", var, val) != 2)
        {
            log_msg(LOG_ERR,
                "[*] Invalid access file entry in %s at line %i.\n - '%s'",
                access_filename, num_lines, access_line_buf
            );
            fclose(file_ptr);
            return EXIT_FAILURE;
        }

        /* 移除冒号（如果存在）
        */
        if((ndx = strrchr(var, ':')) != NULL)
            *ndx = '\0';

        if(CONF_VAR_IS(var, "KEY"))
        {
            if(strcasecmp(val, "__CHANGEME__") == 0)
            {
                log_msg(LOG_ERR,
                    "[*] KEY value is not properly set in stanza source '%s' in access file: '%s'",
                    curr_acc->source, access_filename);
                fclose(file_ptr);
                return EXIT_FAILURE;
            }
            add_acc_string(&(curr_acc->key), val, file_ptr, opts);
            curr_acc->key_len = strlen(curr_acc->key);
            add_acc_bool(&(curr_acc->use_rijndael), "Y");
        }
        else if(CONF_VAR_IS(var, "KEY_BASE64"))
        {
            if(strcasecmp(val, "__CHANGEME__") == 0)
            {
                log_msg(LOG_ERR,
                    "[*] KEY_BASE64 value is not properly set in stanza source '%s' in access file: '%s'",
                    curr_acc->source, access_filename);
                fclose(file_ptr);
                return EXIT_FAILURE;
            }
            if (! is_base64((unsigned char *) val, strlen(val)))
            {
                log_msg(LOG_ERR,
                    "[*] KEY_BASE64 argument '%s' doesn't look like base64-encoded data.",
                    val);
                fclose(file_ptr);
                return EXIT_FAILURE;
            }
            add_acc_string(&(curr_acc->key_base64), val, file_ptr, opts);
            add_acc_b64_string(&(curr_acc->key), &(curr_acc->key_len),
                    curr_acc->key_base64, file_ptr, opts);
            add_acc_bool(&(curr_acc->use_rijndael), "Y");
        }
        else if(CONF_VAR_IS(var, "HMAC_KEY_BASE64"))
        {
            if(strcasecmp(val, "__CHANGEME__") == 0)
            {
                log_msg(LOG_ERR,
                    "[*] HMAC_KEY_BASE64 value is not properly set in stanza source '%s' in access file: '%s'",
                    curr_acc->source, opts->config[CONF_ACCESS_FILE]);
                fclose(file_ptr);
                return EXIT_FAILURE;
            }
            if (! is_base64((unsigned char *) val, strlen(val)))
            {
                log_msg(LOG_ERR,
                    "[*] HMAC_KEY_BASE64 argument '%s' doesn't look like base64-encoded data.",
                    val);
                fclose(file_ptr);
                return EXIT_FAILURE;
            }
            add_acc_string(&(curr_acc->hmac_key_base64), val, file_ptr, opts);
            add_acc_b64_string(&(curr_acc->hmac_key), &(curr_acc->hmac_key_len),
                    curr_acc->hmac_key_base64, file_ptr, opts);
        }
        else if(CONF_VAR_IS(var, "HMAC_KEY"))
        {
            if(strcasecmp(val, "__CHANGEME__") == 0)
            {
                log_msg(LOG_ERR,
                    "[*] HMAC_KEY value is not properly set in stanza source '%s' in access file: '%s'",
                    curr_acc->source, opts->config[CONF_ACCESS_FILE]);
                fclose(file_ptr);
                return EXIT_FAILURE;
            }
            add_acc_string(&(curr_acc->hmac_key), val, file_ptr, opts);
            curr_acc->hmac_key_len = strlen(curr_acc->hmac_key);
        }
        else if(CONF_VAR_IS(var, "GPG_DECRYPT_ID"))
            add_acc_string(&(curr_acc->gpg_decrypt_id), val, file_ptr, opts);
        else if(CONF_VAR_IS(var, "GPG_DECRYPT_PW"))
        {
            if(strcasecmp(val, "__CHANGEME__") == 0)
            {
                log_msg(LOG_ERR,
                    "[*] GPG_DECRYPT_PW value is not properly set in stanza source '%s' in access file: '%s'",
                    curr_acc->source, access_filename);
                fclose(file_ptr);
                return EXIT_FAILURE;
            }
            add_acc_string(&(curr_acc->gpg_decrypt_pw), val, file_ptr, opts);
            add_acc_bool(&(curr_acc->use_gpg), "Y");
        }
        else if(CONF_VAR_IS(var, "GPG_ALLOW_NO_PW"))
        {
            add_acc_bool(&(curr_acc->gpg_allow_no_pw), val);
            if(curr_acc->gpg_allow_no_pw == 1)
            {
                add_acc_bool(&(curr_acc->use_gpg), "Y");
                add_acc_string(&(curr_acc->gpg_decrypt_pw), "", file_ptr, opts);
            }
        }
        else if(CONF_VAR_IS(var, "GPG_REQUIRE_SIG"))
        {
            add_acc_bool(&(curr_acc->gpg_require_sig), val);
        }
        else if(CONF_VAR_IS(var, "GPG_DISABLE_SIG"))
        {
            add_acc_bool(&(curr_acc->gpg_disable_sig), val);
        }
        else if(CONF_VAR_IS(var, "GPG_IGNORE_SIG_VERIFY_ERROR"))
        {
            add_acc_bool(&(curr_acc->gpg_ignore_sig_error), val);
        }
        else if(CONF_VAR_IS(var, "GPG_REMOTE_ID"))
            add_acc_string(&(curr_acc->gpg_remote_id), val, file_ptr, opts);
        else if(CONF_VAR_IS(var, "GPG_FINGERPRINT_ID"))
            add_acc_string(&(curr_acc->gpg_remote_fpr), val, file_ptr, opts);
        else
            log_msg(LOG_INFO, "Ignoring invalid entry: '%s'", var);
    }
    fclose(file_ptr);
    return EXIT_SUCCESS;
}

#ifdef HAVE_C_UNIT_TESTS /* LCOV_EXCL_START */

DECLARE_UTEST(compare_port_list, "check compare_port_list function")
{
    acc_port_list_t *in1_pl = NULL;
    acc_port_list_t *in2_pl = NULL;
    acc_port_list_t *acc_pl = NULL;

    /* 匹配任何测试 */
    free_acc_port_list(in1_pl);
    free_acc_port_list(acc_pl);
    expand_acc_port_list(&in1_pl, "udp/6002");
    expand_acc_port_list(&in2_pl, "udp/6002, udp/6003");
    expand_acc_port_list(&acc_pl, "udp/6002, udp/6003");
    CU_ASSERT(compare_port_list(in1_pl, acc_pl, 1) == 1);	/* 访问端口列表中只需要一个匹配项 - 1 */
    CU_ASSERT(compare_port_list(in2_pl, acc_pl, 1) == 1);	/* 只需要访问端口列表中的匹配项 - 2 */
    CU_ASSERT(compare_port_list(in1_pl, acc_pl, 0) == 1);	/* 所有端口必须与访问端口列表匹配 - 1 */
    CU_ASSERT(compare_port_list(in2_pl, acc_pl, 0) == 1);	/* 所有端口必须与访问端口列表匹配 - 2 */
    CU_ASSERT(compare_port_list(acc_pl, in1_pl, 0) == 0);	/* 所有端口必须在1端口列表中匹配 - 1 */
    CU_ASSERT(compare_port_list(acc_pl, in2_pl, 0) == 1);	/* 所有端口必须在2端口列表中匹配 - 2 */
}

int register_ts_access(void)
{
    ts_init(&TEST_SUITE(access), TEST_SUITE_DESCR(access), NULL, NULL);
    ts_add_utest(&TEST_SUITE(access), UTEST_FCT(compare_port_list), UTEST_DESCR(compare_port_list));

    return register_ts(&TEST_SUITE(access));
}
#endif /* HAVE_C_UNIT_TESTS */ /* LCOV_EXCL_STOP */
/***EOF***/
