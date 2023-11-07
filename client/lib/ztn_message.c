
#include "ztn_common.h"
#include "ztn_message.h"
#include "ztn.h"

static int
have_allow_ip(const char *msg)
{
    const char         *ndx     = msg;
    char                ip_str[MAX_IPV4_STR_LEN];
    int                 dot_ctr = 0, char_ctr = 0;
    int                 res     = ZTN_SUCCESS;

    while(*ndx != ',' && *ndx != '\0')
    {
        ip_str[char_ctr] = *ndx;
        char_ctr++;
        if(char_ctr >= MAX_IPV4_STR_LEN)
        {
            res = ZTN_ERROR_INVALID_ALLOW_IP;
            break;
        }
        if(*ndx == '.')
            dot_ctr++;
        else if(isdigit((int)(unsigned char)*ndx) == 0)
        {
            res = ZTN_ERROR_INVALID_ALLOW_IP;
            break;
        }
        ndx++;
    }

    if(char_ctr < MAX_IPV4_STR_LEN)
        ip_str[char_ctr] = '\0';
    else
        res = ZTN_ERROR_INVALID_ALLOW_IP;

    if(res == ZTN_SUCCESS)
        if (! is_valid_ipv4_addr(ip_str, strlen(ip_str)))
            res = ZTN_ERROR_INVALID_ALLOW_IP;

    return(res);
}

static int
have_port(const char *msg)
{
    const char  *ndx = msg;
    char        port_str[MAX_PORT_STR_LEN+1] = {0};
    int         startlen = strnlen(msg, MAX_SPA_MESSAGE_SIZE);
    int         port_str_len=0, i=0, is_err;

    if(startlen == MAX_SPA_MESSAGE_SIZE)
        return(ZTN_ERROR_INVALID_DATA_MESSAGE_PORT_MISSING);

    /* 端口号必须至少有一个数字 */
    if(isdigit((int)(unsigned char)*ndx) == 0)
        return(ZTN_ERROR_INVALID_SPA_ACCESS_MSG);

    while(*ndx != '\0' && *ndx != ',')
    {
        port_str_len++;
        if((isdigit((int)(unsigned char)*ndx) == 0) || (port_str_len > MAX_PORT_STR_LEN))
            return(ZTN_ERROR_INVALID_SPA_ACCESS_MSG);
        port_str[i] = *ndx;
        ndx++;
        i++;
    }
    port_str[i] = '\0';

    strtol_wrapper(port_str, 1, MAX_PORT, NO_EXIT_UPON_ERR, &is_err);
    if(is_err != ZTN_SUCCESS)
        return(ZTN_ERROR_INVALID_SPA_ACCESS_MSG);

    return ZTN_SUCCESS;
}

/* 设置SPA消息类型。 */
int
ztn_set_spa_message_type(ztn_ctx_t ctx, const short msg_type)
{
#if HAVE_LIBFIU
    fiu_return_on("ztn_set_spa_message_type_init",
            ZTN_ERROR_CTX_NOT_INITIALIZED);
#endif
    /* 必须初始化 */
    if(!CTX_INITIALIZED(ctx))
        return ZTN_ERROR_CTX_NOT_INITIALIZED;

#if HAVE_LIBFIU
    fiu_return_on("ztn_set_spa_message_type_val",
            ZTN_ERROR_INVALID_DATA_MESSAGE_TYPE_VALIDFAIL);
#endif
    if(msg_type < 0 || msg_type >= ZTN_LAST_MSG_TYPE)
        return(ZTN_ERROR_INVALID_DATA_MESSAGE_TYPE_VALIDFAIL);

    ctx->message_type = msg_type;

    ctx->state |= ZTN_SPA_MSG_TYPE_MODIFIED;

    return(ZTN_SUCCESS);
}

/* 返回SPA消息类型。 */
int
ztn_get_spa_message_type(ztn_ctx_t ctx, short *msg_type)
{

#if HAVE_LIBFIU
    fiu_return_on("ztn_get_spa_message_type_init",
            ZTN_ERROR_CTX_NOT_INITIALIZED);
#endif

    /* 必须初始化 */
    if(!CTX_INITIALIZED(ctx))
        return ZTN_ERROR_CTX_NOT_INITIALIZED;

    if(msg_type == NULL)
        return(ZTN_ERROR_INVALID_DATA);

#if HAVE_LIBFIU
    fiu_return_on("ztn_get_spa_message_type_val", ZTN_ERROR_INVALID_DATA);
#endif

    *msg_type = ctx->message_type;

    return(ZTN_SUCCESS);
}

/* 设置SPA MESSAGE数据 */
/* 这段代码是一个名为ztn_set_spa_消息的函数，用于设置一个名为消息的字符串作为SPA（单页申请）消息。 */
int
ztn_set_spa_message(ztn_ctx_t ctx, const char * const msg)
{
    int res = ZTN_ERROR_UNKNOWN;

    /* 必须初始化上下文。 */
    if(!CTX_INITIALIZED(ctx))
        return ZTN_ERROR_CTX_NOT_INITIALIZED;

    /* 必须有一个有效的字符串。 */
    if(msg == NULL || strnlen(msg, MAX_SPA_MESSAGE_SIZE) == 0)
        return(ZTN_ERROR_INVALID_DATA_MESSAGE_EMPTY);

    /* --DSS XXX：暂时退出。但考虑一下 */
    if(strnlen(msg, MAX_SPA_MESSAGE_SIZE) == MAX_SPA_MESSAGE_SIZE)
        return(ZTN_ERROR_DATA_TOO_LARGE);

    /* 基本消息类型和格式检查。。。 */
    if(ctx->message_type == ZTN_COMMAND_MSG)
        res = validate_cmd_msg(msg);
    else
        res = validate_access_msg(msg);

    if(res != ZTN_SUCCESS)
        return(res);

    /* 以防万一这是对该函数的后续调用。我们 */
    if(ctx->message != NULL)
        free(ctx->message);

    ctx->message = strdup(msg);

    ctx->state |= ZTN_DATA_MODIFIED;

    if(ctx->message == NULL)
        return(ZTN_ERROR_MEMORY_ALLOCATION);

    return(ZTN_SUCCESS);
}

/* 返回SPA消息数据。 */
int
ztn_get_spa_message(ztn_ctx_t ctx, char **msg)
{

#if HAVE_LIBFIU
    fiu_return_on("ztn_get_spa_message_init", ZTN_ERROR_CTX_NOT_INITIALIZED);
#endif

    /* 必须初始化 */
    if(!CTX_INITIALIZED(ctx))
        return(ZTN_ERROR_CTX_NOT_INITIALIZED);

    if(msg == NULL)
        return(ZTN_ERROR_INVALID_DATA);

#if HAVE_LIBFIU
    fiu_return_on("ztn_get_spa_message_val", ZTN_ERROR_INVALID_DATA);
#endif

    *msg = ctx->message;

    return(ZTN_SUCCESS);
}

/* 验证命令消息格式。 */
int
validate_cmd_msg(const char *msg)
{
    const char   *ndx;
    int     res         = ZTN_SUCCESS;
    int     startlen    = strnlen(msg, MAX_SPA_CMD_LEN);

    if(startlen == MAX_SPA_CMD_LEN)
        return(ZTN_ERROR_INVALID_DATA_MESSAGE_CMD_MISSING);

    /* 无论消息类型如何，都应始终具有有效的允许IP */
    if((res = have_allow_ip(msg)) != ZTN_SUCCESS)
        return(ZTN_ERROR_INVALID_SPA_COMMAND_MSG);

    /* 命令是相当自由的，所以我们能真正验证的只是 */
    ndx = strchr(msg, ',');
    if(ndx == NULL || (1+(ndx - msg)) >= startlen)
        return(ZTN_ERROR_INVALID_SPA_COMMAND_MSG);

    return(ZTN_SUCCESS);
}

int
validate_access_msg(const char *msg)
{
    const char   *ndx;
    int     res         = ZTN_SUCCESS;
    int     startlen    = strnlen(msg, MAX_SPA_MESSAGE_SIZE);

    if(startlen == MAX_SPA_MESSAGE_SIZE)
        return(ZTN_ERROR_INVALID_DATA_MESSAGE_ACCESS_MISSING);

    /* 无论消息类型如何，都应始终具有有效的允许IP */
    if((res = have_allow_ip(msg)) != ZTN_SUCCESS)
        return(res);

    /* 将自己定位在允许的IP之外，并确保我们 */
    ndx = strchr(msg, ',');
    if(ndx == NULL || (1+(ndx - msg)) >= startlen)
        return(ZTN_ERROR_INVALID_SPA_ACCESS_MSG);

    /* 查找逗号以查看这是否是一个由多部分组成的访问请求。 */
    do {
        ndx++;
        res = validate_proto_port_spec(ndx);
        if(res != ZTN_SUCCESS)
            break;
    } while((ndx = strchr(ndx, ',')));

    return(res);
}

int
validate_nat_access_msg(const char *msg)
{
    const char   *ndx;
    int     host_len;
    int     res         = ZTN_SUCCESS;
    int     startlen    = strnlen(msg, MAX_SPA_MESSAGE_SIZE);

    if(startlen == MAX_SPA_MESSAGE_SIZE)
        return(ZTN_ERROR_INVALID_DATA_MESSAGE_NAT_MISSING);

    /* 这里必须只有一个逗号 */
    if(count_characters(msg, ',', startlen) != 1)
        return(ZTN_ERROR_INVALID_SPA_NAT_ACCESS_MSG);

    /* 不得长于主机名的最大长度 */
    host_len = strcspn(msg, ",");
    if(host_len > MAX_HOSTNAME_LEN)
        return(ZTN_ERROR_INVALID_SPA_NAT_ACCESS_MSG);

    /* 检查一些无效字符 */
    if(strcspn(msg, " /?\"\'\\") < host_len)
        return(ZTN_ERROR_INVALID_SPA_NAT_ACCESS_MSG);

    /* 将自己定位在允许的IP之外，并确保我们 */
    ndx = strchr(msg, ',');
    if(ndx == NULL || (1+(ndx - msg)) >= startlen)
        return(ZTN_ERROR_INVALID_SPA_NAT_ACCESS_MSG);

    ndx++;

    if((res = have_port(ndx)) != ZTN_SUCCESS)
        return(ZTN_ERROR_INVALID_SPA_NAT_ACCESS_MSG);

    if(msg[startlen-1] == ',')
        return(ZTN_ERROR_INVALID_SPA_NAT_ACCESS_MSG);

    return(res);
}

int
validate_proto_port_spec(const char *msg)
{
    int     startlen    = strnlen(msg, MAX_SPA_MESSAGE_SIZE);
    const char   *ndx   = msg;

    if(startlen == MAX_SPA_MESSAGE_SIZE)
        return(ZTN_ERROR_INVALID_DATA_MESSAGE_PORTPROTO_MISSING);

    /* 现在检查proto/port字符串。 */
    if(strncmp(ndx, "tcp", 3)
      && strncmp(ndx, "udp", 3)
      && strncmp(ndx, "icmp", 4)
      && strncmp(ndx, "none", 4))
        return(ZTN_ERROR_INVALID_SPA_ACCESS_MSG);

    ndx = strchr(ndx, '/');
    if(ndx == NULL || ((1+(ndx - msg)) > MAX_PROTO_STR_LEN))
        return(ZTN_ERROR_INVALID_SPA_ACCESS_MSG);

    /* 跳过“/”并确保我们只有数字。 */
    ndx++;

    return have_port(ndx);
}

/* **EOF** */
