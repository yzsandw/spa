
#include "ztn_common.h"
#include "ztn.h"

/* 设置SPA Nat Access数据 */
int
ztn_set_spa_nat_access(ztn_ctx_t ctx, const char * const msg)
{
    int res = ZTN_SUCCESS;

#if HAVE_LIBFIU
    fiu_return_on("ztn_set_spa_nat_access_init", ZTN_ERROR_CTX_NOT_INITIALIZED);
#endif

    /* 必须初始化上下文。 */
    if(!CTX_INITIALIZED(ctx))
        return ZTN_ERROR_CTX_NOT_INITIALIZED;

    /* 必须有一个有效的字符串。 */
    if(msg == NULL || strnlen(msg, MAX_SPA_NAT_ACCESS_SIZE) == 0)
        return(ZTN_ERROR_INVALID_DATA_NAT_EMPTY);

#if HAVE_LIBFIU
    fiu_return_on("ztn_set_spa_nat_access_empty", ZTN_ERROR_INVALID_DATA_NAT_EMPTY);
#endif

    /* --DSS XXX：暂时退出。但考虑一下 */
    if(strnlen(msg, MAX_SPA_NAT_ACCESS_SIZE) == MAX_SPA_NAT_ACCESS_SIZE)
        return(ZTN_ERROR_DATA_TOO_LARGE);

#if HAVE_LIBFIU
    fiu_return_on("ztn_set_spa_nat_access_large", ZTN_ERROR_DATA_TOO_LARGE);
#endif

    if((res = validate_nat_access_msg(msg)) != ZTN_SUCCESS)
        return(res);

    /* 以防万一这是对该函数的后续调用。我们 */
    if(ctx->nat_access != NULL)
        free(ctx->nat_access);

    ctx->nat_access = strdup(msg);

    ctx->state |= ZTN_DATA_MODIFIED;

    if(ctx->nat_access == NULL)
        return(ZTN_ERROR_MEMORY_ALLOCATION);

    /* 如果我们设置nat_access消息，那么我们强制执行message_type */
    if(ctx->client_timeout > 0)
    {
        if(ctx->message_type != ZTN_CLIENT_TIMEOUT_LOCAL_NAT_ACCESS_MSG)
            ctx->message_type = ZTN_CLIENT_TIMEOUT_NAT_ACCESS_MSG;
    }
    else
        if(ctx->message_type != ZTN_LOCAL_NAT_ACCESS_MSG
                && ctx->message_type != ZTN_CLIENT_TIMEOUT_LOCAL_NAT_ACCESS_MSG)
            ctx->message_type = ZTN_NAT_ACCESS_MSG;

    return(ZTN_SUCCESS);
}

/* 返回SPA消息数据。 */
int
ztn_get_spa_nat_access(ztn_ctx_t ctx, char **nat_access)
{

#if HAVE_LIBFIU
    fiu_return_on("ztn_get_spa_nat_access_init", ZTN_ERROR_CTX_NOT_INITIALIZED);
#endif

    /* 必须初始化 */
    if(!CTX_INITIALIZED(ctx))
        return(ZTN_ERROR_CTX_NOT_INITIALIZED);

    if(nat_access == NULL)
        return(ZTN_ERROR_INVALID_DATA);

#if HAVE_LIBFIU
    fiu_return_on("ztn_get_spa_nat_access_val", ZTN_ERROR_INVALID_DATA);
#endif

    *nat_access = ctx->nat_access;

    return(ZTN_SUCCESS);
}

/* **EOF** */
