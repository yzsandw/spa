
#include "fko_common.h"
#include "fko.h"

/* 设置SPA Nat Access数据 */
int
fko_set_spa_nat_access(fko_ctx_t ctx, const char * const msg)
{
    int res = FKO_SUCCESS;

#if HAVE_LIBFIU
    fiu_return_on("fko_set_spa_nat_access_init", FKO_ERROR_CTX_NOT_INITIALIZED);
#endif

    /* 必须初始化上下文。 */
    if(!CTX_INITIALIZED(ctx))
        return FKO_ERROR_CTX_NOT_INITIALIZED;

    /* 必须有一个有效的字符串。 */
    if(msg == NULL || strnlen(msg, MAX_SPA_NAT_ACCESS_SIZE) == 0)
        return(FKO_ERROR_INVALID_DATA_NAT_EMPTY);

#if HAVE_LIBFIU
    fiu_return_on("fko_set_spa_nat_access_empty", FKO_ERROR_INVALID_DATA_NAT_EMPTY);
#endif

    /* --DSS XXX：暂时退出。但考虑一下 */
    if(strnlen(msg, MAX_SPA_NAT_ACCESS_SIZE) == MAX_SPA_NAT_ACCESS_SIZE)
        return(FKO_ERROR_DATA_TOO_LARGE);

#if HAVE_LIBFIU
    fiu_return_on("fko_set_spa_nat_access_large", FKO_ERROR_DATA_TOO_LARGE);
#endif

    if((res = validate_nat_access_msg(msg)) != FKO_SUCCESS)
        return(res);

    /* 以防万一这是对该函数的后续调用。我们 */
    if(ctx->nat_access != NULL)
        free(ctx->nat_access);

    ctx->nat_access = strdup(msg);

    ctx->state |= FKO_DATA_MODIFIED;

    if(ctx->nat_access == NULL)
        return(FKO_ERROR_MEMORY_ALLOCATION);

    /* 如果我们设置nat_access消息，那么我们强制执行message_type */
    if(ctx->client_timeout > 0)
    {
        if(ctx->message_type != FKO_CLIENT_TIMEOUT_LOCAL_NAT_ACCESS_MSG)
            ctx->message_type = FKO_CLIENT_TIMEOUT_NAT_ACCESS_MSG;
    }
    else
        if(ctx->message_type != FKO_LOCAL_NAT_ACCESS_MSG
                && ctx->message_type != FKO_CLIENT_TIMEOUT_LOCAL_NAT_ACCESS_MSG)
            ctx->message_type = FKO_NAT_ACCESS_MSG;

    return(FKO_SUCCESS);
}

/* 返回SPA消息数据。 */
int
fko_get_spa_nat_access(fko_ctx_t ctx, char **nat_access)
{

#if HAVE_LIBFIU
    fiu_return_on("fko_get_spa_nat_access_init", FKO_ERROR_CTX_NOT_INITIALIZED);
#endif

    /* 必须初始化 */
    if(!CTX_INITIALIZED(ctx))
        return(FKO_ERROR_CTX_NOT_INITIALIZED);

    if(nat_access == NULL)
        return(FKO_ERROR_INVALID_DATA);

#if HAVE_LIBFIU
    fiu_return_on("fko_get_spa_nat_access_val", FKO_ERROR_INVALID_DATA);
#endif

    *nat_access = ctx->nat_access;

    return(FKO_SUCCESS);
}

/* **EOF** */
