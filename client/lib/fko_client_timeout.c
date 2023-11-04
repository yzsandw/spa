
#include "fko_common.h"
#include "fko.h"

/* 设置SPA客户端超时数据 */
int
fko_set_spa_client_timeout(fko_ctx_t ctx, const int timeout)
{
    int     old_msg_type;

    /* 必须初始化上下文。 */
    if(!CTX_INITIALIZED(ctx))
        return FKO_ERROR_CTX_NOT_INITIALIZED;

    /* 超时不应为负数 */
    if(timeout < 0)
        return(FKO_ERROR_INVALID_DATA_CLIENT_TIMEOUT_NEGATIVE);

    old_msg_type = ctx->message_type;

    ctx->client_timeout = timeout;

    ctx->state |= FKO_DATA_MODIFIED;

    /* 如果设置了超时，那么我们可能需要验证/更改消息 */
    if(ctx->client_timeout > 0)
    {
        switch(ctx->message_type)
        {
            case FKO_ACCESS_MSG:
                ctx->message_type = FKO_CLIENT_TIMEOUT_ACCESS_MSG;
                break;

            case FKO_NAT_ACCESS_MSG:
                ctx->message_type = FKO_CLIENT_TIMEOUT_NAT_ACCESS_MSG;
                break;

            case FKO_LOCAL_NAT_ACCESS_MSG:
                ctx->message_type = FKO_CLIENT_TIMEOUT_LOCAL_NAT_ACCESS_MSG;
                break;
        }
    }
    else  /* 超时为0，表示忽略它。 */
    {
        switch(ctx->message_type)
        {
            case FKO_CLIENT_TIMEOUT_ACCESS_MSG:
                ctx->message_type = FKO_ACCESS_MSG;
                break;

            case FKO_CLIENT_TIMEOUT_NAT_ACCESS_MSG:
                ctx->message_type = FKO_NAT_ACCESS_MSG;
                break;

            case FKO_CLIENT_TIMEOUT_LOCAL_NAT_ACCESS_MSG:
                ctx->message_type = FKO_LOCAL_NAT_ACCESS_MSG;
                break;
        }
    }

    if(ctx->message_type != old_msg_type)
        ctx->state |= FKO_SPA_MSG_TYPE_MODIFIED;

    return(FKO_SUCCESS);
}

/* 返回SPA消息数据。 */
int
fko_get_spa_client_timeout(fko_ctx_t ctx, int *timeout)
{

#if HAVE_LIBFIU
    fiu_return_on("fko_get_spa_client_timeout_init",
            FKO_ERROR_CTX_NOT_INITIALIZED);
#endif

    /* 必须初始化 */
    if(!CTX_INITIALIZED(ctx))
        return(FKO_ERROR_CTX_NOT_INITIALIZED);

    if(timeout == NULL)
        return(FKO_ERROR_INVALID_DATA);

#if HAVE_LIBFIU
    fiu_return_on("fko_get_spa_client_timeout_val",
            FKO_ERROR_INVALID_DATA);
#endif

    *timeout = ctx->client_timeout;

    return(FKO_SUCCESS);
}

/* **EOF** */
