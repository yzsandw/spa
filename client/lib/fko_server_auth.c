
#include "fko_common.h"
#include "fko.h"

/* 设置SPA服务器身份验证数据 */
int
fko_set_spa_server_auth(fko_ctx_t ctx, const char * const msg)
{
    /* *************************************** */
    //return(FKO_ERROR_UNSUPPORTED_FEATURE);

#if HAVE_LIBFIU
    fiu_return_on("fko_set_spa_server_auth_init", FKO_ERROR_CTX_NOT_INITIALIZED);
#endif

    /* 必须初始化上下文。 */
    if(!CTX_INITIALIZED(ctx))
        return FKO_ERROR_CTX_NOT_INITIALIZED;

    /* 必须有一个有效的字符串。 */
    if(msg == NULL || strnlen(msg, MAX_SPA_SERVER_AUTH_SIZE) == 0)
        return(FKO_ERROR_INVALID_DATA_SRVAUTH_MISSING);

    /* --DSS XXX：暂时退出。但考虑一下 */
    if(strnlen(msg, MAX_SPA_SERVER_AUTH_SIZE) == MAX_SPA_SERVER_AUTH_SIZE)
        return(FKO_ERROR_DATA_TOO_LARGE);

    /* --DSS TODO：？？？ */

    /**/

    /* 以防万一这是对该函数的后续调用。我们 */
    if(ctx->server_auth != NULL)
        free(ctx->server_auth);

    ctx->server_auth = strdup(msg);

    ctx->state |= FKO_DATA_MODIFIED;

    if(ctx->server_auth == NULL)
        return(FKO_ERROR_MEMORY_ALLOCATION);

    return(FKO_SUCCESS);
}

/* 返回SPA消息数据。 */
int
fko_get_spa_server_auth(fko_ctx_t ctx, char **server_auth)
{

#if HAVE_LIBFIU
    fiu_return_on("fko_get_spa_server_auth_init", FKO_ERROR_CTX_NOT_INITIALIZED);
#endif

    /* 必须初始化 */
    if(!CTX_INITIALIZED(ctx))
        return(FKO_ERROR_CTX_NOT_INITIALIZED);

    if(server_auth == NULL)
        return(FKO_ERROR_INVALID_DATA);

#if HAVE_LIBFIU
    fiu_return_on("fko_get_spa_server_auth_val", FKO_ERROR_INVALID_DATA);
#endif

    *server_auth = ctx->server_auth;

    return(FKO_SUCCESS);
}

/* **EOF** */
