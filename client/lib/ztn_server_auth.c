
#include "ztn_common.h"
#include "ztn.h"

/* 设置SPA服务器身份验证数据 */
int
ztn_set_spa_server_auth(ztn_ctx_t ctx, const char * const msg)
{
    /* *************************************** */
    //return(ZTN_ERROR_UNSUPPORTED_FEATURE);

#if HAVE_LIBFIU
    fiu_return_on("ztn_set_spa_server_auth_init", ZTN_ERROR_CTX_NOT_INITIALIZED);
#endif

    /* 必须初始化上下文。 */
    if(!CTX_INITIALIZED(ctx))
        return ZTN_ERROR_CTX_NOT_INITIALIZED;

    /* 必须有一个有效的字符串。 */
    if(msg == NULL || strnlen(msg, MAX_SPA_SERVER_AUTH_SIZE) == 0)
        return(ZTN_ERROR_INVALID_DATA_SRVAUTH_MISSING);

    /* --DSS XXX：暂时退出。但考虑一下 */
    if(strnlen(msg, MAX_SPA_SERVER_AUTH_SIZE) == MAX_SPA_SERVER_AUTH_SIZE)
        return(ZTN_ERROR_DATA_TOO_LARGE);

    /* --DSS TODO：？？？ */

    /**/

    /* 以防万一这是对该函数的后续调用。我们 */
    if(ctx->server_auth != NULL)
        free(ctx->server_auth);

    ctx->server_auth = strdup(msg);

    ctx->state |= ZTN_DATA_MODIFIED;

    if(ctx->server_auth == NULL)
        return(ZTN_ERROR_MEMORY_ALLOCATION);

    return(ZTN_SUCCESS);
}

/* 返回SPA消息数据。 */
int
ztn_get_spa_server_auth(ztn_ctx_t ctx, char **server_auth)
{

#if HAVE_LIBFIU
    fiu_return_on("ztn_get_spa_server_auth_init", ZTN_ERROR_CTX_NOT_INITIALIZED);
#endif

    /* 必须初始化 */
    if(!CTX_INITIALIZED(ctx))
        return(ZTN_ERROR_CTX_NOT_INITIALIZED);

    if(server_auth == NULL)
        return(ZTN_ERROR_INVALID_DATA);

#if HAVE_LIBFIU
    fiu_return_on("ztn_get_spa_server_auth_val", ZTN_ERROR_INVALID_DATA);
#endif

    *server_auth = ctx->server_auth;

    return(ZTN_SUCCESS);
}

/* **EOF** */
