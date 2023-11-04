
#include "fko_common.h"
#include "fko.h"

#ifdef __MINGW32__
  #include "../win32/getlogin.h"
#elif WIN32
  #include <getlogin.h>
#endif

/* 获取或设置fko上下文spa数据的用户名。 */
int
fko_set_username(fko_ctx_t ctx, const char * const spoof_user)
{
    char   *username = NULL;
    int     res = FKO_SUCCESS, is_user_heap_allocated=0;

#if HAVE_LIBFIU
    fiu_return_on("fko_set_username_init", FKO_ERROR_CTX_NOT_INITIALIZED);
#endif

    /* 必须初始化 */
    if(!CTX_INITIALIZED(ctx))
        return FKO_ERROR_CTX_NOT_INITIALIZED;

    /* 如果未传入欺骗用户，请检查spoof_user环境 */
    if(spoof_user != NULL && spoof_user[0] != '\0')
    {
#if HAVE_LIBFIU
        fiu_return_on("fko_set_username_strdup", FKO_ERROR_MEMORY_ALLOCATION);
#endif
        username = strdup(spoof_user);
        if(username == NULL)
            return(FKO_ERROR_MEMORY_ALLOCATION);
        is_user_heap_allocated = 1;
    }
    else
        username = getenv("SPOOF_USER");

    /* 尝试从系统中获取用户名。 */
    if(username == NULL)
    {
        /* 既然我们已经尝试过查看env变量，请尝试 */
        if((username = getenv("LOGNAME")) == NULL)
        {
#ifdef _XOPEN_SOURCE
            /* cuserid将返回有效用户（即su或setuid）。 */
            username = cuserid(NULL);
#else
            username = getlogin();
#endif
            /* 如果我们仍然没有得到用户名，继续后退 */
            if(username == NULL)
            {
                if((username = getenv("USER")) == NULL)
                {
                    username = strdup("NO_USER");
                    if(username == NULL)
                        return(FKO_ERROR_MEMORY_ALLOCATION);
                    is_user_heap_allocated = 1;
                }
            }
        }
    }

    /* 如果用户名太长，请截断用户名。 */
    if(strnlen(username, MAX_SPA_USERNAME_SIZE) == MAX_SPA_USERNAME_SIZE)
        *(username + MAX_SPA_USERNAME_SIZE - 1) = '\0';

    if((res = validate_username(username)) != FKO_SUCCESS)
    {
        if(is_user_heap_allocated == 1)
            free(username);
#if HAVE_LIBFIU
        fiu_return_on("fko_set_username_valuser", FKO_ERROR_INVALID_DATA);
#endif
        return res;
    }

    /* 以防万一这是对该函数的后续调用。我们 */
    if(ctx->username != NULL)
        free(ctx->username);

    ctx->username = strdup(username);

    ctx->state |= FKO_DATA_MODIFIED;

    if(is_user_heap_allocated == 1)
        free(username);

    if(ctx->username == NULL)
        return(FKO_ERROR_MEMORY_ALLOCATION);

    return(FKO_SUCCESS);
}

/* 返回此fko上下文的当前用户名。 */
int
fko_get_username(fko_ctx_t ctx, char **username)
{

#if HAVE_LIBFIU
    fiu_return_on("fko_get_username_init", FKO_ERROR_CTX_NOT_INITIALIZED);
#endif

    /* 必须初始化 */
    if(!CTX_INITIALIZED(ctx))
        return(FKO_ERROR_CTX_NOT_INITIALIZED);

    if(username == NULL)
        return(FKO_ERROR_INVALID_DATA);

#if HAVE_LIBFIU
    fiu_return_on("fko_get_username_val", FKO_ERROR_INVALID_DATA);
#endif

    *username = ctx->username;

    return(FKO_SUCCESS);
}

int
validate_username(const char *username)
{
    int i;

    if(username == NULL || strnlen(username, MAX_SPA_USERNAME_SIZE) == 0)
        return(FKO_ERROR_INVALID_DATA_USER_MISSING);

    /* 排除几个字符-此列表与MS指南一致，因为 */
    for (i=0; i < (int)strnlen(username, MAX_SPA_USERNAME_SIZE); i++)
    {
        if((isalnum((int)(unsigned char)username[i]) == 0)
                && ((username[i] < 0x20 || username[i] > 0x7e)
                /* 不允许使用字符：“/\[]：；|=，+*？>> */
                || (username[i] == 0x22
                    || username[i] == 0x2f
                    || username[i] == 0x5c
                    || username[i] == 0x5b
                    || username[i] == 0x5d
                    || username[i] == 0x3a
                    || username[i] == 0x3b
                    || username[i] == 0x7c
                    || username[i] == 0x3d
                    || username[i] == 0x2c
                    || username[i] == 0x2b
                    || username[i] == 0x2a
                    || username[i] == 0x3f
                    || username[i] == 0x3c
                    || username[i] == 0x3e)))
        {
            if(i == 0)
            {
                return(FKO_ERROR_INVALID_DATA_USER_FIRSTCHAR_VALIDFAIL);
            }
            else
            {
                return(FKO_ERROR_INVALID_DATA_USER_REMCHAR_VALIDFAIL);
            }
        }
    }

    return FKO_SUCCESS;
}

/* **EOF** */
