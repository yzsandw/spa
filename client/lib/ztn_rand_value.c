
#include "ztn_common.h"
#include "ztn.h"

#ifdef WIN32
  #include <sys/timeb.h>
  #include <time.h>
#else
  #ifdef HAVE_SYS_TIME_H
    #include <sys/time.h>
    #ifdef TIME_WITH_SYS_TIME
      #include <time.h>
    #endif
  #endif

  #define RAND_FILE "/dev/urandom"
#endif

/* 设置/生成SPA数据随机值字符串。 */
int
ztn_set_rand_value(ztn_ctx_t ctx, const char * const new_val)
{
#ifdef WIN32
	struct _timeb	tb;
#else
    FILE           *rfd;
    struct timeval  tv;
    size_t          amt_read;
#endif
    unsigned long   seed;
    char           *tmp_buf;

#if HAVE_LIBFIU
    fiu_return_on("ztn_set_rand_value_init", ZTN_ERROR_CTX_NOT_INITIALIZED);
#endif

    /* 必须初始化上下文。 */
    if(!CTX_INITIALIZED(ctx))
        return ZTN_ERROR_CTX_NOT_INITIALIZED;

    /* 如果给定了一个有效的值，请使用它并返回happy。 */
    if(new_val != NULL)
    {

#if HAVE_LIBFIU
        fiu_return_on("ztn_set_rand_value_lenval", ZTN_ERROR_INVALID_DATA_RAND_LEN_VALIDFAIL);
#endif
        if(strnlen(new_val, ZTN_RAND_VAL_SIZE+1) != ZTN_RAND_VAL_SIZE)
            return(ZTN_ERROR_INVALID_DATA_RAND_LEN_VALIDFAIL);

        if(ctx->rand_val != NULL)
            free(ctx->rand_val);

#if HAVE_LIBFIU
        fiu_return_on("ztn_set_rand_value_strdup", ZTN_ERROR_MEMORY_ALLOCATION);
#endif
        ctx->rand_val = strdup(new_val);
        if(ctx->rand_val == NULL)
            return(ZTN_ERROR_MEMORY_ALLOCATION);

        ctx->state |= ZTN_DATA_MODIFIED;

        return(ZTN_SUCCESS);
    }

#ifdef WIN32
	_ftime_s(&tb);
	seed = ((tb.time * 1000) + tb.millitm) & 0xFFFFFFFF;
#else
    /* 尝试从/dev/urandom读取种子数据。如果没有 */
    if((rfd = fopen(RAND_FILE, "r")) != NULL)
    {
        /* 从/dev/urandom读取种子 */
        amt_read = fread(&seed, 4, 1, rfd);
        fclose(rfd);

#if HAVE_LIBFIU
        fiu_return_on("ztn_set_rand_value_read", ZTN_ERROR_FILESYSTEM_OPERATION);
#endif
        if (amt_read != 1)
            return(ZTN_ERROR_FILESYSTEM_OPERATION);
    }
    else
    {
        /* 基于时间的种子（当前用途）。 */
        gettimeofday(&tv, NULL);

        seed = tv.tv_usec;
    }
#endif

    srand(seed);

    if(ctx->rand_val != NULL)
        free(ctx->rand_val);

#if HAVE_LIBFIU
        fiu_return_on("ztn_set_rand_value_calloc1", ZTN_ERROR_MEMORY_ALLOCATION);
#endif
    ctx->rand_val = calloc(1, ZTN_RAND_VAL_SIZE+1);
    if(ctx->rand_val == NULL)
            return(ZTN_ERROR_MEMORY_ALLOCATION);

#if HAVE_LIBFIU
        fiu_return_on("ztn_set_rand_value_calloc2", ZTN_ERROR_MEMORY_ALLOCATION);
#endif
    tmp_buf = calloc(1, ZTN_RAND_VAL_SIZE+1);
    if(tmp_buf == NULL)
            return(ZTN_ERROR_MEMORY_ALLOCATION);

    snprintf(ctx->rand_val, ZTN_RAND_VAL_SIZE, "%u", rand());

    while(strnlen(ctx->rand_val, ZTN_RAND_VAL_SIZE+1) < ZTN_RAND_VAL_SIZE)
    {
        snprintf(tmp_buf, ZTN_RAND_VAL_SIZE, "%u", rand());
        strlcat(ctx->rand_val, tmp_buf, ZTN_RAND_VAL_SIZE+1);
    }

    free(tmp_buf);

    ctx->state |= ZTN_DATA_MODIFIED;

    return(ZTN_SUCCESS);
}

/* 返回当前rand值。 */
int
ztn_get_rand_value(ztn_ctx_t ctx, char **rand_value)
{
    /* 必须初始化 */
    if(!CTX_INITIALIZED(ctx))
        return(ZTN_ERROR_CTX_NOT_INITIALIZED);

    if(rand_value == NULL)
        return(ZTN_ERROR_INVALID_DATA);

    *rand_value = ctx->rand_val;

    return(ZTN_SUCCESS);
}

/* **EOF** */
