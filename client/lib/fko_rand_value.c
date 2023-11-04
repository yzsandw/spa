
#include "fko_common.h"
#include "fko.h"

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
fko_set_rand_value(fko_ctx_t ctx, const char * const new_val)
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
    fiu_return_on("fko_set_rand_value_init", FKO_ERROR_CTX_NOT_INITIALIZED);
#endif

    /* 必须初始化上下文。 */
    if(!CTX_INITIALIZED(ctx))
        return FKO_ERROR_CTX_NOT_INITIALIZED;

    /* 如果给定了一个有效的值，请使用它并返回happy。 */
    if(new_val != NULL)
    {

#if HAVE_LIBFIU
        fiu_return_on("fko_set_rand_value_lenval", FKO_ERROR_INVALID_DATA_RAND_LEN_VALIDFAIL);
#endif
        if(strnlen(new_val, FKO_RAND_VAL_SIZE+1) != FKO_RAND_VAL_SIZE)
            return(FKO_ERROR_INVALID_DATA_RAND_LEN_VALIDFAIL);

        if(ctx->rand_val != NULL)
            free(ctx->rand_val);

#if HAVE_LIBFIU
        fiu_return_on("fko_set_rand_value_strdup", FKO_ERROR_MEMORY_ALLOCATION);
#endif
        ctx->rand_val = strdup(new_val);
        if(ctx->rand_val == NULL)
            return(FKO_ERROR_MEMORY_ALLOCATION);

        ctx->state |= FKO_DATA_MODIFIED;

        return(FKO_SUCCESS);
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
        fiu_return_on("fko_set_rand_value_read", FKO_ERROR_FILESYSTEM_OPERATION);
#endif
        if (amt_read != 1)
            return(FKO_ERROR_FILESYSTEM_OPERATION);
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
        fiu_return_on("fko_set_rand_value_calloc1", FKO_ERROR_MEMORY_ALLOCATION);
#endif
    ctx->rand_val = calloc(1, FKO_RAND_VAL_SIZE+1);
    if(ctx->rand_val == NULL)
            return(FKO_ERROR_MEMORY_ALLOCATION);

#if HAVE_LIBFIU
        fiu_return_on("fko_set_rand_value_calloc2", FKO_ERROR_MEMORY_ALLOCATION);
#endif
    tmp_buf = calloc(1, FKO_RAND_VAL_SIZE+1);
    if(tmp_buf == NULL)
            return(FKO_ERROR_MEMORY_ALLOCATION);

    snprintf(ctx->rand_val, FKO_RAND_VAL_SIZE, "%u", rand());

    while(strnlen(ctx->rand_val, FKO_RAND_VAL_SIZE+1) < FKO_RAND_VAL_SIZE)
    {
        snprintf(tmp_buf, FKO_RAND_VAL_SIZE, "%u", rand());
        strlcat(ctx->rand_val, tmp_buf, FKO_RAND_VAL_SIZE+1);
    }

    free(tmp_buf);

    ctx->state |= FKO_DATA_MODIFIED;

    return(FKO_SUCCESS);
}

/* 返回当前rand值。 */
int
fko_get_rand_value(fko_ctx_t ctx, char **rand_value)
{
    /* 必须初始化 */
    if(!CTX_INITIALIZED(ctx))
        return(FKO_ERROR_CTX_NOT_INITIALIZED);

    if(rand_value == NULL)
        return(FKO_ERROR_INVALID_DATA);

    *rand_value = ctx->rand_val;

    return(FKO_SUCCESS);
}

/* **EOF** */
