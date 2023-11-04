
#include "fko_common.h"
#include "fko.h"


/* 设置时间戳。 */
int
fko_set_timestamp(fko_ctx_t ctx, const int offset)
{
    time_t ts;

#if HAVE_LIBFIU
    fiu_return_on("fko_set_timestamp_init", FKO_ERROR_CTX_NOT_INITIALIZED);
#endif

    /* 必须初始化 */
    if(!CTX_INITIALIZED(ctx))
        return FKO_ERROR_CTX_NOT_INITIALIZED;

    ts = time(NULL) + offset;

#if HAVE_LIBFIU
    fiu_return_on("fko_set_timestamp_val",
            FKO_ERROR_INVALID_DATA_TIMESTAMP_VALIDFAIL);
#endif
    if(ts < 0)
        return(FKO_ERROR_INVALID_DATA_TIMESTAMP_VALIDFAIL);

    ctx->timestamp = ts;

    ctx->state |= FKO_DATA_MODIFIED;

    return(FKO_SUCCESS);
}

/* 返回当前时间戳。 */
int
fko_get_timestamp(fko_ctx_t ctx, time_t *timestamp)
{

#if HAVE_LIBFIU
    fiu_return_on("fko_get_timestamp_init", FKO_ERROR_CTX_NOT_INITIALIZED);
#endif

    /* 必须初始化 */
    if(!CTX_INITIALIZED(ctx))
        return(FKO_ERROR_CTX_NOT_INITIALIZED);

    if(timestamp == NULL)
        return(FKO_ERROR_INVALID_DATA);

#if HAVE_LIBFIU
    fiu_return_on("fko_get_timestamp_val", FKO_ERROR_INVALID_DATA);
#endif

    *timestamp = ctx->timestamp;

    return(FKO_SUCCESS);
}

/* **EOF** */
