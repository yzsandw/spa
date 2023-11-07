
#include "ztn_common.h"
#include "ztn.h"


/* 设置时间戳。 */
int
ztn_set_timestamp(ztn_ctx_t ctx, const int offset)
{
    time_t ts;

#if HAVE_LIBFIU
    fiu_return_on("ztn_set_timestamp_init", ZTN_ERROR_CTX_NOT_INITIALIZED);
#endif

    /* 必须初始化 */
    if(!CTX_INITIALIZED(ctx))
        return ZTN_ERROR_CTX_NOT_INITIALIZED;

    ts = time(NULL) + offset;

#if HAVE_LIBFIU
    fiu_return_on("ztn_set_timestamp_val",
            ZTN_ERROR_INVALID_DATA_TIMESTAMP_VALIDFAIL);
#endif
    if(ts < 0)
        return(ZTN_ERROR_INVALID_DATA_TIMESTAMP_VALIDFAIL);

    ctx->timestamp = ts;

    ctx->state |= ZTN_DATA_MODIFIED;

    return(ZTN_SUCCESS);
}

/* 返回当前时间戳。 */
int
ztn_get_timestamp(ztn_ctx_t ctx, time_t *timestamp)
{

#if HAVE_LIBFIU
    fiu_return_on("ztn_get_timestamp_init", ZTN_ERROR_CTX_NOT_INITIALIZED);
#endif

    /* 必须初始化 */
    if(!CTX_INITIALIZED(ctx))
        return(ZTN_ERROR_CTX_NOT_INITIALIZED);

    if(timestamp == NULL)
        return(ZTN_ERROR_INVALID_DATA);

#if HAVE_LIBFIU
    fiu_return_on("ztn_get_timestamp_val", ZTN_ERROR_INVALID_DATA);
#endif

    *timestamp = ctx->timestamp;

    return(ZTN_SUCCESS);
}

/* **EOF** */
