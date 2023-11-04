
#include "fko_common.h"
#include "fko.h"
#include "digest.h"

/* 设置SPA摘要类型。 */
static int
set_spa_digest_type(fko_ctx_t ctx,
    short *digest_type_field, const short digest_type)
{
#if HAVE_LIBFIU
    fiu_return_on("set_spa_digest_type_init", FKO_ERROR_CTX_NOT_INITIALIZED);
#endif
    /* 必须初始化 */
    if(!CTX_INITIALIZED(ctx))
        return(FKO_ERROR_CTX_NOT_INITIALIZED);

#if HAVE_LIBFIU
    fiu_return_on("set_spa_digest_type_val",
            FKO_ERROR_INVALID_DATA_ENCODE_DIGEST_VALIDFAIL);
#endif
    if(digest_type < 1 || digest_type >= FKO_LAST_DIGEST_TYPE)
        return(FKO_ERROR_INVALID_DATA_ENCODE_DIGEST_VALIDFAIL);

    *digest_type_field = digest_type;

    ctx->state |= FKO_DIGEST_TYPE_MODIFIED;

    return(FKO_SUCCESS);
}

int
fko_set_spa_digest_type(fko_ctx_t ctx, const short digest_type)
{
    return set_spa_digest_type(ctx, &ctx->digest_type, digest_type);
}

int
fko_set_raw_spa_digest_type(fko_ctx_t ctx, const short raw_digest_type)
{
    return set_spa_digest_type(ctx, &ctx->raw_digest_type, raw_digest_type);
}

/* 返回SPA摘要类型。 */
int
fko_get_spa_digest_type(fko_ctx_t ctx, short *digest_type)
{
#if HAVE_LIBFIU
    fiu_return_on("fko_get_spa_digest_type_init",
            FKO_ERROR_CTX_NOT_INITIALIZED);
#endif
    /* 必须初始化 */
    if(!CTX_INITIALIZED(ctx))
        return(FKO_ERROR_CTX_NOT_INITIALIZED);

#if HAVE_LIBFIU
    fiu_return_on("fko_get_spa_digest_type_val",
            FKO_ERROR_INVALID_DATA);
#endif

    if(digest_type == NULL)
        return(FKO_ERROR_INVALID_DATA);

    *digest_type = ctx->digest_type;

    return(FKO_SUCCESS);
}

/* 返回SPA摘要类型。 */
int
fko_get_raw_spa_digest_type(fko_ctx_t ctx, short *raw_digest_type)
{
#if HAVE_LIBFIU
    fiu_return_on("fko_get_raw_spa_digest_type_init",
            FKO_ERROR_CTX_NOT_INITIALIZED);
#endif
    /* 必须初始化 */
    if(!CTX_INITIALIZED(ctx))
        return(FKO_ERROR_CTX_NOT_INITIALIZED);

    if(raw_digest_type == NULL)
        return(FKO_ERROR_INVALID_DATA);

    *raw_digest_type = ctx->raw_digest_type;

    return(FKO_SUCCESS);
}

//将数据进行签名
static int
set_digest(char *data, char **digest, short digest_type, int *digest_len)
{
    char    *md = NULL;
    int     data_len;

    data_len = strnlen(data, MAX_SPA_ENCODED_MSG_SIZE);

#if HAVE_LIBFIU
    fiu_return_on("set_digest_toobig",
            FKO_ERROR_INVALID_DATA_ENCODE_DIGEST_TOOBIG);
#endif

    if(data_len == MAX_SPA_ENCODED_MSG_SIZE)
        return(FKO_ERROR_INVALID_DATA_ENCODE_DIGEST_TOOBIG);

#if HAVE_LIBFIU
    fiu_return_on("set_digest_invalidtype", FKO_ERROR_INVALID_DIGEST_TYPE);
    fiu_return_on("set_digest_calloc", FKO_ERROR_MEMORY_ALLOCATION);
#endif

    switch(digest_type)
    {
        case FKO_DIGEST_MD5:
            md = calloc(1, MD_HEX_SIZE(MD5_DIGEST_LEN)+1);
            if(md == NULL)
                return(FKO_ERROR_MEMORY_ALLOCATION);

            md5_base64(md,
                (unsigned char*)data, data_len);
            *digest_len = MD5_B64_LEN;
            break;

        case FKO_DIGEST_SHA1:
            md = calloc(1, MD_HEX_SIZE(SHA1_DIGEST_LEN)+1);
            if(md == NULL)
                return(FKO_ERROR_MEMORY_ALLOCATION);

            sha1_base64(md,
                (unsigned char*)data, data_len);
            *digest_len = SHA1_B64_LEN;
            break;

        case FKO_DIGEST_SHA256:
            md = calloc(1, MD_HEX_SIZE(SHA256_DIGEST_LEN)+1);
            if(md == NULL)
                return(FKO_ERROR_MEMORY_ALLOCATION);

            sha256_base64(md,
                (unsigned char*)data, data_len);
            *digest_len = SHA256_B64_LEN;
            break;

        case FKO_DIGEST_SHA384:
            md = calloc(1, MD_HEX_SIZE(SHA384_DIGEST_LEN)+1);
            if(md == NULL)
                return(FKO_ERROR_MEMORY_ALLOCATION);

            sha384_base64(md,
                (unsigned char*)data, data_len);
            *digest_len = SHA384_B64_LEN;
            break;

        case FKO_DIGEST_SHA512:
            md = calloc(1, MD_HEX_SIZE(SHA512_DIGEST_LEN)+1);
            if(md == NULL)
                return(FKO_ERROR_MEMORY_ALLOCATION);

            sha512_base64(md,
                (unsigned char*)data, data_len);
            *digest_len = SHA512_B64_LEN;
            break;

        case FKO_DIGEST_SHA3_256:
            md = calloc(1, MD_HEX_SIZE(SHA3_256_DIGEST_LEN)+1);
            if(md == NULL)
                return(FKO_ERROR_MEMORY_ALLOCATION);

            sha3_256_base64(md,
                (unsigned char*)data, data_len);
            *digest_len = SHA3_256_B64_LEN;
            break;

        case FKO_DIGEST_SHA3_512:
            md = calloc(1, MD_HEX_SIZE(SHA3_512_DIGEST_LEN)+1);
            if(md == NULL)
                return(FKO_ERROR_MEMORY_ALLOCATION);

            sha3_512_base64(md,
                (unsigned char*)data, data_len);
            *digest_len = SHA3_512_B64_LEN;
            break;

        default:
            return(FKO_ERROR_INVALID_DIGEST_TYPE);
    }

    /* 以防万一这是对该函数的后续调用。我们 */
    if(*digest != NULL)
        free(*digest);

    *digest = md;

    return(FKO_SUCCESS);
}

//设置spa消息摘要
int
fko_set_spa_digest(fko_ctx_t ctx)
{
#if HAVE_LIBFIU
    fiu_return_on("fko_set_spa_digest_init", FKO_ERROR_CTX_NOT_INITIALIZED);
#endif
    /* 必须初始化 */
    if(!CTX_INITIALIZED(ctx))
        return(FKO_ERROR_CTX_NOT_INITIALIZED);

    /* 必须具有编码的消息数据才能开始。 */
   //判断是否编码过
    if(ctx->encoded_msg == NULL)
        return(FKO_ERROR_MISSING_ENCODED_DATA);

#if HAVE_LIBFIU
    fiu_return_on("fko_set_spa_digest_encoded", FKO_ERROR_MISSING_ENCODED_DATA);
#endif

    //将编码过后的消息进行哈希生成消息摘要
    return set_digest(ctx->encoded_msg, &ctx->digest,
        ctx->digest_type, &ctx->digest_len);
}

int
fko_set_raw_spa_digest(fko_ctx_t ctx)
{
#if HAVE_LIBFIU
    fiu_return_on("fko_set_raw_spa_digest_init", FKO_ERROR_CTX_NOT_INITIALIZED);
#endif
    /* 必须初始化 */
    if(!CTX_INITIALIZED(ctx))
        return(FKO_ERROR_CTX_NOT_INITIALIZED);

    /* 必须具有编码的消息数据才能开始。 */
    if(ctx->encrypted_msg == NULL)
        return(FKO_ERROR_MISSING_ENCODED_DATA);

#if HAVE_LIBFIU
    fiu_return_on("fko_set_raw_spa_digest_val", FKO_ERROR_MISSING_ENCODED_DATA);
#endif

    return set_digest(ctx->encrypted_msg, &ctx->raw_digest,
        ctx->raw_digest_type, &ctx->raw_digest_len);
}

int
fko_get_spa_digest(fko_ctx_t ctx, char **md)
{
#if HAVE_LIBFIU
    fiu_return_on("fko_get_spa_digest_init", FKO_ERROR_CTX_NOT_INITIALIZED);
#endif
    /* 必须初始化 */
    if(!CTX_INITIALIZED(ctx))
        return(FKO_ERROR_CTX_NOT_INITIALIZED);

#if HAVE_LIBFIU
    fiu_return_on("fko_get_spa_digest_val", FKO_ERROR_INVALID_DATA);
#endif
    if(md == NULL)
        return(FKO_ERROR_INVALID_DATA);

    *md = ctx->digest;

    return(FKO_SUCCESS);
}

int
fko_get_raw_spa_digest(fko_ctx_t ctx, char **md)
{
#if HAVE_LIBFIU
    fiu_return_on("fko_get_raw_spa_digest_init", FKO_ERROR_CTX_NOT_INITIALIZED);
#endif
    /* 必须初始化 */
    if(!CTX_INITIALIZED(ctx))
        return(FKO_ERROR_CTX_NOT_INITIALIZED);

    *md = ctx->raw_digest;

    return(FKO_SUCCESS);
}

/* **EOF** */
