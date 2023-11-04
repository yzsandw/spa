
#include "fko_common.h"
#include "fko.h"
#include "cipher_funcs.h"
#include "hmac.h"
#include "base64.h"

int
fko_verify_hmac(fko_ctx_t ctx,
    const char * const hmac_key, const int hmac_key_len)
{
    char    *hmac_digest_from_data = NULL;
    char    *tbuf = NULL;
    int      res = FKO_SUCCESS;
    int      hmac_b64_digest_len = 0, zero_free_rv = FKO_SUCCESS;

    /* 必须初始化 */
    if(!CTX_INITIALIZED(ctx))
        return(FKO_ERROR_CTX_NOT_INITIALIZED);

    if(hmac_key == NULL)
        return(FKO_ERROR_INVALID_DATA);

    if (! is_valid_encoded_msg_len(ctx->encrypted_msg_len))
        return(FKO_ERROR_INVALID_DATA_HMAC_MSGLEN_VALIDFAIL);

    if(hmac_key_len < 0 || hmac_key_len > MAX_DIGEST_BLOCK_LEN)
        return(FKO_ERROR_INVALID_HMAC_KEY_LEN);

    if(ctx->hmac_type == FKO_HMAC_MD5)
        hmac_b64_digest_len = MD5_B64_LEN;
    else if(ctx->hmac_type == FKO_HMAC_SHA1)
        hmac_b64_digest_len = SHA1_B64_LEN;
    else if(ctx->hmac_type == FKO_HMAC_SHA256)
        hmac_b64_digest_len = SHA256_B64_LEN;
    else if(ctx->hmac_type == FKO_HMAC_SHA384)
        hmac_b64_digest_len = SHA384_B64_LEN;
    else if(ctx->hmac_type == FKO_HMAC_SHA512)
        hmac_b64_digest_len = SHA512_B64_LEN;
    else if(ctx->hmac_type == FKO_HMAC_SHA3_256)
        hmac_b64_digest_len = SHA3_256_B64_LEN;
    else if(ctx->hmac_type == FKO_HMAC_SHA3_512)
        hmac_b64_digest_len = SHA3_512_B64_LEN;
    else
        return(FKO_ERROR_UNSUPPORTED_HMAC_MODE);

    if((ctx->encrypted_msg_len - hmac_b64_digest_len)
            < MIN_SPA_ENCODED_MSG_SIZE)
        return(FKO_ERROR_INVALID_DATA_HMAC_ENCMSGLEN_VALIDFAIL);

    /* 获取摘要值 */
    hmac_digest_from_data = strndup((ctx->encrypted_msg
            + ctx->encrypted_msg_len - hmac_b64_digest_len),
            hmac_b64_digest_len);

    if(hmac_digest_from_data == NULL)
        return(FKO_ERROR_MEMORY_ALLOCATION);

    /* 现在我们从加密消息中截取HMAC摘要 */
    tbuf = strndup(ctx->encrypted_msg,
            ctx->encrypted_msg_len - hmac_b64_digest_len);

    if(tbuf == NULL)
    {
        if(zero_free(hmac_digest_from_data, strnlen(hmac_digest_from_data,
                MAX_SPA_ENCODED_MSG_SIZE)) == FKO_SUCCESS)
            return(FKO_ERROR_MEMORY_ALLOCATION);
        else
            return(FKO_ERROR_ZERO_OUT_DATA);
    }

    if(zero_free(ctx->encrypted_msg, ctx->encrypted_msg_len) != FKO_SUCCESS)
        zero_free_rv = FKO_ERROR_ZERO_OUT_DATA;

    ctx->encrypted_msg      = tbuf;
    ctx->encrypted_msg_len -= hmac_b64_digest_len;

    if(ctx->encryption_mode == FKO_ENC_MODE_ASYMMETRIC)
    {
        /* 看看我们是否需要将“hQ”字符串添加到 */
        if(! ctx->added_gpg_prefix)
        {
            res = add_gpg_prefix(ctx);
        }
    }
    else
    {
        /* 看看是否需要将“Salted__”字符串添加到 */
        if(! ctx->added_salted_str)
        {
            res = add_salted_str(ctx);
        }
    }

    if (res != FKO_SUCCESS)
    {
        if(zero_free(hmac_digest_from_data, strnlen(hmac_digest_from_data,
                        MAX_SPA_ENCODED_MSG_SIZE)) != FKO_SUCCESS)
            zero_free_rv = FKO_ERROR_ZERO_OUT_DATA;

        if(zero_free_rv == FKO_SUCCESS)
            return(res);
        else
            return(zero_free_rv);
    }

    /* 根据加密数据计算HMAC，然后 */
    res = fko_set_spa_hmac_type(ctx, ctx->hmac_type);
    if(res == FKO_SUCCESS)
    {
        res = fko_set_spa_hmac(ctx, hmac_key, hmac_key_len);

        if(res == FKO_SUCCESS)
        {
            if(constant_runtime_cmp(hmac_digest_from_data,
                    ctx->msg_hmac, hmac_b64_digest_len) != 0)
            {
                res = FKO_ERROR_INVALID_DATA_HMAC_COMPAREFAIL;
            }
        }
    }

    if(zero_free(hmac_digest_from_data, strnlen(hmac_digest_from_data,
                    MAX_SPA_ENCODED_MSG_SIZE)) != FKO_SUCCESS)
        zero_free_rv = FKO_ERROR_ZERO_OUT_DATA;

    if(res == FKO_SUCCESS)
        return(zero_free_rv);
    else
        return(res);
}

/* 返回fko HMAC数据 */
int
fko_get_spa_hmac(fko_ctx_t ctx, char **hmac_data)
{
    /* 必须初始化 */
    if(!CTX_INITIALIZED(ctx))
        return(FKO_ERROR_CTX_NOT_INITIALIZED);

    if(hmac_data == NULL)
        return(FKO_ERROR_INVALID_DATA);

    *hmac_data = ctx->msg_hmac;

    return(FKO_SUCCESS);
}

/* 设置HMAC类型 */
int
fko_set_spa_hmac_type(fko_ctx_t ctx, const short hmac_type)
{
#if HAVE_LIBFIU
    fiu_return_on("fko_set_spa_hmac_type_init",
            FKO_ERROR_CTX_NOT_INITIALIZED);
#endif

    /* 必须初始化 */
    if(!CTX_INITIALIZED(ctx))
        return(FKO_ERROR_CTX_NOT_INITIALIZED);

#if HAVE_LIBFIU
    fiu_return_on("fko_set_spa_hmac_type_val",
            FKO_ERROR_INVALID_DATA_HMAC_TYPE_VALIDFAIL);
#endif

    if(hmac_type < 0 || hmac_type >= FKO_LAST_HMAC_MODE)
        return(FKO_ERROR_INVALID_DATA_HMAC_TYPE_VALIDFAIL);

    ctx->hmac_type = hmac_type;

    ctx->state |= FKO_HMAC_MODE_MODIFIED;

    return(FKO_SUCCESS);
}

/* 返回fko HMAC类型 */
int
fko_get_spa_hmac_type(fko_ctx_t ctx, short *hmac_type)
{
    /* 必须初始化 */
    if(!CTX_INITIALIZED(ctx))
        return(FKO_ERROR_CTX_NOT_INITIALIZED);

    if(hmac_type == NULL)
        return(FKO_ERROR_INVALID_DATA);

    *hmac_type = ctx->hmac_type;

    return(FKO_SUCCESS);
}

int fko_set_spa_hmac(fko_ctx_t ctx,
    const char * const hmac_key, const int hmac_key_len)
{
    unsigned char hmac[SHA512_DIGEST_STR_LEN] = {0};
    char *hmac_base64 = NULL;
    int   hmac_digest_str_len = 0;
    int   hmac_digest_len = 0;
    int   res = FKO_ERROR_UNKNOWN ;

    /* 必须初始化 */
    if(!CTX_INITIALIZED(ctx))
        return(FKO_ERROR_CTX_NOT_INITIALIZED);

    if(hmac_key == NULL)
        return(FKO_ERROR_INVALID_DATA);

    if(hmac_key_len < 0 || hmac_key_len > MAX_DIGEST_BLOCK_LEN)
        return(FKO_ERROR_INVALID_HMAC_KEY_LEN);

    if(ctx->hmac_type == FKO_HMAC_MD5)
    {
        res = hmac_md5(ctx->encrypted_msg,
            ctx->encrypted_msg_len, hmac, hmac_key, hmac_key_len);

        hmac_digest_len     = MD5_DIGEST_LEN;
        hmac_digest_str_len = MD5_DIGEST_STR_LEN;
    }
    else if(ctx->hmac_type == FKO_HMAC_SHA1)
    {
        res = hmac_sha1(ctx->encrypted_msg,
            ctx->encrypted_msg_len, hmac, hmac_key, hmac_key_len);

        hmac_digest_len     = SHA1_DIGEST_LEN;
        hmac_digest_str_len = SHA1_DIGEST_STR_LEN;
    }
    else if(ctx->hmac_type == FKO_HMAC_SHA256)
    {
        res = hmac_sha256(ctx->encrypted_msg,
            ctx->encrypted_msg_len, hmac, hmac_key, hmac_key_len);

        hmac_digest_len     = SHA256_DIGEST_LEN;
        hmac_digest_str_len = SHA256_DIGEST_STR_LEN;
    }
    else if(ctx->hmac_type == FKO_HMAC_SHA384)
    {
        res = hmac_sha384(ctx->encrypted_msg,
            ctx->encrypted_msg_len, hmac, hmac_key, hmac_key_len);

        hmac_digest_len     = SHA384_DIGEST_LEN;
        hmac_digest_str_len = SHA384_DIGEST_STR_LEN;
    }
    else if(ctx->hmac_type == FKO_HMAC_SHA512)
    {
        res = hmac_sha512(ctx->encrypted_msg,
            ctx->encrypted_msg_len, hmac, hmac_key, hmac_key_len);

        hmac_digest_len     = SHA512_DIGEST_LEN;
        hmac_digest_str_len = SHA512_DIGEST_STR_LEN;
    }
    else if(ctx->hmac_type == FKO_HMAC_SHA3_256)
    {
        res = hmac_sha3_256(ctx->encrypted_msg,
            ctx->encrypted_msg_len, hmac, hmac_key, hmac_key_len);
        hmac_digest_len     = SHA3_256_DIGEST_LEN;
        hmac_digest_str_len = SHA3_256_DIGEST_STR_LEN;

    }
    else if(ctx->hmac_type == FKO_HMAC_SHA3_512)
    {
        res = hmac_sha3_512(ctx->encrypted_msg,
            ctx->encrypted_msg_len, hmac, hmac_key, hmac_key_len);
        hmac_digest_len     = SHA3_512_DIGEST_LEN;
        hmac_digest_str_len = SHA3_512_DIGEST_STR_LEN;

    }

    if (res != FKO_SUCCESS)
        return res;

    hmac_base64 = calloc(1, MD_HEX_SIZE(hmac_digest_len)+1);
    if (hmac_base64 == NULL)
        return(FKO_ERROR_MEMORY_ALLOCATION);

    b64_encode(hmac, hmac_base64, hmac_digest_len);
    strip_b64_eq(hmac_base64);

    if(ctx->msg_hmac != NULL)
        free(ctx->msg_hmac);

    ctx->msg_hmac = strdup(hmac_base64);

    free(hmac_base64);

    if(ctx->msg_hmac == NULL)
        return(FKO_ERROR_MEMORY_ALLOCATION);

    ctx->msg_hmac_len = strnlen(ctx->msg_hmac, hmac_digest_str_len);

    switch(ctx->msg_hmac_len)
    {
        case MD5_B64_LEN:
            break;
        case SHA1_B64_LEN:
            break;
        case SHA256_B64_LEN:
            break;
        case SHA384_B64_LEN:
            break;
        case SHA512_B64_LEN:
            break;
        default:
            return(FKO_ERROR_INVALID_DATA_HMAC_LEN_VALIDFAIL);
    }

    return FKO_SUCCESS;
}

/* **EOF** */
