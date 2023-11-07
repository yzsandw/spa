
#include "ztn_common.h"
#include "ztn.h"
#include "cipher_funcs.h"
#include "hmac.h"
#include "base64.h"

int
ztn_verify_hmac(ztn_ctx_t ctx,
    const char * const hmac_key, const int hmac_key_len)
{
    char    *hmac_digest_from_data = NULL;
    char    *tbuf = NULL;
    int      res = ZTN_SUCCESS;
    int      hmac_b64_digest_len = 0, zero_free_rv = ZTN_SUCCESS;

    /* 必须初始化 */
    if(!CTX_INITIALIZED(ctx))
        return(ZTN_ERROR_CTX_NOT_INITIALIZED);

    if(hmac_key == NULL)
        return(ZTN_ERROR_INVALID_DATA);

    if (! is_valid_encoded_msg_len(ctx->encrypted_msg_len))
        return(ZTN_ERROR_INVALID_DATA_HMAC_MSGLEN_VALIDFAIL);

    if(hmac_key_len < 0 || hmac_key_len > MAX_DIGEST_BLOCK_LEN)
        return(ZTN_ERROR_INVALID_HMAC_KEY_LEN);

    if(ctx->hmac_type == ZTN_HMAC_MD5)
        hmac_b64_digest_len = MD5_B64_LEN;
    else if(ctx->hmac_type == ZTN_HMAC_SHA1)
        hmac_b64_digest_len = SHA1_B64_LEN;
    else if(ctx->hmac_type == ZTN_HMAC_SHA256)
        hmac_b64_digest_len = SHA256_B64_LEN;
    else if(ctx->hmac_type == ZTN_HMAC_SHA384)
        hmac_b64_digest_len = SHA384_B64_LEN;
    else if(ctx->hmac_type == ZTN_HMAC_SHA512)
        hmac_b64_digest_len = SHA512_B64_LEN;
    else if(ctx->hmac_type == ZTN_HMAC_SHA3_256)
        hmac_b64_digest_len = SHA3_256_B64_LEN;
    else if(ctx->hmac_type == ZTN_HMAC_SHA3_512)
        hmac_b64_digest_len = SHA3_512_B64_LEN;
    else
        return(ZTN_ERROR_UNSUPPORTED_HMAC_MODE);

    if((ctx->encrypted_msg_len - hmac_b64_digest_len)
            < MIN_SPA_ENCODED_MSG_SIZE)
        return(ZTN_ERROR_INVALID_DATA_HMAC_ENCMSGLEN_VALIDFAIL);

    /* 获取摘要值 */
    hmac_digest_from_data = strndup((ctx->encrypted_msg
            + ctx->encrypted_msg_len - hmac_b64_digest_len),
            hmac_b64_digest_len);

    if(hmac_digest_from_data == NULL)
        return(ZTN_ERROR_MEMORY_ALLOCATION);

    /* 现在我们从加密消息中截取HMAC摘要 */
    tbuf = strndup(ctx->encrypted_msg,
            ctx->encrypted_msg_len - hmac_b64_digest_len);

    if(tbuf == NULL)
    {
        if(zero_free(hmac_digest_from_data, strnlen(hmac_digest_from_data,
                MAX_SPA_ENCODED_MSG_SIZE)) == ZTN_SUCCESS)
            return(ZTN_ERROR_MEMORY_ALLOCATION);
        else
            return(ZTN_ERROR_ZERO_OUT_DATA);
    }

    if(zero_free(ctx->encrypted_msg, ctx->encrypted_msg_len) != ZTN_SUCCESS)
        zero_free_rv = ZTN_ERROR_ZERO_OUT_DATA;

    ctx->encrypted_msg      = tbuf;
    ctx->encrypted_msg_len -= hmac_b64_digest_len;

    if(ctx->encryption_mode == ZTN_ENC_MODE_ASYMMETRIC)
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

    if (res != ZTN_SUCCESS)
    {
        if(zero_free(hmac_digest_from_data, strnlen(hmac_digest_from_data,
                        MAX_SPA_ENCODED_MSG_SIZE)) != ZTN_SUCCESS)
            zero_free_rv = ZTN_ERROR_ZERO_OUT_DATA;

        if(zero_free_rv == ZTN_SUCCESS)
            return(res);
        else
            return(zero_free_rv);
    }

    /* 根据加密数据计算HMAC，然后 */
    res = ztn_set_spa_hmac_type(ctx, ctx->hmac_type);
    if(res == ZTN_SUCCESS)
    {
        res = ztn_set_spa_hmac(ctx, hmac_key, hmac_key_len);

        if(res == ZTN_SUCCESS)
        {
            if(constant_runtime_cmp(hmac_digest_from_data,
                    ctx->msg_hmac, hmac_b64_digest_len) != 0)
            {
                res = ZTN_ERROR_INVALID_DATA_HMAC_COMPAREFAIL;
            }
        }
    }

    if(zero_free(hmac_digest_from_data, strnlen(hmac_digest_from_data,
                    MAX_SPA_ENCODED_MSG_SIZE)) != ZTN_SUCCESS)
        zero_free_rv = ZTN_ERROR_ZERO_OUT_DATA;

    if(res == ZTN_SUCCESS)
        return(zero_free_rv);
    else
        return(res);
}

/* 返回ztn HMAC数据 */
int
ztn_get_spa_hmac(ztn_ctx_t ctx, char **hmac_data)
{
    /* 必须初始化 */
    if(!CTX_INITIALIZED(ctx))
        return(ZTN_ERROR_CTX_NOT_INITIALIZED);

    if(hmac_data == NULL)
        return(ZTN_ERROR_INVALID_DATA);

    *hmac_data = ctx->msg_hmac;

    return(ZTN_SUCCESS);
}

/* 设置HMAC类型 */
int
ztn_set_spa_hmac_type(ztn_ctx_t ctx, const short hmac_type)
{
#if HAVE_LIBFIU
    fiu_return_on("ztn_set_spa_hmac_type_init",
            ZTN_ERROR_CTX_NOT_INITIALIZED);
#endif

    /* 必须初始化 */
    if(!CTX_INITIALIZED(ctx))
        return(ZTN_ERROR_CTX_NOT_INITIALIZED);

#if HAVE_LIBFIU
    fiu_return_on("ztn_set_spa_hmac_type_val",
            ZTN_ERROR_INVALID_DATA_HMAC_TYPE_VALIDFAIL);
#endif

    if(hmac_type < 0 || hmac_type >= ZTN_LAST_HMAC_MODE)
        return(ZTN_ERROR_INVALID_DATA_HMAC_TYPE_VALIDFAIL);

    ctx->hmac_type = hmac_type;

    ctx->state |= ZTN_HMAC_MODE_MODIFIED;

    return(ZTN_SUCCESS);
}

/* 返回ztn HMAC类型 */
int
ztn_get_spa_hmac_type(ztn_ctx_t ctx, short *hmac_type)
{
    /* 必须初始化 */
    if(!CTX_INITIALIZED(ctx))
        return(ZTN_ERROR_CTX_NOT_INITIALIZED);

    if(hmac_type == NULL)
        return(ZTN_ERROR_INVALID_DATA);

    *hmac_type = ctx->hmac_type;

    return(ZTN_SUCCESS);
}

int ztn_set_spa_hmac(ztn_ctx_t ctx,
    const char * const hmac_key, const int hmac_key_len)
{
    unsigned char hmac[SHA512_DIGEST_STR_LEN] = {0};
    char *hmac_base64 = NULL;
    int   hmac_digest_str_len = 0;
    int   hmac_digest_len = 0;
    int   res = ZTN_ERROR_UNKNOWN ;

    /* 必须初始化 */
    if(!CTX_INITIALIZED(ctx))
        return(ZTN_ERROR_CTX_NOT_INITIALIZED);

    if(hmac_key == NULL)
        return(ZTN_ERROR_INVALID_DATA);

    if(hmac_key_len < 0 || hmac_key_len > MAX_DIGEST_BLOCK_LEN)
        return(ZTN_ERROR_INVALID_HMAC_KEY_LEN);

    if(ctx->hmac_type == ZTN_HMAC_MD5)
    {
        res = hmac_md5(ctx->encrypted_msg,
            ctx->encrypted_msg_len, hmac, hmac_key, hmac_key_len);

        hmac_digest_len     = MD5_DIGEST_LEN;
        hmac_digest_str_len = MD5_DIGEST_STR_LEN;
    }
    else if(ctx->hmac_type == ZTN_HMAC_SHA1)
    {
        res = hmac_sha1(ctx->encrypted_msg,
            ctx->encrypted_msg_len, hmac, hmac_key, hmac_key_len);

        hmac_digest_len     = SHA1_DIGEST_LEN;
        hmac_digest_str_len = SHA1_DIGEST_STR_LEN;
    }
    else if(ctx->hmac_type == ZTN_HMAC_SHA256)
    {
        res = hmac_sha256(ctx->encrypted_msg,
            ctx->encrypted_msg_len, hmac, hmac_key, hmac_key_len);

        hmac_digest_len     = SHA256_DIGEST_LEN;
        hmac_digest_str_len = SHA256_DIGEST_STR_LEN;
    }
    else if(ctx->hmac_type == ZTN_HMAC_SHA384)
    {
        res = hmac_sha384(ctx->encrypted_msg,
            ctx->encrypted_msg_len, hmac, hmac_key, hmac_key_len);

        hmac_digest_len     = SHA384_DIGEST_LEN;
        hmac_digest_str_len = SHA384_DIGEST_STR_LEN;
    }
    else if(ctx->hmac_type == ZTN_HMAC_SHA512)
    {
        res = hmac_sha512(ctx->encrypted_msg,
            ctx->encrypted_msg_len, hmac, hmac_key, hmac_key_len);

        hmac_digest_len     = SHA512_DIGEST_LEN;
        hmac_digest_str_len = SHA512_DIGEST_STR_LEN;
    }
    else if(ctx->hmac_type == ZTN_HMAC_SHA3_256)
    {
        res = hmac_sha3_256(ctx->encrypted_msg,
            ctx->encrypted_msg_len, hmac, hmac_key, hmac_key_len);
        hmac_digest_len     = SHA3_256_DIGEST_LEN;
        hmac_digest_str_len = SHA3_256_DIGEST_STR_LEN;

    }
    else if(ctx->hmac_type == ZTN_HMAC_SHA3_512)
    {
        res = hmac_sha3_512(ctx->encrypted_msg,
            ctx->encrypted_msg_len, hmac, hmac_key, hmac_key_len);
        hmac_digest_len     = SHA3_512_DIGEST_LEN;
        hmac_digest_str_len = SHA3_512_DIGEST_STR_LEN;

    }

    if (res != ZTN_SUCCESS)
        return res;

    hmac_base64 = calloc(1, MD_HEX_SIZE(hmac_digest_len)+1);
    if (hmac_base64 == NULL)
        return(ZTN_ERROR_MEMORY_ALLOCATION);

    b64_encode(hmac, hmac_base64, hmac_digest_len);
    strip_b64_eq(hmac_base64);

    if(ctx->msg_hmac != NULL)
        free(ctx->msg_hmac);

    ctx->msg_hmac = strdup(hmac_base64);

    free(hmac_base64);

    if(ctx->msg_hmac == NULL)
        return(ZTN_ERROR_MEMORY_ALLOCATION);

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
            return(ZTN_ERROR_INVALID_DATA_HMAC_LEN_VALIDFAIL);
    }

    return ZTN_SUCCESS;
}

/* **EOF** */
