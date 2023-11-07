
#include "ztn_common.h"
#include "ztn.h"
#include "cipher_funcs.h"
#include "base64.h"
#include "digest.h"

/* 初始化ztn上下文。 */
//初始化一个新的ztn文本
/* 这段代码是一个函数 ztn_new的实现，用于创建并初始化一个 ztn_ctx_t上下文结构体对象。 */
int
ztn_new(ztn_ctx_t *r_ctx)
{
    ztn_ctx_t   ctx = NULL;
    int         res;
    char       *ver;

#if HAVE_LIBFIU
    fiu_return_on("ztn_new_calloc", ZTN_ERROR_MEMORY_ALLOCATION);
#endif

    ctx = calloc(1, sizeof *ctx); //分配内存并初始化
    if(ctx == NULL)
        return(ZTN_ERROR_MEMORY_ALLOCATION);

    /* 设置默认值和状态。 */
    ctx->initval = ZTN_CTX_INITIALIZED;

    /* 设置版本字符串。 */
    ver = strdup(ZTN_PROTOCOL_VERSION);
    if(ver == NULL)
    {
        ztn_destroy(ctx);
        ctx = NULL;
        return(ZTN_ERROR_MEMORY_ALLOCATION);
    }
    ctx->version = ver;

    /* 随机值。 */
    res = ztn_set_rand_value(ctx, NULL);
    if(res != ZTN_SUCCESS)
    {
        ztn_destroy(ctx);
        ctx = NULL;
        return res;
    }

    /* 用户名。 */
    res = ztn_set_username(ctx, NULL);
    if(res != ZTN_SUCCESS)
    {
        ztn_destroy(ctx);
        ctx = NULL;
        return res;
    }

    /* 时间戳。 */
    res = ztn_set_timestamp(ctx, 0);
    if(res != ZTN_SUCCESS)
    {
        ztn_destroy(ctx);
        ctx = NULL;
        return res;
    }

    /* 默认摘要类型。 */
    res = ztn_set_spa_digest_type(ctx, ZTN_DEFAULT_DIGEST);
    if(res != ZTN_SUCCESS)
    {
        ztn_destroy(ctx);
        ctx = NULL;
        return res;
    }

    /* 默认消息类型。 */
    res = ztn_set_spa_message_type(ctx, ZTN_DEFAULT_MSG_TYPE);
    if(res != ZTN_SUCCESS)
    {
        ztn_destroy(ctx);
        ctx = NULL;
        return res;
    }

    /* 默认加密类型。 */
    res = ztn_set_spa_encryption_type(ctx, ZTN_DEFAULT_ENCRYPTION);
    if(res != ZTN_SUCCESS)
    {
        ztn_destroy(ctx);
        ctx = NULL;
        return res;
    }

    /* CBC模式下的默认值为Rijndael */
    res = ztn_set_spa_encryption_mode(ctx, ZTN_DEFAULT_ENC_MODE);
    if(res != ZTN_SUCCESS)
    {
        ztn_destroy(ctx);
        ctx = NULL;
        return res;
    }

#if HAVE_LIBGPGME
    /* 将gpg签名验证设置为打开。 */
    ctx->verify_gpg_sigs = 1;

#endif /* HAVE_LIBGPGME */

    ZTN_SET_CTX_INITIALIZED(ctx);

    *r_ctx = ctx;

    return(ZTN_SUCCESS);
}

/* 使用外部（加密/编码）数据初始化ztn上下文。 */
/* 详细请查看声明，因为太多不能快捷显示 */
int
ztn_new_with_data(ztn_ctx_t *r_ctx, const char * const enc_msg,
    const char * const dec_key, const int dec_key_len,
    int encryption_mode, const char * const hmac_key,
    const int hmac_key_len, const int hmac_type)
{
    ztn_ctx_t   ctx = NULL;
    int         res = ZTN_SUCCESS; /* 我们乐观吗？ */
    int         enc_msg_len;

#if HAVE_LIBFIU
    fiu_return_on("ztn_new_with_data_msg",
            ZTN_ERROR_INVALID_DATA_FUNCS_NEW_ENCMSG_MISSING);
#endif

    if(enc_msg == NULL)
        return(ZTN_ERROR_INVALID_DATA_FUNCS_NEW_ENCMSG_MISSING);

#if HAVE_LIBFIU
    fiu_return_on("ztn_new_with_data_keylen",
            ZTN_ERROR_INVALID_KEY_LEN);
#endif

    if(dec_key_len < 0 || hmac_key_len < 0)
        return(ZTN_ERROR_INVALID_KEY_LEN);

    ctx = calloc(1, sizeof *ctx);
    if(ctx == NULL)
        return(ZTN_ERROR_MEMORY_ALLOCATION);

    enc_msg_len = strnlen(enc_msg, MAX_SPA_ENCODED_MSG_SIZE);

    if(! is_valid_encoded_msg_len(enc_msg_len))
    {
        free(ctx);
        return(ZTN_ERROR_INVALID_DATA_FUNCS_NEW_MSGLEN_VALIDFAIL);
    }

    /* 首先，将数据添加到上下文中。 */
    ctx->encrypted_msg     = strdup(enc_msg);
    ctx->encrypted_msg_len = enc_msg_len;

    if(ctx->encrypted_msg == NULL)
    {
        free(ctx);
        return(ZTN_ERROR_MEMORY_ALLOCATION);
    }

    /* 默认加密模式（CBC模式下的Rijndael） */
    ctx->initval = ZTN_CTX_INITIALIZED;
    res = ztn_set_spa_encryption_mode(ctx, encryption_mode);
    if(res != ZTN_SUCCESS)
    {
        ztn_destroy(ctx);
        ctx = NULL;
        return res;
    }

    /* HMAC摘要类型 */
    res = ztn_set_spa_hmac_type(ctx, hmac_type);
    if(res != ZTN_SUCCESS)
    {
        ztn_destroy(ctx);
        ctx = NULL;
        return res;
    }

    /* 如果访问节有HMAC密钥，请检查HMAC */
    if(hmac_key_len > 0 && hmac_key != NULL)
        res = ztn_verify_hmac(ctx, hmac_key, hmac_key_len);
    if(res != ZTN_SUCCESS)
    {
        ztn_destroy(ctx);
        ctx = NULL;
        return res;
    }

    /* 请考虑在此处对其进行初始化。 */
    ZTN_SET_CTX_INITIALIZED(ctx);

    /* 如果提供了解密密钥，请继续进行解密和解码。 */
    if(dec_key != NULL)
    {
        res = ztn_decrypt_spa_data(ctx, dec_key, dec_key_len);

        if(res != ZTN_SUCCESS)
        {
            ztn_destroy(ctx);
            ctx = NULL;
            *r_ctx = NULL; /* 确保调用方ctx为null以备不时之需 */
            return(res);
        }
    }

#if HAVE_LIBGPGME
    /* 将gpg签名验证设置为打开。 */
    ctx->verify_gpg_sigs = 1;

#endif /* HAVE_LIBGPGME */

    *r_ctx = ctx;

    return(res);
}

/* 破坏上下文并释放其资源 */
int
ztn_destroy(ztn_ctx_t ctx)
{
    int zero_free_rv = ZTN_SUCCESS;

#if HAVE_LIBGPGME
    ztn_gpg_sig_t   gsig, tgsig;
#endif

    if(!CTX_INITIALIZED(ctx))
        return(zero_free_rv);

    if(ctx->rand_val != NULL)
        free(ctx->rand_val);

    if(ctx->username != NULL)
        free(ctx->username);

    if(ctx->version != NULL)
        free(ctx->version);

    if(ctx->message != NULL)
        free(ctx->message);

    if(ctx->nat_access != NULL)
        free(ctx->nat_access);

    if(ctx->server_auth != NULL)
        free(ctx->server_auth);

    if(ctx->digest != NULL)
        if(zero_free(ctx->digest, ctx->digest_len) != ZTN_SUCCESS)
            zero_free_rv = ZTN_ERROR_ZERO_OUT_DATA;

    if(ctx->raw_digest != NULL)
        if(zero_free(ctx->raw_digest, ctx->raw_digest_len) != ZTN_SUCCESS)
            zero_free_rv = ZTN_ERROR_ZERO_OUT_DATA;

    if(ctx->encoded_msg != NULL)
        if(zero_free(ctx->encoded_msg, ctx->encoded_msg_len) != ZTN_SUCCESS)
            zero_free_rv = ZTN_ERROR_ZERO_OUT_DATA;

    if(ctx->encrypted_msg != NULL)
        if(zero_free(ctx->encrypted_msg, ctx->encrypted_msg_len) != ZTN_SUCCESS)
            zero_free_rv = ZTN_ERROR_ZERO_OUT_DATA;

    if(ctx->msg_hmac != NULL)
        if(zero_free(ctx->msg_hmac, ctx->msg_hmac_len) != ZTN_SUCCESS)
            zero_free_rv = ZTN_ERROR_ZERO_OUT_DATA;

#if HAVE_LIBGPGME
    if(ctx->gpg_exe != NULL)
        free(ctx->gpg_exe);

    if(ctx->gpg_home_dir != NULL)
        free(ctx->gpg_home_dir);

    if(ctx->gpg_recipient != NULL)
        free(ctx->gpg_recipient);

    if(ctx->gpg_signer != NULL)
        free(ctx->gpg_signer);

    if(ctx->recipient_key != NULL)
        gpgme_key_unref(ctx->recipient_key);

    if(ctx->signer_key != NULL)
        gpgme_key_unref(ctx->signer_key);

    if(ctx->gpg_ctx != NULL)
        gpgme_release(ctx->gpg_ctx);

    gsig = ctx->gpg_sigs;
    while(gsig != NULL)
    {
        if(gsig->fpr != NULL)
            free(gsig->fpr);

        tgsig = gsig;
        gsig = gsig->next;

        free(tgsig);
    }

#endif /* HAVE_LIBGPGME */

    memset(ctx, 0x0, sizeof(*ctx));

    free(ctx);

    return(zero_free_rv);
}

/* 从/dev/random和base64生成Rijndael和HMAC密钥 */
/* 这段代码是一个实现密钥生成的函数。它接收一些参数，包括 key_base64、key_len、hmac.key_base64和hmac_key_len和 hmac_ type并返回一个整数。 */
int
ztn_key_gen(char * const key_base64, const int key_len,
        char * const hmac_key_base64, const int hmac_key_len,
        const int hmac_type)
{
    unsigned char key[RIJNDAEL_MAX_KEYSIZE];
    unsigned char hmac_key[SHA512_BLOCK_LEN];
    int klen      = key_len;
    int hmac_klen = hmac_key_len;
    int b64_len   = 0;

    if(key_len == ZTN_DEFAULT_KEY_LEN)
        klen = RIJNDAEL_MAX_KEYSIZE;

    if(hmac_key_len == ZTN_DEFAULT_KEY_LEN)
    {
        if(hmac_type == ZTN_DEFAULT_HMAC_MODE
                || hmac_type == ZTN_HMAC_SHA256)
            hmac_klen = SHA256_BLOCK_LEN;
        else if(hmac_type == ZTN_HMAC_MD5)
            hmac_klen = MD5_DIGEST_LEN;
        else if(hmac_type == ZTN_HMAC_SHA1)
            hmac_klen = SHA1_DIGEST_LEN;
        else if(hmac_type == ZTN_HMAC_SHA384)
            hmac_klen = SHA384_BLOCK_LEN;
        else if(hmac_type == ZTN_HMAC_SHA512)
            hmac_klen = SHA512_BLOCK_LEN;
    }

    if((klen < 1) || (klen > RIJNDAEL_MAX_KEYSIZE))
        return(ZTN_ERROR_INVALID_DATA_FUNCS_GEN_KEYLEN_VALIDFAIL);

    if((hmac_klen < 1) || (hmac_klen > SHA512_BLOCK_LEN))
        return(ZTN_ERROR_INVALID_DATA_FUNCS_GEN_HMACLEN_VALIDFAIL);

    get_random_data(key, klen);
    get_random_data(hmac_key, hmac_klen);

    b64_len = b64_encode(key, key_base64, klen);
    if(b64_len < klen)
        return(ZTN_ERROR_INVALID_DATA_FUNCS_GEN_KEY_ENCODEFAIL);

    b64_len = b64_encode(hmac_key, hmac_key_base64, hmac_klen);
    if(b64_len < hmac_klen)
        return(ZTN_ERROR_INVALID_DATA_FUNCS_GEN_HMAC_ENCODEFAIL);

    return(ZTN_SUCCESS);
}

/* 围绕base64编码/解码函数提供ZTN包装 */



int
ztn_base64_encode(unsigned char * const in, char * const out, int in_len)
{
    return b64_encode(in, out, in_len);
}

int
ztn_base64_decode(const char * const in, unsigned char *out)
{
    return b64_decode(in, out);
}

/* 返回ztn版本 */
// ztn_get_version: 用于获取ztn的版本号
int
ztn_get_version(ztn_ctx_t ctx, char **version)
{

#if HAVE_LIBFIU
    fiu_return_on("ztn_get_version_init", ZTN_ERROR_CTX_NOT_INITIALIZED);
#endif

    /* 必须初始化 */
    if(!CTX_INITIALIZED(ctx))
        return(ZTN_ERROR_CTX_NOT_INITIALIZED);

    if(version == NULL)
        return(ZTN_ERROR_INVALID_DATA);

#if HAVE_LIBFIU
    fiu_return_on("ztn_get_version_val", ZTN_ERROR_INVALID_DATA);
#endif

    *version = ctx->version;

    return(ZTN_SUCCESS);
}

/* 上下文中数据的最终更新和编码。 */

/* 这段代码是一个名为 ztn_spa_data_final的函数，它用于最终处理 SPA（安全密码验证）数据。 */
int
ztn_spa_data_final(ztn_ctx_t ctx,
    const char * const enc_key, const int enc_key_len,
    const char * const hmac_key, const int hmac_key_len)
{
    char   *tbuf;
    int     res = 0, data_with_hmac_len = 0;

    /* 必须初始化 */
    if(!CTX_INITIALIZED(ctx))
        return(ZTN_ERROR_CTX_NOT_INITIALIZED);

    if(enc_key_len < 0)
        return(ZTN_ERROR_INVALID_KEY_LEN);

    res = ztn_encrypt_spa_data(ctx, enc_key, enc_key_len);

    /* 现在计算hmac，如果配置了 */
   //如果设置了要使用HMAC
    if (res == ZTN_SUCCESS && ctx->hmac_type != ZTN_HMAC_UNKNOWN)
    {
        if(hmac_key_len < 0)
            return(ZTN_ERROR_INVALID_KEY_LEN);

        if(hmac_key == NULL)
            return(ZTN_ERROR_INVALID_KEY_LEN);

        //将encrypt_msg生成消息摘要
        res = ztn_set_spa_hmac(ctx, hmac_key, hmac_key_len);

        if (res == ZTN_SUCCESS)
        {
            /* 既然我们有了hmac，就把它附加到 */
            data_with_hmac_len
                = ctx->encrypted_msg_len+1+ctx->msg_hmac_len+1;

            tbuf = realloc(ctx->encrypted_msg, data_with_hmac_len);
            if (tbuf == NULL)
                return(ZTN_ERROR_MEMORY_ALLOCATION);

            //将tbuf设置成encrypted_msg+msg_hmac的形式
            strlcat(tbuf, ctx->msg_hmac, data_with_hmac_len);

            ctx->encrypted_msg     = tbuf;
            ctx->encrypted_msg_len = data_with_hmac_len;
        }
    }

    return res;
}

/* 返回ztn SPA加密数据。 */
/* 在这个函数中，上下文 ctx的作用是存储与 SPA数据相关的信息和状态。该上下文参数 ctx是一个 ztn_ctx_t类型的结构体，在函数调用之前需要先初始化。 */
int
ztn_get_spa_data(ztn_ctx_t ctx, char **spa_data)
{

#if HAVE_LIBFIU
    fiu_return_on("ztn_get_spa_data_init", ZTN_ERROR_CTX_NOT_INITIALIZED);
#endif

    /* 必须初始化 */
    if(!CTX_INITIALIZED(ctx))
        return(ZTN_ERROR_CTX_NOT_INITIALIZED);

    if(spa_data == NULL)
        return(ZTN_ERROR_INVALID_DATA);

#if HAVE_LIBFIU
    fiu_return_on("ztn_get_spa_data_val", ZTN_ERROR_INVALID_DATA);
#endif

    /* 我们希望能够处理加密数据。如果没有，我们保释。 */
   //我们期望有加密数据来处理。如果没有，我们就放弃了。
    if(ctx->encrypted_msg == NULL || ! is_valid_encoded_msg_len(
                strnlen(ctx->encrypted_msg, MAX_SPA_ENCODED_MSG_SIZE)))
        return(ZTN_ERROR_MISSING_ENCODED_DATA);

#if HAVE_LIBFIU
    fiu_return_on("ztn_get_spa_data_encoded", ZTN_ERROR_MISSING_ENCODED_DATA);
#endif

    *spa_data = ctx->encrypted_msg;

    /* 注意，如果Rijndael加密为 */
   //注意，如果使用Rijndael加密，我们省略了前10个字节（以消除一致的“Salted__”字符串），
    //在GnuPG模式下，我们消除了一致的“hQ”base64编码前缀
    if(ctx->encryption_type == ZTN_ENCRYPTION_RIJNDAEL)
        *spa_data += B64_RIJNDAEL_SALT_STR_LEN;
    else if(ctx->encryption_type == ZTN_ENCRYPTION_GPG)
        *spa_data += B64_GPG_PREFIX_STR_LEN;

    return(ZTN_SUCCESS);
}

/* 设置ztn SPA加密数据。 */
/* 这段代码是一个名为 ztn_set_spa_data的函数，用于设置 SPA（安全密码验证）数据。 */
int
ztn_set_spa_data(ztn_ctx_t ctx, const char * const enc_msg)
{
    int         enc_msg_len;

    /* 必须初始化 */
    if(!CTX_INITIALIZED(ctx))
        return ZTN_ERROR_CTX_NOT_INITIALIZED;

    if(enc_msg == NULL)
        return(ZTN_ERROR_INVALID_DATA_FUNCS_SET_MSGLEN_VALIDFAIL);

    enc_msg_len = strnlen(enc_msg, MAX_SPA_ENCODED_MSG_SIZE);

    if(! is_valid_encoded_msg_len(enc_msg_len))
        return(ZTN_ERROR_INVALID_DATA_FUNCS_SET_MSGLEN_VALIDFAIL);

    if(ctx->encrypted_msg != NULL)
        free(ctx->encrypted_msg);

    /* 首先，将数据添加到上下文中。 */
    ctx->encrypted_msg = strdup(enc_msg);
    ctx->encrypted_msg_len = enc_msg_len;

    if(ctx->encrypted_msg == NULL)
        return(ZTN_ERROR_MEMORY_ALLOCATION);

    return(ZTN_SUCCESS);
}

#if AFL_FUZZING
/* 提供了一种直接设置加密数据而无需base64编码的方式。 */
int
ztn_afl_set_spa_data(ztn_ctx_t ctx, const char * const enc_msg, const int enc_msg_len)
{
    /* 必须初始化 */
    if(!CTX_INITIALIZED(ctx))
        return ZTN_ERROR_CTX_NOT_INITIALIZED;

    if(enc_msg == NULL)
        return(ZTN_ERROR_INVALID_DATA_FUNCS_SET_MSGLEN_VALIDFAIL);

    if(! is_valid_encoded_msg_len(enc_msg_len))
        return(ZTN_ERROR_INVALID_DATA_FUNCS_SET_MSGLEN_VALIDFAIL);

    if(ctx->encrypted_msg != NULL)
        free(ctx->encrypted_msg);

    /* 将原始加密数据复制到上下文中 */
    ctx->encrypted_msg = calloc(1, enc_msg_len);
    if(ctx->encrypted_msg == NULL)
        return(ZTN_ERROR_MEMORY_ALLOCATION);

    memcpy(ctx->encrypted_msg, enc_msg, enc_msg_len);

    ctx->encrypted_msg_len = enc_msg_len;

    return(ZTN_SUCCESS);
}
#endif

/* **EOF** */
