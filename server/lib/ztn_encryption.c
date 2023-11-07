
#include "ztn_common.h"
#include "ztn.h"
#include "cipher_funcs.h"
#include "base64.h"
#include "digest.h"

#if HAVE_LIBGPGME
  #include "gpgme_funcs.h"
  #if HAVE_SYS_STAT_H
    #include <sys/stat.h>
  #endif
#endif

/* 使用Rijndael进行准备和加密 */
//AES是Rijndael算法的标准化，其实本质差不多
static int
_rijndael_encrypt(ztn_ctx_t ctx, const char *enc_key, const int enc_key_len)
{
    char           *plaintext;
    char           *b64ciphertext;
    unsigned char  *ciphertext;
    int             cipher_len;
    int             pt_len;
    int             zero_free_rv = ZTN_SUCCESS;

    if(enc_key_len < 0 || enc_key_len > RIJNDAEL_MAX_KEYSIZE)
        return(ZTN_ERROR_INVALID_KEY_LEN);

    if (! is_valid_encoded_msg_len(ctx->encoded_msg_len))
        return(ZTN_ERROR_INVALID_DATA_ENCRYPT_MSGLEN_VALIDFAIL);
    //检查消息摘要长度是否符合要求
    switch(ctx->digest_len)
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
            return(ZTN_ERROR_INVALID_DATA_ENCRYPT_DIGESTLEN_VALIDFAIL);
    }

    pt_len = ctx->encoded_msg_len + ctx->digest_len + RIJNDAEL_BLOCKSIZE + 2;

    /* 制作一个足够大的桶来容纳enc msg+摘要（明文） */
   //明文长度=编码长度+摘要长度+16+2 ？？可能是适当填充
    plaintext = calloc(1, pt_len);

    if(plaintext == NULL)
        return(ZTN_ERROR_MEMORY_ALLOCATION);

    //设置plaintext和pt_len
    pt_len = snprintf(plaintext, pt_len, "%s:%s", ctx->encoded_msg, ctx->digest);

    if(! is_valid_pt_msg_len(pt_len))
    {
        if(zero_free(plaintext, pt_len) == ZTN_SUCCESS)
            return(ZTN_ERROR_INVALID_DATA_ENCRYPT_PTLEN_VALIDFAIL);
        else
            return(ZTN_ERROR_ZERO_OUT_DATA);
    }

    /* 为加密版本制作一个bucket并填充它。 */
    ciphertext = calloc(1, pt_len + 32); /* 加上填充盐和块 */ //填充加盐
    if(ciphertext == NULL)
    {
        if(zero_free(plaintext, pt_len) == ZTN_SUCCESS)
            return(ZTN_ERROR_MEMORY_ALLOCATION);
        else
            return(ZTN_ERROR_ZERO_OUT_DATA);
    }
    //执行加密
    cipher_len = rij_encrypt(
        (unsigned char*)plaintext, pt_len,
        (char*)enc_key, enc_key_len,
        ciphertext, ctx->encryption_mode
    );

    /* 现在为base64编码的版本制作一个bucket并填充它。 */
   //初始化缓冲区
    b64ciphertext = calloc(1, ((cipher_len / 3) * 4) + 8);
    if(b64ciphertext == NULL)
    {
        if(zero_free((char *) ciphertext, pt_len+32) == ZTN_SUCCESS
                && zero_free(plaintext, pt_len) == ZTN_SUCCESS)
            return(ZTN_ERROR_MEMORY_ALLOCATION);
        else
            return(ZTN_ERROR_ZERO_OUT_DATA);
    }

    //将加密后的密文进行base64编码
    b64_encode(ciphertext, b64ciphertext, cipher_len);
    //去除base64编码后的'='符
    strip_b64_eq(b64ciphertext);

    if(ctx->encrypted_msg != NULL)
        zero_free_rv = zero_free(ctx->encrypted_msg,
                strnlen(ctx->encrypted_msg, MAX_SPA_ENCODED_MSG_SIZE));

    //将base64编码后的密文数据赋值给encrypted_msg
    ctx->encrypted_msg = strdup(b64ciphertext);

    /* 清理 */
    if(zero_free(plaintext, pt_len) != ZTN_SUCCESS)
        zero_free_rv = ZTN_ERROR_ZERO_OUT_DATA;

    if(zero_free((char *) ciphertext, pt_len+32) != ZTN_SUCCESS)
        zero_free_rv = ZTN_ERROR_ZERO_OUT_DATA;

    if(zero_free(b64ciphertext, strnlen(b64ciphertext,
                    MAX_SPA_ENCODED_MSG_SIZE)) != ZTN_SUCCESS)
        zero_free_rv = ZTN_ERROR_ZERO_OUT_DATA;

    if(ctx->encrypted_msg == NULL)
        return(ZTN_ERROR_MEMORY_ALLOCATION);

    ctx->encrypted_msg_len = strnlen(ctx->encrypted_msg, MAX_SPA_ENCODED_MSG_SIZE);

    if(! is_valid_encoded_msg_len(ctx->encrypted_msg_len))
        return(ZTN_ERROR_INVALID_DATA_ENCRYPT_RESULT_MSGLEN_VALIDFAIL);

    return(zero_free_rv);
}

/* 将SPA数据解码、解密并解析到上下文中。 */
static int
_rijndael_decrypt(ztn_ctx_t ctx,
    const char *dec_key, const int key_len, int encryption_mode)
{
    unsigned char  *ndx;
    unsigned char  *cipher;
    int             cipher_len=0, pt_len, i, err = 0, res = ZTN_SUCCESS;
    int             zero_free_rv = ZTN_SUCCESS;

    if(key_len < 0 || key_len > RIJNDAEL_MAX_KEYSIZE)
        return(ZTN_ERROR_INVALID_KEY_LEN);

    /* 现在看看我们是否需要将“Salted__”字符串添加到 */
    if(! ctx->added_salted_str)
    {
        res = add_salted_str(ctx);
        if(res != ZTN_SUCCESS)
            return res;
    }

    /* 为（base64）解码的加密数据创建一个bucket，并获取 */
    cipher = calloc(1, ctx->encrypted_msg_len);
    if(cipher == NULL)
        return(ZTN_ERROR_MEMORY_ALLOCATION);

#if AFL_FUZZING
    cipher_len = ctx->encrypted_msg_len;
    memcpy(cipher, ctx->encrypted_msg, ctx->encrypted_msg_len);
#else
    if((cipher_len = b64_decode(ctx->encrypted_msg, cipher)) < 0)
    {
        if(zero_free((char *)cipher, ctx->encrypted_msg_len) == ZTN_SUCCESS)
            return(ZTN_ERROR_INVALID_DATA_ENCRYPT_CIPHERLEN_DECODEFAIL);
        else
            return(ZTN_ERROR_ZERO_OUT_DATA);
    }
#endif

    /* 由于我们使用AES，请确保传入数据是 */
    if((cipher_len % RIJNDAEL_BLOCKSIZE) != 0)
    {
        if(zero_free((char *)cipher, ctx->encrypted_msg_len) == ZTN_SUCCESS)
            return(ZTN_ERROR_INVALID_DATA_ENCRYPT_CIPHERLEN_VALIDFAIL);
        else
            return(ZTN_ERROR_ZERO_OUT_DATA);
    }

    if(ctx->encoded_msg != NULL)
        zero_free_rv = zero_free(ctx->encoded_msg,
                strnlen(ctx->encoded_msg, MAX_SPA_ENCODED_MSG_SIZE));

    /* 为明文数据创建一个bucket并解密消息 */
    ctx->encoded_msg = calloc(1, cipher_len);
    if(ctx->encoded_msg == NULL)
    {
        if(zero_free((char *)cipher, ctx->encrypted_msg_len) == ZTN_SUCCESS)
            return(ZTN_ERROR_MEMORY_ALLOCATION);
        else
            return(ZTN_ERROR_ZERO_OUT_DATA);
    }

    pt_len = rij_decrypt(cipher, cipher_len, dec_key, key_len,
                (unsigned char*)ctx->encoded_msg, encryption_mode);

    /* 密码已完成。。。 */
    if(zero_free((char *)cipher, ctx->encrypted_msg_len) != ZTN_SUCCESS)
        zero_free_rv = ZTN_ERROR_ZERO_OUT_DATA;

    /* 解密数据的长度应在 */
    if(pt_len < (cipher_len - 32) || pt_len <= 0)
        return(ZTN_ERROR_DECRYPTION_SIZE);

    if(ctx->encoded_msg == NULL)
        return(ZTN_ERROR_MISSING_ENCODED_DATA);

    if(! is_valid_encoded_msg_len(pt_len))
        return(ZTN_ERROR_INVALID_DATA_DECODE_MSGLEN_VALIDFAIL);

    if(zero_free_rv != ZTN_SUCCESS)
        return(zero_free_rv);

    ctx->encoded_msg_len = pt_len;

    /* 在这一点上，我们可以检查数据，看看我们是否有一个好的 */
    ndx = (unsigned char *)ctx->encoded_msg;
    for(i=0; i<ZTN_RAND_VAL_SIZE; i++)
        if(!isdigit(*(ndx++)))
            err++;

    if(err > 0 || *ndx != ':')
        return(ZTN_ERROR_DECRYPTION_FAILURE);

    /* 调用ztn_decode并返回结果。 */
    return(ztn_decode_spa_data(ctx));
}


#if HAVE_LIBGPGME

/* 使用gpgme进行准备和加密 */
static int
gpg_encrypt(ztn_ctx_t ctx, const char *enc_key)
{
    int             res;
    char           *plain;
    int             pt_len, zero_free_rv = ZTN_SUCCESS;
    char           *b64cipher;
    unsigned char  *cipher = NULL;
    size_t          cipher_len;
    char           *empty_key = "";

    if (! is_valid_encoded_msg_len(ctx->encoded_msg_len))
        return(ZTN_ERROR_INVALID_DATA_ENCRYPT_GPG_MESSAGE_VALIDFAIL);

    switch(ctx->digest_len)
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
            return(ZTN_ERROR_INVALID_DATA_ENCRYPT_GPG_DIGEST_VALIDFAIL);
    }

    /* 首先确保我们有一个收件人密钥集。 */
    if(ctx->gpg_recipient == NULL)
        return(ZTN_ERROR_MISSING_GPG_KEY_DATA);

    pt_len = ctx->encoded_msg_len + ctx->digest_len + 2;

    /* 制作一个足够大的桶来容纳enc msg+摘要（明文） */
    plain = calloc(1, ctx->encoded_msg_len + ctx->digest_len + 2);
    if(plain == NULL)
        return(ZTN_ERROR_MEMORY_ALLOCATION);

    pt_len = snprintf(plain, pt_len+1, "%s:%s", ctx->encoded_msg, ctx->digest);

    if(! is_valid_pt_msg_len(pt_len))
    {
        if(zero_free(plain, pt_len) == ZTN_SUCCESS)
            return(ZTN_ERROR_INVALID_DATA_ENCRYPT_GPG_MSGLEN_VALIDFAIL);
        else
            return(ZTN_ERROR_ZERO_OUT_DATA);
    }

    if (enc_key != NULL)
    {
        res = gpgme_encrypt(ctx, (unsigned char*)plain, pt_len,
            enc_key, &cipher, &cipher_len
        );
    }
    else
    {
        res = gpgme_encrypt(ctx, (unsigned char*)plain, pt_len,
            empty_key, &cipher, &cipher_len
        );
    }

    /* --DSS XXX：更好地分析出了什么问题会很好：） */
    if(res != ZTN_SUCCESS)
    {
        zero_free_rv = zero_free(plain, pt_len);

        if(cipher != NULL)
            if(zero_free((char *) cipher, cipher_len) != ZTN_SUCCESS)
                zero_free_rv = ZTN_ERROR_ZERO_OUT_DATA;

        if(zero_free_rv == ZTN_SUCCESS)
            return(res);
        else
            return(zero_free_rv);
    }

    /* 现在为base64编码的版本制作一个bucket并填充它。 */
    b64cipher = calloc(1, ((cipher_len / 3) * 4) + 8);
    if(b64cipher == NULL)
    {
        if(zero_free(plain, pt_len) != ZTN_SUCCESS)
            zero_free_rv = ZTN_ERROR_ZERO_OUT_DATA;

        if(cipher != NULL)
            if(zero_free((char *) cipher, cipher_len) != ZTN_SUCCESS)
                zero_free_rv = ZTN_ERROR_ZERO_OUT_DATA;

        if(zero_free_rv == ZTN_SUCCESS)
            return(ZTN_ERROR_MEMORY_ALLOCATION);
        else
            return(zero_free_rv);
    }

    b64_encode(cipher, b64cipher, cipher_len);
    strip_b64_eq(b64cipher);

    if(ctx->encrypted_msg != NULL)
        zero_free_rv = zero_free(ctx->encrypted_msg,
                strnlen(ctx->encrypted_msg, MAX_SPA_ENCODED_MSG_SIZE));

    ctx->encrypted_msg = strdup(b64cipher);

    /* 清理 */
    if(zero_free(plain, pt_len) != ZTN_SUCCESS)
        zero_free_rv = ZTN_ERROR_ZERO_OUT_DATA;

    if(zero_free((char *) cipher, cipher_len) != ZTN_SUCCESS)
        zero_free_rv = ZTN_ERROR_ZERO_OUT_DATA;

    if(zero_free(b64cipher, strnlen(b64cipher,
                    MAX_SPA_ENCODED_MSG_SIZE)) != ZTN_SUCCESS)
        zero_free_rv = ZTN_ERROR_ZERO_OUT_DATA;

    if(ctx->encrypted_msg == NULL)
        return(ZTN_ERROR_MEMORY_ALLOCATION);

    ctx->encrypted_msg_len = strnlen(ctx->encrypted_msg, MAX_SPA_ENCODED_MSG_SIZE);

    if(! is_valid_encoded_msg_len(ctx->encrypted_msg_len))
        return(ZTN_ERROR_INVALID_DATA_ENCRYPT_GPG_RESULT_MSGLEN_VALIDFAIL);

    return(zero_free_rv);
}

/* 使用gpgme准备和解密 */
static int
gpg_decrypt(ztn_ctx_t ctx, const char *dec_key)
{
    unsigned char  *cipher;
    size_t          cipher_len;
    int             res, pt_len, b64_decode_len;

    /* 现在看看我们是否需要将“hQ”字符串添加到 */
    if(! ctx->added_gpg_prefix)
        add_gpg_prefix(ctx);

    /* 为（base64）解码的加密数据创建一个bucket，并获取 */
    cipher = calloc(1, ctx->encrypted_msg_len);
    if(cipher == NULL)
        return(ZTN_ERROR_MEMORY_ALLOCATION);

    if((b64_decode_len = b64_decode(ctx->encrypted_msg, cipher)) < 0)
    {
        if(zero_free((char *) cipher, ctx->encrypted_msg_len) == ZTN_SUCCESS)
            return(ZTN_ERROR_INVALID_DATA_ENCRYPT_GPG_CIPHER_DECODEFAIL);
        else
            return(ZTN_ERROR_ZERO_OUT_DATA);

    }

    cipher_len = b64_decode_len;

    /* 为明文数据创建一个bucket并解密消息 */
    /* --DSS实际上，所需的内存将在gpgme_decrypt中被mallocated */

    res = gpgme_decrypt(ctx, cipher, cipher_len,
        dec_key, (unsigned char**)&ctx->encoded_msg, &cipher_len
    );

    /* 密码已完成。。。 */
    if(zero_free((char *) cipher, ctx->encrypted_msg_len) != ZTN_SUCCESS)
        return(ZTN_ERROR_ZERO_OUT_DATA);
    else
        if(res != ZTN_SUCCESS) /* 如果有其他问题，请保释 */
            return(res);

    if(ctx->encoded_msg == NULL)
        return(ZTN_ERROR_INVALID_DATA_ENCRYPT_DECRYPTED_MESSAGE_MISSING);

    pt_len = strnlen(ctx->encoded_msg, MAX_SPA_ENCODED_MSG_SIZE);

    if(! is_valid_encoded_msg_len(pt_len))
        return(ZTN_ERROR_INVALID_DATA_ENCRYPT_DECRYPTED_MSGLEN_VALIDFAIL);

    ctx->encoded_msg_len = pt_len;

    /* 调用ztn_decode并返回结果。 */
    return(ztn_decode_spa_data(ctx));
}

#endif /* HAVE_LIBGPGME */

/* 设置SPA加密类型。 */
//设置spa加密模式

int
ztn_set_spa_encryption_type(ztn_ctx_t ctx, const short encrypt_type)
{
#if HAVE_LIBFIU
    fiu_return_on("ztn_set_spa_encryption_type_init",
            ZTN_ERROR_CTX_NOT_INITIALIZED);
#endif
    /* 必须初始化 */
    if(!CTX_INITIALIZED(ctx))//有没有经过初始化
        return(ZTN_ERROR_CTX_NOT_INITIALIZED);

#if HAVE_LIBFIU
    fiu_return_on("ztn_set_spa_encryption_type_val",
            ZTN_ERROR_INVALID_DATA_ENCRYPT_TYPE_VALIDFAIL);
#endif
    //判断加密模式是否是有效的
    if(encrypt_type < 0 || encrypt_type >= ZTN_LAST_ENCRYPTION_TYPE)
        return(ZTN_ERROR_INVALID_DATA_ENCRYPT_TYPE_VALIDFAIL);

    ctx->encryption_type = encrypt_type;

    ctx->state |= ZTN_ENCRYPT_TYPE_MODIFIED;

    return(ZTN_SUCCESS);
}

/* 返回SPA加密类型。 */
int
ztn_get_spa_encryption_type(ztn_ctx_t ctx, short *enc_type)
{
    /* 必须初始化 */
    if(!CTX_INITIALIZED(ctx))
        return(ZTN_ERROR_CTX_NOT_INITIALIZED);

    *enc_type = ctx->encryption_type;

    return(ZTN_SUCCESS);
}

/* 设置SPA加密模式。 */
int
ztn_set_spa_encryption_mode(ztn_ctx_t ctx, const int encrypt_mode)
{
#if HAVE_LIBFIU
    fiu_return_on("ztn_set_spa_encryption_mode_init",
            ZTN_ERROR_CTX_NOT_INITIALIZED);
#endif
    /* 必须初始化 */
    if(!CTX_INITIALIZED(ctx))
        return(ZTN_ERROR_CTX_NOT_INITIALIZED);

#if HAVE_LIBFIU
    fiu_return_on("ztn_set_spa_encryption_mode_val",
            ZTN_ERROR_INVALID_DATA_ENCRYPT_MODE_VALIDFAIL);
#endif
    if(encrypt_mode < 0 || encrypt_mode >= ZTN_LAST_ENC_MODE)
        return(ZTN_ERROR_INVALID_DATA_ENCRYPT_MODE_VALIDFAIL);

    ctx->encryption_mode = encrypt_mode;

    ctx->state |= ZTN_ENCRYPT_MODE_MODIFIED;

    return(ZTN_SUCCESS);
}

/* 返回SPA加密模式。 */
//设置SPA数据包加密格式，这种格式是指用哪种加密算法，例如AES、DES等
int
ztn_get_spa_encryption_mode(ztn_ctx_t ctx, int *enc_mode)
{
    /* 必须初始化 */
    if(!CTX_INITIALIZED(ctx))
        return(ZTN_ERROR_CTX_NOT_INITIALIZED);

    if(enc_mode == NULL)
        return(ZTN_ERROR_INVALID_DATA);

    *enc_mode = ctx->encryption_mode;

    return(ZTN_SUCCESS);
}

/* 对编码的SPA数据进行加密。 */
int
ztn_encrypt_spa_data(ztn_ctx_t ctx, const char * const enc_key,
        const int enc_key_len)
{
    int             res = 0;

    /* 必须初始化 */
   //必须初始化过
    if(!CTX_INITIALIZED(ctx))
        return(ZTN_ERROR_CTX_NOT_INITIALIZED);
    //密钥长度必须大于0
    if(enc_key_len < 0)
        return(ZTN_ERROR_INVALID_KEY_LEN);

    /* 如果没有编码数据或者SPA数据已经被修改， */
   //还没有加密数据或者spa数据被修改
    if(ctx->encoded_msg == NULL || ZTN_IS_SPA_DATA_MODIFIED(ctx))
        //编码spa数据包并生成消息摘要
        res = ztn_encode_spa_data(ctx);

    if(res != ZTN_SUCCESS)
        return(res);

    /* 也会对无效的编码消息进行篡改。目前这是一个 */
    if (! is_valid_encoded_msg_len(ctx->encoded_msg_len))
        return(ZTN_ERROR_MISSING_ENCODED_DATA);

    /* 根据类型加密并返回。。。 */
   //加密类型是RIJNDAEL
    if(ctx->encryption_type == ZTN_ENCRYPTION_RIJNDAEL)
    {
        if(enc_key == NULL)
            return(ZTN_ERROR_INVALID_KEY_LEN);
        res = _rijndael_encrypt(ctx, enc_key, enc_key_len);
    }
    //GPG
    else if(ctx->encryption_type == ZTN_ENCRYPTION_GPG)
#if HAVE_LIBGPGME
        res = gpg_encrypt(ctx, enc_key);
#else
        res = ZTN_ERROR_UNSUPPORTED_FEATURE;
#endif
    else
        res = ZTN_ERROR_INVALID_ENCRYPTION_TYPE;

    return(res);
}

/* 将SPA数据解码、解密并解析到上下文中。 */
int
ztn_decrypt_spa_data(ztn_ctx_t ctx, const char * const dec_key, const int key_len)
{
    int     enc_type, res;

    if(!CTX_INITIALIZED(ctx))
        return(ZTN_ERROR_CTX_NOT_INITIALIZED);

    if(key_len < 0)
        return(ZTN_ERROR_INVALID_KEY_LEN);

    /* 获取所使用的（假定的）加密类型。这也将提供 */
    enc_type = ztn_encryption_type(ctx->encrypted_msg);

    if(enc_type == ZTN_ENCRYPTION_GPG
            && ctx->encryption_mode == ZTN_ENC_MODE_ASYMMETRIC)
    {
        ctx->encryption_type = ZTN_ENCRYPTION_GPG;
#if HAVE_LIBGPGME
        res = gpg_decrypt(ctx, dec_key);
#else
        res = ZTN_ERROR_UNSUPPORTED_FEATURE;
#endif
    }
    else if(enc_type == ZTN_ENCRYPTION_RIJNDAEL)
    {
        ctx->encryption_type = ZTN_ENCRYPTION_RIJNDAEL;
        res = _rijndael_decrypt(ctx,
            dec_key, key_len, ctx->encryption_mode);
    }
    else
        return(ZTN_ERROR_INVALID_DATA_ENCRYPT_TYPE_UNKNOWN);

    return(res);
}

/* 返回基于原始加密数据的假定加密类型。 */
int
ztn_encryption_type(const char * const enc_data)
{
    int enc_data_len;

    /* 卫生检查数据。 */
    if(enc_data == NULL)
        return(ZTN_ENCRYPTION_INVALID_DATA);

    enc_data_len = strnlen(enc_data, MAX_SPA_ENCODED_MSG_SIZE);

    if(! is_valid_encoded_msg_len(enc_data_len))
        return(ZTN_ENCRYPTION_UNKNOWN);

    if(enc_data_len >= MIN_GNUPG_MSG_SIZE)
        return(ZTN_ENCRYPTION_GPG);

    else if(enc_data_len < MIN_GNUPG_MSG_SIZE
      && enc_data_len >= MIN_SPA_ENCODED_MSG_SIZE)
        return(ZTN_ENCRYPTION_RIJNDAEL);

    else
        return(ZTN_ENCRYPTION_UNKNOWN);
}

/* 设置GPG收件人密钥名称。 */
//设置GPG加密的收件人，并获取相应的GPG密钥
int
ztn_set_gpg_recipient(ztn_ctx_t ctx, const char * const recip)
{
#if HAVE_LIBGPGME
    int             res;
    gpgme_key_t     key     = NULL;

    /* 必须初始化 */
    if(!CTX_INITIALIZED(ctx))
        return(ZTN_ERROR_CTX_NOT_INITIALIZED);

    if(ctx->encryption_type != ZTN_ENCRYPTION_GPG)
        return(ZTN_ERROR_WRONG_ENCRYPTION_TYPE);

    if(ctx->gpg_recipient != NULL)
        free(ctx->gpg_recipient);

    ctx->gpg_recipient = strdup(recip);
    if(ctx->gpg_recipient == NULL)
        return(ZTN_ERROR_MEMORY_ALLOCATION);

    /* 拿到钥匙。 */
    res = get_gpg_key(ctx, &key, 0);
    if(res != ZTN_SUCCESS)
    {
        free(ctx->gpg_recipient);
        ctx->gpg_recipient = NULL;
        return(res);
    }

    ctx->recipient_key = key;

    ctx->state |= ZTN_DATA_MODIFIED;

    return(ZTN_SUCCESS);
#else
    return(ZTN_ERROR_UNSUPPORTED_FEATURE);
#endif  /* HAVE_LIBGPGME */
}

/* 设置GPG主目录。 */
//设置gpg可执行文件的目录
int
ztn_set_gpg_exe(ztn_ctx_t ctx, const char * const gpg_exe)
{
#if HAVE_LIBGPGME
    struct stat     st;

    /* 必须初始化 */
    if(!CTX_INITIALIZED(ctx))
        return(ZTN_ERROR_CTX_NOT_INITIALIZED);

    /* 如果我们无法统计给定的路径/文件并确定它是否 */
    if(stat(gpg_exe, &st) != 0)
        return(ZTN_ERROR_GPGME_BAD_GPG_EXE);

    if(!S_ISREG(st.st_mode) && !S_ISLNK(st.st_mode))
        return(ZTN_ERROR_GPGME_BAD_GPG_EXE);

    if(ctx->gpg_exe != NULL)
        free(ctx->gpg_exe);

    ctx->gpg_exe = strdup(gpg_exe);
    if(ctx->gpg_exe == NULL)
        return(ZTN_ERROR_MEMORY_ALLOCATION);

    return(ZTN_SUCCESS);
#else
    return(ZTN_ERROR_UNSUPPORTED_FEATURE);
#endif  /* HAVE_LIBGPGME */
}

/* 获取GPG主目录。 */
int
ztn_get_gpg_exe(ztn_ctx_t ctx, char **gpg_exe)
{
#if HAVE_LIBGPGME
    /* 必须初始化 */
    if(!CTX_INITIALIZED(ctx))
        return(ZTN_ERROR_CTX_NOT_INITIALIZED);

    *gpg_exe = ctx->gpg_exe;

    return(ZTN_SUCCESS);
#else
    return(ZTN_ERROR_UNSUPPORTED_FEATURE);
#endif  /* HAVE_LIBGPGME */
}

/* 获取GPG收件人密钥名称。 */
int
ztn_get_gpg_recipient(ztn_ctx_t ctx, char **recipient)
{
#if HAVE_LIBGPGME
    /* 必须初始化 */
    if(!CTX_INITIALIZED(ctx))
        return(ZTN_ERROR_CTX_NOT_INITIALIZED);

    *recipient = ctx->gpg_recipient;

    return(ZTN_SUCCESS);
#else
    return(ZTN_ERROR_UNSUPPORTED_FEATURE);
#endif  /* HAVE_LIBGPGME */
}

/* 设置GPG签名者密钥名称。 */
int
ztn_set_gpg_signer(ztn_ctx_t ctx, const char * const signer)
{
#if HAVE_LIBGPGME
    int             res;
    gpgme_key_t     key     = NULL;

    /* 必须初始化 */
    if(!CTX_INITIALIZED(ctx))
        return(ZTN_ERROR_CTX_NOT_INITIALIZED);

    if(ctx->encryption_type != ZTN_ENCRYPTION_GPG)
        return(ZTN_ERROR_WRONG_ENCRYPTION_TYPE);

    if(ctx->gpg_signer != NULL)
        free(ctx->gpg_signer);

    ctx->gpg_signer = strdup(signer);
    if(ctx->gpg_signer == NULL)
        return(ZTN_ERROR_MEMORY_ALLOCATION);

    /* 拿到钥匙。 */
    res = get_gpg_key(ctx, &key, 1);
    if(res != ZTN_SUCCESS)
    {
        free(ctx->gpg_signer);
        ctx->gpg_signer = NULL;
        return(res);
    }

    ctx->signer_key = key;

    ctx->state |= ZTN_DATA_MODIFIED;

    return(ZTN_SUCCESS);
#else
    return(ZTN_ERROR_UNSUPPORTED_FEATURE);
#endif  /* HAVE_LIBGPGME */
}

/* 获取GPG签名者密钥名称。 */
int
ztn_get_gpg_signer(ztn_ctx_t ctx, char **signer)
{
#if HAVE_LIBGPGME
    /* 必须初始化 */
    if(!CTX_INITIALIZED(ctx))
        return(ZTN_ERROR_CTX_NOT_INITIALIZED);

    *signer = ctx->gpg_signer;

    return(ZTN_SUCCESS);
#else
    return(ZTN_ERROR_UNSUPPORTED_FEATURE);
#endif  /* HAVE_LIBGPGME */
}

/* 设置GPG主目录。 */
int
ztn_set_gpg_home_dir(ztn_ctx_t ctx, const char * const gpg_home_dir)
{
#if HAVE_LIBGPGME
    struct stat     st;

    /* 必须初始化 */
    if(!CTX_INITIALIZED(ctx))
        return(ZTN_ERROR_CTX_NOT_INITIALIZED);

    /* 如果我们无法统计给定的目录，那么返回错误。 */
    if(stat(gpg_home_dir, &st) != 0) //获取文件状态信息
        return(ZTN_ERROR_GPGME_BAD_HOME_DIR);

    if(!S_ISDIR(st.st_mode))
        return(ZTN_ERROR_GPGME_BAD_HOME_DIR);

    if(ctx->gpg_home_dir != NULL)
        free(ctx->gpg_home_dir);

    ctx->gpg_home_dir = strdup(gpg_home_dir);
    if(ctx->gpg_home_dir == NULL)
        return(ZTN_ERROR_MEMORY_ALLOCATION);

    return(ZTN_SUCCESS);
#else
    return(ZTN_ERROR_UNSUPPORTED_FEATURE);
#endif  /* HAVE_LIBGPGME */
}

/* 获取GPG主目录。 */
int
ztn_get_gpg_home_dir(ztn_ctx_t ctx, char **home_dir)
{
#if HAVE_LIBGPGME
    /* 必须初始化 */
    if(!CTX_INITIALIZED(ctx))
        return(ZTN_ERROR_CTX_NOT_INITIALIZED);

    *home_dir = ctx->gpg_home_dir;

    return(ZTN_SUCCESS);
#else
    return(ZTN_ERROR_UNSUPPORTED_FEATURE);
#endif  /* HAVE_LIBGPGME */
}

int
ztn_set_gpg_signature_verify(ztn_ctx_t ctx, const unsigned char val)
{
#if HAVE_LIBGPGME
    /* 必须初始化 */
    if(!CTX_INITIALIZED(ctx))
        return(ZTN_ERROR_CTX_NOT_INITIALIZED);

    ctx->verify_gpg_sigs = (val != 0) ? 1 : 0;

    return(ZTN_SUCCESS);
#else
    return(ZTN_ERROR_UNSUPPORTED_FEATURE);
#endif  /* HAVE_LIBGPGME */
}

int
ztn_get_gpg_signature_verify(ztn_ctx_t ctx, unsigned char * const val)
{
#if HAVE_LIBGPGME
    /* 必须初始化 */
    if(!CTX_INITIALIZED(ctx))
        return(ZTN_ERROR_CTX_NOT_INITIALIZED);

    *val = ctx->verify_gpg_sigs;

    return(ZTN_SUCCESS);
#else
    return(ZTN_ERROR_UNSUPPORTED_FEATURE);
#endif  /* HAVE_LIBGPGME */
}

int
ztn_set_gpg_ignore_verify_error(ztn_ctx_t ctx, const unsigned char val)
{
#if HAVE_LIBGPGME
    /* 必须初始化 */
    if(!CTX_INITIALIZED(ctx))
        return(ZTN_ERROR_CTX_NOT_INITIALIZED);

    ctx->ignore_gpg_sig_error = (val != 0) ? 1 : 0;

    return(ZTN_SUCCESS);
#else
    return(ZTN_ERROR_UNSUPPORTED_FEATURE);
#endif  /* HAVE_LIBGPGME */
}

int
ztn_get_gpg_ignore_verify_error(ztn_ctx_t ctx, unsigned char * const val)
{
#if HAVE_LIBGPGME
    /* 必须初始化 */
    if(!CTX_INITIALIZED(ctx))
        return(ZTN_ERROR_CTX_NOT_INITIALIZED);

    *val = ctx->ignore_gpg_sig_error;

    return(ZTN_SUCCESS);
#else
    return(ZTN_ERROR_UNSUPPORTED_FEATURE);
#endif  /* HAVE_LIBGPGME */
}


int
ztn_get_gpg_signature_fpr(ztn_ctx_t ctx, char **fpr)
{
#if HAVE_LIBGPGME
    /* 必须初始化 */
    if(!CTX_INITIALIZED(ctx))
        return(ZTN_ERROR_CTX_NOT_INITIALIZED);

    /* 必须使用GPG加密。 */
    if(ctx->encryption_type != ZTN_ENCRYPTION_GPG)
        return(ZTN_ERROR_WRONG_ENCRYPTION_TYPE);

    /* 确保我们应该验证签名。 */
    if(ctx->verify_gpg_sigs == 0)
        return(ZTN_ERROR_GPGME_SIGNATURE_VERIFY_DISABLED);

    /* 请确保我们有可供使用的签名。 */
    if(ctx->gpg_sigs == NULL)
        return(ZTN_ERROR_GPGME_NO_SIGNATURE);

    *fpr = ctx->gpg_sigs->fpr;

    return(ZTN_SUCCESS);
#else
    return(ZTN_ERROR_UNSUPPORTED_FEATURE);
#endif  /* HAVE_LIBGPGME */
}

int
ztn_get_gpg_signature_id(ztn_ctx_t ctx, char **id)
{
#if HAVE_LIBGPGME
    /* 必须初始化 */
    if(!CTX_INITIALIZED(ctx))
        return(ZTN_ERROR_CTX_NOT_INITIALIZED);

    /* 必须使用GPG加密。 */
    if(ctx->encryption_type != ZTN_ENCRYPTION_GPG)
        return(ZTN_ERROR_WRONG_ENCRYPTION_TYPE);

    /* 确保我们应该验证签名。 */
    if(ctx->verify_gpg_sigs == 0)
        return(ZTN_ERROR_GPGME_SIGNATURE_VERIFY_DISABLED);

    /* 请确保我们有可供使用的签名。 */
    if(ctx->gpg_sigs == NULL)
        return(ZTN_ERROR_GPGME_NO_SIGNATURE);

    *id = ctx->gpg_sigs->fpr + strlen(ctx->gpg_sigs->fpr) - 8;

    return(ZTN_SUCCESS);
#else
    return(ZTN_ERROR_UNSUPPORTED_FEATURE);
#endif  /* HAVE_LIBGPGME */
}

int
ztn_get_gpg_signature_summary(ztn_ctx_t ctx, int *sigsum)
{
#if HAVE_LIBGPGME
    /* 必须初始化 */
    if(!CTX_INITIALIZED(ctx))
        return(ZTN_ERROR_CTX_NOT_INITIALIZED);

    /* 必须使用GPG加密。 */
    if(ctx->encryption_type != ZTN_ENCRYPTION_GPG)
        return(ZTN_ERROR_WRONG_ENCRYPTION_TYPE);

    /* 确保我们应该验证签名。 */
    if(ctx->verify_gpg_sigs == 0)
        return(ZTN_ERROR_GPGME_SIGNATURE_VERIFY_DISABLED);

    /* 请确保我们有可供使用的签名。 */
    if(ctx->gpg_sigs == NULL)
        return(ZTN_ERROR_GPGME_NO_SIGNATURE);

    *sigsum = ctx->gpg_sigs->summary;

    return(ZTN_SUCCESS);
#else
    return(ZTN_ERROR_UNSUPPORTED_FEATURE);
#endif  /* HAVE_LIBGPGME */
}

int
ztn_get_gpg_signature_status(ztn_ctx_t ctx, int *sigstat)
{
#if HAVE_LIBGPGME
    /* 必须初始化 */
    if(!CTX_INITIALIZED(ctx))
        return(ZTN_ERROR_CTX_NOT_INITIALIZED);

    /* 必须使用GPG加密。 */
    if(ctx->encryption_type != ZTN_ENCRYPTION_GPG)
        return(ZTN_ERROR_WRONG_ENCRYPTION_TYPE);

    /* 确保我们应该验证签名。 */
    if(ctx->verify_gpg_sigs == 0)
        return(ZTN_ERROR_GPGME_SIGNATURE_VERIFY_DISABLED);

    /* 请确保我们有可供使用的签名。 */
    if(ctx->gpg_sigs == NULL)
        return(ZTN_ERROR_GPGME_NO_SIGNATURE);

    *sigstat = ctx->gpg_sigs->status;

    return(ZTN_SUCCESS);
#else
    return(ZTN_ERROR_UNSUPPORTED_FEATURE);
#endif  /* HAVE_LIBGPGME */
}

int
ztn_gpg_signature_id_match(ztn_ctx_t ctx, const char * const id,
        unsigned char * const result)
{
#if HAVE_LIBGPGME
    char *curr_id;
    int   rv = ZTN_SUCCESS;

    /* 必须初始化 */
    if(!CTX_INITIALIZED(ctx))
        return(ZTN_ERROR_CTX_NOT_INITIALIZED);

    /* 必须使用GPG加密。 */
    if(ctx->encryption_type != ZTN_ENCRYPTION_GPG)
        return(ZTN_ERROR_WRONG_ENCRYPTION_TYPE);

    /* 确保我们应该验证签名。 */
    if(ctx->verify_gpg_sigs == 0)
        return(ZTN_ERROR_GPGME_SIGNATURE_VERIFY_DISABLED);

    /* 请确保我们有可供使用的签名。 */
    if(ctx->gpg_sigs == NULL)
        return(ZTN_ERROR_GPGME_NO_SIGNATURE);

    rv = ztn_get_gpg_signature_id(ctx, &curr_id);
    if(rv != ZTN_SUCCESS)
        return rv;

    *result = strcmp(id, curr_id) == 0 ? 1 : 0;

    return(ZTN_SUCCESS);
#else
    return(ZTN_ERROR_UNSUPPORTED_FEATURE);
#endif  /* HAVE_LIBGPGME */
}

int
ztn_gpg_signature_fpr_match(ztn_ctx_t ctx, const char * const id,
        unsigned char * const result)
{
#if HAVE_LIBGPGME
    /* 必须初始化 */
    if(!CTX_INITIALIZED(ctx))
        return(ZTN_ERROR_CTX_NOT_INITIALIZED);

    /* 必须使用GPG加密。 */
    if(ctx->encryption_type != ZTN_ENCRYPTION_GPG)
        return(ZTN_ERROR_WRONG_ENCRYPTION_TYPE);

    /* 确保我们应该验证签名。 */
    if(ctx->verify_gpg_sigs == 0)
        return(ZTN_ERROR_GPGME_SIGNATURE_VERIFY_DISABLED);

    /* 请确保我们有可供使用的签名。 */
    if(ctx->gpg_sigs == NULL)
        return(ZTN_ERROR_GPGME_NO_SIGNATURE);

    *result = strcmp(id, ctx->gpg_sigs->fpr) == 0 ? 1 : 0;

    return(ZTN_SUCCESS);
#else
    return(ZTN_ERROR_UNSUPPORTED_FEATURE);
#endif  /* HAVE_LIBGPGME */
}

/* **EOF** */
