

#include "fko_common.h"
#include "fko.h"

#if HAVE_LIBGPGME
#include "gpgme_funcs.h"

int
init_gpgme(fko_ctx_t fko_ctx)
{
    gpgme_error_t       err;

    /* 如果我们已经有了背景，我们就完了。 */
    if(fko_ctx->have_gpgme_context)
        return(FKO_SUCCESS);

    /* 因为gpgme手册上说你应该这样做。 */
    gpgme_check_version(NULL);

    /* 检查OpenPGP支持 */
    err = gpgme_engine_check_version(GPGME_PROTOCOL_OpenPGP);
    if(gpg_err_code(err) != GPG_ERR_NO_ERROR)
    {
        /* GPG发动机不可用。 */
        fko_ctx->gpg_err = err;
        return(FKO_ERROR_GPGME_NO_OPENPGP);
    }

    /* 提取当前gpgme引擎信息。 */
    gpgme_set_engine_info(
            GPGME_PROTOCOL_OpenPGP,
            (fko_ctx->gpg_exe != NULL) ? fko_ctx->gpg_exe : GPG_EXE,
            fko_ctx->gpg_home_dir   /* 如果为NULL，则使用默认值 */
    );

    /* 创建我们的gpgme上下文 */
    err = gpgme_new(&(fko_ctx->gpg_ctx));
    if(gpg_err_code(err) != GPG_ERR_NO_ERROR)
    {
        fko_ctx->gpg_err = err;
        return(FKO_ERROR_GPGME_CONTEXT);
    }

    fko_ctx->have_gpgme_context = 1;

    return(FKO_SUCCESS);
}

/* 回调函数，在gpgme需要时提供密码。 */
gpgme_error_t
my_passphrase_cb(
  void *pw, const char *uid_hint, const char *passphrase_info,
  int prev_was_bad, int fd)
{
    /* 我们只需要尝试一次，因为它是由程序提供的 */
    if(prev_was_bad)
        return(GPG_ERR_CANCELED);

    if(write(fd, (const char*)pw, strlen((const char*)pw))
      != strlen((const char*)pw))
        return(GPG_ERR_SYSTEM_ERROR); /* 肯定是GPG错误，但是哪一个？ */

    if(write(fd, "\n", 1) != 1)
        return(GPG_ERR_SYSTEM_ERROR); /* 肯定是GPG错误，但是哪一个？ */

    return 0;
}

/* 在Verify_result集中验证gpg签名。 */
static int
process_sigs(fko_ctx_t fko_ctx, gpgme_verify_result_t vres)
{
    unsigned int        sig_cnt = 0;
    gpgme_signature_t   sig     = vres->signatures;
    fko_gpg_sig_t       fgs;

    /* 只想看到一个签名（目前）。 */
    if(!sig)
        return(FKO_ERROR_GPGME_NO_SIGNATURE);

    /* 遍历sigs并存储我们感兴趣的信息 */
    while(sig != NULL)
    {
        fgs = calloc(1, sizeof(struct fko_gpg_sig));
        if(fgs == NULL)
            return(FKO_ERROR_MEMORY_ALLOCATION);

        /* 获取摘要值和状态值。 */
        fgs->summary    = sig->summary;
        fgs->status     = sig->status;
        fgs->validity   = sig->validity;

        /* 抓住签名指纹。 */
        if(sig->fpr != NULL)
        {
            fgs->fpr = strdup(sig->fpr);
            if(fgs->fpr == NULL)
            {
                free(fgs);
                return(FKO_ERROR_MEMORY_ALLOCATION);
            }
        }

        if(sig_cnt == 0)
            fko_ctx->gpg_sigs = fgs;
        else
            fko_ctx->gpg_sigs->next = fgs;

        sig_cnt++;
        sig = sig->next;
    }

    /* 如果我们忽略了错误的签名，请在此处返回success。 */
    if(fko_ctx->ignore_gpg_sig_error != 0)
        return(FKO_SUCCESS);

    /* 否则，我们将在此处进行检查并做出相应的回应。 */
    fgs = fko_ctx->gpg_sigs;

    if(fgs->status != GPG_ERR_NO_ERROR || fgs->validity < 3) {
        fko_ctx->gpg_err = fgs->status;

        return(FKO_ERROR_GPGME_BAD_SIGNATURE);
    }

    return(FKO_SUCCESS);
}

/* 获取给定名称或ID的GPG密钥。 */
/* 首先创建一个用于密钥列表的gpgme上下文对象列表_ctx以及两个密钥对象钥匙和键2 */
int
get_gpg_key(fko_ctx_t fko_ctx, gpgme_key_t *mykey, const int signer)
{
    int             res;
    const char     *name;

    gpgme_ctx_t     list_ctx    = NULL;
    gpgme_key_t     key         = NULL;
    gpgme_key_t     key2        = NULL;
    gpgme_error_t   err;

    /* 为列表创建gpgme上下文 */
    /* 初始化gpgme */
    res = init_gpgme(fko_ctx);
    if(res != FKO_SUCCESS)
    {
        if(signer)
            return(FKO_ERROR_GPGME_CONTEXT_SIGNER_KEY);
        else
            return(FKO_ERROR_GPGME_CONTEXT_RECIPIENT_KEY);
    }

    list_ctx = fko_ctx->gpg_ctx;

    if(signer)
        name = fko_ctx->gpg_signer;
    else
        name = fko_ctx->gpg_recipient;

    err = gpgme_op_keylist_start(list_ctx, name, signer);
    if (err)
    {
        gpgme_release(list_ctx);

        fko_ctx->gpg_err = err;

        if(signer)
            return(FKO_ERROR_GPGME_SIGNER_KEYLIST_START);
        else
            return(FKO_ERROR_GPGME_RECIPIENT_KEYLIST_START);
    }

    /* 抓住列表中的第一个键（我们希望它是唯一的一个）。 */
    err = gpgme_op_keylist_next(list_ctx, &key);
    if(gpg_err_code(err) != GPG_ERR_NO_ERROR)
    {
        /* 找不到密钥 */
        fko_ctx->gpg_err = err;

        if(signer)
            return(FKO_ERROR_GPGME_SIGNER_KEY_NOT_FOUND);
        else
            return(FKO_ERROR_GPGME_RECIPIENT_KEY_NOT_FOUND);
    }

    /* 我们努力争取下一场关键比赛。如果我们这样做，那么名称是 */
    err = gpgme_op_keylist_next(list_ctx, &key2);
    if(gpg_err_code(err) == GPG_ERR_NO_ERROR) /* 注意：查找无错误 */
    {
        /* 密钥说明不明确 */
        gpgme_key_unref(key);
        gpgme_key_unref(key2);

        fko_ctx->gpg_err = err;

        if(signer)
            return(FKO_ERROR_GPGME_SIGNER_KEY_AMBIGUOUS);
        else
            return(FKO_ERROR_GPGME_RECIPIENT_KEY_AMBIGUOUS);
    }

    gpgme_op_keylist_end(list_ctx);

    gpgme_key_unref(key2);

    *mykey = key;

    return(FKO_SUCCESS);
}

/* libfko的主要GPG加密例程。 */
int
gpgme_encrypt(fko_ctx_t fko_ctx, unsigned char *indata, size_t in_len,
        const char *pw, unsigned char **out, size_t *out_len)
{
    char               *tmp_buf;
    int                 res;

    gpgme_ctx_t         gpg_ctx     = NULL;
    gpgme_data_t        cipher      = NULL;
    gpgme_data_t        plaintext   = NULL;
    gpgme_key_t         key[2]      = { NULL, NULL };
    gpgme_error_t       err;

    /* 初始化gpgme */
    res = init_gpgme(fko_ctx);
    if(res != FKO_SUCCESS)
        return(res);

    gpg_ctx = fko_ctx->gpg_ctx;

    /* 初始化明文数据（放入gpgme_data对象中） */
    err = gpgme_data_new_from_mem(&plaintext, (char*)indata, in_len, 1);
    if(gpg_err_code(err) != GPG_ERR_NO_ERROR)
    {
        gpgme_release(gpg_ctx);
        fko_ctx->gpg_ctx = NULL;
        fko_ctx->gpg_err = err;

        return(FKO_ERROR_GPGME_PLAINTEXT_DATA_OBJ);
    }

    /* 设置协议 */
    err = gpgme_set_protocol(gpg_ctx, GPGME_PROTOCOL_OpenPGP);
    if(gpg_err_code(err) != GPG_ERR_NO_ERROR)
    {
        gpgme_data_release(plaintext);
        gpgme_release(gpg_ctx);
        fko_ctx->gpg_ctx = NULL;

        fko_ctx->gpg_err = err;

        return(FKO_ERROR_GPGME_SET_PROTOCOL);
    }

    /* 关闭ascii盔甲（我们将对加密数据进行base64编码 */
    gpgme_set_armor(gpg_ctx, 0);

    /* gpgme_encrypt。。。。函数采用一个接收方密钥数组，因此我们添加 */
    key[0] = fko_ctx->recipient_key;

    /* 为我们的加密数据创建缓冲区。 */
    err = gpgme_data_new(&cipher);
    if(gpg_err_code(err) != GPG_ERR_NO_ERROR)
    {
        gpgme_data_release(plaintext);
        gpgme_release(gpg_ctx);
        fko_ctx->gpg_ctx = NULL;

        fko_ctx->gpg_err = err;

        return(FKO_ERROR_GPGME_CIPHER_DATA_OBJ);
    }

    /* 在这里，我们将签名者添加到gpgme上下文中（如果有的话）。 */
    if(fko_ctx->gpg_signer != NULL) {
        gpgme_signers_clear(gpg_ctx);
        err = gpgme_signers_add(gpg_ctx, fko_ctx->signer_key);
        if(gpg_err_code(err) != GPG_ERR_NO_ERROR)
        {
            gpgme_data_release(plaintext);
            gpgme_data_release(cipher);
            gpgme_release(gpg_ctx);
            fko_ctx->gpg_ctx = NULL;

            fko_ctx->gpg_err = err;

            return(FKO_ERROR_GPGME_ADD_SIGNER);
        }
    }

    /* 设置密码短语回调。 */
    gpgme_set_passphrase_cb(gpg_ctx, my_passphrase_cb, (void*)pw);

    /* 对SPA数据进行加密和签名（如果提供了sig）。 */
    if(fko_ctx->gpg_signer == NULL)
        err = gpgme_op_encrypt(
            gpg_ctx, key, GPGME_ENCRYPT_ALWAYS_TRUST, plaintext, cipher
        );
    else
        err = gpgme_op_encrypt_sign(
            gpg_ctx, key, GPGME_ENCRYPT_ALWAYS_TRUST, plaintext, cipher
        );

    if(gpg_err_code(err) != GPG_ERR_NO_ERROR)
    {
        gpgme_data_release(plaintext);
        gpgme_data_release(cipher);
        gpgme_release(gpg_ctx);
        fko_ctx->gpg_ctx = NULL;

        fko_ctx->gpg_err = err;

        if(gpgme_err_code(err) == GPG_ERR_CANCELED)
            return(FKO_ERROR_GPGME_BAD_PASSPHRASE);

        return(FKO_ERROR_GPGME_ENCRYPT_SIGN);
    }

    /* 用明文完成。 */
    gpgme_data_release(plaintext);

    /* 从gpgme数据对象中获取加密数据及其长度。 */
    tmp_buf = gpgme_data_release_and_get_mem(cipher, out_len);

    *out = calloc(1, *out_len); /* 这是在fko_ctx销毁后释放的。 */
    if(*out == NULL)
        res = FKO_ERROR_MEMORY_ALLOCATION;
    else
    {
        memcpy(*out, tmp_buf, *out_len);
        res = FKO_SUCCESS;
    }

    gpgme_free(tmp_buf);

    return(res);
}

/* libfko的主要GPG解密例程。 */
int
gpgme_decrypt(fko_ctx_t fko_ctx, unsigned char *indata,
        size_t in_len, const char *pw, unsigned char **out, size_t *out_len)
{
    char                   *tmp_buf;
    int                     res;

    gpgme_ctx_t             gpg_ctx     = NULL;
    gpgme_data_t            cipher      = NULL;
    gpgme_data_t            plaintext   = NULL;
    gpgme_error_t           err;
    gpgme_decrypt_result_t  decrypt_res;
    gpgme_verify_result_t   verify_res;

    /* 初始化gpgme */
    res = init_gpgme(fko_ctx);
    if(res != FKO_SUCCESS)
        return(res);

    gpg_ctx = fko_ctx->gpg_ctx;

    err = gpgme_data_new(&plaintext);
    if(gpg_err_code(err) != GPG_ERR_NO_ERROR)
    {
        gpgme_release(gpg_ctx);
        fko_ctx->gpg_ctx = NULL;

        fko_ctx->gpg_err = err;

        return(FKO_ERROR_GPGME_PLAINTEXT_DATA_OBJ);
    }

    /* 初始化密码数据（放入gpgme_data对象中） */
    err = gpgme_data_new_from_mem(&cipher, (char*)indata, in_len, 0);
    if(gpg_err_code(err) != GPG_ERR_NO_ERROR)
    {
        gpgme_data_release(plaintext);
        gpgme_release(gpg_ctx);
        fko_ctx->gpg_ctx = NULL;

        fko_ctx->gpg_err = err;

        return(FKO_ERROR_GPGME_CIPHER_DATA_OBJ);
    }

    /* 设置密码短语回调。 */
    gpgme_set_passphrase_cb(gpg_ctx, my_passphrase_cb, (void*)pw);

    /* 现在解密并验证。 */
    err = gpgme_op_decrypt_verify(gpg_ctx, cipher, plaintext);
    if(gpg_err_code(err) != GPG_ERR_NO_ERROR)
    {
        gpgme_data_release(plaintext);
        gpgme_data_release(cipher);
        gpgme_release(gpg_ctx);
        fko_ctx->gpg_ctx = NULL;

        fko_ctx->gpg_err = err;

        return(FKO_ERROR_GPGME_DECRYPT_FAILED);
    }

    /* 密码文本处理完毕。 */
    gpgme_data_release(cipher);

    /* 我们检查解密结果中的“usupported_agorithm”标志。 */
    decrypt_res = gpgme_op_decrypt_result(gpg_ctx);

    if(decrypt_res->unsupported_algorithm)
    {
        gpgme_data_release(plaintext);
        gpgme_release(gpg_ctx);
        fko_ctx->gpg_ctx = NULL;

        return(FKO_ERROR_GPGME_DECRYPT_UNSUPPORTED_ALGORITHM);
    }

    /* 现在验证签名（如果已配置）。 */
    if(fko_ctx->verify_gpg_sigs)
    {
        verify_res  = gpgme_op_verify_result(gpg_ctx);

        res = process_sigs(fko_ctx, verify_res);

        if(res != FKO_SUCCESS)
        {
            gpgme_data_release(plaintext);
            gpgme_release(gpg_ctx);
            fko_ctx->gpg_ctx = NULL;

            return(res);
        }
    }

    /* 从gpgme数据对象中获取加密数据及其长度。 */
    tmp_buf = gpgme_data_release_and_get_mem(plaintext, out_len);

    /* 此处使用带额外字节的calloc，因为我不确定是否所有系统 */
    *out = calloc(1, *out_len+1); /* 这是在fko_ctx销毁后释放的。 */

    if(*out == NULL)
        res = FKO_ERROR_MEMORY_ALLOCATION;
    else
    {
        memcpy(*out, tmp_buf, *out_len);
        res = FKO_SUCCESS;
    }

    gpgme_free(tmp_buf);

    return(res);
}

#endif /* HAVE_LIBGPGME */

/* **EOF** */
