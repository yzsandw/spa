
#include "ztn_common.h"
#include "ztn.h"
#include "base64.h"
#include "digest.h"

/* 取一个给定的字符串，对其进行base64编码并将其附加到给定的 */
//获取给定的字符串，对其进行 base64 编码并将其附加到给定的缓冲区。
static int
append_b64(char* tbuf, char *str)
{
    int   len = strnlen(str, MAX_SPA_ENCODED_MSG_SIZE); //计算字符串的长度，不超过1500
    char *bs;

#if HAVE_LIBFIU
    fiu_return_on("append_b64_toobig",
            ZTN_ERROR_INVALID_DATA_ENCODE_MESSAGE_TOOBIG);
#endif

    if(len >= MAX_SPA_ENCODED_MSG_SIZE)
        return(ZTN_ERROR_INVALID_DATA_ENCODE_MESSAGE_TOOBIG);

#if HAVE_LIBFIU
    fiu_return_on("append_b64_calloc", ZTN_ERROR_MEMORY_ALLOCATION);
#endif
    
    bs = calloc(1, ((len/3)*4)+8); //为bs分配内存空间并初始化为0
    if(bs == NULL)
        return(ZTN_ERROR_MEMORY_ALLOCATION);

    b64_encode((unsigned char*)str, bs, len); //进行base64编码

    /* --DSS XXX：如果以后解码，请务必在此处检查 */
    strip_b64_eq(bs); //将base64编码后的'='符号去除

    strlcat(tbuf, bs, ZTN_ENCODE_TMP_BUF_SIZE); //将base64编码附加到缓冲区后

    free(bs); //释放bs缓冲区

    return(ZTN_SUCCESS);
}

/* 设置SPA加密类型。 */
//加密spa数据包
int
ztn_encode_spa_data(ztn_ctx_t ctx)
{
    int     res, offset = 0;
    char   *tbuf;

#if HAVE_LIBFIU
//libfiu是什么？
    //如果 libfiu 选择注入 "ztn_encode_spa_data_init" 故障，就会返回错误码
    fiu_return_on("ztn_encode_spa_data_init", ZTN_ERROR_CTX_NOT_INITIALIZED);
#endif
    /* 必须初始化 */
    if(!CTX_INITIALIZED(ctx))
        return(ZTN_ERROR_CTX_NOT_INITIALIZED);

    /* 检查先决条件。 */
#if HAVE_LIBFIU
    fiu_return_on("ztn_encode_spa_data_valid", ZTN_ERROR_INCOMPLETE_SPA_DATA);
#endif
    if(  validate_username(ctx->username) != ZTN_SUCCESS
      || ctx->version  == NULL || strnlen(ctx->version, MAX_SPA_VERSION_SIZE)  == 0
      || ctx->message  == NULL || strnlen(ctx->message, MAX_SPA_MESSAGE_SIZE)  == 0)
    {
        return(ZTN_ERROR_INCOMPLETE_SPA_DATA);
    }

    if(ctx->message_type == ZTN_NAT_ACCESS_MSG)
    {
        if(ctx->nat_access == NULL || strnlen(ctx->nat_access, MAX_SPA_MESSAGE_SIZE) == 0)
            return(ZTN_ERROR_INCOMPLETE_SPA_DATA);
    }

#if HAVE_LIBFIU
    fiu_return_on("ztn_encode_spa_data_calloc", ZTN_ERROR_MEMORY_ALLOCATION);
#endif
    /* 分配我们的初始tmp缓冲区。 */
    tbuf = calloc(1, ZTN_ENCODE_TMP_BUF_SIZE);
    if(tbuf == NULL)
        return(ZTN_ERROR_MEMORY_ALLOCATION);

    /* 从兰特价值开始，一次把它拼成一块。 */
   //随机值
    strlcpy(tbuf, ctx->rand_val, ZTN_ENCODE_TMP_BUF_SIZE);

    /* 添加base64编码的用户名。 */
    strlcat(tbuf, ":", ZTN_ENCODE_TMP_BUF_SIZE);
    //对username进行base64编码，附加到tbuf缓冲区中
    if((res = append_b64(tbuf, ctx->username)) != ZTN_SUCCESS)
    {
        free(tbuf);
        return(res);
    }

    /* 添加时间戳。 */
   //获取当前的tbuf的长度
    offset = strlen(tbuf);
    //在tbuf缓冲区后加上时间戳
    snprintf(((char*)tbuf+offset), ZTN_ENCODE_TMP_BUF_SIZE - offset,
            ":%u:", (unsigned int) ctx->timestamp);

    /* 添加版本字符串。 */
   //添加版本信息
    strlcat(tbuf, ctx->version, ZTN_ENCODE_TMP_BUF_SIZE);

    /* 在添加消息类型值之前，我们将再次 */
   //设置超时值以便服务端验证数据包有效期
    ztn_set_spa_client_timeout(ctx, ctx->client_timeout);

    /* 添加消息类型值。 */
   //添加消息类型(TIMEOUT或者没超时)
    offset = strlen(tbuf);
    snprintf(((char*)tbuf+offset), ZTN_ENCODE_TMP_BUF_SIZE - offset,
            ":%i:", ctx->message_type);
 
    /* 添加base64编码的SPA消息。 */
   //将spa message进行base64编码，附加到tbuf后
    if((res = append_b64(tbuf, ctx->message)) != ZTN_SUCCESS)
    {
        free(tbuf);
        return(res);
    }

    /* 如果给定了nat_access消息，请将其添加到SPA */
   //如果有访问NAT字符串，将其编码添加到tubf后
    if(ctx->nat_access != NULL)
    {
        strlcat(tbuf, ":", ZTN_ENCODE_TMP_BUF_SIZE);
        if((res = append_b64(tbuf, ctx->nat_access)) != ZTN_SUCCESS)
        {
            free(tbuf);
            return(res);
        }
    }

    /* 如果我们有一个server_auth字段集。将其添加到此处。 */
   //将服务器认证信息编码，添加到tbuf后
    if(ctx->server_auth != NULL)
    {
        strlcat(tbuf, ":", ZTN_ENCODE_TMP_BUF_SIZE);
        if((res = append_b64(tbuf, ctx->server_auth)) != ZTN_SUCCESS)
        {
            free(tbuf);
            return(res);
        }
    }

    /* 如果指定了客户端超时，而我们没有处理 */
   //如果指定了客户端超时，而我们没有处理SPA命令消息，在此处添加超时。
    if(ctx->client_timeout > 0 && ctx->message_type != ZTN_COMMAND_MSG)
    {
        offset = strlen(tbuf);
        snprintf(((char*)tbuf+offset), ZTN_ENCODE_TMP_BUF_SIZE - offset,
                ":%i", ctx->client_timeout);
    }

    /* 如果encoded_msg不为null，那么我们假设它需要 */
   //先清理encoded_msg
    if(ctx->encoded_msg != NULL)
        free(ctx->encoded_msg);

    /* 将我们的编码数据复制到上下文中。 */
   //把编码后的数据赋值给encoded_msg
    ctx->encoded_msg = strdup(tbuf);
    free(tbuf);

    if(ctx->encoded_msg == NULL)
        return(ZTN_ERROR_MEMORY_ALLOCATION);

    ctx->encoded_msg_len = strnlen(ctx->encoded_msg, MAX_SPA_ENCODED_MSG_SIZE);

    if(! is_valid_encoded_msg_len(ctx->encoded_msg_len))
        return(ZTN_ERROR_INVALID_DATA_ENCODE_MSGLEN_VALIDFAIL);

    /* 在这一点上，我们可以计算这个SPA数据的摘要。 */
   //设置消息摘要
    if((res = ztn_set_spa_digest(ctx)) != ZTN_SUCCESS)
        return(res);

    /* 在这里，我们可以清除SPA数据字段上的修改标志。 */
    ZTN_CLEAR_SPA_DATA_MODIFIED(ctx);

    return(ZTN_SUCCESS);
}

/* 返回ztn SPA加密数据。 */
int
ztn_get_encoded_data(ztn_ctx_t ctx, char **enc_msg)
{
    /* 必须初始化 */
    if(!CTX_INITIALIZED(ctx))
        return(ZTN_ERROR_CTX_NOT_INITIALIZED);

    if(enc_msg == NULL)
        return(ZTN_ERROR_INVALID_DATA);

    *enc_msg = ctx->encoded_msg;

    return(ZTN_SUCCESS);
}

/* 设置ztn SPA编码数据（这是一种方便 */
#if FUZZING_INTERFACES
int
ztn_set_encoded_data(ztn_ctx_t ctx,
        const char * const encoded_msg, const int msg_len,
        const int require_digest, const int digest_type)
{
    char *tbuf   = NULL;
    int          res = ZTN_SUCCESS, mlen;

    /* 必须初始化 */
    if(!CTX_INITIALIZED(ctx))
        return(ZTN_ERROR_CTX_NOT_INITIALIZED);

    if(encoded_msg == NULL)
        return(ZTN_ERROR_INVALID_DATA);

    ctx->encoded_msg = strdup(encoded_msg);

    ctx->state |= ZTN_DATA_MODIFIED;

    if(ctx->encoded_msg == NULL)
        return(ZTN_ERROR_MEMORY_ALLOCATION);

    /* 允许任意长度（即，让解码例程验证 */
    ctx->encoded_msg_len = msg_len;

    if(require_digest)
    {
        ztn_set_spa_digest_type(ctx, digest_type);
        if((res = ztn_set_spa_digest(ctx)) != ZTN_SUCCESS)
        {
            return res;
        }

        /* 将摘要附加到编码消息缓冲区 */
        mlen = ctx->encoded_msg_len + ctx->digest_len + 2;
        tbuf = calloc(1, mlen);
        if(tbuf == NULL)
            return(ZTN_ERROR_MEMORY_ALLOCATION);

        /* memcpy，因为提供的编码缓冲区可能 */
        mlen = snprintf(tbuf, mlen, "%s:%s", ctx->encoded_msg, ctx->digest);

        if(ctx->encoded_msg != NULL)
            free(ctx->encoded_msg);

        ctx->encoded_msg = strdup(tbuf);
        free(tbuf);

        if(ctx->encoded_msg == NULL)
            return(ZTN_ERROR_MEMORY_ALLOCATION);

        ctx->encoded_msg_len = mlen;
    }

    ZTN_CLEAR_SPA_DATA_MODIFIED(ctx);

    return(ZTN_SUCCESS);
}
#endif

/* **EOF** */
