
#include "ztn_common.h"
#include "ztn.h"
#include "cipher_funcs.h"
#include "base64.h"
#include "digest.h"

#define FIELD_PARSERS 9

/* 用于分隔SPA数据包中SPA字段的字符 */
#define SPA_FIELD_SEPARATOR    ":"

#ifdef HAVE_C_UNIT_TESTS /* LCOV_EXCL_START */
DECLARE_TEST_SUITE(ztn_decode, "ZTN decode test suite");
#endif /* LCOV_EXCL_STOP */

static int
num_fields(char *str)
{
    int    i=0;
    char   *tmp = NULL;

    /* 统计剩余SPA数据包字段的数量 */
    for (i=0; i <= MAX_SPA_FIELDS+1; i++)
    {
        if ((tmp = strchr(str, ':')) == NULL)
            break;
        str = tmp + 1;
    }
    return i;
}

static int
last_field(char *str)
{
    int    i=0, pos_last=0;
    char   *tmp = NULL;

    /* 计算最后一个“：”字符的字节数 */
    for (i=0; i <= MAX_SPA_FIELDS+1; i++)
    {
        if ((tmp = strchr(str, ':')) == NULL)
            break;

        pos_last += (tmp - str) + 1;
        str = tmp + 1;
    }
    return pos_last;
}

static int
verify_digest(char *tbuf, int t_size, ztn_ctx_t ctx)
{
#if AFL_FUZZING
    return ZTN_SUCCESS;
#endif

    switch(ctx->digest_type)
    {
        case ZTN_DIGEST_MD5:
            md5_base64(tbuf, (unsigned char*)ctx->encoded_msg, ctx->encoded_msg_len);
            break;

        case ZTN_DIGEST_SHA1:
            sha1_base64(tbuf, (unsigned char*)ctx->encoded_msg, ctx->encoded_msg_len);
            break;

        case ZTN_DIGEST_SHA256:
            sha256_base64(tbuf, (unsigned char*)ctx->encoded_msg, ctx->encoded_msg_len);
            break;

        case ZTN_DIGEST_SHA384:
            sha384_base64(tbuf, (unsigned char*)ctx->encoded_msg, ctx->encoded_msg_len);
            break;

        case ZTN_DIGEST_SHA512:
            sha512_base64(tbuf, (unsigned char*)ctx->encoded_msg, ctx->encoded_msg_len);
            break;

        /* 请注意，我们在下面检查SHA3_256和SHA3_512，因为 */

        default: /* 无效或不受支持的摘要 */
            return(ZTN_ERROR_INVALID_DIGEST_TYPE);
    }

    /* 如果计算的摘要与 */
    if(constant_runtime_cmp(ctx->digest, tbuf, t_size) != 0)
    {
        /* 也可能是SHA3_256或SHA3_512 */
        if(ctx->digest_type == ZTN_DIGEST_SHA256)
        {
            memset(tbuf, 0, ZTN_ENCODE_TMP_BUF_SIZE);
            sha3_256_base64(tbuf, (unsigned char*)ctx->encoded_msg, ctx->encoded_msg_len);
            if(constant_runtime_cmp(ctx->digest, tbuf, t_size) != 0)
            {
                return(ZTN_ERROR_DIGEST_VERIFICATION_FAILED);
            }
            else
            {
                ctx->digest_type = ZTN_DIGEST_SHA3_256;
                ctx->digest_len  = SHA3_256_B64_LEN;
            }

        }
        else if(ctx->digest_type == ZTN_DIGEST_SHA512)
        {
            memset(tbuf, 0, ZTN_ENCODE_TMP_BUF_SIZE);
            sha3_512_base64(tbuf, (unsigned char*)ctx->encoded_msg, ctx->encoded_msg_len);
            if(constant_runtime_cmp(ctx->digest, tbuf, t_size) != 0)
            {
                return(ZTN_ERROR_DIGEST_VERIFICATION_FAILED);
            }
            else
            {
                ctx->digest_type = ZTN_DIGEST_SHA3_512;
                ctx->digest_len  = SHA3_512_B64_LEN;
            }

        }
        else
            return(ZTN_ERROR_DIGEST_VERIFICATION_FAILED);
    }

    return ZTN_SUCCESS;
}

static int
is_valid_digest_len(int t_size, ztn_ctx_t ctx)
{
    switch(t_size)
    {
        case MD5_B64_LEN:
            ctx->digest_type = ZTN_DIGEST_MD5;
            ctx->digest_len  = MD5_B64_LEN;
            break;

        case SHA1_B64_LEN:
            ctx->digest_type = ZTN_DIGEST_SHA1;
            ctx->digest_len  = SHA1_B64_LEN;
            break;

        /* 也可以匹配在verify_edigest（）中处理的SHA3_256_B64_LEN */
        case SHA256_B64_LEN:
            ctx->digest_type = ZTN_DIGEST_SHA256;
            ctx->digest_len  = SHA256_B64_LEN;
            break;

        case SHA384_B64_LEN:
            ctx->digest_type = ZTN_DIGEST_SHA384;
            ctx->digest_len  = SHA384_B64_LEN;
            break;

        /* 也可以匹配在verify_edigest（）中处理的SHA3_512_B64_LEN */
        case SHA512_B64_LEN:
            ctx->digest_type = ZTN_DIGEST_SHA512;
            ctx->digest_len  = SHA512_B64_LEN;
            break;

        default: /* 无效或不受支持的摘要 */
            return(ZTN_ERROR_INVALID_DIGEST_TYPE);
    }

    if (ctx->encoded_msg_len - t_size < 0)
        return(ZTN_ERROR_INVALID_DATA_DECODE_ENC_MSG_LEN_MT_T_SIZE);

    return ZTN_SUCCESS;
}

static int
parse_msg(char *tbuf, char **ndx, int *t_size, ztn_ctx_t ctx)
{
    if((*t_size = strcspn(*ndx, ":")) < 1)
        return(ZTN_ERROR_INVALID_DATA_DECODE_MESSAGE_MISSING);

    if (*t_size > MAX_SPA_MESSAGE_SIZE)
        return(ZTN_ERROR_INVALID_DATA_DECODE_MESSAGE_TOOBIG);

    strlcpy(tbuf, *ndx, *t_size+1);

    if(ctx->message != NULL)
        free(ctx->message);

    ctx->message = calloc(1, *t_size+1); /* 是的，比我们需要的还多 */

    if(ctx->message == NULL)
        return(ZTN_ERROR_MEMORY_ALLOCATION);

    if(b64_decode(tbuf, (unsigned char*)ctx->message) < 0)
        return(ZTN_ERROR_INVALID_DATA_DECODE_MESSAGE_DECODEFAIL);

    if(ctx->message_type == ZTN_COMMAND_MSG)
    {
        /* 需要类似于以下内容的消息：1.2.3.4，＜command＞ */
        if(validate_cmd_msg(ctx->message) != ZTN_SUCCESS)
        {
            return(ZTN_ERROR_INVALID_DATA_DECODE_MESSAGE_VALIDFAIL);
        }
    }
    else
    {
        /* 需要类似于以下内容的消息：1.2.3.4，tcp/22 */
        if(validate_access_msg(ctx->message) != ZTN_SUCCESS)
        {
            return(ZTN_ERROR_INVALID_DATA_DECODE_ACCESS_VALIDFAIL);
        }
    }

    *ndx += *t_size + 1;
    return ZTN_SUCCESS;
}

static int
parse_nat_msg(char *tbuf, char **ndx, int *t_size, ztn_ctx_t ctx)
{
    if(  ctx->message_type == ZTN_NAT_ACCESS_MSG
      || ctx->message_type == ZTN_LOCAL_NAT_ACCESS_MSG
      || ctx->message_type == ZTN_CLIENT_TIMEOUT_NAT_ACCESS_MSG
      || ctx->message_type == ZTN_CLIENT_TIMEOUT_LOCAL_NAT_ACCESS_MSG)
    {
        if((*t_size = strcspn(*ndx, ":")) < 1)
            return(ZTN_ERROR_INVALID_DATA_DECODE_NATACCESS_MISSING);

        if (*t_size > MAX_SPA_MESSAGE_SIZE)
            return(ZTN_ERROR_INVALID_DATA_DECODE_NATACCESS_TOOBIG);

        strlcpy(tbuf, *ndx, *t_size+1);

        if(ctx->nat_access != NULL)
            free(ctx->nat_access);

        ctx->nat_access = calloc(1, *t_size+1); /* 是的，比我们需要的还多 */
        if(ctx->nat_access == NULL)
            return(ZTN_ERROR_MEMORY_ALLOCATION);

        if(b64_decode(tbuf, (unsigned char*)ctx->nat_access) < 0)
            return(ZTN_ERROR_INVALID_DATA_DECODE_NATACCESS_DECODEFAIL);

        if(validate_nat_access_msg(ctx->nat_access) != ZTN_SUCCESS)
            return(ZTN_ERROR_INVALID_DATA_DECODE_NATACCESS_VALIDFAIL);

        *ndx += *t_size + 1;
    }

    return ZTN_SUCCESS;
}

static int
parse_server_auth(char *tbuf, char **ndx, int *t_size, ztn_ctx_t ctx)
{
    if((*t_size = strlen(*ndx)) > 0)
    {
        if (*t_size > MAX_SPA_MESSAGE_SIZE)
        {
            return(ZTN_ERROR_INVALID_DATA_DECODE_SRVAUTH_MISSING);
        }
    }
    else
        return ZTN_SUCCESS;

    if(  ctx->message_type == ZTN_CLIENT_TIMEOUT_ACCESS_MSG
      || ctx->message_type == ZTN_CLIENT_TIMEOUT_NAT_ACCESS_MSG
      || ctx->message_type == ZTN_CLIENT_TIMEOUT_LOCAL_NAT_ACCESS_MSG)
    {
        /* 如果我们在这里，那么我们可能仍然有一个server_auth字符串， */
        if(strchr(*ndx, ':'))
        {
            *t_size = strcspn(*ndx, ":");

            if (*t_size > MAX_SPA_MESSAGE_SIZE)
                return(ZTN_ERROR_INVALID_DATA_DECODE_EXTRA_TOOBIG);

            strlcpy(tbuf, *ndx, *t_size+1);

            if(ctx->server_auth != NULL)
                free(ctx->server_auth);

            ctx->server_auth = calloc(1, *t_size+1); /* 是的，比我们需要的还多 */
            if(ctx->server_auth == NULL)
                return(ZTN_ERROR_MEMORY_ALLOCATION);

            if(b64_decode(tbuf, (unsigned char*)ctx->server_auth) < 0)
                return(ZTN_ERROR_INVALID_DATA_DECODE_EXTRA_DECODEFAIL);

            *ndx += *t_size + 1;
        }
    }
    else
    {
        strlcpy(tbuf, *ndx, *t_size+1);

        if(ctx->server_auth != NULL)
            free(ctx->server_auth);

        ctx->server_auth = calloc(1, *t_size+1); /* 是的，比我们需要的还多 */
        if(ctx->server_auth == NULL)
            return(ZTN_ERROR_MEMORY_ALLOCATION);

        if(b64_decode(tbuf, (unsigned char*)ctx->server_auth) < 0)
            return(ZTN_ERROR_INVALID_DATA_DECODE_SRVAUTH_DECODEFAIL);
    }

    return ZTN_SUCCESS;
}

static int
parse_client_timeout(char *tbuf, char **ndx, int *t_size, ztn_ctx_t ctx)
{
    int         is_err;

    if(  ctx->message_type == ZTN_CLIENT_TIMEOUT_ACCESS_MSG
      || ctx->message_type == ZTN_CLIENT_TIMEOUT_NAT_ACCESS_MSG
      || ctx->message_type == ZTN_CLIENT_TIMEOUT_LOCAL_NAT_ACCESS_MSG)
    {
        if((*t_size = strlen(*ndx)) < 1)
            return(ZTN_ERROR_INVALID_DATA_DECODE_TIMEOUT_MISSING);

        if (*t_size > MAX_SPA_MESSAGE_SIZE)
            return(ZTN_ERROR_INVALID_DATA_DECODE_TIMEOUT_TOOBIG);

        /* 应该只是一个数字。 */
        if(strspn(*ndx, "0123456789") != *t_size)
            return(ZTN_ERROR_INVALID_DATA_DECODE_TIMEOUT_VALIDFAIL);

        ctx->client_timeout = (unsigned int) strtol_wrapper(*ndx, 0,
                (2 << 15), NO_EXIT_UPON_ERR, &is_err);
        if(is_err != ZTN_SUCCESS)
            return(ZTN_ERROR_INVALID_DATA_DECODE_TIMEOUT_DECODEFAIL);
    }

    return ZTN_SUCCESS;
}

static int
parse_msg_type(char *tbuf, char **ndx, int *t_size, ztn_ctx_t ctx)
{
    int    is_err, remaining_fields;

    if((*t_size = strcspn(*ndx, ":")) < 1)
        return(ZTN_ERROR_INVALID_DATA_DECODE_MSGTYPE_MISSING);

    if(*t_size > MAX_SPA_MESSAGE_TYPE_SIZE)
        return(ZTN_ERROR_INVALID_DATA_DECODE_MSGTYPE_TOOBIG);

    strlcpy(tbuf, *ndx, *t_size+1);

    ctx->message_type = strtol_wrapper(tbuf, 0,
            ZTN_LAST_MSG_TYPE-1, NO_EXIT_UPON_ERR, &is_err);

    if(is_err != ZTN_SUCCESS)
        return(ZTN_ERROR_INVALID_DATA_DECODE_MSGTYPE_DECODEFAIL);

    /* 现在我们有了一个有效的类型，请确保 */
    remaining_fields = num_fields(*ndx);

    switch(ctx->message_type)
    {
        /* 可选server_auth+摘要 */
        case ZTN_COMMAND_MSG:
        case ZTN_ACCESS_MSG:
            if(remaining_fields > 2)
                return ZTN_ERROR_INVALID_DATA_DECODE_WRONG_NUM_FIELDS;
            break;

        /* nat或客户端超时+可选服务器身份验证+摘要 */
        case ZTN_NAT_ACCESS_MSG:
        case ZTN_LOCAL_NAT_ACCESS_MSG:
        case ZTN_CLIENT_TIMEOUT_ACCESS_MSG:
            if(remaining_fields > 3)
                return ZTN_ERROR_INVALID_DATA_DECODE_WRONG_NUM_FIELDS;
            break;

        /* 客户端超时+nat+可选服务器身份验证+摘要 */
        case ZTN_CLIENT_TIMEOUT_NAT_ACCESS_MSG:
        case ZTN_CLIENT_TIMEOUT_LOCAL_NAT_ACCESS_MSG:
            if(remaining_fields > 4)
                return ZTN_ERROR_INVALID_DATA_DECODE_WRONG_NUM_FIELDS;
            break;

        default: /* 不应该到达这里 */
            return(ZTN_ERROR_INVALID_DATA_DECODE_MSGTYPE_DECODEFAIL);
    }

    *ndx += *t_size + 1;
    return ZTN_SUCCESS;
}

static int
parse_version(char *tbuf, char **ndx, int *t_size, ztn_ctx_t ctx)
{
    if((*t_size = strcspn(*ndx, ":")) < 1)
        return(ZTN_ERROR_INVALID_DATA_DECODE_VERSION_MISSING);

    if (*t_size > MAX_SPA_VERSION_SIZE)
        return(ZTN_ERROR_INVALID_DATA_DECODE_VERSION_TOOBIG);

    if(ctx->version != NULL)
        free(ctx->version);

    ctx->version = calloc(1, *t_size+1);
    if(ctx->version == NULL)
        return(ZTN_ERROR_MEMORY_ALLOCATION);

    strlcpy(ctx->version, *ndx, *t_size+1);

    *ndx += *t_size + 1;
    return ZTN_SUCCESS;
}

static int
parse_timestamp(char *tbuf, char **ndx, int *t_size, ztn_ctx_t ctx)
{
    int         is_err;

    if((*t_size = strcspn(*ndx, ":")) < 1)
        return(ZTN_ERROR_INVALID_DATA_DECODE_TIMESTAMP_MISSING);

    if (*t_size > MAX_SPA_TIMESTAMP_SIZE)
        return(ZTN_ERROR_INVALID_DATA_DECODE_TIMESTAMP_TOOBIG);

    strlcpy(tbuf, *ndx, *t_size+1);

    ctx->timestamp = (unsigned int) strtol_wrapper(tbuf,
            0, -1, NO_EXIT_UPON_ERR, &is_err);
    if(is_err != ZTN_SUCCESS)
        return(ZTN_ERROR_INVALID_DATA_DECODE_TIMESTAMP_DECODEFAIL);

    *ndx += *t_size + 1;

    return ZTN_SUCCESS;
}

static int
parse_username(char *tbuf, char **ndx, int *t_size, ztn_ctx_t ctx)
{
    if((*t_size = strcspn(*ndx, ":")) < 1)
        return(ZTN_ERROR_INVALID_DATA_DECODE_USERNAME_MISSING);

    if (*t_size > MAX_SPA_USERNAME_SIZE)
        return(ZTN_ERROR_INVALID_DATA_DECODE_USERNAME_TOOBIG);

    strlcpy(tbuf, *ndx, *t_size+1);

    if(ctx->username != NULL)
        free(ctx->username);

    ctx->username = calloc(1, *t_size+1); /* 是的，比我们需要的还多 */
    if(ctx->username == NULL)
        return(ZTN_ERROR_MEMORY_ALLOCATION);

    if(b64_decode(tbuf, (unsigned char*)ctx->username) < 0)
        return(ZTN_ERROR_INVALID_DATA_DECODE_USERNAME_DECODEFAIL);

    if(validate_username(ctx->username) != ZTN_SUCCESS)
        return(ZTN_ERROR_INVALID_DATA_DECODE_USERNAME_VALIDFAIL);

    *ndx += *t_size + 1;

    return ZTN_SUCCESS;
}

static int
parse_rand_val(char *tbuf, char **ndx, int *t_size, ztn_ctx_t ctx)
{
    if((*t_size = strcspn(*ndx, ":")) < ZTN_RAND_VAL_SIZE)
        return(ZTN_ERROR_INVALID_DATA_DECODE_RAND_MISSING);

    if(ctx->rand_val != NULL)
        free(ctx->rand_val);

    ctx->rand_val = calloc(1, ZTN_RAND_VAL_SIZE+1);
    if(ctx->rand_val == NULL)
        return(ZTN_ERROR_MEMORY_ALLOCATION);

    ctx->rand_val = strncpy(ctx->rand_val, *ndx, ZTN_RAND_VAL_SIZE);

    *ndx += *t_size + 1;

    return ZTN_SUCCESS;
}

/* 对编码的SPA数据进行解码。 */
int
ztn_decode_spa_data(ztn_ctx_t ctx)
{
    char       *tbuf, *ndx;
    int         t_size, i, res;

    /* 指向SPA字段解析函数的函数指针数组 */
    int (*field_parser[FIELD_PARSERS])(char *tbuf, char **ndx, int *t_size, ztn_ctx_t ctx)
        = { parse_rand_val,       /* 提取随机值 */
            parse_username,       /* 提取用户名 */
            parse_timestamp,      /* 客户端时间戳 */
            parse_version,        /* SPA版本 */
            parse_msg_type,       /* SPA消息类型 */
            parse_msg,            /* SPA消息字符串 */
            parse_nat_msg,        /* SPA NAT消息字符串 */
            parse_server_auth,    /* 可选的服务器身份验证方法 */
            parse_client_timeout  /* 客户端定义的超时 */
          };

    if (! is_valid_encoded_msg_len(ctx->encoded_msg_len))
        return(ZTN_ERROR_INVALID_DATA_DECODE_MSGLEN_VALIDFAIL);

    /* 确保没有非ascii可打印字符 */
    for (i=0; i < (int)strnlen(ctx->encoded_msg, MAX_SPA_ENCODED_MSG_SIZE); i++)
        if(isprint((int)(unsigned char)ctx->encoded_msg[i]) == 0)
            return(ZTN_ERROR_INVALID_DATA_DECODE_NON_ASCII);

    /* 确保SPA数据包中有足够的字段 */
    ndx = ctx->encoded_msg;

    if (num_fields(ndx) < MIN_SPA_FIELDS)
        return(ZTN_ERROR_INVALID_DATA_DECODE_LT_MIN_FIELDS);

    ndx += last_field(ndx);

    t_size = strnlen(ndx, SHA512_B64_LEN+1);

    /* 验证摘要长度 */
    res = is_valid_digest_len(t_size, ctx);
    if(res != ZTN_SUCCESS)
        return res;

    if(ctx->digest != NULL)
        free(ctx->digest);

    /* 将摘要复制到上下文中并终止编码数据 */
    ctx->digest = strdup(ndx);
    if(ctx->digest == NULL)
        return(ZTN_ERROR_MEMORY_ALLOCATION);

    /* 从encoded_msg存储桶中剪切摘要。。。 */
    bzero((ndx-1), t_size);

    ctx->encoded_msg_len -= t_size+1;

    /* 制作一个tmp存储桶，用于处理base64编码的数据和 */
    tbuf = calloc(1, ZTN_ENCODE_TMP_BUF_SIZE);
    if(tbuf == NULL)
        return(ZTN_ERROR_MEMORY_ALLOCATION);

    /* 现在可以验证摘要。 */
    res = verify_digest(tbuf, t_size, ctx);
    if(res != ZTN_SUCCESS)
    {
        free(tbuf);
        return(ZTN_ERROR_DIGEST_VERIFICATION_FAILED);
    }

    /* 现在我们将处理编码数据并提取（和base64- */
    ndx = ctx->encoded_msg;

    for (i=0; i < FIELD_PARSERS; i++)
    {
        res = (*field_parser[i])(tbuf, &ndx, &t_size, ctx);
        if(res != ZTN_SUCCESS)
        {
            free(tbuf);
            return res;
        }
    }

    /* 使用tmp缓冲区完成。 */
    free(tbuf);

    /* 调用已初始化的上下文。 */
    ctx->initval = ZTN_CTX_INITIALIZED;
    ZTN_SET_CTX_INITIALIZED(ctx);

    return(ZTN_SUCCESS);
}

#ifdef HAVE_C_UNIT_TESTS /* LCOV_EXCL_START */

DECLARE_UTEST(num_fields, "Count the number of SPA fields in a SPA packet")
{
    int ix_field=0;
    char spa_packet[(MAX_SPA_FIELDS+1)*3];

    /* 将水疗包归零 */
    memset(spa_packet, 0, sizeof(spa_packet));

    /* 检查我们是否能够统计SPA字段的数量 */
    for(ix_field=0 ; ix_field<=MAX_SPA_FIELDS+2 ; ix_field++)
    {
        strcat(spa_packet, "x");
        CU_ASSERT(num_fields(spa_packet) == ix_field);
        strcat(spa_packet, SPA_FIELD_SEPARATOR);
    }

    /* 检查是否存在可能的溢出 */
    strcat(spa_packet, "x");
    CU_ASSERT(num_fields(spa_packet) == MAX_SPA_FIELDS + 2);
    strcat(spa_packet, "x");
    strcat(spa_packet, SPA_FIELD_SEPARATOR);
    CU_ASSERT(num_fields(spa_packet) == MAX_SPA_FIELDS + 2);
}

DECLARE_UTEST(last_field, "Count the number of bytes to the last :")
{
    int ix_field;
    char spa_packet[(MAX_SPA_FIELDS+1)*3];

    /* 将水疗包归零 */
    memset(spa_packet, 0, sizeof(spa_packet));

    /* 当字段数小于MAX_SPA_FIELDS时，检查有效计数 */
    CU_ASSERT(last_field("a:") == 2);
    CU_ASSERT(last_field("ab:abc:") == 7);
    CU_ASSERT(last_field("abc:abcd:") == 9);
    CU_ASSERT(last_field("abc:abcd:abc") == 9);


    /*  */
    for(ix_field=0 ; ix_field<=MAX_SPA_FIELDS+2 ; ix_field++)
    {
        strcat(spa_packet, "x");
        strcat(spa_packet, SPA_FIELD_SEPARATOR);
    }
    CU_ASSERT(last_field(spa_packet) == ((MAX_SPA_FIELDS+2)*2));
}

int register_ts_ztn_decode(void)
{
    ts_init(&TEST_SUITE(ztn_decode), TEST_SUITE_DESCR(ztn_decode), NULL, NULL);
    ts_add_utest(&TEST_SUITE(ztn_decode), UTEST_FCT(num_fields), UTEST_DESCR(num_fields));
    ts_add_utest(&TEST_SUITE(ztn_decode), UTEST_FCT(last_field), UTEST_DESCR(last_field));

    return register_ts(&TEST_SUITE(ztn_decode));
}

#endif /* 有_单元_测试 */ /* LCOV_EXCL_STOP */
/* **EOF** */
