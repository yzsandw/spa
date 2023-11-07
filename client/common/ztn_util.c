
#include "ztn_common.h"
#include "ztn_util.h"
#include <errno.h>
#include <stdarg.h>

#ifndef WIN32
  /* 用于inet_aton（）IP验证 */
  #include <sys/socket.h>
  #include <netinet/in.h>
  #include <arpa/inet.h>
#endif

/* 检查函数是否返回ZTN错误并返回错误代码 */
#define RETURN_ON_ZTN_ERROR(e, f)   do { if (((e)=(f)) != ZTN_SUCCESS) { return (e); } } while(0);

#define ZTN_ENCRYPTION_MODE_BUFSIZE 16                      /* ！<加密模式字符串的最大大小 */
#define ZTN_ENC_MODE_SUPPORTED      0                       /* ！<定义了支持的ztn加密模式 */
#define ZTN_ENC_MODE_NOT_SUPPORTED  !ZTN_ENC_MODE_SUPPORTED /* ！<定义了不受支持的ztn加密模式 */

#define NULL_STRING                 "<NULL>"                /* ！<表示NULL缓冲区的字符串 */



/* * */
typedef struct ztn_enc_mode_str
{
    const char  str[ZTN_ENCRYPTION_MODE_BUFSIZE];   /* ！<表示ZTN库的加密模式值的字符串 */
    int         val;                                /* ！<根据ZTN库的加密模式值 */
    int         supported;                          /* ！<支持或不支持 */
} ztn_enc_mode_str_t;

/* * */
static ztn_enc_mode_str_t ztn_enc_mode_strs[] =
{
    { "CBC",            ZTN_ENC_MODE_CBC,           ZTN_ENC_MODE_SUPPORTED      },
    { "ECB",            ZTN_ENC_MODE_ECB,           ZTN_ENC_MODE_SUPPORTED      },
    { "CFB",            ZTN_ENC_MODE_CFB,           ZTN_ENC_MODE_SUPPORTED      },
    { "PCBC",           ZTN_ENC_MODE_PCBC,          ZTN_ENC_MODE_NOT_SUPPORTED  },
    { "OFB",            ZTN_ENC_MODE_OFB,           ZTN_ENC_MODE_SUPPORTED      },
    { "CTR",            ZTN_ENC_MODE_CTR,           ZTN_ENC_MODE_SUPPORTED      },
    { "Asymmetric",     ZTN_ENC_MODE_ASYMMETRIC,    ZTN_ENC_MODE_SUPPORTED      },
    { "legacy",         ZTN_ENC_MODE_CBC_LEGACY_IV, ZTN_ENC_MODE_SUPPORTED      }
};

/* 将所有字节与恒定运行时间进行比较，无论 */
int
constant_runtime_cmp(const char *a, const char *b, int len)
{
    int good = 0;
    int bad  = 0;
    int i;

    for(i=0; i < len; i++) {
        if (a[i] == b[i])
            good++;
        else
            bad++;
    }

    if (good == len)
        return 0;
    else
        return 0 - bad;
}

/* 验证编码消息长度 */
int
is_valid_encoded_msg_len(const int len)
{
#if HAVE_LIBFIU
    fiu_return_on("is_valid_encoded_msg_len_val", 0);
#endif
    if(len < MIN_SPA_ENCODED_MSG_SIZE || len >= MAX_SPA_ENCODED_MSG_SIZE)
        return(0);

    return(1);
}

/* 验证IPv4地址 */
int
is_valid_ipv4_addr(const char * const ip_str, const int len)
{
    const char         *ndx     = ip_str;
    char         tmp_ip_str[MAX_IPV4_STR_LEN + 1] = {0};
    int                 dot_ctr = 0, char_ctr = 0;
    int                 res     = 1;
#if HAVE_SYS_SOCKET_H
    struct in_addr      in;
#endif

    if(ip_str == NULL)
        return 0;

    if((len > MAX_IPV4_STR_LEN) || (len < MIN_IPV4_STR_LEN))
        return 0;

    while(char_ctr < len)
    {
        /* 如果我们在给定的长度内命中了一个null，那么不管怎样都是无效的 */
        if(*ndx == '\0')
            return 0;

        char_ctr++;

        if(*ndx == '.')
            dot_ctr++;
        else if(isdigit((int)(unsigned char)*ndx) == 0)
        {
            res = 0;
            break;
        }
        ndx++;
    }

    if((res == 1) && (dot_ctr != 3))
        res = 0;

#if HAVE_SYS_SOCKET_H
    /* 现在我们有了一个看起来 */
    if(res == 1) {
        strncpy(tmp_ip_str, ip_str, len);
        if (inet_aton(tmp_ip_str, &in) == 0)
            res = 0;
    }
#endif
    return(res);
}

/* 验证主机名 */
int
is_valid_hostname(const char * const hostname_str, const int len)
{
    int                 label_size = 0, total_size = 0;
    const char         *ndx     = hostname_str;

    if (hostname_str == NULL)
        return 0;

    if (len > 254)
        return 0;

    while(total_size < len)
    {
        if (*ndx == '\0')
            return 0;

        if (label_size == 0) //More restrictions on first character of a label
        {
            if (!isalnum((int)(unsigned char)*ndx))
                return 0;
        }
        else if (!(isalnum((int)(unsigned char)*ndx) | (*ndx == '.') | (*ndx == '-')))
            return 0;

        if (*ndx == '.')
        {
            if (label_size > 63)
                return 0;
            if (!isalnum((int)(unsigned char)*(ndx-1)))  //checks that previous character was not a . or -
                return 0;

            label_size = 0;
        }
        else
        {
            label_size++;
        }

        total_size++;

        ndx++; //move to next character
    }
    /* 在这一点上，我们指向的是null。递减ndx以简化 */
    ndx--;
    if (*ndx == '-')
        return 0;

    if (*ndx == '.')
        total_size--;

    if (label_size > 63)
        return 0;

    /* 到目前为止，如果无效，我们已经保释 */
    return 1;
}

/* 将digest_type字符串转换为其整数值。 */
short
digest_strtoint(const char *dt_str)
{
    if(strcasecmp(dt_str, "md5") == 0)
        return(ZTN_DIGEST_MD5);
    else if(strcasecmp(dt_str, "sha1") == 0)
        return(ZTN_DIGEST_SHA1);
    else if(strcasecmp(dt_str, "sha256") == 0)
        return(ZTN_DIGEST_SHA256);
    else if(strcasecmp(dt_str, "sha384") == 0)
        return(ZTN_DIGEST_SHA384);
    else if(strcasecmp(dt_str, "sha512") == 0)
        return(ZTN_DIGEST_SHA512);
    else if(strcasecmp(dt_str, "sha3_256") == 0)
        return(ZTN_DIGEST_SHA3_256);
    else if(strcasecmp(dt_str, "sha3_512") == 0)
        return(ZTN_DIGEST_SHA3_512);
    else
        return(-1);
}

/* * */
short
digest_inttostr(int digest, char* digest_str, size_t digest_size)
{
    short digest_not_valid = 0;

    memset(digest_str, 0, digest_size);

    switch (digest)
    {
        case ZTN_DIGEST_MD5:
            strlcpy(digest_str, "MD5", digest_size);
            break;
        case ZTN_DIGEST_SHA1:
            strlcpy(digest_str, "SHA1", digest_size);
            break;
        case ZTN_DIGEST_SHA256:
            strlcpy(digest_str, "SHA256", digest_size);
            break;
        case ZTN_DIGEST_SHA384:
            strlcpy(digest_str, "SHA384", digest_size);
            break;
        case ZTN_DIGEST_SHA512:
            strlcpy(digest_str, "SHA512", digest_size);
            break;
        case ZTN_DIGEST_SHA3_256:
            strlcpy(digest_str, "SHA3_256", digest_size);
            break;
        case ZTN_DIGEST_SHA3_512:
            strlcpy(digest_str, "SHA3_512", digest_size);
            break;
        default:
            strlcpy(digest_str, "Unknown", digest_size);
            digest_not_valid = -1;
            break;
    }

    return digest_not_valid;
}

short
hmac_digest_strtoint(const char *dt_str)
{
    if(strcasecmp(dt_str, "md5") == 0)
        return(ZTN_HMAC_MD5);
    else if(strcasecmp(dt_str, "sha1") == 0)
        return(ZTN_HMAC_SHA1);
    else if(strcasecmp(dt_str, "sha256") == 0)
        return(ZTN_HMAC_SHA256);
    else if(strcasecmp(dt_str, "sha384") == 0)
        return(ZTN_HMAC_SHA384);
    else if(strcasecmp(dt_str, "sha512") == 0)
        return(ZTN_HMAC_SHA512);
    else if(strcasecmp(dt_str, "sha3_256") == 0)
        return(ZTN_HMAC_SHA3_256);
    else if(strcasecmp(dt_str, "sha3_512") == 0)
        return(ZTN_HMAC_SHA3_512);
    else
        return(-1);
}


/* 返回加密类型字符串表示形式 */
const char *
enc_type_inttostr(const int type)
{
    if(type == ZTN_ENC_MODE_UNKNOWN)
        return("Unknown encryption type");
    else if(type == ZTN_ENCRYPTION_RIJNDAEL)
        return("Rijndael");
    else if(type == ZTN_ENCRYPTION_GPG)
        return("GPG");

    return("Unknown encryption type");
}

/* 返回消息类型字符串表示 */
const char *
msg_type_inttostr(const int type)
{
    if(type == ZTN_COMMAND_MSG)
        return("Command msg");
    else if(type == ZTN_ACCESS_MSG)
        return("Access msg");
    else if(type == ZTN_NAT_ACCESS_MSG)
        return("NAT access msg");
    else if(type == ZTN_CLIENT_TIMEOUT_ACCESS_MSG)
        return("Client timeout access msg");
    else if(type == ZTN_CLIENT_TIMEOUT_NAT_ACCESS_MSG)
        return("Client timeout NAT access msg");
    else if(type == ZTN_LOCAL_NAT_ACCESS_MSG)
        return("Local NAT access msg");
    else if(type == ZTN_CLIENT_TIMEOUT_LOCAL_NAT_ACCESS_MSG)
        return("Client timeout local NAT access msg");

    return("Unknown message type");
}

/* * */
short
hmac_digest_inttostr(int digest, char* digest_str, size_t digest_size)
{
    short digest_not_valid = 0;

    memset(digest_str, 0, digest_size);

    switch (digest)
    {
        case ZTN_HMAC_MD5:
            strlcpy(digest_str, "MD5", digest_size);
            break;
        case ZTN_HMAC_SHA1:
            strlcpy(digest_str, "SHA1", digest_size);
            break;
        case ZTN_HMAC_SHA256:
            strlcpy(digest_str, "SHA256", digest_size);
            break;
        case ZTN_HMAC_SHA384:
            strlcpy(digest_str, "SHA384", digest_size);
            break;
        case ZTN_HMAC_SHA512:
            strlcpy(digest_str, "SHA512", digest_size);
            break;
        case ZTN_HMAC_SHA3_256:
            strlcpy(digest_str, "SHA3_256", digest_size);
            break;
        case ZTN_HMAC_SHA3_512:
            strlcpy(digest_str, "SHA3_512", digest_size);
            break;
        default:
            strlcpy(digest_str, "Unknown", digest_size);
            digest_not_valid = -1;
            break;
    }

    return digest_not_valid;
}

/* 验证明文输入大小 */
int
is_valid_pt_msg_len(const int len)
{
#if HAVE_LIBFIU
    fiu_return_on("is_valid_pt_msg_len_val", 0);
#endif
    if(len < MIN_SPA_PLAINTEXT_MSG_SIZE || len >= MAX_SPA_PLAINTEXT_MSG_SIZE)
        return(0);

    return(1);
}

/* * */
int
enc_mode_strtoint(const char *enc_mode_str)
{
    unsigned char           ndx_enc_mode;
    int                     enc_mode_int = -1;     /* 加密模式整数值 */
    ztn_enc_mode_str_t     *enc_mode_str_pt;

    /* 查看ztn_ec_mode_strs数组以找出正确的加密模式 */
    for (ndx_enc_mode = 0 ; ndx_enc_mode < ARRAY_SIZE(ztn_enc_mode_strs) ; ndx_enc_mode++)
    {
        enc_mode_str_pt = &(ztn_enc_mode_strs[ndx_enc_mode]);

        /* 如果加密模式匹配，请获取它 */
        if (   (strcasecmp(enc_mode_str, enc_mode_str_pt->str) == 0)
            && (enc_mode_str_pt->supported == ZTN_ENC_MODE_SUPPORTED) )
        {
            enc_mode_int = enc_mode_str_pt->val;
            break;
        }
    }

    return enc_mode_int;
}

/* * */
short
enc_mode_inttostr(int enc_mode, char* enc_mode_str, size_t enc_mode_size)
{
    short                   enc_mode_error = -1;
    unsigned char           ndx_enc_mode;
    ztn_enc_mode_str_t     *enc_mode_str_pt;

    /* 初始化协议字符串 */
    memset(enc_mode_str, 0, enc_mode_size);

    /* 查看ztn_ec_mode_strs数组以找到正确的协议 */
    for (ndx_enc_mode = 0 ; ndx_enc_mode < ARRAY_SIZE(ztn_enc_mode_strs) ; ndx_enc_mode++)
    {
        enc_mode_str_pt = &(ztn_enc_mode_strs[ndx_enc_mode]);

        /* 如果加密模式匹配，请获取它 */
        if (   (enc_mode_str_pt->val == enc_mode)
            && (enc_mode_str_pt->supported == ZTN_ENC_MODE_SUPPORTED) )
        {
            strlcpy(enc_mode_str, enc_mode_str_pt->str, enc_mode_size);
            enc_mode_error = 0;
            break;
        }
    }

    return enc_mode_error;
}

int
strtol_wrapper(const char * const str, const int min,
    const int max, const int exit_upon_err, int *err)
{
    int val;

    errno = 0;
    *err = ZTN_SUCCESS;

    val = strtol(str, (char **) NULL, 10);

    if ((errno == ERANGE || (errno != 0 && val == 0)))
    {
        *err = errno;
        if(exit_upon_err == EXIT_UPON_ERR)
        {
            perror("strtol");
            fprintf(stderr, "[*] Value %d out of range [(%d)-(%d)]\n",
                val, min, max);
            exit(EXIT_FAILURE);
        }
    }

    if(val < min)
    {
        *err = ZTN_ERROR_INVALID_DATA_UTIL_STRTOL_LT_MIN;
        if(exit_upon_err == EXIT_UPON_ERR)
        {
            fprintf(stderr, "[*] Value %d out of range [(%d)-(%d)]\n",
                val, min, max);
            exit(EXIT_FAILURE);
        }
    }

    /* 允许max==-1作为一个例外，在这里我们不关心 */
    if((max >= 0) && (val > max))
    {
        *err = ZTN_ERROR_INVALID_DATA_UTIL_STRTOL_GT_MAX;
        if(exit_upon_err == EXIT_UPON_ERR)
        {
            fprintf(stderr, "[*] Value %d out of range [(%d)-(%d)]\n",
                val, min, max);
            exit(EXIT_FAILURE);
        }
    }

#if HAVE_LIBFIU
    fiu_return_on("strtol_wrapper_lt_min",
            ZTN_ERROR_INVALID_DATA_UTIL_STRTOL_LT_MIN);
    fiu_return_on("strtol_wrapper_gt_max",
            ZTN_ERROR_INVALID_DATA_UTIL_STRTOL_GT_MAX);
#endif

    return val;
}

/* 从字符串末尾剪掉空白（必须以NULL结尾） */
void
chop_whitespace(char *str)
{
    int i;
    for (i=strlen(str)-1; i > 0; i--)
    {
        if (! isspace(str[i]))
        {
            if (i < strlen(str)-1)
                str[i+1] = 0x0;
            break;
        }
    }
    return;
}

/* free（）之前清空缓冲区 */
int zero_free(char *buf, int len)
{
    int res = ZTN_SUCCESS;

    if(buf == NULL)
        return res;

    if(len == 0)
    {
        free(buf);  /* 如果buf！=则始终为free（）NULL */
        return res;
    }

    res = zero_buf(buf, len);

    free(buf);

#if HAVE_LIBFIU
    fiu_return_on("zero_free_err", ZTN_ERROR_ZERO_OUT_DATA);
#endif

    return res;
}

/* 以编译器未优化的方式清除敏感信息 */
int
zero_buf(char *buf, int len)
{
    int i, res = ZTN_SUCCESS;

#if HAVE_LIBFIU
    fiu_return_on("zero_buf_err", ZTN_ERROR_ZERO_OUT_DATA);
#endif

    if(buf == NULL || len == 0)
        return res;

    if(len < 0 || len > MAX_SPA_ENCODED_MSG_SIZE)
        return ZTN_ERROR_ZERO_OUT_DATA;

    for(i=0; i < len; i++)
        buf[i] = 0x0;

    for(i=0; i < len; i++)
        if(buf[i] != 0x0)
            res = ZTN_ERROR_ZERO_OUT_DATA;

    return res;
}

#if defined(WIN32) || !defined(HAVE_STRNDUP)
/* Windows没有strndup，所以我们在这里很好地实现了它。 */
char
*strndup( const char * s, size_t len )
{
    char* ns = NULL;
    if(s) {
        ns = calloc(1, len + 1);
        if(ns) {
            ns[len] = 0;
            // strncpy to be pedantic about modification in multithreaded
            // applications
            return strncpy(ns, s, len);
        }
    }
    return ns;
}
#endif

/* * */
static int
append_msg_to_buf(char *buf, size_t buf_size, const char* msg, ...)
{
    int     bytes_written = 0;  /* 写入buf的字节数 */
    va_list ap;

    /* 检查缓冲区是否有效 */
    if (buf_size > 0)
    {
        va_start(ap, msg);

        /* 将消息格式化为printf消息 */
        bytes_written = vsnprintf(buf, buf_size, msg, ap);

        /* 消息似乎已被截断或出现错误 */
        if (bytes_written < 0)
            bytes_written = 0;

        else if (bytes_written >= buf_size)
            bytes_written = buf_size;

        /* 消息格式已正确 */
        else;

        va_end(ap);
    }

    /* 没有提供有效的缓冲区，因此我们不写任何内容 */
    else;

    /* 返回写入缓冲区的字节数 */
    return bytes_written;
}

/* 确定缓冲区是否只包含base64中的字符 */
int
is_base64(const unsigned char * const buf, const unsigned short int len)
{
    unsigned short int  i;
    int                 rv = 1;

    for(i=0; i<len; i++)
    {
        if(!(isalnum(buf[i]) || buf[i] == '/' || buf[i] == '+' || buf[i] == '='))
        {
            rv = 0;
            break;
        }
    }

    return rv;
}

void
chop_char(char *str, const char chop)
{
    if(str != NULL
            && str[0] != 0x0
            && strlen(str) > 1 /* 不要截断单个字符字符串 */
            && str[strlen(str)-1] == chop)
        str[strlen(str)-1] = 0x0;
    return;
}

void
chop_newline(char *str)
{
    chop_char(str, 0x0a);
    return;
}

void chop_spaces(char *str)
{
    int i;
    if (str != NULL && str[0] != 0x0)
    {
        for (i=strlen(str)-1; i > 0; i--)
        {
            if(str[i] != 0x20)
                break;
            str[i] = 0x0;
        }
    }
    return;
}

static int
add_argv(char **argv_new, int *argc_new, const char *new_arg)
{
    int buf_size = 0;

    buf_size = strlen(new_arg) + 1;
    argv_new[*argc_new] = calloc(1, buf_size);

    if(argv_new[*argc_new] == NULL)
        return 0;

    strlcpy(argv_new[*argc_new], new_arg, buf_size);

    *argc_new += 1;

    if(*argc_new >= MAX_CMDLINE_ARGS-1)
        return 0;

    argv_new[*argc_new] = NULL;

    return 1;
}
//用于将字符串解析为命令行参数数组
int
strtoargv(const char * const args_str, char **argv_new, int *argc_new)
{
    int       current_arg_ctr = 0, i;
    char      arg_tmp[MAX_ARGS_LINE_LEN] = {0};

    for (i=0; i < (int)strlen(args_str); i++)
    {
        if (!isspace((int)(unsigned char)args_str[i]))
        {
            arg_tmp[current_arg_ctr] = args_str[i];
            current_arg_ctr++;
        }
        else
        {
            if(current_arg_ctr > 0)
            {
                arg_tmp[current_arg_ctr] = '\0';
                if (add_argv(argv_new, argc_new, arg_tmp) != 1)
                {
                    free_argv(argv_new, argc_new);
                    return 0;
                }
                current_arg_ctr = 0;
            }
        }
    }

    /* 拾取字符串中的最后一个参数 */
    if(current_arg_ctr > 0)
    {
        arg_tmp[current_arg_ctr] = '\0';
        if (add_argv(argv_new, argc_new, arg_tmp) != 1)
        {
            free_argv(argv_new, argc_new);
            return 0;
        }
    }
    return 1;
}

void
free_argv(char **argv_new, int *argc_new)
{
    int i;

    if(argv_new == NULL || *argv_new == NULL)
        return;

    for (i=0; i < *argc_new; i++)
    {
        if(argv_new[i] == NULL)
            break;
        else
            free(argv_new[i]);
    }
    return;
}

#define ASCII_LEN 16

/* 通用十六进制转储函数。 */
void
hex_dump(const unsigned char *data, const int size)
{
    int ln=0, i=0, j=0;
    char ascii_str[ASCII_LEN+1] = {0};

    for(i=0; i<size; i++)
    {
        if((i % ASCII_LEN) == 0)
        {
            printf(" %s\n  0x%.4x:  ", ascii_str, i);
            memset(ascii_str, 0x0, ASCII_LEN-1);
            j = 0;
        }

        printf("%.2x ", data[i]);

        ascii_str[j++] = (data[i] < 0x20 || data[i] > 0x7e) ? '.' : data[i];

        if(j == 8)
            printf(" ");
    }

    /* 余数 */
    ln = strlen(ascii_str);
    if(ln > 0)
    {
        for(i=0; i < ASCII_LEN-ln; i++)
            printf("   ");
        if(ln < 8)
            printf(" ");

        printf(" %s\n\n", ascii_str);
    }
    return;
}

/* * */
//将ZTN上下文转储到缓冲区
int
dump_ctx_to_buffer(ztn_ctx_t ctx, char *dump_buf, size_t dump_buf_len)
{
    int         cp = 0;
    int         err = ZTN_LAST_ERROR;

    char       *rand_val        = NULL;//随机值
    char       *username        = NULL;//用户名
    char       *version         = NULL;//版本
    char       *spa_message     = NULL;//spa消息
    char       *nat_access      = NULL;//nat访问
    char       *server_auth     = NULL;//服务器认证
    char       *enc_data        = NULL;
    char       *hmac_data       = NULL;
    char       *spa_digest      = NULL;//spa摘要
#if HAVE_LIBGPGME
    char          *gpg_signer        = NULL;
    char          *gpg_recip         = NULL;
    char          *gpg_sig_id        = NULL;
    unsigned char  gpg_sig_verify    = 0;
    unsigned char  gpg_ignore_verify = 0;
    char          *gpg_sig_fpr       = NULL;
    char          *gpg_home_dir      = NULL;
    char          *gpg_exe           = NULL;
    int            gpg_sigsum        = -1;
    int            gpg_sig_stat      = -1;
#endif
    char       *spa_data         = NULL;
    char        digest_str[24]   = {0};
    char        hmac_str[24]     = {0};
    char        enc_mode_str[ZTN_ENCRYPTION_MODE_BUFSIZE] = {0};

    time_t      timestamp       = 0;
    short       msg_type        = -1;
    short       digest_type     = -1;
    short       hmac_type       = -1;
    short       encryption_type = -1;
    int         encryption_mode = -1;
    int         client_timeout  = -1;

    /* 将缓冲区归零 */
    memset(dump_buf, 0, dump_buf_len);

    /* 确保ZTN上下文在打印之前已初始化 */
    if(!CTX_INITIALIZED(ctx))
        err = ZTN_ERROR_CTX_NOT_INITIALIZED;

    else
    {
        /* 分析ZTN上下文并收集数据 */
        RETURN_ON_ZTN_ERROR(err, ztn_get_rand_value(ctx, &rand_val));
        RETURN_ON_ZTN_ERROR(err, ztn_get_username(ctx, &username));
        RETURN_ON_ZTN_ERROR(err, ztn_get_timestamp(ctx, &timestamp));
        RETURN_ON_ZTN_ERROR(err, ztn_get_version(ctx, &version));
        RETURN_ON_ZTN_ERROR(err, ztn_get_spa_message_type(ctx, &msg_type));
        RETURN_ON_ZTN_ERROR(err, ztn_get_spa_message(ctx, &spa_message));
        RETURN_ON_ZTN_ERROR(err, ztn_get_spa_nat_access(ctx, &nat_access));
        RETURN_ON_ZTN_ERROR(err, ztn_get_spa_server_auth(ctx, &server_auth));
        RETURN_ON_ZTN_ERROR(err, ztn_get_spa_client_timeout(ctx, &client_timeout));
        RETURN_ON_ZTN_ERROR(err, ztn_get_spa_digest_type(ctx, &digest_type));
        RETURN_ON_ZTN_ERROR(err, ztn_get_spa_hmac_type(ctx, &hmac_type));
        RETURN_ON_ZTN_ERROR(err, ztn_get_spa_encryption_type(ctx, &encryption_type));
        RETURN_ON_ZTN_ERROR(err, ztn_get_spa_encryption_mode(ctx, &encryption_mode));
        RETURN_ON_ZTN_ERROR(err, ztn_get_encoded_data(ctx, &enc_data));
        RETURN_ON_ZTN_ERROR(err, ztn_get_spa_hmac(ctx, &hmac_data));
        RETURN_ON_ZTN_ERROR(err, ztn_get_spa_digest(ctx, &spa_digest));
        RETURN_ON_ZTN_ERROR(err, ztn_get_spa_data(ctx, &spa_data));

#if HAVE_LIBGPGME
        if(encryption_mode == ZTN_ENC_MODE_ASYMMETRIC)
        {
            /* 填充GPG变量 */
            RETURN_ON_ZTN_ERROR(err, ztn_get_gpg_signer(ctx, &gpg_signer));
            RETURN_ON_ZTN_ERROR(err, ztn_get_gpg_recipient(ctx, &gpg_recip));
            RETURN_ON_ZTN_ERROR(err, ztn_get_gpg_signature_verify(ctx, &gpg_sig_verify));
            RETURN_ON_ZTN_ERROR(err, ztn_get_gpg_ignore_verify_error(ctx, &gpg_ignore_verify));
            RETURN_ON_ZTN_ERROR(err, ztn_get_gpg_home_dir(ctx, &gpg_home_dir));
            RETURN_ON_ZTN_ERROR(err, ztn_get_gpg_exe(ctx, &gpg_exe));
            if(ztn_get_gpg_signature_id(ctx, &gpg_sig_id) != ZTN_SUCCESS)
                gpg_sig_id = NULL;
            if(ztn_get_gpg_signature_summary(ctx, &gpg_sigsum) != ZTN_SUCCESS)
                gpg_sigsum = -1;
            if(ztn_get_gpg_signature_status(ctx, &gpg_sig_stat) != ZTN_SUCCESS)
                gpg_sig_stat = -1;
            if(ztn_get_gpg_signature_fpr(ctx, &gpg_sig_fpr) != ZTN_SUCCESS)
                gpg_sig_fpr = NULL;
        }
#endif

        /* 将摘要整数转换为字符串 */
        if (digest_inttostr(digest_type, digest_str, sizeof(digest_str)) != 0)
            return (ZTN_ERROR_INVALID_DIGEST_TYPE);

        /* 将加密模式整数转换为字符串 */
        if (enc_mode_inttostr(encryption_mode, enc_mode_str, sizeof(enc_mode_str)) != 0)
            return (ZTN_ERROR_INVALID_ENCRYPTION_TYPE);

        /* 如果HMAC消息可用，请将HMAC摘要整数转换为字符串 */
        if (ctx->msg_hmac_len != 0)
        {
            if (hmac_digest_inttostr(hmac_type, hmac_str, sizeof(hmac_str)) != 0)
                return (ZTN_ERROR_UNSUPPORTED_HMAC_MODE);
        }

        /* 填充要转储的缓冲区 */
        cp  = append_msg_to_buf(dump_buf,    dump_buf_len,    "SPA Field Values:\n=================\n");
        cp += append_msg_to_buf(dump_buf+cp, dump_buf_len-cp, "   Random Value: %s\n", rand_val == NULL ? NULL_STRING : rand_val);
        cp += append_msg_to_buf(dump_buf+cp, dump_buf_len-cp, "       Username: %s\n", username == NULL ? NULL_STRING : username);
        cp += append_msg_to_buf(dump_buf+cp, dump_buf_len-cp, "      Timestamp: %u\n", (unsigned int) timestamp);
        cp += append_msg_to_buf(dump_buf+cp, dump_buf_len-cp, "    ZTN Version: %s\n", version == NULL ? NULL_STRING : version);
        cp += append_msg_to_buf(dump_buf+cp, dump_buf_len-cp, "   Message Type: %i (%s)\n", msg_type, msg_type_inttostr(msg_type));
        cp += append_msg_to_buf(dump_buf+cp, dump_buf_len-cp, " Message String: %s\n", spa_message == NULL ? NULL_STRING : spa_message);
        cp += append_msg_to_buf(dump_buf+cp, dump_buf_len-cp, "     Nat Access: %s\n", nat_access == NULL ? NULL_STRING : nat_access);
        cp += append_msg_to_buf(dump_buf+cp, dump_buf_len-cp, "    Server Auth: %s\n", server_auth == NULL ? NULL_STRING : server_auth);
        cp += append_msg_to_buf(dump_buf+cp, dump_buf_len-cp, " Client Timeout: %u\n", client_timeout);
        cp += append_msg_to_buf(dump_buf+cp, dump_buf_len-cp, "    Digest Type: %u (%s)\n", digest_type, digest_str);
        cp += append_msg_to_buf(dump_buf+cp, dump_buf_len-cp, "      HMAC Type: %u (%s)\n", hmac_type, hmac_type == 0 ? "None" : hmac_str);
        cp += append_msg_to_buf(dump_buf+cp, dump_buf_len-cp, "Encryption Type: %d (%s)\n", encryption_type, enc_type_inttostr(encryption_type));
        cp += append_msg_to_buf(dump_buf+cp, dump_buf_len-cp, "Encryption Mode: %d (%s)\n", encryption_mode, enc_mode_str);
#if HAVE_LIBGPGME
        if(encryption_mode == ZTN_ENC_MODE_ASYMMETRIC)
        {
            cp += append_msg_to_buf(dump_buf+cp, dump_buf_len-cp, "     GPG signer: %s\n", gpg_signer == NULL ? NULL_STRING : gpg_signer);
            cp += append_msg_to_buf(dump_buf+cp, dump_buf_len-cp, "  GPG recipient: %s\n", gpg_recip == NULL ? NULL_STRING : gpg_recip);
            cp += append_msg_to_buf(dump_buf+cp, dump_buf_len-cp, " GPG sig verify: %s\n", gpg_sig_verify == 0 ? "No" : "Yes");
            cp += append_msg_to_buf(dump_buf+cp, dump_buf_len-cp, " GPG ignore sig: %s\n", gpg_ignore_verify == 0 ? "No" : "Yes");
            cp += append_msg_to_buf(dump_buf+cp, dump_buf_len-cp, "     GPG sig ID: %s\n", gpg_sig_id == NULL ? NULL_STRING : gpg_sig_id);
            cp += append_msg_to_buf(dump_buf+cp, dump_buf_len-cp, "    GPG sig fpr: %s\n", gpg_sig_fpr == NULL ? NULL_STRING : gpg_sig_fpr);
            cp += append_msg_to_buf(dump_buf+cp, dump_buf_len-cp, "GPG sig summary: %d\n", gpg_sigsum);
            cp += append_msg_to_buf(dump_buf+cp, dump_buf_len-cp, " GPG sig status: %d\n", gpg_sig_stat);
            cp += append_msg_to_buf(dump_buf+cp, dump_buf_len-cp, "   GPG home dir: %s\n", gpg_home_dir == NULL ? NULL_STRING : gpg_home_dir);
            cp += append_msg_to_buf(dump_buf+cp, dump_buf_len-cp, "        GPG exe: %s\n", gpg_exe == NULL ? GPG_EXE : gpg_exe);
        }
#endif
        cp += append_msg_to_buf(dump_buf+cp, dump_buf_len-cp, "   Encoded Data: %s\n", enc_data == NULL ? NULL_STRING : enc_data);
        cp += append_msg_to_buf(dump_buf+cp, dump_buf_len-cp, "SPA Data Digest: %s\n", spa_digest == NULL ? NULL_STRING : spa_digest);
        cp += append_msg_to_buf(dump_buf+cp, dump_buf_len-cp, "           HMAC: %s\n", hmac_data == NULL ? NULL_STRING : hmac_data);
        append_msg_to_buf(dump_buf+cp, dump_buf_len-cp, " Final SPA Data: %s\n", spa_data);

        err = ZTN_SUCCESS;
    }

    return (err);
}

/* * */
static void *
get_in_addr(struct sockaddr *sa)
{
  if (sa->sa_family == AF_INET)
  {
    return &(((struct sockaddr_in*)sa)->sin_addr);
  }

  else
  {
    return &(((struct sockaddr_in6*)sa)->sin6_addr);
  }
}

/* * */
int
ipv4_resolve(const char *dns_str, char *ip_str)
{
    int                 error;      /* 函数错误返回代码 */
    size_t ip_bufsize = MAX_IPV4_STR_LEN;
    struct addrinfo     hints;
    struct addrinfo    *result;     /* getaddrinfo（）的结果 */
    struct addrinfo    *rp;         /* getaddrinfo（）返回的链表的元素 */

#if WIN32 && WINVER <= 0x0600
    struct sockaddr_in *in;
    char               *win_ip;
#else
    struct sockaddr_in *sai_remote; /* 作为sockaddr_in结构的远程主机信息 */
#endif

#if WIN32
    WSADATA wsa_data;
	error = WSAStartup( MAKEWORD(1,1), &wsa_data );
    if( error != 0 )
    {
        fprintf(stderr, "Winsock initialization error %d", error);
        return(error);
    }
#endif

    memset(&hints, 0 , sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    /* 尝试解析主机名 */
    error = getaddrinfo(dns_str, NULL, &hints, &result);
    if (error != 0)
        fprintf(stderr, "ipv4_resolve() : %s\n", gai_strerror(error));

    else
    {
        error = 1;

        /* 浏览addrinfo结构的链接列表 */
        for (rp = result; rp != NULL; rp = rp->ai_next)
        {
            memset(ip_str, 0, ip_bufsize);

#if WIN32 && WINVER <= 0x0600
                        /* 在较旧的Windows系统上（Vista之前的任何系统？）， */
                        in = (struct sockaddr_in*)(rp->ai_addr);
                        win_ip = inet_ntoa(in->sin_addr);

                        if (win_ip != NULL && (strlcpy(ip_str, win_ip, ip_bufsize) > 0))
#else
            sai_remote = (struct sockaddr_in *)get_in_addr((struct sockaddr *)(rp->ai_addr));
            if (inet_ntop(rp->ai_family, sai_remote, ip_str, ip_bufsize) != NULL)
#endif
            {
                error = 0;
                break;
            }
        }

        /* 从getaddrinfo（）释放我们的结果 */
        freeaddrinfo(result);
    }

#if WIN32
	WSACleanup();
#endif
    return error;
}

int
count_characters(const char *str, const char match, int len)
{
    int i, count = 0;

    for (i=0; i < len && str[i] != '\0'; i++) {
        if (str[i] == match)
            count++;
    }
    return count;
}


/* **EOF** */
