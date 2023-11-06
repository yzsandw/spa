
#include "fwknop_common.h"
#include "netinet_common.h"
#include "config_init.h"
#include "cmd_opts.h"
#include "utils.h"
#include <sys/stat.h>
#include <fcntl.h>

#ifdef WIN32
  #define STDIN_FILENO 0
#endif

#define RC_PARAM_TEMPLATE           "%-24s    %s\n"                     /* ！<在rc文件中定义param=val的模板 */
#define RC_SECTION_DEFAULT          "default"                           /* ！<fwknoprc中默认节的名称 */
#define RC_SECTION_TEMPLATE         "[%s]\n"                            /* ！<在rc文件中定义节的模板 */
#define FWKNOPRC_OFLAGS             (O_WRONLY|O_CREAT|O_EXCL)           /* ！<用于使用open函数创建fwknoprc文件的O_flags */
#define FWKNOPRC_MODE               (S_IRUSR|S_IWUSR)                   /* ！<用于使用open函数创建fwknoprc文件的模式 */
#define PARAM_YES_VALUE             "Y"                                 /* ！<表示fwknoprc中参数的YES值的字符串 */
#define PARAM_NO_VALUE              "N"                                 /* ！<表示fwknoprc中参数的NO值的字符串 */
#define POSITION_TO_BITMASK(x)      ((uint32_t)(1) << ((x) % 32))       /* ！<宏确实从某个位置获取位掩码 */
#define BITMASK_ARRAY_SIZE          2                                   /* ！<用于处理fko_var_bitmask_t结构中的位掩码的32位整数的数目 */
#define LF_CHAR                     0x0A                                /* ！<与LF字符关联的十六进制值 */

#ifdef HAVE_C_UNIT_TESTS /* LCOV_EXCL_START */
  #include "cunit_common.h"
  DECLARE_TEST_SUITE(config_init, "Config init test suite");
#endif /* LCOV_EXCL_STOP */

/* * */
typedef struct fko_var_bitmask
{
    uint32_t dw[BITMASK_ARRAY_SIZE];        /* ！<位掩码数组 */
} fko_var_bitmask_t;

/* * */
//这个结构体用来处理rc文件中的变量（名称和值）
typedef struct rc_file_param
{
    char name[MAX_LINE_LEN];    /* ！<变量名称 */
    char val[MAX_LINE_LEN];     /* ！<变量值 */
} rc_file_param_t;

/* * */
typedef struct fko_var
{
    const char      name[32];   /* ！<fwknoprc中的变量名称 */
    unsigned int    pos;        /* ！<fwknop_cli_arg_t枚举中的变量位置 */
} fko_var_t;

enum
{
    FWKNOP_CLI_FIRST_ARG = 0,
    FWKNOP_CLI_ARG_DIGEST_TYPE = 0,
    FWKNOP_CLI_ARG_SPA_SERVER_PROTO,
    FWKNOP_CLI_ARG_SPA_SERVER_PORT,
    FWKNOP_CLI_ARG_SPA_SOURCE_PORT,
    FWKNOP_CLI_ARG_FW_TIMEOUT,
    FWKNOP_CLI_ARG_ALLOW_IP,
    FWKNOP_CLI_ARG_TIME_OFFSET,
    FWKNOP_CLI_ARG_ENCRYPTION_MODE,
    FWKNOP_CLI_ARG_USE_GPG,
    FWKNOP_CLI_ARG_USE_GPG_AGENT,
    FWKNOP_CLI_ARG_GPG_NO_SIGNING_PW,
    FWKNOP_CLI_ARG_GPG_RECIPIENT,
    FWKNOP_CLI_ARG_GPG_SIGNER,
    FWKNOP_CLI_ARG_GPG_HOMEDIR,
    FWKNOP_CLI_ARG_GPG_EXE_PATH,
    FWKNOP_CLI_ARG_SPOOF_USER,
    FWKNOP_CLI_ARG_SPOOF_SOURCE_IP,
    FWKNOP_CLI_ARG_ACCESS,
    FWKNOP_CLI_ARG_SPA_SERVER,
    FWKNOP_CLI_ARG_RAND_PORT,
    FWKNOP_CLI_ARG_KEY_RIJNDAEL,
    FWKNOP_CLI_ARG_KEY_RIJNDAEL_BASE64,
    FWKNOP_CLI_ARG_GPG_SIGNING_PW,
    FWKNOP_CLI_ARG_GPG_SIGNING_PW_BASE64,
    FWKNOP_CLI_ARG_HMAC_DIGEST_TYPE,
    FWKNOP_CLI_ARG_KEY_HMAC_BASE64,
    FWKNOP_CLI_ARG_KEY_HMAC,
    FWKNOP_CLI_ARG_USE_HMAC,
    FWKNOP_CLI_ARG_USE_WGET_USER_AGENT,
    FWKNOP_CLI_ARG_KEY_FILE,
    FWKNOP_CLI_ARG_HMAC_KEY_FILE,
    FWKNOP_CLI_ARG_NAT_ACCESS,
    FWKNOP_CLI_ARG_HTTP_USER_AGENT,
    FWKNOP_CLI_ARG_RESOLVE_URL,
    FWKNOP_CLI_ARG_SERVER_RESOLVE_IPV4,
    FWKNOP_CLI_ARG_NAT_LOCAL,
    FWKNOP_CLI_ARG_NAT_RAND_PORT,
    FWKNOP_CLI_ARG_NAT_PORT,
    FWKNOP_CLI_ARG_VERBOSE,
    FWKNOP_CLI_ARG_RESOLVE_IP_HTTP,
    FWKNOP_CLI_ARG_RESOLVE_IP_HTTPS,
    FWKNOP_CLI_ARG_RESOLVE_HTTP_ONLY,
    FWKNOP_CLI_ARG_WGET_CMD,
    FWKNOP_CLI_ARG_NO_SAVE_ARGS,
    FWKNOP_CLI_LAST_ARG
} fwknop_cli_arg_t;

static fko_var_t fko_var_array[FWKNOP_CLI_LAST_ARG] =
{
    { "DIGEST_TYPE",           FWKNOP_CLI_ARG_DIGEST_TYPE           },
    { "SPA_SERVER_PROTO",      FWKNOP_CLI_ARG_SPA_SERVER_PROTO      },
    { "SPA_SERVER_PORT",       FWKNOP_CLI_ARG_SPA_SERVER_PORT       },
    { "SPA_SOURCE_PORT",       FWKNOP_CLI_ARG_SPA_SOURCE_PORT       },
    { "FW_TIMEOUT",            FWKNOP_CLI_ARG_FW_TIMEOUT            },
    { "ALLOW_IP",              FWKNOP_CLI_ARG_ALLOW_IP              },
    { "TIME_OFFSET",           FWKNOP_CLI_ARG_TIME_OFFSET           },
    { "ENCRYPTION_MODE",       FWKNOP_CLI_ARG_ENCRYPTION_MODE       },
    { "USE_GPG",               FWKNOP_CLI_ARG_USE_GPG               },
    { "USE_GPG_AGENT",         FWKNOP_CLI_ARG_USE_GPG_AGENT         },
    { "GPG_RECIPIENT",         FWKNOP_CLI_ARG_GPG_RECIPIENT         },
    { "GPG_SIGNER",            FWKNOP_CLI_ARG_GPG_SIGNER            },
    { "GPG_HOMEDIR",           FWKNOP_CLI_ARG_GPG_HOMEDIR           },
    { "GPG_EXE",               FWKNOP_CLI_ARG_GPG_EXE_PATH          },
    { "GPG_SIGNING_PW",        FWKNOP_CLI_ARG_GPG_SIGNING_PW        },
    { "GPG_SIGNING_PW_BASE64", FWKNOP_CLI_ARG_GPG_SIGNING_PW_BASE64 },
    { "GPG_NO_SIGNING_PW",     FWKNOP_CLI_ARG_GPG_NO_SIGNING_PW     },
    { "SPOOF_USER",            FWKNOP_CLI_ARG_SPOOF_USER            },
    { "SPOOF_SOURCE_IP",       FWKNOP_CLI_ARG_SPOOF_SOURCE_IP       },
    { "ACCESS",                FWKNOP_CLI_ARG_ACCESS                },
    { "SPA_SERVER",            FWKNOP_CLI_ARG_SPA_SERVER            },
    { "RAND_PORT",             FWKNOP_CLI_ARG_RAND_PORT             },
    { "KEY",                   FWKNOP_CLI_ARG_KEY_RIJNDAEL          },
    { "KEY_BASE64",            FWKNOP_CLI_ARG_KEY_RIJNDAEL_BASE64   },
    { "HMAC_DIGEST_TYPE",      FWKNOP_CLI_ARG_HMAC_DIGEST_TYPE      },
    { "HMAC_KEY_BASE64",       FWKNOP_CLI_ARG_KEY_HMAC_BASE64       },
    { "HMAC_KEY",              FWKNOP_CLI_ARG_KEY_HMAC              },
    { "USE_HMAC",              FWKNOP_CLI_ARG_USE_HMAC              },
    { "USE_WGET_USER_AGENT",   FWKNOP_CLI_ARG_USE_WGET_USER_AGENT   },
    { "KEY_FILE",              FWKNOP_CLI_ARG_KEY_FILE              },
    { "HMAC_KEY_FILE",         FWKNOP_CLI_ARG_HMAC_KEY_FILE         },
    { "NAT_ACCESS",            FWKNOP_CLI_ARG_NAT_ACCESS            },
    { "HTTP_USER_AGENT",       FWKNOP_CLI_ARG_HTTP_USER_AGENT       },
    { "RESOLVE_URL",           FWKNOP_CLI_ARG_RESOLVE_URL           },
    { "SERVER_RESOLVE_IPV4",   FWKNOP_CLI_ARG_SERVER_RESOLVE_IPV4   },
    { "NAT_LOCAL",             FWKNOP_CLI_ARG_NAT_LOCAL             },
    { "NAT_RAND_PORT",         FWKNOP_CLI_ARG_NAT_RAND_PORT         },
    { "NAT_PORT",              FWKNOP_CLI_ARG_NAT_PORT              },
    { "VERBOSE",               FWKNOP_CLI_ARG_VERBOSE               },
    { "RESOLVE_IP_HTTP",       FWKNOP_CLI_ARG_RESOLVE_IP_HTTP       },
    { "RESOLVE_IP_HTTPS",      FWKNOP_CLI_ARG_RESOLVE_IP_HTTPS      },
    { "RESOLVE_HTTP_ONLY",     FWKNOP_CLI_ARG_RESOLVE_HTTP_ONLY     },
    { "WGET_CMD",              FWKNOP_CLI_ARG_WGET_CMD              },
    { "NO_SAVE_ARGS",          FWKNOP_CLI_ARG_NO_SAVE_ARGS          }
};

/* 数组来定义哪些配置变量是关键的，不应该是 */
/* 数组用于定义哪些配置变量是关键的，当使用 --保存rc节参数 */
static int critical_var_array[] =
{
    FWKNOP_CLI_ARG_KEY_RIJNDAEL,
    FWKNOP_CLI_ARG_KEY_RIJNDAEL_BASE64,
    FWKNOP_CLI_ARG_KEY_HMAC,
    FWKNOP_CLI_ARG_KEY_HMAC_BASE64,
    FWKNOP_CLI_ARG_GPG_RECIPIENT,
    FWKNOP_CLI_ARG_GPG_SIGNER,
    FWKNOP_CLI_ARG_GPG_SIGNING_PW,
    FWKNOP_CLI_ARG_GPG_SIGNING_PW_BASE64
};

/* * */
static void
generate_keys(fko_cli_options_t *options)
{
    int res;

    /* 如果被要求，我们必须生成密钥 */
    if(options->key_gen)
    {
        /* 将密钥缓冲区清零 */
        memset(&(options->key_base64), 0x00, sizeof(options->key_base64));
        memset(&(options->hmac_key_base64), 0x00, sizeof(options->hmac_key_base64));

        /* 通过libfko生成密钥 */
        res = fko_key_gen(options->key_base64, options->key_len,
                options->hmac_key_base64, options->hmac_key_len,
                options->hmac_type);

        /* 密钥生成失败时退出 */
        if(res != FKO_SUCCESS)
        {
            log_msg(LOG_VERBOSITY_ERROR, "%s: fko_key_gen: Error %i - %s",
                MY_NAME, res, fko_errstr(res));
            exit(EXIT_FAILURE);
        }

        /* 一切都好-没什么可做的 */
        else;
    }

    /* 无需密钥生成-无需执行任何操作 */
    else;
}

/* * */
static int
var_is_critical(short var_pos)
{
    int ndx;            /* critical_var_array数组上的索引 */
    int var_found = 0;

    /* 遍历关键变量数组 */
    for (ndx=0 ; ndx<ARRAY_SIZE(critical_var_array) ; ndx++)
    {
        /* 检查我们是否找到 */
        if (var_pos == critical_var_array[ndx])
        {
            var_found = 1;
            break;
        }
    }

    return var_found;
}

/* * */
static void
add_var_to_bitmask(short var_pos, fko_var_bitmask_t *bm)
{
    unsigned int bitmask_ndx;

    /* 查找我们必须处理的uint32_t数组上的索引 */
    bitmask_ndx = var_pos / 32;

    /* 根据找到的索引设置位掩码 */
    if (bitmask_ndx < BITMASK_ARRAY_SIZE)
        bm->dw[bitmask_ndx] |= POSITION_TO_BITMASK(var_pos);

    /* uint32_t位掩码上的索引无效 */
    else
        log_msg(LOG_VERBOSITY_WARNING,
                "add_var_to_bitmask() : Bad variable position %u", var_pos);
}

/* * */
static void
remove_var_from_bitmask(short var_pos, fko_var_bitmask_t *bm)
{
    unsigned int bitmask_ndx;

    /* 查找我们必须处理的uint32_t数组上的索引 */
    bitmask_ndx = var_pos / 32;

    /* 根据找到的索引设置位掩码 */
    if (bitmask_ndx < BITMASK_ARRAY_SIZE)
        bm->dw[bitmask_ndx] &= ~POSITION_TO_BITMASK(var_pos);

    /* uint32_t位掩码上的索引无效 */
    else
        log_msg(LOG_VERBOSITY_WARNING,
                "remove_from_bitmask() : Bad variable position %u", var_pos);
}

/* * */
static int
bitmask_has_var(short var_pos, fko_var_bitmask_t *bm)
{
    unsigned int    bitmask_ndx;
    int             var_found = 0;

    /* 查找我们必须处理的uint32_t数组上的索引 */
    bitmask_ndx = var_pos / 32;

    /* 根据找到的索引检查位掩码 */
    if (bitmask_ndx < BITMASK_ARRAY_SIZE)
    {
        if ( bm->dw[bitmask_ndx] & POSITION_TO_BITMASK(var_pos) )
            var_found = 1;
    }

    /* uint32_t位掩码上的索引无效 */
    else
        log_msg(LOG_VERBOSITY_WARNING, "bitmask_has_var_ndx() : Bad variable position %u", var_pos);

    return var_found;
}

/* * */
static int
ask_overwrite_var(const char *var, const char *stanza)
{
    char    user_input = 'N';
    int     overwrite = 0;
    int     c;
    int     first_char = 1;;

    log_msg(LOG_VERBOSITY_NORMAL,
            "Variable '%s' found in stanza '%s'. Overwrite [N/y] ? ",
            var, stanza);

    while ((c=getchar()) != LF_CHAR)
    {
        if (first_char)
            user_input = c;
        first_char = 0;
    }

    if (user_input == 'y')
        overwrite = 1;

    return overwrite;
}

/* * */
static fko_var_t *
lookup_var_by_name(const char *var_name)
{
    short       ndx;            /* fko_var_array表上的索引 */
    fko_var_t  *var = NULL;

    /* 根据fko_var_array中的每个可用变量检查str */
    for (ndx=0 ; ndx<ARRAY_SIZE(fko_var_array) ; ndx++)
    {
        if (CONF_VAR_IS(var_name, fko_var_array[ndx].name))
        {
            var = &(fko_var_array[ndx]);
            break;
        }
    }

    return var;
}

/* * */
static fko_var_t *
lookup_var_by_position(short var_pos)
{
    short       ndx;            /* fko_var_array表上的索引 */
    fko_var_t  *var = NULL;

    /* 根据fko_var_array中的每个可用变量检查str */
    for (ndx=0 ; ndx<ARRAY_SIZE(fko_var_array) ; ndx++)
    {
        if (var_pos == fko_var_array[ndx].pos)
        {
            var = &(fko_var_array[ndx]);
            break;
        }
    }

    return var;
}

/* * */
static void
bool_to_yesno(int val, char* s, size_t len)
{
    if (val == 0)
        strlcpy(s, PARAM_NO_VALUE, len);
    else
        strlcpy(s, PARAM_YES_VALUE, len);
}

/* * */
static int
is_yes_str(const char *s)
{
    int valid;

    if (strcasecmp(PARAM_YES_VALUE, s) == 0)
        valid = 1;
    else
        valid = 0;

    return valid;
}

/* * */
static int
is_rc_section(const char* line, uint16_t line_size, char* rc_section, uint16_t rc_section_size)
{
    char    *ndx, *emark;
    char    buf[MAX_LINE_LEN] = {0};
    int     section_found = 0;

    if (line_size < sizeof(buf))
    {
        strlcpy(buf, line, sizeof(buf));

        ndx = buf;

        while(isspace((int)(unsigned char)*ndx))
            ndx++;

        if(*ndx == '[')
        {
            ndx++;
            emark = strchr(ndx, ']');
            if(emark != NULL)
            {
                *emark = '\0';
                memset(rc_section, 0, rc_section_size);
                strlcpy(rc_section, ndx, rc_section_size);
                section_found = 1;
            }
            else
            {
            }
        }
    }
    else
    {
    }

    return section_found;
}

/* * */
static int
is_rc_param(const char *line, rc_file_param_t *param)
{
    char    var[MAX_LINE_LEN] = {0};
    char    val[MAX_LINE_LEN] = {0};
    char    *ndx;

    memset(param, 0, sizeof(*param));

    /* 获取变量及其值 */
    if(sscanf(line, "%s %[^ ;\t\n\r#]", var, val) != 2)
    {
        log_msg(LOG_VERBOSITY_WARNING,
            "*Invalid entry in '%s'", line);
        return 0;
    }

    /* 删除var末尾的任何冒号 */
    if((ndx = strrchr(var, ':')) != NULL)
        *ndx = '\0';

    /* 即使sscanf应该自动添加终止 */
    var[MAX_LINE_LEN-1] = 0x0;
    val[MAX_LINE_LEN-1] = 0x0;

    /* 从值中删除任何尾随空格 */
    chop_whitespace(val);

    /* 复制回结构中的val和var */
    strlcpy(param->name, var, sizeof(param->name));
    strlcpy(param->val, val, sizeof(param->val));

    return 1;
}

/* * */
static int
dump_configured_stanzas_from_rcfile(const char* rcfile)
{
    FILE   *rc;
    char    line[MAX_LINE_LEN]   = {0};
    char    curr_stanza[MAX_LINE_LEN] = {0};

    /* 以读取模式打开rcfile */
    if ((rc = fopen(rcfile, "r")) == NULL)
    {
        log_msg(LOG_VERBOSITY_WARNING, "Unable to open rc file: %s: %s",
            rcfile, strerror(errno));

        return EXIT_FAILURE;
    }

    log_msg(LOG_VERBOSITY_NORMAL, "The following stanzas are configured in %s :", rcfile);

    /* 逐行分析rcfile以查找节 */
    while ((fgets(line, MAX_LINE_LEN, rc)) != NULL)
    {
        line[MAX_LINE_LEN-1] = '\0';

        /* 获取过去的评论和空行（注意：我们只看第一行 */
        if(IS_EMPTY_LINE(line[0]))
            continue;

        /* 检查我们正在处理的部分 */
        else if (is_rc_section(line, strlen(line), curr_stanza, sizeof(curr_stanza)))
        {
            /* 打印节并继续-我们排除默认节 */
            if (strcasecmp(curr_stanza, RC_SECTION_DEFAULT) != 0)
                log_msg(LOG_VERBOSITY_NORMAL, " - %s", curr_stanza);
            continue;
        }

        /* 我们什么都不在乎 */
        else;
    }

    fclose(rc);

    return EXIT_SUCCESS;
}

/* 为fwknop rc文件分配路径 */
static void
set_rc_file(char *rcfile, fko_cli_options_t *options)
{
    int     rcf_offset;
    char    *homedir;

    memset(rcfile, 0x0, MAX_PATH_LEN);

    if(options->rc_file[0] == 0x0)
    {
        if(options->no_home_dir)
        {
            log_msg(LOG_VERBOSITY_ERROR,
                    "Warning: in --no-home-dir mode, must set --rc-file path.");
            exit(EXIT_FAILURE);
        }
#ifdef WIN32
        homedir = getenv("USERPROFILE");
#else
        homedir = getenv("HOME");
#endif

        if(homedir == NULL)
        {
            log_msg(LOG_VERBOSITY_ERROR, "Warning: Unable to determine HOME directory.\n"
                " No .fwknoprc file processed.");
            exit(EXIT_FAILURE);
        }

        strlcpy(rcfile, homedir, MAX_PATH_LEN);

        rcf_offset = strlen(rcfile);

        /* Sanity检查到.fknoprc的路径。 */
        if(rcf_offset > (MAX_PATH_LEN - 11))
        {
            log_msg(LOG_VERBOSITY_ERROR, "Warning: Path to .fwknoprc file is too long.\n"
                " No .fwknoprc file processed.");
            exit(EXIT_FAILURE);
        }

        rcfile[rcf_offset] = PATH_SEP;
        strlcat(rcfile, ".fwknoprc", MAX_PATH_LEN);
    }
    else
    {
        strlcpy(rcfile, options->rc_file, MAX_PATH_LEN);
    }

    /* 检查rc文件权限-如果除了用户读/写之外， */
    if(verify_file_perms_ownership(rcfile, -1) != 1)
        exit(EXIT_FAILURE);

    return;
}

static void
keys_status(fko_cli_options_t *options)
{
    FILE  *key_gen_file_ptr = NULL;
    char   rcfile[MAX_PATH_LEN] = {0};

    if(options->key_gen == 1)
    {
        if(options->key_gen_file[0] != '\0')
        {
            if ((key_gen_file_ptr = fopen(options->key_gen_file, "w")) == NULL)
            {
                log_msg(LOG_VERBOSITY_ERROR, "Unable to create key gen file: %s: %s",
                    options->key_gen_file, strerror(errno));
                exit(EXIT_FAILURE);
            }
            fprintf(key_gen_file_ptr, "KEY_BASE64: %s\nHMAC_KEY_BASE64: %s\n",
                options->key_base64, options->hmac_key_base64);
            fclose(key_gen_file_ptr);
            log_msg(LOG_VERBOSITY_NORMAL,
                    "[+] Wrote Rijndael and HMAC keys to: %s",
                options->key_gen_file);
        }
        else
        {
            if(options->save_rc_stanza == 1)
            {
                set_rc_file(rcfile, options);
                log_msg(LOG_VERBOSITY_NORMAL,
                    "[+] Wrote Rijndael and HMAC keys to rc file: %s", rcfile);
            }
            else
                log_msg(LOG_VERBOSITY_NORMAL,
                        "KEY_BASE64: %s\nHMAC_KEY_BASE64: %s",
                        options->key_base64, options->hmac_key_base64);
        }

        /* 由于fwknopd服务器，始终以--key-gen模式退出 */
        exit(EXIT_SUCCESS);
    }
}


/* 从命令行分析任何时间偏移 */
static int
parse_time_offset(const char *offset_str, int *offset)
{
    int i, j;
    int offset_type = TIME_OFFSET_SECONDS;
    int os_len      = strlen(offset_str);
    int is_err = 0;

    char offset_digits[MAX_TIME_STR_LEN] = {0};

    j=0;
    for (i=0; i < os_len; i++) {
        if (isdigit((int)(unsigned char)offset_str[i])) {
            offset_digits[j] = offset_str[i];
            j++;
            if(j >= MAX_TIME_STR_LEN)
            {
                return 0;
            }
        } else if (offset_str[i] == 'm' || offset_str[i] == 'M') {
            offset_type = TIME_OFFSET_MINUTES;
            break;
        } else if (offset_str[i] == 'h' || offset_str[i] == 'H') {
            offset_type = TIME_OFFSET_HOURS;
            break;
        } else if (offset_str[i] == 'd' || offset_str[i] == 'D') {
            offset_type = TIME_OFFSET_DAYS;
            break;
        }
    }

    offset_digits[j] = '\0';

    if (j < 1)
        return 0;

    *offset = strtol_wrapper(offset_digits, 0, (2 << 15),
            NO_EXIT_UPON_ERR, &is_err);

    /* 应用offset_type乘数 */
    *offset *= offset_type;

    return is_err == 0 ? 1 : 0;
}

static int
create_fwknoprc(const char *rcfile)
{
    FILE *rc = NULL;
    int   rcfile_fd = -1;

    log_msg(LOG_VERBOSITY_NORMAL, "[*] Creating initial rc file: %s.", rcfile);

    /* 尝试仅使用用户读/写权限创建初始rcfile。 */
    rcfile_fd = open(rcfile, FWKNOPRC_OFLAGS ,FWKNOPRC_MODE);

    // If an error occurred ...
    if (rcfile_fd == -1) {
            log_msg(LOG_VERBOSITY_WARNING, "Unable to create initial rc file: %s: %s",
                rcfile, strerror(errno));
            return(-1);
    }

    // Free the rcfile descriptor
    close(rcfile_fd);

    if ((rc = fopen(rcfile, "w")) == NULL)
    {
        log_msg(LOG_VERBOSITY_WARNING, "Unable to write default setup to rcfile: %s: %s",
            rcfile, strerror(errno));
        return(-1);
    }

    fprintf(rc,
        "# .fwknoprc\n"
        "##############################################################################\n"
        "#\n"
        "# Firewall Knock Operator (fwknop) client rc file.\n"
        "#\n"
        "# This file contains user-specific fwknop client configuration default\n"
        "# and named parameter sets for specific invocations of the fwknop client.\n"
        "#\n"
        "# Each section (or stanza) is identified and started by a line in this\n"
        "# file that contains a single identifier surrounded by square brackets.\n"
        "# It is this identifier (or name) that is used from the fwknop command line\n"
        "# via the '-n <name>' argument to reference the corresponding stanza.\n"
        "#\n"
        "# The parameters within the stanza typically match corresponding client \n"
        "# command-line parameters.\n"
        "#\n"
        "# The first one should always be `[default]' as it defines the global\n"
        "# default settings for the user. These override the program defaults\n"
        "# for these parameters.  If a named stanza is used, its entries will\n"
        "# override any of the default values.  Command-line options will trump them\n"
        "# all.\n"
        "#\n"
        "# Subsequent stanzas will have only the overriding and destination\n"
        "# specific parameters.\n"
        "#\n"
        "# Lines starting with `#' and empty lines are ignored.\n"
        "#\n"
        "# See the fwknop.8 man page for a complete list of valid parameters\n"
        "# and their values.\n"
        "#\n"
        "##############################################################################\n"
        "#\n"
        "# We start with the 'default' stanza.  Uncomment and edit for your\n"
        "# preferences.  The client will use its built-in default for those items\n"
        "# that are commented out.\n"
        "#\n"
        "[default]\n"
        "\n"
        "#DIGEST_TYPE         sha256\n"
        "#FW_TIMEOUT          30\n"
        "#SPA_SERVER_PORT     62201\n"
        "#SPA_SERVER_PROTO    udp\n"
        "#ALLOW_IP            <ip addr>\n"
        "#SPOOF_USER          <username>\n"
        "#SPOOF_SOURCE_IP     <IPaddr>\n"
        "#TIME_OFFSET         0\n"
        "#USE_GPG             N\n"
        "#GPG_HOMEDIR         /path/to/.gnupg\n"
        "#GPG_EXE             /path/to/gpg\n"
        "#GPG_SIGNER          <signer ID>\n"
        "#GPG_RECIPIENT       <recipient ID>\n"
        "#NO_SAVE_ARGS        N\n"
        "\n"
        "# User-provided named stanzas:\n"
        "\n"
        "# Example for a destination server of 192.168.1.20 to open access to\n"
        "# SSH for an IP that is resolved externally, and one with a NAT request\n"
        "# for a specific source IP that maps port 8088 on the server\n"
        "# to port 88 on 192.168.1.55 with timeout.\n"
        "#\n"
        "#[myssh]\n"
        "#SPA_SERVER          192.168.1.20\n"
        "#ACCESS              tcp/22\n"
        "#ALLOW_IP            resolve\n"
        "#\n"
        "#[mynatreq]\n"
        "#SPA_SERVER          192.168.1.20\n"
        "#ACCESS              tcp/8088\n"
        "#ALLOW_IP            10.21.2.6\n"
        "#NAT_ACCESS          192.168.1.55,88\n"
        "#CLIENT_TIMEOUT      60\n"
        "#\n"
        "\n"
    );

    fclose(rc);

    return(0);
}

static int
parse_rc_param(fko_cli_options_t *options, const char *var_name, char * val)
{
    int         tmpint, is_err;
    int         parse_error = 0;    /* 如果变量已成功处理，则为0，否则为<0 */
    fko_var_t  *var;                /* fwknop变量结构上的指针 */

    log_msg(LOG_VERBOSITY_DEBUG, "parse_rc_param() : Parsing variable %s...", var_name);

    /* 根据变量的名称查找该变量。 */
    var = lookup_var_by_name(var_name);

    /* 如果变量的指针为NULL，则不处理该变量 */
    if (var == NULL)
        parse_error = -1;

    /* 摘要类型 */
    else if (var->pos == FWKNOP_CLI_ARG_DIGEST_TYPE)
    {
        tmpint = digest_strtoint(val);
        if(tmpint < 0)
            parse_error = -1;
        else
            options->digest_type = tmpint;
    }
    /* 服务器协议 */
    else if (var->pos == FWKNOP_CLI_ARG_SPA_SERVER_PROTO)
    {
        tmpint = proto_strtoint(val);
        if(tmpint < 0)
            parse_error = -1;
        else
            options->spa_proto = tmpint;
    }
    /* 服务器端口 */
    else if (var->pos == FWKNOP_CLI_ARG_SPA_SERVER_PORT)
    {
        tmpint = strtol_wrapper(val, 0, MAX_PORT, NO_EXIT_UPON_ERR, &is_err);
        if(is_err == FKO_SUCCESS)
            options->spa_dst_port = tmpint;
        else
            parse_error = -1;
    }
    /* 源端口 */
    else if (var->pos == FWKNOP_CLI_ARG_SPA_SOURCE_PORT)
    {
        tmpint = strtol_wrapper(val, 0, MAX_PORT, NO_EXIT_UPON_ERR, &is_err);
        if(is_err == FKO_SUCCESS)
            options->spa_src_port = tmpint;
        else
            parse_error = -1;
    }
    /* 防火墙规则超时 */
    else if (var->pos == FWKNOP_CLI_ARG_FW_TIMEOUT)
    {
        tmpint = strtol_wrapper(val, 0, (2 << 15), NO_EXIT_UPON_ERR, &is_err);
        if(is_err == FKO_SUCCESS)
            options->fw_timeout = tmpint;
        else
            parse_error = -1;
    }
    /* 允许IP */
    else if (var->pos == FWKNOP_CLI_ARG_ALLOW_IP)
    {
        /* 如果这是以前设置的 */
        options->resolve_ip_http_https = 0;

        /* 使用源、解析或实际IP */
        if(strcasecmp(val, "source") == 0)
            strlcpy(options->allow_ip_str, "0.0.0.0", sizeof(options->allow_ip_str));
        else if(strcasecmp(val, "resolve") == 0)
            options->resolve_ip_http_https = 1;
        else /* 假设IP地址并验证 */
        {
            strlcpy(options->allow_ip_str, val, sizeof(options->allow_ip_str));
            if(! is_valid_ipv4_addr(options->allow_ip_str, strlen(options->allow_ip_str)))
                parse_error = -1;
        }
    }
    /* 时间偏移 */
    else if (var->pos == FWKNOP_CLI_ARG_TIME_OFFSET)
    {
        if(val[0] == '-')
        {
            val++;
            if(! parse_time_offset(val, &options->time_offset_minus))
                parse_error = -1;
        }
        else
            if (! parse_time_offset(val, &options->time_offset_plus))
                parse_error = -1;

        if(parse_error == -1)
            log_msg(LOG_VERBOSITY_WARNING,
                    "TIME_OFFSET argument '%s' invalid.", val);
    }
    /* 对称加密模式 */
    else if (var->pos == FWKNOP_CLI_ARG_ENCRYPTION_MODE)
    {
        tmpint = enc_mode_strtoint(val);
        if(tmpint < 0)
            parse_error = -1;
        else
            options->encryption_mode = tmpint;
    }
    /* 使用GPG？ */
    else if (var->pos == FWKNOP_CLI_ARG_USE_GPG)
    {
        if (is_yes_str(val))
            options->use_gpg = 1;
        else;
    }
    /* 使用GPG代理？ */
    else if (var->pos == FWKNOP_CLI_ARG_USE_GPG_AGENT)
    {
        if (is_yes_str(val))
            options->use_gpg_agent = 1;
        else;
    }
    /* 没有GPG签名密码？ */
    else if (var->pos == FWKNOP_CLI_ARG_GPG_NO_SIGNING_PW)
    {
        if (is_yes_str(val))
            options->gpg_no_signing_pw = 1;
        else;
    }
    /* GPG收件人 */
    else if (var->pos == FWKNOP_CLI_ARG_GPG_RECIPIENT)
    {
        strlcpy(options->gpg_recipient_key, val, sizeof(options->gpg_recipient_key));
    }
    /* GPG签署人 */
    else if (var->pos == FWKNOP_CLI_ARG_GPG_SIGNER)
    {
        strlcpy(options->gpg_signer_key, val, sizeof(options->gpg_signer_key));
    }
    /* GPG主页目录 */
    else if (var->pos == FWKNOP_CLI_ARG_GPG_HOMEDIR)
    {
        strlcpy(options->gpg_home_dir, val, sizeof(options->gpg_home_dir));
    }
    /* GPG路径 */
    else if (var->pos == FWKNOP_CLI_ARG_GPG_EXE_PATH)
    {
        strlcpy(options->gpg_exe, val, sizeof(options->gpg_exe));
    }
    /* 后台处理用户 */
    else if (var->pos == FWKNOP_CLI_ARG_SPOOF_USER)
    {
        strlcpy(options->spoof_user, val, sizeof(options->spoof_user));
    }
    /* 后台处理源IP */
    else if (var->pos == FWKNOP_CLI_ARG_SPOOF_SOURCE_IP)
    {
        strlcpy(options->spoof_ip_src_str, val, sizeof(options->spoof_ip_src_str));
    }
    /* ACCESS请求 */
    else if (var->pos == FWKNOP_CLI_ARG_ACCESS)
    {
        strlcpy(options->access_str, val, sizeof(options->access_str));
    }
    /* SPA服务器（目标） */
    else if (var->pos == FWKNOP_CLI_ARG_SPA_SERVER)
    {
        strlcpy(options->spa_server_str, val, sizeof(options->spa_server_str));
    }
    /* 兰德端口？ */
    else if (var->pos == FWKNOP_CLI_ARG_RAND_PORT)
    {
        if (is_yes_str(val))
            options->rand_port = 1;
        else;
    }
    /* Rijndael钥匙 */
    else if (var->pos == FWKNOP_CLI_ARG_KEY_RIJNDAEL)
    {
        strlcpy(options->key, val, sizeof(options->key));
        options->have_key = 1;
    }
    /* Rijndael密钥（base-64编码） */
    else if (var->pos == FWKNOP_CLI_ARG_KEY_RIJNDAEL_BASE64)
    {
        if (! is_base64((unsigned char *) val, strlen(val)))
        {
            log_msg(LOG_VERBOSITY_WARNING,
                "KEY_BASE64 argument '%s' doesn't look like base64-encoded data.",
                val);
            parse_error = -1;
        }
        strlcpy(options->key_base64, val, sizeof(options->key_base64));
        options->have_base64_key = 1;
    }
    /* GnuPG签名密码 */
    else if (var->pos == FWKNOP_CLI_ARG_GPG_SIGNING_PW)
    {
        strlcpy(options->key, val, sizeof(options->key));
        options->have_key = 1;
    }
    /* GnuPG签名密码短语（base-64编码） */
    else if (var->pos == FWKNOP_CLI_ARG_GPG_SIGNING_PW_BASE64)
    {
        if (! is_base64((unsigned char *) val, strlen(val)))
        {
            log_msg(LOG_VERBOSITY_WARNING,
                "GPG_SIGNING_KEY_BASE64 argument '%s' doesn't look like base64-encoded data.",
                val);
            parse_error = -1;
        }
        strlcpy(options->key_base64, val, sizeof(options->key_base64));
        options->have_base64_key = 1;
    }
    /* HMAC摘要类型 */
    else if (var->pos == FWKNOP_CLI_ARG_HMAC_DIGEST_TYPE)
    {
        tmpint = hmac_digest_strtoint(val);
        if(tmpint < 0)
        {
            log_msg(LOG_VERBOSITY_WARNING,
                    "HMAC_DIGEST_TYPE argument '%s' must be one of {md5,sha1,sha256,sha384,sha512,sha3_256,sha3_512}",
                    val);
            parse_error = -1;
        }
        else
        {
            options->hmac_type = tmpint;
        }
    }
    /* HMAC密钥（base64编码） */
    else if (var->pos == FWKNOP_CLI_ARG_KEY_HMAC_BASE64)
    {
        if (! is_base64((unsigned char *) val, strlen(val)))
        {
            log_msg(LOG_VERBOSITY_WARNING,
                "HMAC_KEY_BASE64 argument '%s' doesn't look like base64-encoded data.",
                val);
            parse_error = -1;
        }
        strlcpy(options->hmac_key_base64, val, sizeof(options->hmac_key_base64));
        options->have_hmac_base64_key = 1;
        options->use_hmac = 1;
    }

    /* HMAC密钥 */
    else if (var->pos == FWKNOP_CLI_ARG_KEY_HMAC)
    {
        strlcpy(options->hmac_key, val, sizeof(options->hmac_key));
        options->have_hmac_key = 1;
        options->use_hmac = 1;
    }

    /* --使用hmac */
    else if (var->pos == FWKNOP_CLI_ARG_USE_HMAC)
    {
        if (is_yes_str(val))
            options->use_hmac = 1;
    }
    /* --使用wget用户代理 */
    else if (var->pos == FWKNOP_CLI_ARG_USE_WGET_USER_AGENT)
    {
        if (is_yes_str(val))
            options->use_wget_user_agent = 1;
    }
    /* 密钥文件 */
    else if (var->pos == FWKNOP_CLI_ARG_KEY_FILE)
    {
        strlcpy(options->get_key_file, val, sizeof(options->get_key_file));
    }
    /* HMAC密钥文件 */
    else if (var->pos == FWKNOP_CLI_ARG_HMAC_KEY_FILE)
    {
        strlcpy(options->get_key_file, val,
            sizeof(options->get_hmac_key_file));
    }
    /* NAT访问请求 */
    else if (var->pos == FWKNOP_CLI_ARG_NAT_ACCESS)
    {
        strlcpy(options->nat_access_str, val, sizeof(options->nat_access_str));
    }
    /* HTTP用户代理 */
    else if (var->pos == FWKNOP_CLI_ARG_HTTP_USER_AGENT)
    {
        strlcpy(options->http_user_agent, val, sizeof(options->http_user_agent));
    }
    /* 解析URL */
    else if (var->pos == FWKNOP_CLI_ARG_RESOLVE_URL)
    {
        if(options->resolve_url != NULL)
            free(options->resolve_url);
        tmpint = strlen(val)+1;
        options->resolve_url = calloc(1, tmpint);
        if(options->resolve_url == NULL)
        {
            log_msg(LOG_VERBOSITY_ERROR,"Memory allocation error for resolve URL.");
            exit(EXIT_FAILURE);
        }
        strlcpy(options->resolve_url, val, tmpint);
    }
    /* 解析SPA服务器（通过DNS）-仅接受IPv4地址？ */
    else if (var->pos == FWKNOP_CLI_ARG_SERVER_RESOLVE_IPV4)
    {
        if (is_yes_str(val))
        {
            options->spa_server_resolve_ipv4 = 1;
        }
    }
    /* wget命令 */
    else if (var->pos == FWKNOP_CLI_ARG_WGET_CMD)
    {
        if(options->wget_bin != NULL)
            free(options->wget_bin);
        tmpint = strlen(val)+1;
        options->wget_bin = calloc(1, tmpint);
        if(options->wget_bin == NULL)
        {
            log_msg(LOG_VERBOSITY_ERROR,"Memory allocation error for wget command path.");
            exit(EXIT_FAILURE);
        }
        strlcpy(options->wget_bin, val, tmpint);
    }
    /* NAT本地？ */
    else if (var->pos == FWKNOP_CLI_ARG_NAT_LOCAL)
    {
        if (is_yes_str(val))
            options->nat_local = 1;
        else;
    }
    /* NAT rand端口？ */
    else if (var->pos == FWKNOP_CLI_ARG_NAT_RAND_PORT)
    {
        if (is_yes_str(val))
            options->nat_rand_port = 1;
        else;
    }
    /* NAT端口 */
    else if (var->pos == FWKNOP_CLI_ARG_NAT_PORT)
    {
        tmpint = strtol_wrapper(val, 0, MAX_PORT, NO_EXIT_UPON_ERR, &is_err);
        if(is_err == FKO_SUCCESS)
            options->nat_port = tmpint;
        else
            parse_error = -1;
    }
    /* VERBOSE级别 */
    else if (var->pos == FWKNOP_CLI_ARG_VERBOSE)
    {
        if (is_yes_str(val))
            options->verbose = 1;
        else
        {
            tmpint = strtol_wrapper(val, 0, LOG_LAST_VERBOSITY - 1, NO_EXIT_UPON_ERR, &is_err);
            if(is_err == FKO_SUCCESS)
                options->verbose = tmpint;
            else
                parse_error = -1;
        }

        if (parse_error == 0)
            log_set_verbosity(LOG_DEFAULT_VERBOSITY + options->verbose);
    }
    /* RESOLVE_IP_HTTPS？ */
    else if (var->pos == FWKNOP_CLI_ARG_RESOLVE_IP_HTTPS)
    {
        if (is_yes_str(val))
            options->resolve_ip_http_https = 1;
        else;
    }
    /* RESOLVE_IP_HTTP？这实际上会在默认情况下导致HTTPS解析 */
    else if (var->pos == FWKNOP_CLI_ARG_RESOLVE_IP_HTTP)
    {
        if (is_yes_str(val))
            options->resolve_ip_http_https = 1;
        else;
    }
    /* 仅解决HTTP_ONLY？强制HTTP而不是HTTPS IP解析。 */
    else if (var->pos == FWKNOP_CLI_ARG_RESOLVE_HTTP_ONLY)
    {
        if (is_yes_str(val))
            options->resolve_http_only = 1;
        else;
    }
    /* 避免保存。默认情况下运行fwknop.run */
    else if (var->pos == FWKNOP_CLI_ARG_NO_SAVE_ARGS)
    {
        if (is_yes_str(val))
            options->no_save_args = 1;
        else;
    }
    /* 变量不是配置变量 */
    else
    {
        parse_error = -1;
    }

    return(parse_error);
}

/* * */
static void
add_single_var_to_rc(FILE* fhandle, short var_pos, fko_cli_options_t *options)
{
    char        val[MAX_LINE_LEN] = {0};
    fko_var_t  *var;

    var = lookup_var_by_position(var_pos);

    if (var == NULL)
        return;

    if (fhandle == NULL)
        return;

    /* 选择要添加的参数并将其字符串值存储到val中 */
    switch (var->pos)
    {
        case FWKNOP_CLI_ARG_DIGEST_TYPE :
            digest_inttostr(options->digest_type, val, sizeof(val));
            break;
        case FWKNOP_CLI_ARG_SPA_SERVER_PROTO :
            proto_inttostr(options->spa_proto, val, sizeof(val));
            break;
        case FWKNOP_CLI_ARG_SPA_SERVER_PORT :
            snprintf(val, sizeof(val)-1, "%d", options->spa_dst_port);
            break;
        case FWKNOP_CLI_ARG_SPA_SOURCE_PORT :
            snprintf(val, sizeof(val)-1, "%d", options->spa_src_port);
            break;
        case FWKNOP_CLI_ARG_FW_TIMEOUT :
            snprintf(val, sizeof(val)-1, "%d", options->fw_timeout);
            break;
        case FWKNOP_CLI_ARG_ALLOW_IP :
            strlcpy(val, options->allow_ip_str, sizeof(val));
            break;
        case FWKNOP_CLI_ARG_TIME_OFFSET :
            if (options->time_offset_minus != 0)
                snprintf(val, sizeof(val)-1, "-%d", options->time_offset_minus);
            else if (options->time_offset_plus != 0)
                snprintf(val, sizeof(val)-1, "%d", options->time_offset_plus);
            else;
            break;
        case FWKNOP_CLI_ARG_ENCRYPTION_MODE :
            enc_mode_inttostr(options->encryption_mode, val, sizeof(val));
            break;
        case FWKNOP_CLI_ARG_USE_GPG :
            bool_to_yesno(options->use_gpg, val, sizeof(val));
            break;
        case FWKNOP_CLI_ARG_USE_GPG_AGENT :
            bool_to_yesno(options->use_gpg_agent, val, sizeof(val));
            break;
        case FWKNOP_CLI_ARG_GPG_RECIPIENT :
            strlcpy(val, options->gpg_recipient_key, sizeof(val));
            break;
        case FWKNOP_CLI_ARG_GPG_SIGNER :
            strlcpy(val, options->gpg_signer_key, sizeof(val));
            break;
        case FWKNOP_CLI_ARG_GPG_HOMEDIR :
            strlcpy(val, options->gpg_home_dir, sizeof(val));
            break;
        case FWKNOP_CLI_ARG_GPG_EXE_PATH :
            strlcpy(val, options->gpg_exe, sizeof(val));
            break;
        case FWKNOP_CLI_ARG_GPG_NO_SIGNING_PW :
            bool_to_yesno(options->gpg_no_signing_pw, val, sizeof(val));
            break;
        case FWKNOP_CLI_ARG_SPOOF_USER :
            strlcpy(val, options->spoof_user, sizeof(val));
            break;
        case FWKNOP_CLI_ARG_SPOOF_SOURCE_IP :
            strlcpy(val, options->spoof_ip_src_str, sizeof(val));
            break;
        case FWKNOP_CLI_ARG_ACCESS :
            strlcpy(val, options->access_str, sizeof(val));
            break;
        case FWKNOP_CLI_ARG_SPA_SERVER :
            strlcpy(val, options->spa_server_str, sizeof(val));
            break;
        case FWKNOP_CLI_ARG_RAND_PORT :
            bool_to_yesno(options->rand_port, val, sizeof(val));
            break;
        case FWKNOP_CLI_ARG_KEY_FILE :
            strlcpy(val, options->get_key_file, sizeof(val));
            break;
        case FWKNOP_CLI_ARG_HMAC_KEY_FILE :
            strlcpy(val, options->get_hmac_key_file, sizeof(val));
            break;
        case FWKNOP_CLI_ARG_KEY_RIJNDAEL:
            strlcpy(val, options->key, sizeof(val));
            break;
        case FWKNOP_CLI_ARG_KEY_RIJNDAEL_BASE64:
            strlcpy(val, options->key_base64, sizeof(val));
            break;
        case FWKNOP_CLI_ARG_KEY_HMAC_BASE64:
            strlcpy(val, options->hmac_key_base64, sizeof(val));
            break;
        case FWKNOP_CLI_ARG_KEY_HMAC:
            strlcpy(val, options->hmac_key, sizeof(val));
            break;
        case FWKNOP_CLI_ARG_HMAC_DIGEST_TYPE :
            hmac_digest_inttostr(options->hmac_type, val, sizeof(val));
            break;
        case FWKNOP_CLI_ARG_USE_HMAC :
            bool_to_yesno(options->use_hmac, val, sizeof(val));
            break;
        case FWKNOP_CLI_ARG_USE_WGET_USER_AGENT :
            bool_to_yesno(options->use_wget_user_agent, val, sizeof(val));
            break;
        case FWKNOP_CLI_ARG_NAT_ACCESS :
            strlcpy(val, options->nat_access_str, sizeof(val));
            break;
        case FWKNOP_CLI_ARG_HTTP_USER_AGENT :
            strlcpy(val, options->http_user_agent, sizeof(val));
            break;
        case FWKNOP_CLI_ARG_RESOLVE_URL :
            if (options->resolve_url != NULL)
                strlcpy(val, options->resolve_url, sizeof(val));
            else;
            break;
        case FWKNOP_CLI_ARG_SERVER_RESOLVE_IPV4:
            bool_to_yesno(options->spa_server_resolve_ipv4, val, sizeof(val));
            break;
        case FWKNOP_CLI_ARG_NAT_LOCAL :
            bool_to_yesno(options->nat_local, val, sizeof(val));
            break;
        case FWKNOP_CLI_ARG_NAT_RAND_PORT :
            bool_to_yesno(options->nat_rand_port, val, sizeof(val));
            break;
        case FWKNOP_CLI_ARG_NAT_PORT :
            snprintf(val, sizeof(val)-1, "%d", options->nat_port);
            break;
        case FWKNOP_CLI_ARG_VERBOSE:
            if((options->verbose == 0) || (options->verbose == 1))
                bool_to_yesno(options->verbose, val, sizeof(val));
            else
                snprintf(val, sizeof(val)-1, "%d", options->verbose);
            break;
        case FWKNOP_CLI_ARG_RESOLVE_IP_HTTPS:
            bool_to_yesno(options->resolve_ip_http_https, val, sizeof(val));
            break;
        case FWKNOP_CLI_ARG_RESOLVE_IP_HTTP:
            bool_to_yesno(options->resolve_ip_http_https, val, sizeof(val));
            break;
        case FWKNOP_CLI_ARG_RESOLVE_HTTP_ONLY:
            bool_to_yesno(options->resolve_http_only, val, sizeof(val));
            break;
        case FWKNOP_CLI_ARG_WGET_CMD :
            if (options->wget_bin != NULL)
                strlcpy(val, options->wget_bin, sizeof(val));
            break;
        case FWKNOP_CLI_ARG_NO_SAVE_ARGS :
            bool_to_yesno(options->no_save_args, val, sizeof(val));
            break;
        default:
            log_msg(LOG_VERBOSITY_WARNING,
                    "Warning from add_single_var_to_rc() : Bad variable position %u",
                    var->pos);
            return;
    }

    log_msg(LOG_VERBOSITY_DEBUG,
            "add_single_var_to_rc() : Updating param (%u) %s to %s",
            var->pos, var->name, val);

    fprintf(fhandle, RC_PARAM_TEMPLATE, var->name, val);
    return;
}

/* * */
static void
add_multiple_vars_to_rc(FILE* rc, fko_cli_options_t *options, fko_var_bitmask_t *bitmask)
{
    short ndx = 0;      /* fko_var_array表中配置变量的索引 */
    short position;     /* 配置变量的位置 */

    for (ndx=0 ; ndx<ARRAY_SIZE(fko_var_array) ; ndx++)
    {
        position = fko_var_array[ndx].pos;
        if (bitmask_has_var(position, bitmask))
            add_single_var_to_rc(rc, position, options);
    }
}

/* * */
static int
process_rc_section(char *section_name, fko_cli_options_t *options)
{
    FILE           *rc;
    int             line_num = 0, do_exit = 0;
    char            line[MAX_LINE_LEN] = {0};
    char            rcfile[MAX_PATH_LEN] = {0};
    char            curr_stanza[MAX_LINE_LEN] = {0};
    rc_file_param_t param;
    int             rc_section_found = 0;

    set_rc_file(rcfile, options);

    /* 打开rc文件进行读取，如果它不存在，则创建 */
    if ((rc = fopen(rcfile, "r")) == NULL)
    {
        if(errno == ENOENT)
        {
            if(create_fwknoprc(rcfile) != 0)
                return -1;
        }
        else
            log_msg(LOG_VERBOSITY_WARNING, "Unable to open rc file: %s: %s",
                rcfile, strerror(errno));

        return -1;
    }

    log_msg(LOG_VERBOSITY_DEBUG, "process_rc_section() : Parsing section '%s' ...",
                section_name);

    while ((fgets(line, MAX_LINE_LEN, rc)) != NULL)
    {
        line_num++;
        line[MAX_LINE_LEN-1] = '\0';

        /* 获取过去的评论和空行（注意：我们只查看 */
        if(IS_EMPTY_LINE(line[0]))
            continue;

        /* 检查我们正在处理的部分 */
        if (is_rc_section(line, strlen(line), curr_stanza, sizeof(curr_stanza)))
        {
            rc_section_found = (strcasecmp(curr_stanza, section_name) == 0) ? 1 : 0;

            if (strcasecmp(curr_stanza, options->use_rc_stanza) == 0)
                options->got_named_stanza = 1;

            continue;
        }

        /* 我们不在好地段 */
        else if (rc_section_found == 0)
            continue;

        /* 我们没有找到有效的参数 */
        else if (is_rc_param(line, &param) == 0)
        {
            do_exit = 1;  /* 我们不允许格式不正确的行 */
            break;
        }

        /* 我们有一个有效的参数 */
        else
        {
           if(parse_rc_param(options, param.name, param.val) < 0)
            {
                log_msg(LOG_VERBOSITY_WARNING,
                    "Parameter error in %s, line %i: var=%s, val=%s",
                    rcfile, line_num, param.name, param.val);
                do_exit = 1;
            }
        }
    }

    fclose(rc);

    if (do_exit)
        exit(EXIT_FAILURE);

    return 0;
}

/* * */
static void
update_rc(fko_cli_options_t *options, fko_var_bitmask_t *bitmask)
{
    FILE           *rc;
    FILE           *rc_update;
    int             rcfile_fd = -1;
    int             stanza_found = 0;
    int             stanza_updated = 0;
    char            line[MAX_LINE_LEN]   = {0};
    char            rcfile[MAX_PATH_LEN] = {0};
    char            rcfile_update[MAX_PATH_LEN] = {0};
    char            curr_stanza[MAX_LINE_LEN]   = {0};
    rc_file_param_t param;                              /* 结构，以包含一个具有其值的conf.变量名 */
    fko_var_t      *var;

    set_rc_file(rcfile, options);

    strlcpy(rcfile_update, rcfile, sizeof(rcfile_update));
    strlcat(rcfile_update, ".updated", sizeof(rcfile_update));

    /* 创建一个新的临时rc文件 */
    rcfile_fd = open(rcfile_update, FWKNOPRC_OFLAGS, FWKNOPRC_MODE);
    if (rcfile_fd == -1)
    {
        log_msg(LOG_VERBOSITY_WARNING,
                "update_rc() : Unable to create temporary rc file: %s: %s",
                rcfile_update, strerror(errno));
        return;
    }
    close(rcfile_fd);

    /* 在read和 */
    if ((rc = fopen(rcfile, "r")) == NULL)
    {
        log_msg(LOG_VERBOSITY_WARNING,
                "update_rc() : Unable to open rc file: %s: %s",
                rcfile, strerror(errno));
        return;
    }

    if ((rc_update = fopen(rcfile_update, "w")) == NULL)
    {
        log_msg(LOG_VERBOSITY_WARNING,
                "update_rc() : Unable to open rc file: %s: %s",
                rcfile_update, strerror(errno));
        fclose(rc);
        return;
    }

    /* 逐行浏览文件 */
    stanza_found = 0;
    while ((fgets(line, MAX_LINE_LEN, rc)) != NULL)
    {
        line[MAX_LINE_LEN-1] = '\0';

        /* 获取过去的评论和空行（注意：我们只查看 */
        if(IS_EMPTY_LINE(line[0]))
            continue;

        /* 如果我们找到一个部分。。。 */
        if(is_rc_section(line, strlen(line), curr_stanza, sizeof(curr_stanza)) == 1)
        {
            /* 我们已经解析了要保存的部分 */
            if (stanza_found)
            {
                log_msg(LOG_VERBOSITY_DEBUG, "update_rc() : Updating %s stanza", options->use_rc_stanza);
                add_multiple_vars_to_rc(rc_update, options, bitmask);
                fprintf(rc_update, "\n");
                stanza_found   = 0;
                stanza_updated = 1;
            }

            /* 这就是我们要找的，我们设定了诗节 */
            else if (strncasecmp(curr_stanza, options->use_rc_stanza, MAX_LINE_LEN) == 0)
                stanza_found = 1;

            /* 否则我们将禁用节 */
            else
                stanza_found = 0;
        }

        /* 如果我们正在处理节的参数 */
        else if (stanza_found)
        {
            /* 并且用户已经指定了强制选项，则无需 */
            if (options->force_save_rc_stanza)
                continue;

            /* 询问用户如何处理在 */
            else if (is_rc_param(line, &param))
            {
                if (   ((var=lookup_var_by_name(param.name)) != NULL)
                    && var_is_critical(var->pos) )
                {
                    if (ask_overwrite_var(var->name, curr_stanza))
                        continue;
                    else
                        remove_var_from_bitmask(var->pos, bitmask);
                }
                else
                    continue;
            }
            else
            {
                /* is_rc_param（）仅在存在 */
                fclose(rc);
                fclose(rc_update);
                return;
            }
        }

        /* 我们没有处理节中的任何重要变量，也没有新的 */
        else;

        /* 将行添加到新的rcfile */
        fprintf(rc_update, "%s", line);
    }

    /* 配置尚未更新 */
    if (stanza_updated == 0)
    {
        /* 但是节已经找到了，我们现在更新它。 */
        if (stanza_found == 1)
            log_msg(LOG_VERBOSITY_DEBUG, "update_rc() : Updating %s stanza",
                    options->use_rc_stanza);

        /* 否则，我们会将新设置附加到文件中 */
        else
        {
            fprintf(rc_update, "\n");
            log_msg(LOG_VERBOSITY_DEBUG, "update_rc() : Inserting new %s stanza",
                    options->use_rc_stanza);
            fprintf(rc_update, RC_SECTION_TEMPLATE, options->use_rc_stanza);
        }

        add_multiple_vars_to_rc(rc_update, options, bitmask);
    }

    /* 否则我们已经做了所有的事情。没事可做。 */
    else;

    /* 关闭文件句柄 */
    fclose(rc);
    fclose(rc_update);

    /* 将临时文件重命名为新的rc文件 */
    if (remove(rcfile) != 0)
    {
        log_msg(LOG_VERBOSITY_WARNING,
                "update_rc() : Unable to remove %s to %s : %s",
                rcfile_update, rcfile, strerror(errno));
    }

    if (rename(rcfile_update, rcfile) != 0)
    {
        log_msg(LOG_VERBOSITY_WARNING,
                "update_rc() : Unable to rename %s to %s",
                rcfile_update, rcfile);
    }
}

/* 各种选项的健康度和边界检查。 */
static void
validate_options(fko_cli_options_t *options)
{
    if ( (options->use_rc_stanza[0] != 0x0)
        && (options->got_named_stanza == 0)
        && (options->save_rc_stanza == 0) )
    {
        log_msg(LOG_VERBOSITY_ERROR,
                "Named configuration stanza: [%s] was not found.",
                options->use_rc_stanza);
        exit(EXIT_FAILURE);
    }

    if ( (options->save_rc_stanza == 1)  && (options->use_rc_stanza[0] == 0) )
    {
        /* 将节名称设置为-D arg值 */
        if (options->spa_server_str[0] == 0x0)
        {
            log_msg(LOG_VERBOSITY_ERROR,
                "Must use --destination unless --test mode is used");
            exit(EXIT_FAILURE);
        }

        strlcpy(options->use_rc_stanza, options->spa_server_str, sizeof(options->use_rc_stanza));
    }

    /* 必须有目的地，除非我们只是在测试或获取 */
    if(!options->test
        && !options->key_gen
        && !options->version
        && !options->show_last_command
        && !options->run_last_command)
    {
        if (options->spa_server_str[0] == 0x0)
        {
            log_msg(LOG_VERBOSITY_ERROR,
                "Must use --destination unless --test mode is used");
            exit(EXIT_FAILURE);
        }

        if (options->resolve_url != NULL)
            options->resolve_ip_http_https = 1;

        if (!options->resolve_ip_http_https)
        {
            if(options->allow_ip_str[0] == 0x0)
            {
                log_msg(LOG_VERBOSITY_ERROR,
                    "Must use one of [-s|-R|-a] to specify IP for SPA access.");
                exit(EXIT_FAILURE);
            }
            else if(options->verbose
                    && strncmp(options->allow_ip_str, "0.0.0.0", strlen("0.0.0.0")) == 0)
            {
                log_msg(LOG_VERBOSITY_WARNING,
                    "[-] WARNING: Should use -a or -R to harden SPA against potential MITM attacks");
            }
        }
    }

    /* 确保-a覆盖IP解析 */
    if(options->allow_ip_str[0] != 0x0
            && strncasecmp(options->allow_ip_str, "resolve", strlen("resolve")) != 0)
    {
        options->resolve_ip_http_https = 0;

        if(! is_valid_ipv4_addr(options->allow_ip_str, strlen(options->allow_ip_str)))
        {
            log_msg(LOG_VERBOSITY_ERROR,
                "Invalid allow IP specified for SPA access");
            exit(EXIT_FAILURE);
        }
    }

    if (options->spoof_ip_src_str[0] != 0x00)
    {
        if(! is_valid_ipv4_addr(options->spoof_ip_src_str, strlen(options->spoof_ip_src_str)))
        {
            log_msg(LOG_VERBOSITY_ERROR, "Invalid spoof IP");
            exit(EXIT_FAILURE);
        }
        if(options->spa_proto != FKO_PROTO_TCP_RAW
                && options->spa_proto != FKO_PROTO_UDP_RAW
                && options->spa_proto != FKO_PROTO_ICMP)
        {
            log_msg(LOG_VERBOSITY_ERROR,
                    "Must set -P <udpraw|tcpraw|icmp> with a spoofed source IP");
            exit(EXIT_FAILURE);
        }
    }

    if(options->resolve_ip_http_https || options->spa_proto == FKO_PROTO_HTTP)
        if (options->http_user_agent[0] == '\0')
            snprintf(options->http_user_agent, HTTP_MAX_USER_AGENT_LEN,
                "%s%s", "Fwknop/", MY_VERSION);

    if(options->http_proxy[0] != 0x0 && options->spa_proto != FKO_PROTO_HTTP)
    {
        log_msg(LOG_VERBOSITY_ERROR,
            "Cannot set --http-proxy with a non-HTTP protocol.");
        exit(EXIT_FAILURE);
    }

    /* 如果我们使用gpg，我们必须至少有一个收件人集。 */
    if(options->use_gpg)
    {
        if(strlen(options->gpg_recipient_key) == 0)
        {
            log_msg(LOG_VERBOSITY_ERROR,
                "Must specify --gpg-recipient-key when GPG is used.");
            exit(EXIT_FAILURE);
        }
    }

    if(options->encryption_mode == FKO_ENC_MODE_ASYMMETRIC
            && ! options->use_gpg)
    {
        log_msg(LOG_VERBOSITY_ERROR,
            "Must specify GPG recipient/signing keys when Asymmetric encryption mode is used.");
        exit(EXIT_FAILURE);
    }

    if(options->encryption_mode == FKO_ENC_MODE_CBC_LEGACY_IV
            && options->use_hmac)
    {
        log_msg(LOG_VERBOSITY_ERROR,
            "Legacy encryption mode is incompatible with HMAC usage.");
        exit(EXIT_FAILURE);
    }

    /* 验证HMAC摘要类型 */
    if(options->use_hmac && options->hmac_type == FKO_HMAC_UNKNOWN)
        options->hmac_type = FKO_DEFAULT_HMAC_MODE;

    if(options->key_gen && options->hmac_type == FKO_HMAC_UNKNOWN)
        options->hmac_type = FKO_DEFAULT_HMAC_MODE;

    return;
}

/* 建立一些默认值，如UDP/62201，用于发送SPA */
static void
set_defaults(fko_cli_options_t *options)
{
    options->spa_proto      = FKO_DEFAULT_PROTO;
    options->spa_dst_port   = FKO_DEFAULT_PORT;
    options->fw_timeout     = -1;

    options->key_len        = FKO_DEFAULT_KEY_LEN;
    options->hmac_key_len   = FKO_DEFAULT_HMAC_KEY_LEN;
    options->hmac_type      = FKO_HMAC_UNKNOWN;  /* 使用HMAC密钥时更新 */

    options->spa_icmp_type  = ICMP_ECHOREPLY;  /* 仅用于“-P icmp”模式 */
    options->spa_icmp_code  = 0;               /* 仅用于“-P icmp”模式 */

    options->input_fd       = FD_INVALID;

    return;
}

/* 通过配置文件和/或命令行初始化程序配置 */
//这个函数是用来初始化配置文件的
void
config_init(fko_cli_options_t *options, int argc, char **argv)
{
    int                 cmd_arg, index, is_err, rlen=0;
    fko_var_bitmask_t   var_bitmask;
    char                rcfile[MAX_PATH_LEN] = {0};

    /* 清零选项、opts_track和bitmask。 */
   //初始化

    memset(options, 0x00, sizeof(fko_cli_options_t));
    memset(&var_bitmask, 0x00, sizeof(fko_var_bitmask_t));

    /* 确保设置了一些合理的默认值 */
   //设置一些默认值
    set_defaults(options);

    /* 首先传递cmd_line参数，查看 */
   //第一次遍历命令行参数，看看是否使用了配置文件中的命名段
    while ((cmd_arg = getopt_long(argc, argv,
            GETOPTS_OPTION_STRING, cmd_opts, &index)) != -1) {
        switch(cmd_arg) {
            case 'h':
                usage();
                exit(EXIT_SUCCESS);
            case NO_SAVE_ARGS:
                options->no_save_args = 1;
                break;
            case 'n':
                strlcpy(options->use_rc_stanza, optarg, sizeof(options->use_rc_stanza));
                break;
            case NO_HOME_DIR:
                options->no_home_dir = 1;
                break;
            case NO_RC_FILE:
                options->no_rc_file = 1;
                break;
            case SAVE_RC_STANZA:
                options->save_rc_stanza = 1;
                break;
            case STANZA_LIST:
                options->stanza_list = 1;
                break;
            case 'E':
                strlcpy(options->args_save_file, optarg, sizeof(options->args_save_file));
                break;
            case RC_FILE_PATH:
                strlcpy(options->rc_file, optarg, sizeof(options->rc_file));
                break;
            case 'v':
                options->verbose++;
                add_var_to_bitmask(FWKNOP_CLI_ARG_VERBOSE, &var_bitmask);
                break;
        }
    }

    /* 更新日志模块的详细级别 */
    log_set_verbosity(LOG_DEFAULT_VERBOSITY + options->verbose);

    if(options->no_rc_file)
    {
        if(options->save_rc_stanza)
        {
            log_msg(LOG_VERBOSITY_ERROR,
                    "Cannot save an rc stanza in --no-rc-file mode.");
            exit(EXIT_FAILURE);
        }
        if (options->use_rc_stanza[0] != 0x0)
        {
            log_msg(LOG_VERBOSITY_ERROR,
                    "Cannot set stanza name in --no-rc-file mode.");
            exit(EXIT_FAILURE);
        }
        if (options->stanza_list)
        {
            log_msg(LOG_VERBOSITY_ERROR,
                    "Cannot list stanzas in --no-rc-file mode.");
            exit(EXIT_FAILURE);
        }
    }
    else
    {
        /* 从rc文件转储配置的节 */
        if (options->stanza_list == 1)
        {
            set_rc_file(rcfile, options);
            exit(dump_configured_stanzas_from_rcfile(rcfile));
        }

        /* 首先处理.fwknprc文件。 */
        process_rc_section(RC_SECTION_DEFAULT, options);

        /* 从.fwknprc文件加载用户指定的节 */
        if ( (options->got_named_stanza) && (options->save_rc_stanza == 0) )
            process_rc_section(options->use_rc_stanza, options);
    }

    /* 重置选项索引，以便我们可以再次浏览它们。 */
    optind = 0;

    while ((cmd_arg = getopt_long(argc, argv,
            GETOPTS_OPTION_STRING, cmd_opts, &index)) != -1) {

        switch(cmd_arg) {
            case 'a':
                strlcpy(options->allow_ip_str, optarg, sizeof(options->allow_ip_str));
                add_var_to_bitmask(FWKNOP_CLI_ARG_ALLOW_IP, &var_bitmask);
                break;
            case 'A':
                strlcpy(options->access_str, optarg, sizeof(options->access_str));
                add_var_to_bitmask(FWKNOP_CLI_ARG_ACCESS, &var_bitmask);
                break;
            case 'b':
                options->save_packet_file_append = 1;
                break;
            case 'B':
                strlcpy(options->save_packet_file, optarg, sizeof(options->save_packet_file));
                break;
            case 'C':
                strlcpy(options->server_command, optarg, sizeof(options->server_command));
                break;
            case 'D':
                strlcpy(options->spa_server_str, optarg, sizeof(options->spa_server_str));
                add_var_to_bitmask(FWKNOP_CLI_ARG_SPA_SERVER, &var_bitmask);
                break;
            case 'E':
                strlcpy(options->args_save_file, optarg, sizeof(options->args_save_file));
                break;
            case 'f':
                options->fw_timeout = strtol_wrapper(optarg, 0,
                        (2 << 16), NO_EXIT_UPON_ERR, &is_err);
                if(is_err != FKO_SUCCESS)
                {
                    log_msg(LOG_VERBOSITY_ERROR, "--fw-timeout must be within [%d-%d]",
                            0, (2 << 16));
                    exit(EXIT_FAILURE);
                }
                add_var_to_bitmask(FWKNOP_CLI_ARG_FW_TIMEOUT, &var_bitmask);
                break;
            case FAULT_INJECTION_TAG:
#if HAVE_LIBFIU
                strlcpy(options->fault_injection_tag, optarg, sizeof(options->fault_injection_tag));
#else
                log_msg(LOG_VERBOSITY_ERROR,
                    "fwknop not compiled with fault injection support.", optarg);
                exit(EXIT_FAILURE);
#endif
                break;
            case 'g':
            case GPG_ENCRYPTION:
                options->use_gpg = 1;
                add_var_to_bitmask(FWKNOP_CLI_ARG_USE_GPG, &var_bitmask);
                break;
            case 'G':
                strlcpy(options->get_key_file, optarg, sizeof(options->get_key_file));
                add_var_to_bitmask(FWKNOP_CLI_ARG_KEY_FILE, &var_bitmask);
                break;
            case GET_HMAC_KEY:
                strlcpy(options->get_hmac_key_file, optarg,
                    sizeof(options->get_hmac_key_file));
                options->use_hmac = 1;
                add_var_to_bitmask(FWKNOP_CLI_ARG_HMAC_KEY_FILE, &var_bitmask);
                break;
            case 'H':
                options->spa_proto = FKO_PROTO_HTTP;
                strlcpy(options->http_proxy, optarg, sizeof(options->http_proxy));
                break;
            case 'k':
                options->key_gen = 1;
                break;
            case 'K':
                options->key_gen = 1;
                strlcpy(options->key_gen_file, optarg, sizeof(options->key_gen_file));
                break;
            case KEY_RIJNDAEL:
                strlcpy(options->key, optarg, sizeof(options->key));
                options->have_key = 1;
                add_var_to_bitmask(FWKNOP_CLI_ARG_KEY_RIJNDAEL, &var_bitmask);
                break;
            case KEY_RIJNDAEL_BASE64:
                if (! is_base64((unsigned char *) optarg, strlen(optarg)))
                {
                    log_msg(LOG_VERBOSITY_ERROR,
                        "Base64 encoded Rijndael argument '%s' doesn't look like base64-encoded data.",
                        optarg);
                    exit(EXIT_FAILURE);
                }
                strlcpy(options->key_base64, optarg, sizeof(options->key_base64));
                options->have_base64_key = 1;
                add_var_to_bitmask(FWKNOP_CLI_ARG_KEY_RIJNDAEL_BASE64, &var_bitmask);
                break;
            case KEY_HMAC_BASE64:
                if (! is_base64((unsigned char *) optarg, strlen(optarg)))
                {
                    log_msg(LOG_VERBOSITY_ERROR,
                        "Base64 encoded HMAC argument '%s' doesn't look like base64-encoded data.",
                        optarg);
                    exit(EXIT_FAILURE);
                }
                strlcpy(options->hmac_key_base64, optarg, sizeof(options->hmac_key_base64));
                options->have_hmac_base64_key = 1;
                options->use_hmac = 1;
                add_var_to_bitmask(FWKNOP_CLI_ARG_KEY_HMAC_BASE64, &var_bitmask);
                add_var_to_bitmask(FWKNOP_CLI_ARG_USE_HMAC, &var_bitmask);
                break;
            case KEY_HMAC:
                strlcpy(options->hmac_key, optarg, sizeof(options->hmac_key));
                options->have_hmac_key = 1;
                options->use_hmac = 1;
                add_var_to_bitmask(FWKNOP_CLI_ARG_KEY_HMAC, &var_bitmask);
                add_var_to_bitmask(FWKNOP_CLI_ARG_USE_HMAC, &var_bitmask);
                break;
            case KEY_LEN:
                options->key_len = strtol_wrapper(optarg, 1,
                        MAX_KEY_LEN, NO_EXIT_UPON_ERR, &is_err);
                if(is_err != FKO_SUCCESS)
                {
                    log_msg(LOG_VERBOSITY_ERROR,
                            "Invalid key length '%s', must be in [%d-%d]",
                            optarg, 1, MAX_KEY_LEN);
                    exit(EXIT_FAILURE);
                }
                break;
            case HMAC_DIGEST_TYPE:
                if((options->hmac_type = hmac_digest_strtoint(optarg)) < 0)
                {
                    log_msg(LOG_VERBOSITY_ERROR,
                        "* Invalid hmac digest type: %s, use {md5,sha1,sha256,sha384,sha512,sha3_256,sha3_512}",
                        optarg);
                    exit(EXIT_FAILURE);
                }
                add_var_to_bitmask(FWKNOP_CLI_ARG_HMAC_DIGEST_TYPE, &var_bitmask);
                add_var_to_bitmask(FWKNOP_CLI_ARG_USE_HMAC, &var_bitmask);
                options->use_hmac = 1;
                break;
            case HMAC_KEY_LEN:
                options->hmac_key_len = strtol_wrapper(optarg, 1,
                        MAX_KEY_LEN, NO_EXIT_UPON_ERR, &is_err);
                if(is_err != FKO_SUCCESS)
                {
                    log_msg(LOG_VERBOSITY_ERROR,
                            "Invalid hmac key length '%s', must be in [%d-%d]",
                            optarg, 1, MAX_KEY_LEN);
                    exit(EXIT_FAILURE);
                }
                add_var_to_bitmask(FWKNOP_CLI_ARG_USE_HMAC, &var_bitmask);
                options->use_hmac = 1;
                break;
            case SPA_ICMP_TYPE:
                options->spa_icmp_type = strtol_wrapper(optarg, 0,
                        MAX_ICMP_TYPE, NO_EXIT_UPON_ERR, &is_err);
                if(is_err != FKO_SUCCESS)
                {
                    log_msg(LOG_VERBOSITY_ERROR,
                            "Invalid icmp type '%s', must be in [%d-%d]",
                            optarg, 0, MAX_ICMP_TYPE);
                    exit(EXIT_FAILURE);
                }
                break;
            case SPA_ICMP_CODE:
                options->spa_icmp_code = strtol_wrapper(optarg, 0,
                        MAX_ICMP_CODE, NO_EXIT_UPON_ERR, &is_err);
                if(is_err != FKO_SUCCESS)
                {
                    log_msg(LOG_VERBOSITY_ERROR,
                            "Invalid icmp code '%s', must be in [%d-%d]",
                            optarg, 0, MAX_ICMP_CODE);
                    exit(EXIT_FAILURE);
                }
                break;
            case 'l':
                options->run_last_command = 1;
                break;
            case 'm':
            case FKO_DIGEST_NAME:
                if((options->digest_type = digest_strtoint(optarg)) < 0)
                {
                    log_msg(LOG_VERBOSITY_ERROR,
                        "* Invalid digest type: %s, use {md5,sha1,sha256,sha384,sha512,sha3_256,sha3_512}",
                    optarg);
                    exit(EXIT_FAILURE);
                }
                add_var_to_bitmask(FWKNOP_CLI_ARG_DIGEST_TYPE, &var_bitmask);
                break;
            case 'M':
            case ENCRYPTION_MODE:
                if((options->encryption_mode = enc_mode_strtoint(optarg)) < 0)
                {
                    log_msg(LOG_VERBOSITY_ERROR,
                        "* Invalid encryption mode: %s, use {CBC,CTR,legacy,Asymmetric}",
                    optarg);
                    exit(EXIT_FAILURE);
                }
                add_var_to_bitmask(FWKNOP_CLI_ARG_ENCRYPTION_MODE, &var_bitmask);
                break;
            case NO_SAVE_ARGS:
                options->no_save_args = 1;
                add_var_to_bitmask(FWKNOP_CLI_ARG_NO_SAVE_ARGS, &var_bitmask);
                break;
            case 'n':
                /* 我们早些时候已经处理过了，所以我们在这里什么都不做 */
                break;
            case 'N':
                strlcpy(options->nat_access_str, optarg, sizeof(options->nat_access_str));
                add_var_to_bitmask(FWKNOP_CLI_ARG_NAT_ACCESS, &var_bitmask);
                break;
            case 'p':
                options->spa_dst_port = strtol_wrapper(optarg, 0,
                        MAX_PORT, EXIT_UPON_ERR, &is_err);
                add_var_to_bitmask(FWKNOP_CLI_ARG_SPA_SERVER_PORT, &var_bitmask);
                break;
            case 'P':
                if((options->spa_proto = proto_strtoint(optarg)) < 0)
                {
                    log_msg(LOG_VERBOSITY_ERROR, "Unrecognized protocol: %s", optarg);
                    exit(EXIT_FAILURE);
                }
                add_var_to_bitmask(FWKNOP_CLI_ARG_SPA_SERVER_PROTO, &var_bitmask);
                break;
            case 'Q':
                strlcpy(options->spoof_ip_src_str, optarg, sizeof(options->spoof_ip_src_str));
                add_var_to_bitmask(FWKNOP_CLI_ARG_SPOOF_SOURCE_IP, &var_bitmask);
                break;
            case RC_FILE_PATH:
                strlcpy(options->rc_file, optarg, sizeof(options->rc_file));
                break;
            case 'r':
                options->rand_port = 1;
                add_var_to_bitmask(FWKNOP_CLI_ARG_RAND_PORT, &var_bitmask);
                break;
            case 'R':
                options->resolve_ip_http_https = 1;
                add_var_to_bitmask(FWKNOP_CLI_ARG_RESOLVE_IP_HTTPS, &var_bitmask);
                break;
            case RESOLVE_HTTP_ONLY:
                options->resolve_http_only = 1;
                options->resolve_ip_http_https = 1;
                add_var_to_bitmask(FWKNOP_CLI_ARG_RESOLVE_HTTP_ONLY, &var_bitmask);
                add_var_to_bitmask(FWKNOP_CLI_ARG_RESOLVE_IP_HTTPS, &var_bitmask);
                break;
            case RESOLVE_URL:
                if(options->resolve_url != NULL)
                    free(options->resolve_url);
                rlen = strlen(optarg) + 1;
                options->resolve_url = calloc(1, rlen);
                if(options->resolve_url == NULL)
                {
                    log_msg(LOG_VERBOSITY_ERROR, "Memory allocation error for resolve URL.");
                    exit(EXIT_FAILURE);
                }
                strlcpy(options->resolve_url, optarg, rlen);
                add_var_to_bitmask(FWKNOP_CLI_ARG_RESOLVE_URL, &var_bitmask);
                break;
            case SERVER_RESOLVE_IPV4:
                options->spa_server_resolve_ipv4 = 1;
                add_var_to_bitmask(FWKNOP_CLI_ARG_SERVER_RESOLVE_IPV4, &var_bitmask);
                break;
            case 'w':
                if(options->wget_bin != NULL)
                    free(options->wget_bin);
                rlen = strlen(optarg) + 1;
                options->wget_bin = calloc(1, rlen);
                if(options->wget_bin == NULL)
                {
                    log_msg(LOG_VERBOSITY_ERROR, "Memory allocation error for resolve URL.");
                    exit(EXIT_FAILURE);
                }
                strlcpy(options->wget_bin, optarg, rlen);
                add_var_to_bitmask(FWKNOP_CLI_ARG_WGET_CMD, &var_bitmask);
                break;
            case SHOW_LAST_ARGS:
                options->show_last_command = 1;
                break;
            case 's':
                strlcpy(options->allow_ip_str, "0.0.0.0", sizeof(options->allow_ip_str));
                break;
            case 'S':
                options->spa_src_port = strtol_wrapper(optarg, 0,
                        MAX_PORT, EXIT_UPON_ERR, &is_err);
                add_var_to_bitmask(FWKNOP_CLI_ARG_SPA_SOURCE_PORT, &var_bitmask);
                break;
            case SAVE_RC_STANZA:
                /* 我们早些时候已经处理过了，所以我们在这里什么都不做 */
                break;
            case 'T':
                options->test = 1;
                break;
            case 'u':
                strlcpy(options->http_user_agent, optarg, sizeof(options->http_user_agent));
                add_var_to_bitmask(FWKNOP_CLI_ARG_HTTP_USER_AGENT, &var_bitmask);
                break;
            case 'U':
                strlcpy(options->spoof_user, optarg, sizeof(options->spoof_user));
                add_var_to_bitmask(FWKNOP_CLI_ARG_SPOOF_USER, &var_bitmask);
                break;
            case 'v':
                /* 处理得更早。 */
                break;
            case 'V':
                options->version = 1;
                break;
            case GPG_RECIP_KEY:
                options->use_gpg = 1;
                strlcpy(options->gpg_recipient_key, optarg, sizeof(options->gpg_recipient_key));
                add_var_to_bitmask(FWKNOP_CLI_ARG_USE_GPG, &var_bitmask);
                add_var_to_bitmask(FWKNOP_CLI_ARG_GPG_RECIPIENT, &var_bitmask);
                break;
            case GPG_SIGNER_KEY:
                options->use_gpg = 1;
                strlcpy(options->gpg_signer_key, optarg, sizeof(options->gpg_signer_key));
                add_var_to_bitmask(FWKNOP_CLI_ARG_USE_GPG, &var_bitmask);
                add_var_to_bitmask(FWKNOP_CLI_ARG_GPG_SIGNER, &var_bitmask);
                break;
            case GPG_HOME_DIR:
                options->use_gpg = 1;
                strlcpy(options->gpg_home_dir, optarg, sizeof(options->gpg_home_dir));
                chop_char(options->gpg_home_dir, PATH_SEP);
                add_var_to_bitmask(FWKNOP_CLI_ARG_USE_GPG, &var_bitmask);
                add_var_to_bitmask(FWKNOP_CLI_ARG_GPG_HOMEDIR, &var_bitmask);
                break;
            case GPG_EXE_PATH:
                options->use_gpg = 1;
                strlcpy(options->gpg_exe, optarg, sizeof(options->gpg_exe));
                add_var_to_bitmask(FWKNOP_CLI_ARG_USE_GPG, &var_bitmask);
                add_var_to_bitmask(FWKNOP_CLI_ARG_GPG_EXE_PATH, &var_bitmask);
                break;
            case GPG_AGENT:
                options->use_gpg = 1;
                options->use_gpg_agent = 1;
                add_var_to_bitmask(FWKNOP_CLI_ARG_USE_GPG, &var_bitmask);
                add_var_to_bitmask(FWKNOP_CLI_ARG_USE_GPG_AGENT, &var_bitmask);
                break;
            case GPG_ALLOW_NO_SIGNING_PW:
                options->use_gpg = 1;
                options->gpg_no_signing_pw = 1;
                add_var_to_bitmask(FWKNOP_CLI_ARG_USE_GPG, &var_bitmask);
                add_var_to_bitmask(FWKNOP_CLI_ARG_GPG_NO_SIGNING_PW, &var_bitmask);
                break;
            case NAT_LOCAL:
                options->nat_local = 1;
                add_var_to_bitmask(FWKNOP_CLI_ARG_NAT_LOCAL, &var_bitmask);
                break;
            case NAT_RAND_PORT:
                options->nat_rand_port = 1;
                add_var_to_bitmask(FWKNOP_CLI_ARG_NAT_RAND_PORT, &var_bitmask);
                break;
            case NAT_PORT:
                options->nat_port = strtol_wrapper(optarg, 0,
                        MAX_PORT, EXIT_UPON_ERR, &is_err);
                add_var_to_bitmask(FWKNOP_CLI_ARG_NAT_PORT, &var_bitmask);
                break;
            case NO_HOME_DIR:
                /* 我们早些时候已经处理过了，所以我们在这里什么都不做 */
                break;
            case NO_RC_FILE:
                /* 我们早些时候已经处理过了，所以我们在这里什么都不做 */
                break;
            case TIME_OFFSET_PLUS:
                if (! parse_time_offset(optarg, &options->time_offset_plus))
                {
                    log_msg(LOG_VERBOSITY_WARNING,
                        "Invalid time offset: '%s'", optarg);
                    exit(EXIT_FAILURE);
                }
                add_var_to_bitmask(FWKNOP_CLI_ARG_TIME_OFFSET, &var_bitmask);
                break;
            case TIME_OFFSET_MINUS:
                if (! parse_time_offset(optarg, &options->time_offset_minus))
                {
                    log_msg(LOG_VERBOSITY_WARNING,
                        "Invalid time offset: '%s'", optarg);
                    exit(EXIT_FAILURE);
                }
                add_var_to_bitmask(FWKNOP_CLI_ARG_TIME_OFFSET, &var_bitmask);
                break;
            case USE_HMAC:
                add_var_to_bitmask(FWKNOP_CLI_ARG_USE_HMAC, &var_bitmask);
                options->use_hmac = 1;
                break;
            case USE_WGET_USER_AGENT:
                add_var_to_bitmask(FWKNOP_CLI_ARG_USE_WGET_USER_AGENT, &var_bitmask);
                options->use_wget_user_agent = 1;
                break;
            case FORCE_SAVE_RC_STANZA:
                options->force_save_rc_stanza = 1;
                break;
            case FD_SET_STDIN:
                options->input_fd = STDIN_FILENO;
                break;
            case FD_SET_ALT:
#ifdef WIN32
                log_msg(LOG_VERBOSITY_ERROR, "Read password from FD not supported on Windows");
                exit(EXIT_FAILURE);
#endif
                options->input_fd = strtol_wrapper(optarg, 0,
                        -1, EXIT_UPON_ERR, &is_err);
                break;
            default:
                usage();
                exit(EXIT_FAILURE);
        }
    }

    /* 现在我们已经设置了所有选项，我们可以验证它们 */
    // 现在我们已经设置了所有选项，我们可以验证它们
    validate_options(options);

    /* 从/dev/random和base64编码生成Rijndael+HMAC密钥 */
   // 从/dev/random生成Rijndael + HMAC密钥并对其进行base64编码
    generate_keys(options);

    /* 我们可以使用命令上设置的参数升级设置 */
    // 我们可以通过用户在命令行上设置的参数来升级我们的设置
    if (options->save_rc_stanza == 1)
    {
        /* 如果我们被要求生成密钥，我们会将它们添加到位掩码中，这样 */
        if (options->key_gen == 1)
        {
            add_var_to_bitmask(FWKNOP_CLI_ARG_KEY_RIJNDAEL_BASE64, &var_bitmask);
            add_var_to_bitmask(FWKNOP_CLI_ARG_KEY_HMAC_BASE64, &var_bitmask);
        }
        else;

        update_rc(options, &var_bitmask);
    }
    else;

    keys_status(options);

    return;
}

/* 打印使用情况消息。。。 */
void
usage(void)
{
    log_msg(LOG_VERBOSITY_NORMAL,
            "\n%s client version %s\n%s - http://%s/fwknop/\n",
            MY_NAME, MY_VERSION, MY_DESC, HTTP_RESOLVE_HOST);
    /* 中文的日志解释 */
    log_msg(LOG_VERBOSITY_NORMAL,
      "Usage: fwknop -A <port list> [-s|-R|-a] -D <spa_server> [options]\n\n"
      " -n, --named-config          Specify a named configuration stanza in the\n"
      "                             '$HOME/.fwknoprc' file to provide some of all\n"
      "                             of the configuration parameters.\n"
      "                             If more arguments are set through the command\n"
      "                             line, the configuration is updated accordingly.\n"
      " -A, --access                Provide a list of ports/protocols to open\n"
      "                             on the server (e.g. 'tcp/22').\n"
      " -a, --allow-ip              Specify IP address to allow within the SPA\n"
      "                             packet (e.g. '123.2.3.4').\n"
      " -D, --destination           Specify the hostname or IP address of the\n"
      "                             fwknop server.\n"
      " --use-hmac                  Add an HMAC to the outbound SPA packet for\n"
      "                             authenticated encryption.\n"
      " -h, --help                  Print this usage message and exit.\n"
      " -B, --save-packet           Save the generated packet data to the\n"
      "                             specified file.\n"
      " -b, --save-packet-append    Append the generated packet data to the\n"
      "                             file specified with the -B option.\n"
      " -C, --server-cmd            Specify a command that the fwknop server will\n"
      "                             execute on behalf of the fwknop client..\n"
      " -N, --nat-access            Gain NAT access to an internal service.\n"
      " -p, --server-port           Set the destination port for outgoing SPA\n"
      "                             packet.\n"
      " -P, --server-proto          Set the protocol (udp, tcp, http, tcpraw,\n"
      "                             icmp) for the outgoing SPA packet.\n"
      "                             Note: The 'tcpraw' and 'icmp' modes use raw\n"
      "                             sockets and thus require root access to use.\n"
      " -s, --source-ip             Tell the fwknopd server to accept whatever\n"
      "                             source IP the SPA packet has as the IP that\n"
      "                             needs access (not recommended, and the\n"
      "                             fwknopd server can ignore such requests).\n"
      " -S, --source-port           Set the source port for outgoing SPA packet.\n"
      " -Q, --spoof-source          Set the source IP for outgoing SPA packet.\n"
      " -R, --resolve-ip-https      Resolve the external network IP by\n"
      "                             connecting to a URL such as the default of:\n"
      "                             https://" HTTP_RESOLVE_HOST HTTP_RESOLVE_URL "\n"
      "                             with wget in --secure-protocol mode (SSL).\n"
      "                             The URL can be overridden with the\n"
      "                             --resolve-url option.\n"
      "     --resolve-http-only     Force external IP resolution via HTTP instead\n"
      "                             HTTPS (via the URL mentioned above). This is\n"
      "                             not recommended since it would open fwknop\n"
      "                             to potential MITM attacks if the IP resolution\n"
      "                             HTTP connection is altered en-route by a third\n"
      "                             party.\n"
      "     --resolve-url           Override the default URL used for resolving\n"
      "                             the source IP address.\n"
      " -u, --user-agent            Set the HTTP User-Agent for resolving the\n"
      "                             external IP via -R, or for sending SPA\n"
      "                             packets over HTTP. The default is\n"
      "                             Fwknop/<version> if this option is not used.\n"
      "     --use-wget-user-agent   Use the default wget User-Agent string instead\n"
      "                             of Fwknop/<version>.\n"
      " -w, --wget-cmd              Manually set the path to wget in -R mode.\n"
      " -H, --http-proxy            Specify an HTTP proxy host through which the\n"
      "                             SPA packet will be sent.  The port can also be\n"
      "                             specified here by following the host/ip with\n"
      "                             \":<port>\".\n"
      " -U, --spoof-user            Set the username within outgoing SPA packet.\n"
      " -l, --last-cmd              Run the fwknop client with the same command\n"
      "                             line args as the last time it was executed\n"
      "                             (args are read from the ~/.fwknop.run file).\n"
      " -G, --get-key               Load an encryption key/password from a file.\n"
      "     --stdin                 Read the encryption key/password from stdin.\n"
      "     --fd                    Specify the file descriptor to read the\n"
      "                             encryption key/password from.\n"
      " -k, --key-gen               Generate SPA Rijndael + HMAC keys.\n"
      " -K, --key-gen-file          Write generated Rijndael + HMAC keys to a\n"
      "                             file.\n"
      "     --key-rijndael          Specify the Rijndael key. Since the password is\n"
      "                             visible to utilities (like 'ps' under Unix)\n"
      "                             this form should only be used where security is\n"
      "                             not important.\n"
      "     --key-base64-rijndael   Specify the base64 encoded Rijndael key. Since\n"
      "                             the password is visible to utilities (like 'ps'\n"
      "                             under Unix) this form should only be used where\n"
      "                             security is not important.\n"
      "     --key-base64-hmac       Specify the base64 encoded HMAC key. Since the\n"
      "                             password is visible to utilities (like 'ps'\n"
      "                             under Unix) this form should only be used where\n"
      "                             security is not important.\n"
      " -r, --rand-port             Send the SPA packet over a randomly assigned\n"
      "                             port (requires a broader pcap filter on the\n"
      "                             server side than the default of udp 62201).\n"
      " -T, --test                  Build the SPA packet but do not send it over\n"
      "                             the network.\n"
      " -v, --verbose               Set verbose mode (may specify multiple times).\n"
      " -V, --version               Print version number.\n"
      " -m, --digest-type           Specify the message digest algorithm to use.\n"
      "                             (md5, sha1, sha256, sha384, or sha512). The\n"
      "                             default is sha256.\n"
      " -M, --encryption-mode       Specify the encryption mode when AES is used\n"
      "                             for encrypting SPA packets.The default is CBC\n"
      "                             mode, but others can be chosen such as CFB or\n"
      "                             OFB as long as this is also specified in the\n"
      "                             access.conf file on the server side. Note that\n"
      "                             the string ``legacy'' can be specified in order\n"
      "                             to generate SPA packets with the old initialization\n"
      "                             vector strategy used by versions of *fwknop*\n"
      "                             before 2.5.\n"
      " -f, --fw-timeout            Specify SPA server firewall timeout from the\n"
      "                             client side.\n"
      "     --hmac-digest-type      Set the HMAC digest algorithm (default is\n"
      "                             sha256). Options are md5, sha1, sha256,\n"
      "                             sha384, or sha512.\n"
      "     --icmp-type             Set the ICMP type (used with '-P icmp').\n"
      "     --icmp-code             Set the ICMP code (used with '-P icmp').\n"
      "     --gpg-encryption        Use GPG encryption (default is Rijndael).\n"
      "     --gpg-recipient-key     Specify the recipient GPG key name or ID.\n"
      "     --gpg-signer-key        Specify the signer's GPG key name or ID.\n"
      "     --gpg-no-signing-pw     Allow no signing password if none associated\n"
      "                             with GPG key.\n"
      "     --gpg-home-dir          Specify the GPG home directory.\n"
      "     --gpg-agent             Use GPG agent if available.\n"
      "     --gpg-exe               Set path to GPG binary.\n"
      "     --no-save-args          Do not save fwknop command line args to the\n"
      "                             $HOME/fwknop.run file.\n"
      "     --rc-file               Specify path to the fwknop rc file (default\n"
      "                             is $HOME/.fwknoprc).\n"
      "     --server-resolve-ipv4   Force IPv4 address resolution from DNS for\n"
      "                             SPA server when using a hostname.\n"
      "     --save-rc-stanza        Save command line arguments to the\n"
      "                             $HOME/.fwknoprc stanza specified with the\n"
      "                             -n option.\n"
      "     --force-stanza          Used with --save-rc-stanza to overwrite all of\n"
      "                             the variables for the specified stanza.\n"
      "     --stanza-list           Dump a list of the stanzas found in\n"
      "                             $HOME/.fwknoprc.\n"
      "     --nat-local             Access a local service via a forwarded port\n"
      "                             on the fwknopd server system.\n"
      "     --nat-port              Specify the port to forward to access a\n"
      "                             service via NAT.\n"
      "     --nat-rand-port         Have the fwknop client assign a random port\n"
      "                             for NAT access.\n"
      "     --no-home-dir           Do not allow the fwknop client to look for\n"
      "                             the user home directory.\n"
      "     --no-rc-file            Perform fwknop client operations without\n"
      "                             referencing a ~/.fwknoprc file.\n"
      "     --show-last             Show the last fwknop command line arguments.\n"
      "     --time-offset-plus      Add time to outgoing SPA packet timestamp.\n"
      "     --time-offset-minus     Subtract time from outgoing SPA packet\n"
      "                             timestamp.\n"
    );

    return;
}

