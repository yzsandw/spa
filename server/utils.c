#include "fwknopd_common.h"
#include "utils.h"
#include "log_msg.h"
#include "replay_cache.h"
#include "config_init.h"
#include "fw_util.h"
#include "cmd_cycle.h"

/* 基本目录/二进制文件检查（使用stat()并检查路径是目录还是可执行文件）。
*/
static int
is_valid_path(const char *path, const int file_type)
{
    if (strnlen(path, MAX_PATH_LEN) == MAX_PATH_LEN)
    {
        log_msg(LOG_ERR, "[-] 提供的路径太长");
        return (0);
    }

#if HAVE_STAT || HAVE_LSTAT
    struct stat st;

    /* 如果我们无法对给定路径进行stat，那么返回错误。
    */
  #if HAVE_LSTAT /* 优先使用lstat()而不是stat() */
    if (lstat(path, &st) != 0)
    {
        log_msg(LOG_ERR, "[-] 无法使用lstat()对路径进行stat：%s: %s",
            path, strerror(errno));
        return (0);
    }
  #else
    if (stat(path, &st) != 0)
    {
        log_msg(LOG_ERR, "[-] 无法使用stat()对路径进行stat：%s: %s",
            path, strerror(errno));
        return (0);
    }
  #endif

    if (file_type == IS_DIR)
    {
        if (!S_ISDIR(st.st_mode))
            return (0);
    }
    else if (file_type == IS_EXE)
    {
        if (!S_ISREG(st.st_mode) || !(st.st_mode & S_IXUSR))
            return (0);
    }
    else if (file_type == IS_FILE)
    {
        if (!S_ISREG(st.st_mode))
            return (0);
    }
    else
        return (0);

#endif /* HAVE_STAT || HAVE_LSTAT */

    return (1);
}

int
is_valid_dir(const char *path)
{
    return is_valid_path(path, IS_DIR);
}

int
is_valid_exe(const char *path)
{
    return is_valid_path(path, IS_EXE);
}

int
is_valid_file(const char *path)
{
    return is_valid_path(path, IS_FILE);
}

int
verify_file_perms_ownership(const char *file, int fd)
{
#if HAVE_FSTAT && HAVE_STAT
    struct stat st;

    /* fwknopd处理的每个文件都应该由用户拥有，并且权限设置为600（用户读/写）
    */
    if ((fd >= 0 && fstat(fd, &st) == 0) || stat(file, &st) == 0)
    {
        /* 确保它是一个普通文件
        */
        if (S_ISREG(st.st_mode) != 1 && S_ISLNK(st.st_mode) != 1)
        {
            log_msg(LOG_WARNING,
                "[-] 文件：%s 不是普通文件或符号链接。",
                file
            );
            return 0;
        }

        if ((st.st_mode & (S_IRWXU | S_IRWXG | S_IRWXO)) != (S_IRUSR | S_IWUSR))
        {
            log_msg(LOG_WARNING,
                "[-] 文件：%s 权限应该只有用户读/写（0600, -rw-------）",
                file
            );
            /* 当我们开始强制执行而不仅仅是警告用户时
            res = 0;
            */
        }

        if (st.st_uid != getuid())
        {
            log_msg(LOG_WARNING, "[-] 文件：%s 不是当前有效用户ID所拥有",
                file);
            /* 当我们开始强制执行而不仅仅是警告用户时
            res = 0;
            */
        }
    }
    else
    {
        /* 如果路径不存在，只需返回，但如果发生其他错误，说明有问题
        */
        if (errno != ENOENT)
        {
            log_msg(LOG_ERR, "[-] 对文件：%s 进行stat()返回：%s",
                file, strerror(errno));
            return 0;
        }
    }

#endif

    return 1;
}

void
truncate_partial_line(char *str)
{
    int i, have_newline = 0;

    if (str != NULL && str[0] != 0x0)
    {
        for (i = 0; i < strlen(str); i++)
        {
            if (str[i] == 0x0a)
            {
                have_newline = 1;
                break;
            }
        }

        /* 除非至少有一个换行符，否则不要清零任何数据
        */
        if (have_newline)
        {
            for (i = strlen(str) - 1; i > 0; i--)
            {
                if (str[i] == 0x0a)
                    break;
                str[i] = 0x0;
            }
        }
    }
    return;
}

/* 简单测试字符串是否仅包含数字
*/
int
is_digits(const char * const str)
{
    int i;
    if (str != NULL && str[0] != 0x0)
    {
        for (i = 0; i < strlen(str); i++)
        {
            if (!isdigit((int)(unsigned char)str[i]))
                return 0;
        }
    }
    return 1;
}

void
clean_exit(fko_srv_options_t *opts, unsigned int fw_cleanup_flag, unsigned int exit_status)
{
#if HAVE_LIBFIU
    if (opts->config[CONF_FAULT_INJECTION_TAG] != NULL)
    {
        fiu_disable(opts->config[CONF_FAULT_INJECTION_TAG]);
    }
#endif

    if (!opts->test && opts->enable_fw && (fw_cleanup_flag == FW_CLEANUP))
        fw_cleanup(opts);

#if USE_FILE_CACHE
    free_replay_list(opts);
#endif

    free_logging();
    free_cmd_cycle_list(opts);
    free_configs(opts);
    exit(exit_status);
}

/***EOF***/
