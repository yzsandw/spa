/**
 * \file server/extcmd.c
 *
 * \brief 用于执行和处理外部命令的例程。
 */

#include "fwknopd_common.h"
#include "extcmd.h"
#include "log_msg.h"
#include "utils.h"

#include <errno.h>
#include <signal.h>

#if HAVE_SYS_WAIT_H
  #include <sys/wait.h>
#endif

/*
静态sig_atomic_t got_sigarm；
*/

/* 获取文件描述符并使其成为非阻塞的。
static int
set_nonblock(int fd)
{
    int val;

    if((val = fcntl(fd, F_GETFL, 0)) < 0)
    {
        perror("fcntl F_GETFL error:");
        return(-1);
    }

    val |= O_NONBLOCK;

    if(fcntl(fd, F_SETFL, val) < 0)
    {
        perror("fcntl F_SETFL error setting O_NONBLOCK");
        return(-1);
    }

    return(0);
}

static void 
alarm_handler(int sig)
{
    got_sigalrm = 1;
}
*/

static void
copy_or_search(char *so_read_buf, char *so_buf, const size_t so_buf_sz,
        const char *substr_search, const int cflag, int *found_str,
        int *do_break)
{
    if(so_buf != NULL)
    {
        if(cflag & WANT_STDOUT_GETLINE)
        {
            memset(so_buf, 0x0, so_buf_sz);
            strlcpy(so_buf, so_read_buf, so_buf_sz);
        }
        else
        {
            strlcat(so_buf, so_read_buf, so_buf_sz);
            if(strlen(so_buf) >= so_buf_sz-1)
                *do_break = 1;
        }
    }

    if(substr_search != NULL) /* we are looking for a substring */
    {
        /* 在so_read_buf中搜索当前行，而不是在so_buf（此时末尾可能包含部分行）中搜索。
         */
        if(!IS_EMPTY_LINE(so_read_buf[0])
                && strstr(so_read_buf, substr_search) != NULL)
        {
            *found_str = 1;
            *do_break = 1;
        }
    }
    return;
}

/* 运行一个返回退出状态的外部命令，并可以选择用STDOUT输出填充提供的缓冲区，直到提供的大小为止。
 *
 * 注：我们目前没有使用timeout参数。我们仍然需要实现可靠的超时机制。
*/
static int
_run_extcmd(uid_t uid, gid_t gid, const char *cmd, char *so_buf,
        const size_t so_buf_sz, const int cflag, const int timeout,
        const char *substr_search, int *pid_status,
        const fko_srv_options_t * const opts)
{
    char    so_read_buf[IO_READ_BUF_LEN] = {0};
    pid_t   pid=0;
    FILE   *output;
    int     retval = EXTCMD_SUCCESS_ALL_OUTPUT;
    int     line_ctr = 0, found_str = 0, do_break = 0;
    int     es = 0;

    char   *argv_new[MAX_CMDLINE_ARGS]; /* for validation and/or execvp() */
    int     argc_new=0;

#if HAVE_EXECVP
    int     pipe_fd[2];
#endif

#if AFL_FUZZING
    /* 不允许在AFL模糊模式下执行命令
    */
    return 0;
#endif

    *pid_status = 0;

    /* 即使没有execvp（），我们也会根据参数的数量来检查命令的基本有效性
    */
    memset(argv_new, 0x0, sizeof(argv_new));

    if(strtoargv(cmd, argv_new, &argc_new) != 1)
    {
        log_msg(LOG_ERR,
                "run_extcmd(): Error converting cmd str to argv via strtoargv()");
        return EXTCMD_ARGV_ERROR;
    }

#if !HAVE_EXECVP
    /* 如果我们不使用execvp（），则无条件释放argvnew，因为它仅用于验证
    */
    free_argv(argv_new, &argc_new);
#endif

#if HAVE_EXECVP
    if(opts->verbose > 1)
        log_msg(LOG_INFO, "run_extcmd() (with execvp()): running CMD: %s", cmd);

    if(so_buf != NULL || substr_search != NULL)
    {
        if(pipe(pipe_fd) < 0)
        {
            log_msg(LOG_ERR, "run_extcmd(): pipe() failed: %s", strerror(errno));
            free_argv(argv_new, &argc_new);
            return EXTCMD_PIPE_ERROR;
        }
    }

    pid = fork();
    if (pid == 0)
    {
        if(chdir("/") != 0)
            exit(EXTCMD_CHDIR_ERROR);

        if(so_buf != NULL || substr_search != NULL)
        {
            close(pipe_fd[0]);
            dup2(pipe_fd[1], STDOUT_FILENO);
            if(cflag & WANT_STDERR)
                dup2(pipe_fd[1], STDERR_FILENO);
            else
                close(STDERR_FILENO);
        }

        /* 在运行该命令之前，请注意gid/uid设置。
        */
        if(gid > 0)
            if(setgid(gid) < 0)
                exit(EXTCMD_SETGID_ERROR);

        if(uid > 0)
            if(setuid(uid) < 0)
                exit(EXTCMD_SETUID_ERROR);

        /* 不要使用env
        */
        es = execvp(argv_new[0], argv_new);

        if(es == -1)
            log_msg(LOG_ERR, "run_extcmd(): execvp() failed: %s", strerror(errno));

        /* 只有当execvp（）出现问题时，我们才会在这里执行，
        *  所以在这里exit（）是为了不让另一个fwknopd进程在fork（）之后运行。
        */
        exit(es);
    }
    else if(pid == -1)
    {
        log_msg(LOG_ERR, "run_extcmd(): fork() failed: %s", strerror(errno));
        free_argv(argv_new, &argc_new);
        return EXTCMD_FORK_ERROR;
    }

    /* 只有父进程才能到达此处
    */
    if(so_buf != NULL || substr_search != NULL)
    {
        close(pipe_fd[1]);
        if ((output = fdopen(pipe_fd[0], "r")) != NULL)
        {
            if(so_buf != NULL)
                memset(so_buf, 0x0, so_buf_sz);

            while((fgets(so_read_buf, IO_READ_BUF_LEN, output)) != NULL)
            {
                line_ctr++;

                copy_or_search(so_read_buf, so_buf, so_buf_sz,
                        substr_search, cflag, &found_str, &do_break);

                if(do_break)
                    break;
            }
            fclose(output);

            /* 确保我们只有完整的线路
            */
            if(!(cflag & ALLOW_PARTIAL_LINES))
                truncate_partial_line(so_buf);
        }
        else
        {
            log_msg(LOG_ERR,
                    "run_extcmd(): could not fdopen() pipe output file descriptor.");
            free_argv(argv_new, &argc_new);
            return EXTCMD_OPEN_ERROR;
        }
    }

    free_argv(argv_new, &argc_new);

    waitpid(pid, pid_status, 0);

#else

    if(opts->verbose > 1)
        log_msg(LOG_INFO, "run_extcmd() (without execvp()): running CMD: %s", cmd);

    if(so_buf == NULL && substr_search == NULL)
    {
        /* 由于我们不必捕获输出，我们将在这里分叉（如果我们也以另一个用户的身份运行，我们无论如何都必须这样做）
         * */
        pid = fork();
        if(pid == -1)
        {
            log_msg(LOG_ERR, "run_extcmd: fork failed: %s", strerror(errno));
            return(EXTCMD_FORK_ERROR);
        }
        else if (pid == 0)
        {

            if(chdir("/") != 0)
                exit(EXTCMD_CHDIR_ERROR);

            /* 在运行该命令之前，请注意gid/uid设置。
            */
            if(gid > 0)
                if(setgid(gid) < 0)
                    exit(EXTCMD_SETGID_ERROR);

            if(uid > 0)
                if(setuid(uid) < 0)
                    exit(EXTCMD_SETUID_ERROR);

            *pid_status = system(cmd);
            exit(*pid_status);
        }
        /* Retval被强制为0，因为我们不关心子进程的退出状态（目前）
        */
        retval = EXTCMD_SUCCESS_ALL_OUTPUT;
    }
    else
    {
        /* 寻找输出使用popen和填充缓冲区的限制。
         */
        output = popen(cmd, "r");
        if(output == NULL)
        {
            log_msg(LOG_ERR, "Got popen error %i: %s", errno, strerror(errno));
            retval = EXTCMD_OPEN_ERROR;
        }
        else
        {
            if(so_buf != NULL)
                memset(so_buf, 0x0, so_buf_sz);

            while((fgets(so_read_buf, IO_READ_BUF_LEN, output)) != NULL)
            {
                line_ctr++;

                copy_or_search(so_read_buf, so_buf, so_buf_sz,
                        substr_search, cflag, &found_str, &do_break);

                if(do_break)
                    break;
            }
            pclose(output);

            /* 确保我们只有完整的线路
            */
            if(!(cflag & ALLOW_PARTIAL_LINES))
                truncate_partial_line(so_buf);
        }
    }

#endif

    if(substr_search != NULL)
    {
        /* 返回值的语义在搜索模式中更改为找到子字符串匹配的行号，如果没有找到，则为零
        */
        if(found_str)
            retval = line_ctr;
        else
            retval = 0;
    }
    else
    {
        if(WIFEXITED(*pid_status))
        {
            /*即使子进程在出现错误的情况下退出，如果我们在这里成功，
            * 那么就操作系统而言，子进程也会正常退出（即没有崩溃或被信号击中）
            */
            retval = EXTCMD_SUCCESS_ALL_OUTPUT;
        }
        else
            retval = EXTCMD_EXECUTION_ERROR;
    }

    if(opts->verbose > 1)
        log_msg(LOG_INFO,
            "run_extcmd(): returning %d, pid_status: %d",
            retval, WIFEXITED(*pid_status) ? WEXITSTATUS(*pid_status) : *pid_status);

    return(retval);
}


#if 0 /* --DSS—在某些系统上不起作用的原始方法 */

    /* 创建用于从子进程获取stdout和stderr的管道。
    */
    if(pipe(so) != 0)
        return(EXTCMD_PIPE_ERROR);

    if(pipe(se) != 0)
        return(EXTCMD_PIPE_ERROR);

    /* 派生一个子进程来运行命令并提供其输出。
    */
    pid = fork();
    if(pid == -1)
    {
        return(EXTCMD_FORK_ERROR);
    }
    else if (pid == 0)
    {
        /* 我们是子进程，所以我们将stdout和stderr分别复制到管道的写入端，
        *关闭管道的stdin和读取端（因为这里不需要它们）。
        *然后使用system（）运行该命令，并使用该命令的退出状态退出，
        *这样我们就可以从父级中的waitpid调用中获取它。
        */
        close(fileno(stdin));
        dup2(so[1], fileno(stdout));
        dup2(se[1], fileno(stderr));
        close(so[0]);
        close(se[0]);

        /* 如果user不为null，那么我们在运行命令之前将uid设置为该用户。
        */
        if(uid > 0)
        {
            if(setuid(uid) < 0)
            {
                exit(EXTCMD_SETUID_ERROR);
            }
        }

        /* --DSS 现在，我们使用system（）并使用外部命令exit状态退出
        */
        exit(WEXITSTATUS(system(cmd)));
    }


    /* 将退出状态的初始值设置为-1。
    */
    *status = -1;

    /* 关闭管道的写入端（我们只是在读）。
    */
    close(so[1]);
    close(se[1]);

    /* 将我们的管道设置为无堵塞
    */
    set_nonblock(so[0]);
    set_nonblock(se[0]);

    tv.tv_sec = EXTCMD_DEF_TIMEOUT;
    tv.tv_usec = 0;

    /* 初始化并设置我们的文件描述符集以进行选择。
    */
    FD_ZERO(&rfds);
    FD_ZERO(&efds);
    FD_SET(so[0], &rfds);
    FD_SET(se[0], &rfds);
    FD_SET(so[0], &efds);
    FD_SET(se[0], &efds);

    /* 从完全清除缓冲区开始。
    */
    memset(so_buf, 0x0, so_buf_sz);
    memset(se_buf, 0x0, se_buf_sz);

    /* 从子级读取stdout和stderr，直到我们得到eof、填充缓冲区或出错为止。
    */
    while(so_buf_remaining > 0 || se_buf_remaining > 0)
    {
        selval = select(8, &rfds, NULL, &efds, &tv);

        if(selval == -1)
        {
            /* 选择错误-所以杀死子进程并释放
            */
            kill(pid, SIGTERM);
            retval |= EXTCMD_SELECT_ERROR;
            break;
        }

        if(selval == 0)
        {
            /* 超时-所以杀死子进程并释放
            */
            kill(pid, SIGTERM);
            retval |= EXTCMD_EXECUTION_TIMEOUT;
            break;
        }


        bytes_read = read(so[0], so_read_buf, IO_READ_BUF_LEN);
        if(so_buf_remaining > 0)
        {
            if(bytes_read > 0)
            {
                /* 我们有数据，所以处理它。
                */
                if(bytes_read > so_buf_remaining)
                {
                    bytes_read = so_buf_remaining;
                    retval |= EXTCMD_SUCCESS_PARTIAL_STDOUT;
                }

                memcpy(so_buf, so_read_buf, bytes_read);
                so_buf += bytes_read;
                so_buf_remaining -= bytes_read;
            }
            else if(bytes_read < 0)
            {
                /*EAGAIN或EWOULDBLOCK以外的任何东西都被认为是错误的，
                * 我们在这里完成了释放，所以我们强制将buf_remaining设置为0。
                */
                if(errno != EAGAIN && errno != EWOULDBLOCK)
                {
                    retval |= EXTCMD_STDOUT_READ_ERROR;
                    so_buf_remaining = 0;
                }
            }
            else
            {
                /* 读取的字节数为0，表示文件结束。
                */
                so_buf_remaining = 0;
            }
        }
        else
            break;

        /* stderr管道
        */
        bytes_read = read(se[0], se_read_buf, IO_READ_BUF_LEN);
        if(se_buf_remaining > 0)
        {
            if(bytes_read > 0)
            {

                if(bytes_read > se_buf_remaining)
                {
                    bytes_read = se_buf_remaining;
                    retval |= EXTCMD_SUCCESS_PARTIAL_STDERR;
                }

                memcpy(se_buf, se_read_buf, bytes_read);
                se_buf += bytes_read;
                se_buf_remaining -= bytes_read;
            }
            else if(bytes_read < 0)
            {

                if(errno != EAGAIN && errno != EWOULDBLOCK)
                {
                    retval |= EXTCMD_STDERR_READ_ERROR;
                    se_buf_remaining = 0;
                }
            }
            else
            {

                se_buf_remaining = 0;
            }
        }
        else
            break;
    }

    close(so[0]);
    close(se[0]);

    /* 等待外部命令完成并捕获其退出状态。
    */
    waitpid(pid, status, 0);

    if(*status != 0)
        retval != EXTCMD_EXECUTION_ERROR;

    /* 返回此操作命令的状态。
    */
    return(retval);
}
#endif

int _run_extcmd_write(const char *cmd, const char *cmd_write, int *pid_status,
        const fko_srv_options_t * const opts)
{
    int     retval = EXTCMD_SUCCESS_ALL_OUTPUT;
    char   *argv_new[MAX_CMDLINE_ARGS]; /* for validation and/or execvp() */
    int     argc_new=0;

#if HAVE_EXECVP
    int     pipe_fd[2];
    pid_t   pid=0;
#else
    FILE       *fd = NULL;
#endif

#if AFL_FUZZING
    return 0;
#endif

    *pid_status = 0;

    /* 即使没有execvp（），我们也会根据参数的数量来检查命令的基本有效性
    */
    memset(argv_new, 0x0, sizeof(argv_new));

    if(strtoargv(cmd, argv_new, &argc_new) != 1)
    {
        log_msg(LOG_ERR,
                "run_extcmd_write(): Error converting cmd str to argv via strtoargv()");
        return EXTCMD_ARGV_ERROR;
    }

#if !HAVE_EXECVP
    /* 如果我们不使用execvp（），则无条件释放argvnew，因为它仅用于验证
    */
    free_argv(argv_new, &argc_new);
#endif

#if HAVE_EXECVP
    if(opts->verbose > 1)
        log_msg(LOG_INFO, "run_extcmd_write() (with execvp()): running CMD: %s | %s",
                cmd_write, cmd);

    if(pipe(pipe_fd) < 0)
    {
        log_msg(LOG_ERR, "run_extcmd_write(): pipe() failed: %s", strerror(errno));
        free_argv(argv_new, &argc_new);
        return EXTCMD_PIPE_ERROR;
    }

    pid = fork();
    if (pid == 0)
    {
        if(chdir("/") != 0)
            exit(EXTCMD_CHDIR_ERROR);

        close(pipe_fd[1]);
        dup2(pipe_fd[0], STDIN_FILENO);

        /* 不要使用env
        */
        execvp(argv_new[0], argv_new);
    }
    else if(pid == -1)
    {
        log_msg(LOG_ERR, "run_extcmd_write(): fork() failed: %s", strerror(errno));
        free_argv(argv_new, &argc_new);
        return EXTCMD_FORK_ERROR;
    }

    close(pipe_fd[0]);
    if(write(pipe_fd[1], cmd_write, strlen(cmd_write)) < 0)
        retval = EXTCMD_WRITE_ERROR;
    close(pipe_fd[1]);

    free_argv(argv_new, &argc_new);

    waitpid(pid, pid_status, 0);

#else
    if(opts->verbose > 1)
        log_msg(LOG_INFO, "run_extcmd_write() (without execvp()): running CMD: %s | %s",
                cmd_write, cmd);

    if ((fd = popen(cmd, "w")) == NULL)
    {
        log_msg(LOG_ERR, "Got popen error %i: %s", errno, strerror(errno));
        retval = EXTCMD_OPEN_ERROR;
    }
    else
    {
        if (fwrite(cmd_write, strlen(cmd_write), 1, fd) != 1)
        {
            log_msg(LOG_ERR, "Could not write to cmd stdin");
            retval = -1;
        }
        pclose(fd);
    }

#endif
    return retval;
}

/* _run_extcmd（）包装器，运行一个外部命令。
*/
int
run_extcmd(const char *cmd, char *so_buf, const size_t so_buf_sz,
        const int want_stderr, const int timeout, int *pid_status,
        const fko_srv_options_t * const opts)
{
    return _run_extcmd(ROOT_UID, ROOT_GID, cmd, so_buf, so_buf_sz,
            want_stderr, timeout, NULL, pid_status, opts);
}

/*_run_extcmd（）包装器，以指定用户身份运行外部命令。
*/
int
run_extcmd_as(uid_t uid, gid_t gid, const char *cmd,char *so_buf,
        const size_t so_buf_sz, const int want_stderr, const int timeout,
        int *pid_status, const fko_srv_options_t * const opts)
{
    return _run_extcmd(uid, gid, cmd, so_buf, so_buf_sz,
            want_stderr, timeout, NULL, pid_status, opts);
}

/* _run_extcmd（）包装器，搜索子字符串的命令输出。
*/
int
search_extcmd(const char *cmd, const int want_stderr, const int timeout,
        const char *substr_search, int *pid_status,
        const fko_srv_options_t * const opts)
{
    return _run_extcmd(ROOT_UID, ROOT_GID, cmd, NULL, 0, want_stderr,
            timeout, substr_search, pid_status, opts);
}

/* _run_extcmd（）包装器，搜索子字符串的命令输出并返回匹配行。
*/
int
search_extcmd_getline(const char *cmd, char *so_buf, const size_t so_buf_sz,
        const int timeout, const char *substr_search, int *pid_status,
        const fko_srv_options_t * const opts)
{
    return _run_extcmd(ROOT_UID, ROOT_GID, cmd, so_buf, so_buf_sz,
            WANT_STDERR | WANT_STDOUT_GETLINE, timeout, substr_search,
            pid_status, opts);
}

/* _run_extcmd_write（）包装器，运行期望通过stdin输入的命令
*/
int run_extcmd_write(const char *cmd, const char *cmd_write, int *pid_status,
        const fko_srv_options_t * const opts)
{
    return _run_extcmd_write(cmd, cmd_write, pid_status, opts);
}
