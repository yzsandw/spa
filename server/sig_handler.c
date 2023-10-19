#include "fwknopd_common.h"
#include "log_msg.h"
#include "sig_handler.h"

#if HAVE_SYS_WAIT_H
  #include <sys/wait.h>
#endif

sig_atomic_t got_signal     = 0;    /* 通用信号标志（中断捕获） */

sig_atomic_t got_sighup     = 0;    /* SIGHUP 标志  */
sig_atomic_t got_sigint     = 0;    /* SIGINT 标志  */
sig_atomic_t got_sigterm    = 0;    /* SIGTERM 标志 */
sig_atomic_t got_sigusr1    = 0;    /* SIGUSR1 标志 */
sig_atomic_t got_sigusr2    = 0;    /* SIGUSR2 标志 */
sig_atomic_t got_sigchld    = 0;    /* SIGCHLD 标志 */

sigset_t    *csmask;

/* SIGHUP 处理程序
*/
void
sig_handler(int sig)
{
    int o_errno;
    got_signal = sig;

    switch(sig) {
        case SIGHUP:
            got_sighup = 1;
            return;
        case SIGINT:
            got_sigint = 1;
            return;
        case SIGTERM:
            got_sigterm = 1;
            return;
        case SIGUSR1:
            got_sigusr1 = 1;
            return;
        case SIGUSR2:
            got_sigusr2 = 1;
            return;
        case SIGCHLD:
            o_errno = errno; /* 保存 errno */
            got_sigchld = 1;
            waitpid(-1, NULL, WNOHANG);
            errno = o_errno; /* 恢复 errno（以防被 waitpid 重置） */
            return;
    }
}

/* 设置信号处理程序
*/
int
set_sig_handlers(void)
{
    int                 err = 0;
    struct sigaction    act;

    /* 清除信号标志。
    */
    got_signal     = 0;
    got_sighup     = 0;
    got_sigint     = 0;
    got_sigterm    = 0;
    got_sigusr1    = 0;
    got_sigusr2    = 0;

    /* 设置处理程序
    */
    act.sa_handler = sig_handler;
    sigemptyset(&act.sa_mask);
    act.sa_flags = SA_RESTART;

    if(sigaction(SIGHUP, &act, NULL) < 0)
    {
        log_msg(LOG_ERR, "* 设置 SIGHUP 处理程序时出错：%s",
            strerror(errno));
        err++;
    }

    if(sigaction(SIGINT, &act, NULL) < 0)
    {
        log_msg(LOG_ERR, "* 设置 SIGINT 处理程序时出错：%s",
            strerror(errno));
        err++;
    }

    if(sigaction(SIGTERM, &act, NULL) < 0)
    {
        log_msg(LOG_ERR, "* 设置 SIGTERM 处理程序时出错：%s",
            strerror(errno));
        err++;
    }

    if(sigaction(SIGUSR1, &act, NULL) < 0)
    {
        log_msg(LOG_ERR, "* 设置 SIGUSR1 处理程序时出错：%s",
            strerror(errno));
        err++;
    }

    if(sigaction(SIGUSR2, &act, NULL) < 0)
    {
        log_msg(LOG_ERR, "* 设置 SIGUSR2 处理程序时出错：%s",
            strerror(errno));
        err++;
    }

    if(sigaction(SIGCHLD, &act, NULL) < 0)
    {
        log_msg(LOG_ERR, "* 设置 SIGCHLD 处理程序时出错：%s",
            strerror(errno));
        err++;
    }

    return(err);
}

int
sig_do_stop(void)
{
    /* 任何信号，除了 USR1、USR2 和 SIGCHLD，都意味着中断循环。
    */
    if(got_signal != 0)
    {
        if(got_sigint || got_sigterm || got_sighup)
        {
            return 1;
        }
        else if(got_sigusr1 || got_sigusr2)
        {
            /* 目前对这些信号不执行任何操作。
            */
            got_sigusr1 = got_sigusr2 = 0;
            got_signal = 0;
        }
        else
            got_signal = 0;
    }
    return 0;
}

/***EOF***/
