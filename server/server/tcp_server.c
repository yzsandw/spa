/**
 * \file server/tcp_server.c
 *
 * \brief 为spad生成虚拟tcp服务器。其目的是接受tcp连接，然后在第一个数据包之后丢弃它。
 */

#include "spad_common.h"
#include "tcp_server.h"
#include "log_msg.h"
#include "utils.h"
#include <errno.h>

#if HAVE_SYS_SOCKET_H
  #include <sys/socket.h>
#endif
#if HAVE_ARPA_INET_H
  #include <arpa/inet.h>
#endif
#if HAVE_NETDB
  #include <netdb.h>
#endif

#include <fcntl.h>
#include <sys/select.h>

/* 分叉并运行“虚拟”TCP服务器。返回值是子进程的PID，如果存在分叉错误，则返回-1。
*/
int
run_tcp_server(ztn_srv_options_t *opts)
{
#if !CODE_COVERAGE
    pid_t               pid, ppid;
#endif
    int                 s_sock, c_sock, sfd_flags, clen, selval;
    int                 reuse_addr = 1, rv=1;
    fd_set              sfd_set;
    struct sockaddr_in  saddr, caddr;
    struct timeval      tv;
    char                sipbuf[MAX_IPV4_STR_LEN] = {0};

    log_msg(LOG_INFO, "Kicking off TCP server to listen on port %i.",
            opts->tcpserv_port);

#if !CODE_COVERAGE
    /* 分叉子进程以运行命令并提供其输出。
    */
    pid = fork();

    /* 非零pid表示我们是父级，或者存在分叉错误。在任何一种情况下，我们都只是将该值返回给调用者。
    */
    if (pid != 0)
    {
        opts->tcp_server_pid = pid;
        return(pid);
    }

    /* 获取父PID，以便我们可以定期检查它。我们想知道它何时消失，因此我们也可以。
    */
    ppid = getppid();

    /* 我们是孩子。要做的第一件事是关闭父PID文件的副本，这样，
    *  如果父PID文件突然死亡，我们就不会持有锁，而这也不会让我们退出。
    */
    close(opts->lock_fd);
#endif

    /* 制作一个TCP服务器
    */
    if ((s_sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
    {
        log_msg(LOG_ERR, "run_tcp_server: socket() failed: %s",
            strerror(errno));
        return -1;
    }

    /* 因此，我们可以在没有TIME_WAIT问题的情况下重新绑定到它
    */
    if(setsockopt(s_sock, SOL_SOCKET, SO_REUSEADDR, &reuse_addr, sizeof(reuse_addr)) == -1)
    {
        log_msg(LOG_ERR, "run_tcp_server: setsockopt error: %s",
            strerror(errno));
        close(s_sock);
        return -1;
    }

    /* 使主套接字无阻塞，这样我们就不必一直在侦听传入的连接。
    */
    if((sfd_flags = fcntl(s_sock, F_GETFL, 0)) < 0)
    {
        log_msg(LOG_ERR, "run_tcp_server: fcntl F_GETFL error: %s",
            strerror(errno));
        close(s_sock);
        return -1;
    }

#if !CODE_COVERAGE
    sfd_flags |= O_NONBLOCK;

    if(fcntl(s_sock, F_SETFL, sfd_flags) < 0)
    {
        log_msg(LOG_ERR, "run_tcp_server: fcntl F_SETFL error setting O_NONBLOCK: %s",
            strerror(errno));
        close(s_sock);
        return -1;
    }
#endif

    /* 构建本地地址结构 */
    memset(&saddr, 0, sizeof(saddr));
    saddr.sin_family      = AF_INET;           /* Internet地址系列 */
    saddr.sin_addr.s_addr = htonl(INADDR_ANY); /* 任何传入接口 */
    saddr.sin_port        = htons(opts->tcpserv_port);  /* 本地端口 */

    /* 绑定到本地地址 */
    if (bind(s_sock, (struct sockaddr *) &saddr, sizeof(saddr)) < 0)
    {
        log_msg(LOG_ERR, "run_tcp_server: bind() failed: %s",
            strerror(errno));
        close(s_sock);

    /* 在代码覆盖率的情况下，不要在bind（）失败时死亡，因为netcat可能正在运行 */
#if CODE_COVERAGE
        return 0;
#endif
        return -1;
    }

    /* 标记套接字，使其侦听传入连接（但一次只能侦听一个）
    */
    if (listen(s_sock, 1) < 0)
    {
        log_msg(LOG_ERR, "run_tcp_server: listen() failed: %s",
            strerror(errno));
        close(s_sock);
        return -1;
    }

    FD_ZERO(&sfd_set);

    /* 现在在第一个数据包后或短时间内循环并接受和断开连接
    */
    while(1)
    {
        clen = sizeof(caddr);

        /* 初始化并设置用于选择的套接字。
        */
        FD_SET(s_sock, &sfd_set);

        /* 将选择超时设置为200毫秒。
        */
        tv.tv_sec = 0;
        tv.tv_usec = 200000;

        selval = select(s_sock+1, &sfd_set, NULL, NULL, &tv);

        if(selval == -1)
        {
 
            log_msg(LOG_ERR, "run_tcp_server: select error socket: %s",
                strerror(errno));
            rv = -1;
            break;
        }

#if !CODE_COVERAGE
        if(selval == 0)
        {

            if(kill(ppid, 0) != 0 && errno == ESRCH)
            {
                rv = -1;
                break;
            }
            continue;
        }
#endif

        if(! FD_ISSET(s_sock, &sfd_set))
            continue;

        /* 等待客户端连接
        */
        if((c_sock = accept(s_sock, (struct sockaddr *) &caddr, (socklen_t *)&clen)) < 0)
        {
            log_msg(LOG_ERR, "run_tcp_server: accept() failed: %s",
                strerror(errno));
            rv = -1;
            break;
        }

        if(opts->verbose)
        {
            memset(sipbuf, 0x0, MAX_IPV4_STR_LEN);
            inet_ntop(AF_INET, &(caddr.sin_addr.s_addr), sipbuf, MAX_IPV4_STR_LEN);
            log_msg(LOG_INFO, "tcp_server: Got TCP connection from %s.", sipbuf);
        }

        usleep(1000000);
        shutdown(c_sock, SHUT_RDWR);
        close(c_sock);

#if CODE_COVERAGE
        break;
#endif
    } /* 无限while循环 */

    close(s_sock);
    return rv;
}

/***EOF***/
