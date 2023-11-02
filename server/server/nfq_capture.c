/**
 * \file server/nfq_capture.c
 *
 * \brief 这是使用libnetfilter_queue的fwknopd的捕获例程。
 */


#include "fwknopd_common.h"
#include "nfq_capture.h"
#include "process_packet.h"
#include "sig_handler.h"
#include "fw_util.h"
#include "log_msg.h"
#include "fwknopd_errors.h"
#include "sig_handler.h"
#include "tcp_server.h"
#include <fcntl.h>
#if HAVE_SYS_WAIT_H
  #include <sys/wait.h>
#endif

#include <limits.h>
#include <linux/netfilter_ipv4.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

static int process_nfq_packet(struct nfq_q_handle *qh,
        struct nfgenmsg *nfmsg,
        struct nfq_data *nfa,
        void *data)
{
    struct nfqnl_msg_packet_hdr *ph;
    int pkt_len = 0;
    int verdict;
    unsigned char *full_packet;
    fko_srv_options_t   *opts = (fko_srv_options_t *)data;

    ph = nfq_get_msg_packet_hdr(nfa);
    if (ph) {

        /* 
          id = ntohl(ph->packet_id);
          hook = ph->hook;
          hw_proto = ph->protocol;
        */

        /* 检索数据包有效载荷。
        */
        pkt_len = nfq_get_payload(nfa, &full_packet);

        process_packet(opts, pkt_len, full_packet);

        /* 对数据包的处理决策：如果它来自输入链（NF_IP_LOCAL_IN）
        * 则假定为SPA数据包并可以被丢弃；否则，允许其继续传递。
        */
        verdict = (ph->hook == NF_IP_LOCAL_IN) ? NF_DROP : NF_ACCEPT;
        nfq_set_verdict(qh, ph->packet_id, verdict, 0, NULL);
    }
    return 0;
}


/* nfq捕获例程。
*/
int
nfq_capture(fko_srv_options_t *opts)
{
    int                 res, child_pid, fd_flags;
    int                 nfq_errcnt = 0;
    int                 pending_break = 0;
    int                 status;
    char                nfq_buf[1500];
    int                 chk_rm_all = 0;

    /* 与Netfilter相关的句柄
    */
    int                  nfq_fd;
    struct nfq_handle   *nfq_h;
    struct nfq_q_handle *nfq_qh;
    struct nfnl_handle  *nfq_nh;

    nfq_h = nfq_open();
    if (!nfq_h) {
        log_msg(LOG_ERR, "[*] nfq_open error\n");
        clean_exit(opts, FW_CLEANUP, EXIT_FAILURE);
    }

    /* 解除已存在的AF_INET下的nf_queue处理程序绑定（如果有的话）
    */
    res = nfq_unbind_pf(nfq_h, AF_INET);
    if (res < 0)  {
        log_msg(LOG_WARNING, "[*] Error during nfq_unbind_pf() error: %d\n", res);
    }

    /* 将给定的队列连接句柄绑定以处理数据包
    */
    res =  nfq_bind_pf(nfq_h, AF_INET);
    if ( res < 0) {
        log_msg(LOG_ERR, "Error during nfq_bind_pf(), error: %d\n", res);
        clean_exit(opts, FW_CLEANUP, EXIT_FAILURE);
    }

    /* Create queue
    */
    nfq_qh = nfq_create_queue(nfq_h,  atoi(opts->config[CONF_NFQ_QUEUE_NUMBER]), &process_nfq_packet, opts);
    if (!nfq_qh) {
        log_msg(LOG_ERR, "Error during nfq_create_queue()\n");
        clean_exit(opts, FW_CLEANUP, EXIT_FAILURE);
    }

    /* 设置每个排队到给定队列的数据包要复制到用户空间的数据量。
    */
    if (nfq_set_mode(nfq_qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        log_msg(LOG_ERR, "Can't set packet_copy mode\n");
        clean_exit(opts, FW_CLEANUP, EXIT_FAILURE);
    }

    /* 获取与给定队列连接句柄相关联的Netlink句柄。然后使用它来获取我们将用于接收排队数据包的文件描述符。
    */
    nfq_nh = nfq_nfnlh(nfq_h);
    nfq_fd = nfnl_fd(nfq_nh);

    /* 设置我们的nfq句柄为非阻塞模式。
     *
    */
    if((fd_flags = fcntl(nfq_fd, F_GETFL, 0)) < 0)
    {
        log_msg(LOG_ERR, "nfq_capture: fcntl F_GETFL error: %s",
            strerror(errno));
        clean_exit(opts, FW_CLEANUP, EXIT_FAILURE);
    }

    fd_flags |= O_NONBLOCK;

    if(fcntl(nfq_fd, F_SETFL, fd_flags) < 0)
    {
        log_msg(LOG_ERR, "nfq_capture: fcntl F_SETFL error setting O_NONBLOCK: %s",
            strerror(errno));
        exit(EXIT_FAILURE);
    }

    log_msg(LOG_INFO, "Starting fwknopd main event loop.");

    /* 进入我们自己编写的数据包捕获循环。
    */
    while(1)
    {
        /* 如果我们收到了SIGCHLD信号，并且它来自于TCP服务器进程，那么在这里处理它。
        */
        if(got_sigchld)
        {
            if(opts->tcp_server_pid > 0)
            {
                child_pid = waitpid(0, &status, WNOHANG);

                if(child_pid == opts->tcp_server_pid)
                {
                    if(WIFSIGNALED(status))
                        log_msg(LOG_WARNING, "TCP server got signal: %i",  WTERMSIG(status));

                    log_msg(LOG_WARNING,
                        "TCP server exited with status of %i. Attempting restart.",
                        WEXITSTATUS(status)
                    );

                    opts->tcp_server_pid = 0;

                    /* 尝试重新启动TCP服务器吗？ */
                    usleep(1000000);
                    run_tcp_server(opts);
                }
            }

            got_sigchld = 0;
        }

        /* 除了USR1、USR2和SIGCHLD之外的任何信号都意味着中断循环。
        */
        if(got_signal != 0)
        {
            if(got_sigint || got_sigterm || got_sighup)
            {
                pending_break = 1;
            }
            else if(got_sigusr1 || got_sigusr2)
            {
                /* 目前尚未对这些信号采取任何操作
                */
                got_sigusr1 = got_sigusr2 = 0;
                got_signal = 0;
            }
            else
                got_signal = 0;
        }

        res = recv(nfq_fd, nfq_buf, sizeof(nfq_buf), 0);

        /* 计算已处理的数据包数
        */
        if(res > 0)
        {
            nfq_handle_packet(nfq_h, nfq_buf, res);

            /* 计算已处理的数据包集合（nfq_dispatch()的返回值），无论在这一点上SPA数据包是否有效，
            * 我们都将其用作--packet-limit的比较值。
            */
            opts->packet_ctr += res;
            if (opts->packet_ctr_limit && opts->packet_ctr >= opts->packet_ctr_limit)
            {
                log_msg(LOG_WARNING,
                    "* Incoming packet count limit of %i reached",
                    opts->packet_ctr_limit
                );

                pending_break = 1;
            }
        }
        /* 如果出现错误，进行报错并继续（在放弃之前进行一定程度的尝试）。
        */
        else if(res < 0 && errno != EAGAIN)
        {

            log_msg(LOG_ERR, "[*] Error reading from  nfq descriptor: %s", strerror);

            if(nfq_errcnt++ > MAX_NFQ_ERRORS_BEFORE_BAIL)
            {
                log_msg(LOG_ERR, "[*] %i consecutive nfq errors.  Giving up",
                    nfq_errcnt
                );
                clean_exit(opts, FW_CLEANUP, EXIT_FAILURE);
            }

        }
        else if(pending_break == 1 || res == -2)
        {
            log_msg(LOG_INFO, "Gracefully leaving the fwknopd event loop.");
            break;
        }
        else
            nfq_errcnt = 0;

        /* 检查是否有任何已过期的防火墙规则，并处理它们。
        */
        check_firewall_rules(opts, chk_rm_all);

        usleep(atoi(opts->config[CONF_NFQ_LOOP_SLEEP]));
    }

    nfq_destroy_queue(nfq_qh);
    nfq_close(nfq_h);

    return(0);
}
/***EOF***/
