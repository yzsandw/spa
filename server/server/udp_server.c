/**
 * \file server/udp_server.c
 *
 * \brief 通过UDP服务器收集SPA数据包。
 */

#include "spad_common.h"
#include "sig_handler.h"
#include "incoming_spa.h"
#include "log_msg.h"
#include "fw_util.h"
#include "cmd_cycle.h"
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

int
run_udp_server(ztn_srv_options_t *opts)
{
    int                 s_sock, sfd_flags, selval, pkt_len;
    int                 rv=1, chk_rm_all=0;
    fd_set              sfd_set;
    struct sockaddr_in  saddr, caddr;
    struct timeval      tv;
    char                sipbuf[MAX_IPV4_STR_LEN] = {0};
    char                dgram_msg[MAX_SPA_PACKET_LEN+1] = {0};
    socklen_t           clen;

    log_msg(LOG_INFO, "Kicking off UDP server to listen on port %i.",
            opts->udpserv_port);

    /* 制作一个UDP服务器
    */
    if ((s_sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    {
        log_msg(LOG_ERR, "run_udp_server: socket() failed: %s",
            strerror(errno));
        return -1;
    }

    /* 使我们的主套接字非阻塞，这样我们就不必一直在侦听传入的数据报。
    */
    if((sfd_flags = fcntl(s_sock, F_GETFL, 0)) < 0)
    {
        log_msg(LOG_ERR, "run_udp_server: fcntl F_GETFL error: %s",
            strerror(errno));
        close(s_sock);
        return -1;
    }

    sfd_flags |= O_NONBLOCK;

    if(fcntl(s_sock, F_SETFL, sfd_flags) < 0)
    {
        log_msg(LOG_ERR, "run_udp_server: fcntl F_SETFL error setting O_NONBLOCK: %s",
            strerror(errno));
        close(s_sock);
        return -1;
    }

    /* 构建本地地址结构 */
    memset(&saddr, 0x0, sizeof(saddr));
    saddr.sin_family      = AF_INET;           /* Internet地址系列 */
    saddr.sin_addr.s_addr = htonl(INADDR_ANY); /* 任何传入接口 */
    saddr.sin_port        = htons(opts->udpserv_port); /*本地端口 */

    /* 绑定到本地地址 */
    if (bind(s_sock, (struct sockaddr *) &saddr, sizeof(saddr)) < 0)
    {
        log_msg(LOG_ERR, "run_udp_server: bind() failed: %s",
            strerror(errno));
        close(s_sock);
        return -1;
    }

    FD_ZERO(&sfd_set);

    /*现在循环并接收SPA数据包
    */
    while(1)
    {
        if(sig_do_stop())
        {
            if(opts->verbose)
                log_msg(LOG_INFO,
                        "udp_server: terminating signal received, will stop.");
            break;
        }

        if(!opts->test)
        {
            /* 检查是否存在任何过期的防火墙规则，并处理它们。
            */
            if(opts->enable_fw)
            {
                if(opts->rules_chk_threshold > 0)
                {
                    opts->check_rules_ctr++;
                    if ((opts->check_rules_ctr % opts->rules_chk_threshold) == 0)
                    {
                        chk_rm_all = 1;
                        opts->check_rules_ctr = 0;
                    }
                }
                check_firewall_rules(opts, chk_rm_all);
                chk_rm_all = 0;
            }

            /* 查看是否需要执行任何CMD_CYCLE_CLOSE命令。
            */
            cmd_cycle_close(opts);
        }

        /* 初始化并设置用于选择的套接字。
        */
        FD_SET(s_sock, &sfd_set);

        /* 将选择超时设置为（默认情况下为500ms）。
        */
        tv.tv_sec = 0;
        tv.tv_usec = opts->udpserv_select_timeout;

        selval = select(s_sock+1, &sfd_set, NULL, NULL, &tv);

        if(selval == -1)
        {
            if(errno == EINTR)
            {
                /* 重新启动循环，但仅在我们检查上述sig_do_stop（）中的终止信号之后
                */
                continue;
            }
            else
            {
                log_msg(LOG_ERR, "run_udp_server: select error socket: %s",
                    strerror(errno));
                rv = -1;
                break;
            }
        }

        if(selval == 0)
            continue;

        if(! FD_ISSET(s_sock, &sfd_set))
            continue;

        /* 如果我们在这里做，那么就有一个数据报要处理
        */
        clen = sizeof(caddr);

        pkt_len = recvfrom(s_sock, dgram_msg, MAX_SPA_PACKET_LEN,
                0, (struct sockaddr *)&caddr, &clen);

        dgram_msg[pkt_len] = 0x0;

        if(opts->verbose)
        {
            memset(sipbuf, 0x0, MAX_IPV4_STR_LEN);
            inet_ntop(AF_INET, &(caddr.sin_addr.s_addr), sipbuf, MAX_IPV4_STR_LEN);
            log_msg(LOG_INFO, "udp_server: Got UDP datagram (%d bytes) from: %s",
                    pkt_len, sipbuf);
        }

        /* 期望数据不要太大
        */
        if(pkt_len <= MAX_SPA_PACKET_LEN)
        {
            /* 复制数据包以进行SPA处理
            */
            strlcpy((char *)opts->spa_pkt.packet_data, dgram_msg, pkt_len+1);
            opts->spa_pkt.packet_data_len = pkt_len;
            opts->spa_pkt.packet_proto    = IPPROTO_UDP;
            opts->spa_pkt.packet_src_ip   = caddr.sin_addr.s_addr;
            opts->spa_pkt.packet_dst_ip   = saddr.sin_addr.s_addr;
            opts->spa_pkt.packet_src_port = ntohs(caddr.sin_port);
            opts->spa_pkt.packet_dst_port = ntohs(saddr.sin_port);

            incoming_spa(opts);
        }

        memset(dgram_msg, 0x0, sizeof(dgram_msg));

        opts->packet_ctr += 1;
        if(opts->foreground == 1 && opts->verbose > 2)
            log_msg(LOG_DEBUG, "run_udp_server() processed: %d packets",
                    opts->packet_ctr);

        if (opts->packet_ctr_limit && opts->packet_ctr >= opts->packet_ctr_limit)
        {
            log_msg(LOG_WARNING,
                "* Incoming packet count limit of %i reached",
                opts->packet_ctr_limit
            );
            break;
        }

    } /* 无限while循环 */

    close(s_sock);
    return rv;
}

/***EOF***/
