

#if USE_LIBPCAP
  #include <pcap.h>
  #include <errno.h>
#endif

#include "fwknopd_common.h"
#include "pcap_capture.h"
#include "process_packet.h"
#include "fw_util.h"
#include "cmd_cycle.h"
#include "log_msg.h"
#include "fwknopd_errors.h"
#include "sig_handler.h"
#include "tcp_server.h"

#if HAVE_SYS_WAIT_H
  #include <sys/wait.h>
#endif

#if USE_LIBPCAP

/* 
pcap 抓包例程
*/
int
pcap_capture(fko_srv_options_t *opts)
{
    pcap_t              *pcap;
    char                errstr[PCAP_ERRBUF_SIZE] = {0};
    struct bpf_program  fp;
    int                 res;
    int                 pcap_errcnt = 0;
    int                 pending_break = 0;
    int                 promisc = 0;
    int                 set_direction = 1;
    int                 pcap_file_mode = 0;
    int                 status;
    int                 chk_rm_all = 0;
    pid_t               child_pid;

#if FIREWALL_IPFW
    time_t              now;
#endif

    
   // 设置混杂模式 如果配置文件中设置了混杂模式 则设置为混杂模式
    if(strncasecmp(opts->config[CONF_ENABLE_PCAP_PROMISC], "Y", 1) == 0)
        promisc = 1;

    if(opts->config[CONF_PCAP_FILE] != NULL
            && opts->config[CONF_PCAP_FILE][0] != '\0')
        pcap_file_mode = 1;

    if(pcap_file_mode == 1) {
        log_msg(LOG_INFO, "Reading pcap file: %s",
            opts->config[CONF_PCAP_FILE]);

        pcap = pcap_open_offline(opts->config[CONF_PCAP_FILE], errstr);

        if(pcap == NULL)
        {
            log_msg(LOG_ERR, "[*] pcap_open_offline() error: %s",
                    errstr);
            clean_exit(opts, FW_CLEANUP, EXIT_FAILURE);
        }
    }
    else
    {
        log_msg(LOG_INFO, "Sniffing interface: %s",
            opts->config[CONF_PCAP_INTF]);

        pcap = pcap_open_live(opts->config[CONF_PCAP_INTF],
            opts->max_sniff_bytes, promisc, 100, errstr
        );

        if(pcap == NULL)
        {
            log_msg(LOG_ERR, "[*] pcap_open_live() error: %s", errstr);
            clean_exit(opts, FW_CLEANUP, EXIT_FAILURE);
        }
    }

    
   // 设置过滤器
    if (opts->config[CONF_PCAP_FILTER][0] != '\0')
    {
        if(pcap_compile(pcap, &fp, opts->config[CONF_PCAP_FILTER], 1, 0) == -1)
        {
            log_msg(LOG_ERR, "[*] Error compiling pcap filter: %s",
                pcap_geterr(pcap)
            );
            clean_exit(opts, FW_CLEANUP, EXIT_FAILURE);
        }

        if(pcap_setfilter(pcap, &fp) == -1)
        {
            log_msg(LOG_ERR, "[*] Error setting pcap filter: %s",
                pcap_geterr(pcap)
            );
            clean_exit(opts, FW_CLEANUP, EXIT_FAILURE);
        }

        log_msg(LOG_INFO, "PCAP filter is: '%s'", opts->config[CONF_PCAP_FILTER]);

        pcap_freecode(&fp);
    }

    
   // 设置数据链路偏移量
    switch(pcap_datalink(pcap)) {
        case DLT_EN10MB:
            opts->data_link_offset = 14;
            break;
#if defined(__linux__)
        case DLT_LINUX_SLL:
            opts->data_link_offset = 16;
            break;
#elif defined(__OpenBSD__)
        case DLT_LOOP:
            set_direction = 0;
            opts->data_link_offset = 4;
            break;
#endif
        case DLT_NULL:
            set_direction = 0;
            opts->data_link_offset = 4;
            break;
        default:
            opts->data_link_offset = 0;
            break;
    }

    
   // 设置数据包方向
    if ((opts->pcap_any_direction == 0)
            && (set_direction == 1) && (pcap_file_mode == 0)
            && (pcap_setdirection(pcap, PCAP_D_IN) < 0))
        if(opts->verbose)
            log_msg(LOG_WARNING, "[*] Warning: pcap error on setdirection: %s.",
                pcap_geterr(pcap));

    /* 将我们的 pcap 句柄设置为非阻塞模式。
 *
 * 注意：目前仅设置为 0，直到我们找到实际需要使用此模式的情况（当在 FreeBSD 系统上设置时，它会默默地中断数据包捕获）。
 */

if ((pcap_file_mode == 0) && (pcap_setnonblock(pcap, DEF_PCAP_NONBLOCK, errstr)) == -1)
{
    log_msg(LOG_ERR, "[*] 设置 pcap 非阻塞模式为 %i 时出错：%s",
        0, errstr
    );
    clean_exit(opts, FW_CLEANUP, EXIT_FAILURE);
}

log_msg(LOG_INFO, "开始 fwknopd 主事件循环。");

/* 进入我们自己编写的数据包捕获循环。
*/

    while(1)
    {
        
        // 如果收到了 SIGCHLD 信号，并且它是 tcp 服务器，则在此处处理它。
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

                    
                    // 如果配置文件中设置了 tcp 服务器，则尝试重启 tcp 服务器
                    usleep(1000000);
                    run_tcp_server(opts);
                }
            }

            got_sigchld = 0;
        }

        if(sig_do_stop())
        {
            pcap_breakloop(pcap);
            pending_break = 1;
        }

        res = pcap_dispatch(pcap, opts->pcap_dispatch_count,
            (pcap_handler)&process_packet, (unsigned char *)opts);

      
       // 计算已处理的数据包数
        if(res > 0)
        {
            if(opts->foreground == 1 && opts->verbose > 2)
                log_msg(LOG_DEBUG, "pcap_dispatch() processed: %d packets", res);

            
           /* 计算已处理的数据包数（pcap_dispatch() 返回值） - 我们使用这个值作为 --packet-limit 的比较值，而
           不管此时 SPA 数据包的有效性如何。
           * */

            opts->packet_ctr += res;
            if (opts->packet_ctr_limit && opts->packet_ctr >= opts->packet_ctr_limit)
            {
                log_msg(LOG_WARNING,
                    "* Incoming packet count limit of %i reached",
                    opts->packet_ctr_limit
                );

                pcap_breakloop(pcap);
                pending_break = 1;
            }
        }
        
       // 如果出现错误，则进行投诉并继续（在放弃之前的某种程度上）。
        else if(res == -1)
        {
            if((strncasecmp(opts->config[CONF_EXIT_AT_INTF_DOWN], "Y", 1) == 0)
                    && errno == ENETDOWN)
            {
                log_msg(LOG_ERR, "[*] Fatal error from pcap_dispatch: %s",
                    pcap_geterr(pcap)
                );
                clean_exit(opts, FW_CLEANUP, EXIT_FAILURE);
            }
            else
            {
                log_msg(LOG_ERR, "[*] Error from pcap_dispatch: %s",
                    pcap_geterr(pcap)
                );
            }

            if(pcap_errcnt++ > MAX_PCAP_ERRORS_BEFORE_BAIL)
            {
                log_msg(LOG_ERR, "[*] %i consecutive pcap errors.  Giving up",
                    pcap_errcnt
                );
                clean_exit(opts, FW_CLEANUP, EXIT_FAILURE);
            }
        }
        else if(pending_break == 1 || res == -2)
        {
            
            // pcap_breakloop 被调用，所以我们放弃。
            log_msg(LOG_INFO, "Gracefully leaving the fwknopd event loop.");
            break;
        }
        else
            pcap_errcnt = 0;

        if(!opts->test)
        {
            if(opts->enable_fw)
            {
                
               // 检查防火墙规则是否过期
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

           
           // 检查是否需要执行任何 CMD_CYCLE_CLOSE 命令。
            cmd_cycle_close(opts);
        }

#if FIREWALL_IPFW
        
       // 清除过期的规则
        if(opts->fw_config->total_rules > 0)
        {
            time(&now);
            if(opts->fw_config->last_purge < (now - opts->fw_config->purge_interval))
            {
                ipfw_purge_expired_rules(opts);
                opts->fw_config->last_purge = now;
            }
        }
#endif

        usleep(opts->pcap_loop_sleep);
    }

    pcap_close(pcap);

    return(0);
}

#endif 


