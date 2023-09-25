/**
 * \file server/fwknopd.c
 *
 * \brief An implementation of an fwknop server.
 *
 *  Fwknop is developed primarily by the people listed in the file 'AUTHORS'.
 *  Copyright (C) 2009-2015 fwknop developers and contributors. For a full
 *  list of contributors, see the file 'CREDITS'.
 *
 *  License (GNU General Public License):
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License
 *  as published by the Free Software Foundation; either version 2
 *  of the License, or (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307
 *  USA
 *
 *****************************************************************************
*/
#include "fwknopd.h"
#include "access.h"
#include "config_init.h"
#include "log_msg.h"
#include "utils.h"
#include "fw_util.h"
#include "sig_handler.h"
#include "replay_cache.h"
#include "tcp_server.h"
#include "udp_server.h"

#if USE_LIBNETFILTER_QUEUE
  #include "nfq_capture.h"
#endif
#if USE_LIBPCAP
  #include "pcap_capture.h"
#endif

/* Prototypes
*/
//检查目录文件
static int check_dir_path(const char * const path,
        const char * const path_name, const unsigned char use_basename);
//创建目录文件
static int make_dir_path(const char * const path);
//将进程转变为守护进程 ？？？
static void daemonize_process(fko_srv_options_t * const opts);

// 停止运行的fwknopd进程
static int stop_fwknopd(fko_srv_options_t * const opts);
// 获取fwknopd进程的状态
static int status_fwknopd(fko_srv_options_t * const opts);

//重启fwknopd进程
static int restart_fwknopd(fko_srv_options_t * const opts);

//将进程的PID写入PID文件 PID即进程ID
static int write_pid_file(fko_srv_options_t *opts);

//处理收到的信号
static int handle_signals(fko_srv_options_t *opts);

//设置PID相关的配置
static void setup_pid(fko_srv_options_t *opts);

// 根据配置文件中的设置初始化重放缓存
static void init_digest_cache(fko_srv_options_t *opts);

//设置本地化语言环境
static void set_locale(fko_srv_options_t *opts);
//获取正在运行fwknop进程的PID
static pid_t get_running_pid(const fko_srv_options_t *opts);
#if AFL_FUZZING
//从文件中读取加密的SPA数据包，并对其进行解码和处理。
static void afl_enc_pkt_from_file(fko_srv_options_t *opts);
//从标准输入中读取SPA数据包，并进行解码和处理
static void afl_pkt_from_stdin(fko_srv_options_t *opts);
#endif

#if HAVE_LIBFIU
//启用故障注入
static void enable_fault_injections(fko_srv_options_t * const opts);
#endif

#if AFL_FUZZING
#define AFL_MAX_PKT_SIZE  1024
#define AFL_DUMP_CTX_SIZE 4096
#endif

//进入一个无限循环，在循环中处理各种命令行选项和信号。
int
main(int argc, char **argv)
{
    fko_srv_options_t   opts;
    int depth = 0;

    while(1)
    {
        /* Handle command line
        */
        config_init(&opts, argc, argv);

#if HAVE_LIBFIU
        /* Set any fault injection points early
        */
        enable_fault_injections(&opts);
#endif

        /* Process any options that do their thing and exit.
        */

        /* Kill the currently running fwknopd process?
        */
        if(opts.kill == 1)
            clean_exit(&opts, NO_FW_CLEANUP, stop_fwknopd(&opts));

        /* Status of the currently running fwknopd process?
        */
        if(opts.status == 1)
            clean_exit(&opts, NO_FW_CLEANUP, status_fwknopd(&opts));

        /* Restart the currently running fwknopd process?
        */
        if(opts.restart == 1)
            clean_exit(&opts, NO_FW_CLEANUP, restart_fwknopd(&opts));

        /* Initialize logging.
        */
        init_logging(&opts);

        /* Update the verbosity level for the log module */
        log_set_verbosity(LOG_DEFAULT_VERBOSITY + opts.verbose);

#if HAVE_LOCALE_H
        /* Set the locale if specified.
        */
        set_locale(&opts);
#endif

        /* Make sure we have a valid run dir and path leading to digest file
         * in case it configured to be somewhere other than the run dir.
        */
        if(!opts.afl_fuzzing
                && ! check_dir_path((const char *)opts.config[CONF_FWKNOP_RUN_DIR], "Run", 0))
            clean_exit(&opts, NO_FW_CLEANUP, EXIT_FAILURE);
        /* Initialize our signal handlers. You can check the return value for
         * the number of signals that were *not* set.  Those that were not set
         * will be listed in the log/stderr output.
        */
        if(set_sig_handlers() > 0) {
            log_msg(LOG_ERR, "Errors encountered when setting signal handlers.");
            clean_exit(&opts, NO_FW_CLEANUP, EXIT_FAILURE);
        }

        /* Initialize the firewall rules handler based on the fwknopd.conf
         * file, but (for iptables firewalls) don't flush any rules or create
         * any chains yet. This allows us to dump the current firewall rules
         * via fw_rules_dump() in --fw-list mode before changing around any rules
         * of an existing fwknopd process.
        */
        if(fw_config_init(&opts) != 1)
            clean_exit(&opts, NO_FW_CLEANUP, EXIT_FAILURE);

        if(opts.fw_list == 1 || opts.fw_list_all == 1)
        {
            fw_dump_rules(&opts);
            clean_exit(&opts, NO_FW_CLEANUP, EXIT_SUCCESS);
        }

        if(opts.fw_flush == 1)
        {
            fprintf(stdout, "Deleting any existing firewall rules...\n");
            opts.enable_fw = 1;
            clean_exit(&opts, FW_CLEANUP, EXIT_SUCCESS);
        }

        if (opts.config[CONF_ACCESS_FOLDER] != NULL) //If we have an access folder, process it
        {
            if (parse_access_folder(&opts, opts.config[CONF_ACCESS_FOLDER], &depth) != EXIT_SUCCESS)
            {
                clean_exit(&opts, NO_FW_CLEANUP, EXIT_FAILURE);
            }
        }
        /* Process the access.conf file, but only if no access.conf folder was specified.
        */
        else if (parse_access_file(&opts, opts.config[CONF_ACCESS_FILE], &depth) != EXIT_SUCCESS)
        {
            clean_exit(&opts, NO_FW_CLEANUP, EXIT_FAILURE);
        }

        /* We must have at least one valid access stanza at this point
        */
        if(! valid_access_stanzas(opts.acc_stanzas))
        {
            log_msg(LOG_ERR, "Fatal, could not find any valid access.conf stanzas");
            clean_exit(&opts, NO_FW_CLEANUP, EXIT_FAILURE);
        }

        /* Show config (including access.conf vars) and exit dump config was
         * wanted.
        */
        if(opts.dump_config == 1)
        {
            dump_config(&opts);
            dump_access_list(&opts);
            clean_exit(&opts, NO_FW_CLEANUP, EXIT_SUCCESS);
        }

        /* Now is the right time to bail if we're just parsing the configs
        */
        if(opts.exit_after_parse_config)
        {
            log_msg(LOG_INFO, "Configs parsed, exiting.");
            clean_exit(&opts, NO_FW_CLEANUP, EXIT_SUCCESS);
        }

        /* Acquire pid, become a daemon or run in the foreground, write pid
         * to pid file.
        */
        if(! opts.exit_parse_digest_cache)
            setup_pid(&opts);

        if(opts.verbose > 1 && opts.foreground)
        {
            dump_config(&opts);
            dump_access_list(&opts);
        }

        /* Initialize the digest cache for replay attack detection (either
         * with dbm support or with the default simple cache file strategy)
         * if so configured.
        */
        init_digest_cache(&opts);

        if(opts.exit_parse_digest_cache)
        {
            log_msg(LOG_INFO, "Digest cache parsed, exiting.");
            clean_exit(&opts, NO_FW_CLEANUP, EXIT_SUCCESS);
        }

#if AFL_FUZZING
        /* SPA data from STDIN. */
        if(opts.afl_fuzzing)
        {
            if(opts.config[CONF_AFL_PKT_FILE] != 0x0)
            {
                afl_enc_pkt_from_file(&opts);
            }
            else
            {
                afl_pkt_from_stdin(&opts);
            }
        }
#endif

        /* Prepare the firewall - i.e. flush any old rules and (for iptables)
         * create fwknop chains.
        */
        if(!opts.test && opts.enable_fw && (fw_initialize(&opts) != 1))
            clean_exit(&opts, FW_CLEANUP, EXIT_FAILURE);

#if USE_LIBNETFILTER_QUEUE
        /* If we are to acquire SPA data via a libnetfilter_queue, start it up here.
        */
        if(opts.enable_nfq_capture ||
                strncasecmp(opts.config[CONF_ENABLE_NFQ_CAPTURE], "Y", 1) == 0)
        {
            nfq_capture(&opts);
        }
        else
#endif
        /* If we are to acquire SPA data via a UDP socket, start it up here.
        */
        if(opts.enable_udp_server ||
                strncasecmp(opts.config[CONF_ENABLE_UDP_SERVER], "Y", 1) == 0)
        {
            if(run_udp_server(&opts) < 0)
            {
                log_msg(LOG_ERR, "Fatal run_udp_server() error");
                clean_exit(&opts, FW_CLEANUP, EXIT_FAILURE);
            }
            else
            {
                break;
            }
        }

        /* If the TCP server option was set, fire it up here. Note that in
         * this mode, fwknopd still acquires SPA packets via libpcap. If you
         * want to use UDP only without the libpcap dependency, then fwknop
         * needs to be compiled with --enable-udp-server. Note that the UDP
         * server can be run even when fwknopd links against libpcap as well,
         * but there is no reason to link against it if SPA packets are
         * always going to be acquired via a UDP socket.
        */
        if(strncasecmp(opts.config[CONF_ENABLE_TCP_SERVER], "Y", 1) == 0)
        {
            if(run_tcp_server(&opts) < 0)
            {
                log_msg(LOG_ERR, "Fatal run_tcp_server() error");
                clean_exit(&opts, FW_CLEANUP, EXIT_FAILURE);
            }
        }

#if USE_LIBPCAP
        /* Intiate pcap capture mode...
        */
        if(!opts.enable_udp_server
            && strncasecmp(opts.config[CONF_ENABLE_UDP_SERVER], "N", 1) == 0)
        {
            pcap_capture(&opts);
        }
        else
        {
            log_msg(LOG_ERR, "No available capture mode specified.  Aborting.");
            clean_exit(&opts, FW_CLEANUP, EXIT_FAILURE);
        }
#endif

        /* Deal with any signals that we've received and break out
         * of the loop for any terminating signals
        */
        if(handle_signals(&opts) == 1)
            break;
    }

    log_msg(LOG_INFO, "Shutting Down fwknopd.");

    /* Kill the TCP server (if we have one running).
    */
    if(opts.tcp_server_pid > 0)
    {
        log_msg(LOG_INFO, "Killing the TCP server (pid=%i)",
            opts.tcp_server_pid);

        kill(opts.tcp_server_pid, SIGTERM);

        /* --DSS XXX: This seems to be necessary if the tcp server
         *            was restarted by this program. We need to
         *            investigate and fix this. For now, this works
         *            (it is kludgy, but does no harm afaik).
        */
        kill(opts.tcp_server_pid, SIGKILL);
    }

    clean_exit(&opts, FW_CLEANUP, EXIT_SUCCESS);

    return(EXIT_SUCCESS);  /* This never gets called */
}

//设置本地化语言环境
static void set_locale(fko_srv_options_t *opts)
{
    char               *locale;
	
	//判断CONF_LOCALE不为空且不为NONE
    if(opts->config[CONF_LOCALE] != NULL
      && strncasecmp(opts->config[CONF_LOCALE], "NONE", 4) != 0)
    {
    	/*
    	设置CONF_LOCALE，参数分别为：
    	1.要设置所有的区域设置（包括语言、日期时间格式、货币等）
    	2.要设置的区域设置的值，即CONF_LOCALE
		*/
        locale = setlocale(LC_ALL, opts->config[CONF_LOCALE]);

        if(locale == NULL)
        {//配置失败
            log_msg(LOG_ERR,
                "WARNING: Unable to set locale to '%s'.",
                opts->config[CONF_LOCALE]
            );
        }
        else
        {//配置成功
            log_msg(LOG_INFO,
                "Locale set to '%s'.", opts->config[CONF_LOCALE]
            );
        }
    }
    return;
}

#if AFL_FUZZING
//从文件中读取加密的SPA数据包，并对其进行解密和处理。
static void afl_enc_pkt_from_file(fko_srv_options_t *opts)
{
    FILE                *fp = NULL;
    fko_ctx_t           decrypt_ctx = NULL;
    unsigned char       enc_spa_pkt[AFL_MAX_PKT_SIZE] = {0}, rc;
    int                 res = 0, es = EXIT_SUCCESS, enc_msg_len;
    char                dump_buf[AFL_DUMP_CTX_SIZE];
	
	//打开指定的文件
    fp = fopen(opts->config[CONF_AFL_PKT_FILE], "rb");
	//成功打开
    if(fp != NULL)
    {
        enc_msg_len = 0;
		//读文件
        while(fread(&rc, 1, 1, fp))
        {
            enc_spa_pkt[enc_msg_len] = rc;
            enc_msg_len++;//密文长度
            if(enc_msg_len == AFL_MAX_PKT_SIZE-1)
                break;
        }
        fclose(fp);
		//fko_new函数用于初始化fwknop上下文 ？？？
        fko_new(&decrypt_ctx);
		
		//fko_afl_set_spa_data函数将读取到的数据包设置为加密数据
        res = fko_afl_set_spa_data(decrypt_ctx, (const char *)enc_spa_pkt,
                enc_msg_len);

		//解码SPA数据，fwknoptest是指定的解密密钥
        if(res == FKO_SUCCESS)
            res = fko_decrypt_spa_data(decrypt_ctx, "fwknoptest",
                    strlen("fwknoptest"));

		//将解码后的上下文信息转储到dump_buf缓冲区
        if(res == FKO_SUCCESS)
            res = dump_ctx_to_buffer(decrypt_ctx, dump_buf, sizeof(dump_buf));

		//打印解码上下文信息
        if(res == FKO_SUCCESS)
            log_msg(LOG_INFO, "%s", dump_buf);
        else
            log_msg(LOG_ERR, "Error (%d): %s", res, fko_errstr(res));

		//销毁解码上下文
        fko_destroy(decrypt_ctx);

		//检查解码结果并打印成功和失败信息
        if(res == FKO_SUCCESS)
        {
            log_msg(LOG_INFO, "SPA packet decode: %s", fko_errstr(res));
            es = EXIT_SUCCESS;
        }
        else
        {
            log_msg(LOG_ERR, "Could not decode SPA packet: %s", fko_errstr(res));
            es = EXIT_FAILURE;
        }
    }
    else
        log_msg(LOG_ERR, "Could not acquire SPA packet from file: %s.",
                opts->config[CONF_AFL_PKT_FILE]);

    clean_exit(opts, NO_FW_CLEANUP, es);
}

//从标准输入中读取SPA数据包，并进行解码和处理
static void afl_pkt_from_stdin(fko_srv_options_t *opts)
{
    FILE                *fp = NULL;
    fko_ctx_t           decode_ctx = NULL;
    unsigned char       spa_pkt[AFL_MAX_PKT_SIZE] = {0};
    int                 res = 0, es = EXIT_SUCCESS;
    char                dump_buf[AFL_DUMP_CTX_SIZE];

    fp = fdopen(STDIN_FILENO, "r");
    if(fp != NULL)
    {
    	//从标准输入中读取一行数据，将其存储在名为spa_pkt的字符数组中。读取的数据包字符串包含加密的SPA数据。
        if(fgets((char *)spa_pkt, AFL_MAX_PKT_SIZE, fp) == NULL)
        {
            fclose(fp);
            clean_exit(opts, NO_FW_CLEANUP, EXIT_FAILURE);
        }

        fclose(fp);

        fko_new(&decode_ctx);

		//设置fwknop的编码数据。参数分别是fwknop上下文、数据包字符串、数据包字符串的长度、起始索引(0)和SHA256哈希算法
        res = fko_set_encoded_data(decode_ctx, (char *) spa_pkt,
                strlen((char *)spa_pkt), 0, FKO_DIGEST_SHA256);

		//通过fko_set_spa_data将SPA数据设置到上下文对象中，fwknop程序可以在后续的操作中使用这些数据，例如加密、解密、验证等
        if(res == FKO_SUCCESS)
            res = fko_set_spa_data(decode_ctx, (const char *) spa_pkt);
		//对数据进行解码
        if(res == FKO_SUCCESS)
            res = fko_decode_spa_data(decode_ctx);
		//将fwknop上下文的状态转储到dump_buf中
        if(res == FKO_SUCCESS)
            res = dump_ctx_to_buffer(decode_ctx, dump_buf, sizeof(dump_buf));
		//计入日志
        if(res == FKO_SUCCESS)
            log_msg(LOG_INFO, "%s", dump_buf);

		//销毁解码数据
        fko_destroy(decode_ctx);

        if(res == FKO_SUCCESS)
        {
            log_msg(LOG_INFO, "SPA packet decode: %s", fko_errstr(res));
            es = EXIT_SUCCESS;
        }
        else
        {
            log_msg(LOG_ERR, "Could not decode SPA packet: %s", fko_errstr(res));
            es = EXIT_FAILURE;
        }
    }
    else
        log_msg(LOG_ERR, "Could not acquire SPA packet from stdin.");

    clean_exit(opts, NO_FW_CLEANUP, es);
}
#endif

// 根据配置文件中的设置初始化重放缓存
static void init_digest_cache(fko_srv_options_t *opts)
{
    int     rp_cache_count;

#if AFL_FUZZING
    if(opts->afl_fuzzing)
        return;
#endif
    //检查配置文件中的ENABLE_DIGEST_PERSISTENCE是否打开
    if(strncasecmp(opts->config[CONF_ENABLE_DIGEST_PERSISTENCE], "Y", 1) == 0)
    {
        //记录当前重放缓存中的条目数量
        rp_cache_count = replay_cache_init(opts);

        if(rp_cache_count < 0)
        {
            //记录日志消息
            log_msg(LOG_WARNING,
                "Error opening digest cache file. Incoming digests will not be remembered."
            );
            /* Destination points to heap memory, and is guaranteed to be
             * at least two bytes large via validate_options(),
             * DEF_ENABLE_DIGEST_PERSISTENCE, and set_config_entry()
            */
            strlcpy(opts->config[CONF_ENABLE_DIGEST_PERSISTENCE], "N", 2);
        }

        if(opts->verbose)
            log_msg(LOG_ERR,
                "Using Digest Cache: '%s' (entry count = %i)",
#if USE_FILE_CACHE
                opts->config[CONF_DIGEST_FILE], rp_cache_count
#else
                opts->config[CONF_DIGEST_DB_FILE], rp_cache_count
#endif
            );
    }
    return;
}

//设置PID相关的配置
static void setup_pid(fko_srv_options_t *opts)
{
    pid_t    old_pid;

#if AFL_FUZZING
    if(opts->afl_fuzzing)
        return;
#endif

    /* If we are a new process (just being started), proceed with normal
     * start-up. Otherwise, we are here as a result of a signal sent to an
     * existing process and we want to restart.
    */
    //存在正在运行的线程
    if(get_running_pid(opts) != getpid())
    {
        /* If foreground mode is not set, then fork off and become a daemon.
        * Otherwise, attempt to get the pid file lock and go on.
        */
        //判断在配置中设置了后台模式
        if(opts->foreground == 0)
        {
        	//将进程转为守护进程
            daemonize_process(opts);
        }
        else
        {
        	/*
        	write_pid_file函数将当前进程的PID写入PID文件
        	如果PID文件已存在，并且成功读取到旧的PID值，那么old_pid将被设置为旧的PID值
        	不存在或者无法读取旧的PID值，返回值为-1
        	*/
            old_pid = write_pid_file(opts);
            if(old_pid > 0)
            {
                fprintf(stderr,
                    "[*] An instance of fwknopd is already running: (PID=%i).\n", old_pid
                );

                clean_exit(opts, NO_FW_CLEANUP, EXIT_FAILURE);
            }
            else if(old_pid < 0)
            {
                fprintf(stderr, "[*] PID file error. The lock may not be effective.\n");
            }
        }

        log_msg(LOG_INFO, "Starting %s", MY_NAME);
    }
    else
    {
        log_msg(LOG_INFO, "Re-starting %s", MY_NAME);
    }

    return;
}

//重启fwknop进程
static int restart_fwknopd(fko_srv_options_t * const opts)
{
    int      res = 0;
    pid_t    old_pid;

    old_pid = get_running_pid(opts);

    if(old_pid > 0)
    {
    	//发送SIGHUP信号重启进程
        res = kill(old_pid, SIGHUP);
		//成功返回EXIT_SUCCESS(0)
        if(res == 0)
        {
            fprintf(stdout, "Sent restart signal to fwknopd (pid=%i)\n", old_pid);
            return EXIT_SUCCESS;
        }
        else
        {
        	//失败返回EXIT_FAILURE(-1)
            perror("Unable to send signal to fwknop: ");
            return EXIT_FAILURE;
        }
    }

    fprintf(stdout, "No running fwknopd detected.\n");
    return EXIT_FAILURE;
}

/*
    获取fwknopd进程的状态
    有进程返回1
    无进程返回0
*/ 
static int status_fwknopd(fko_srv_options_t * const opts)
{
    pid_t    old_pid;

    //先获取进程的PID
    old_pid = write_pid_file(opts);

    //PID>0，检测到有fwknop的进程，返回EXIT_SUCCESS，打印进程信息
    if(old_pid > 0)
    {
        fprintf(stdout, "Detected fwknopd is running (pid=%i).\n", old_pid);
        return EXIT_SUCCESS;
    }

    //PID=0，无fwknop进程，返回EXIT_FAILURE
    fprintf(stdout, "No running fwknopd detected.\n");
    return EXIT_FAILURE;
}

static int handle_signals(fko_srv_options_t *opts)
{
    int      last_sig = 0, rv = 1;

	//检查got_signal变量是否为真，表示是否收到信号
    if(got_signal) {
        last_sig   = got_signal;
        got_signal = 0;
		//收到SIGHUP信号，表示需要重新读取配置文件
        if(got_sighup)
        {
            log_msg(LOG_WARNING, "Got SIGHUP. Re-reading configs.");
			//释放旧的配置并重新读取配置文件
            free_configs(opts);
			//并且如果TCP服务器正在运行，会向其发送SIGTERM信号终止进程。然后函数返回0，表示fwknopd进程不会退出。
            if(opts->tcp_server_pid > 0)
                kill(opts->tcp_server_pid, SIGTERM);
            usleep(1000000);
            got_sighup = 0;
            rv = 0;  /* this means fwknopd will not exit */
        }
		//SIGINT信号，表示需要退出进程，函数会输出相应的日志信息，然后返回1，表示fwknopd进程需要退出
        else if(got_sigint)
        {
            log_msg(LOG_WARNING, "Got SIGINT. Exiting...");
            got_sigint = 0;
        }
		//SIGTERM信号，表示需要退出进程，函数会输出相应的日志信息，然后返回1，表示fwknopd进程需要退出。
        else if(got_sigterm)
        {
            log_msg(LOG_WARNING, "Got SIGTERM. Exiting...");
            got_sigterm = 0;
        }
        else
        {
            log_msg(LOG_WARNING,
                "Got signal %i. No defined action but to exit.", last_sig);
        }
    }
	//检查是否达到了配置中设置的packet_ctr_limit数据包计数限制，如果达到限制，输出相应的日志信息，返回1
    else if (opts->packet_ctr_limit > 0
        && opts->packet_ctr >= opts->packet_ctr_limit)
    {
        log_msg(LOG_INFO,
            "Packet count limit (%d) reached. Exiting...",
            opts->packet_ctr_limit);
    }
    else    /* got_signal was not set (should be if we are here) */
    {
        log_msg(LOG_WARNING,
            "Capture ended without signal. Exiting...");
    }
    return rv;
}

// 停止正在运行的fwknopd进程
static int stop_fwknopd(fko_srv_options_t * const opts)
{
    int      res = 0, is_err = 0, sleep_num = 0;
    pid_t    old_pid;

	//获取正在运行的进程的PID
    old_pid = get_running_pid(opts);

	
    if(old_pid > 0)
    {
    	//发送SIGTERM信号来关闭
        res    = kill(old_pid, SIGTERM);
        is_err = kill(old_pid, 0);

        if(res == 0 && is_err != 0)
        {
            fprintf(stdout, "Killed fwknopd (pid=%i)\n", old_pid);
            return EXIT_SUCCESS;
        }
        else
        {
            /* give a bit of time for process shutdown and check again
            */
            for (sleep_num = 0; sleep_num < 4; sleep_num++) {
                is_err = kill(old_pid, 0);
                if(is_err != 0)
                {
                    fprintf(stdout, "Killed fwknopd (pid=%i) via SIGTERM\n",
                            old_pid);
                    return EXIT_SUCCESS;
                }
                sleep(1);
            }

            /* if we make it here at all, then we were unsuccessful with the
             * above attempt to kill the process with SIGTERM
            */
            //发送SIGKILL信号强制关闭
            res    = kill(old_pid, SIGKILL);
            is_err = kill(old_pid, 0);
            if(res == 0 && is_err != 0)
            {
                fprintf(stdout,
                        "Killed fwknopd (pid=%i) via SIGKILL\n",
                        old_pid);
                return EXIT_SUCCESS;
            }
            else
            {
                sleep(1);
                is_err = kill(old_pid, 0);
                //is_err=0代表关闭失败
                if(is_err != 0)
                {
                    fprintf(stdout,
                            "Killed fwknopd (pid=%i) via SIGKILL\n",
                            old_pid);
                    return EXIT_SUCCESS;
                }
                else
                {
                    perror("Unable to kill fwknop: ");
                    return EXIT_FAILURE;
                }
            }
        }
    }

    fprintf(stderr, "No running fwknopd detected.\n");
    return EXIT_FAILURE;
}

/* 
    Ensure the specified directory exists. If not, create it or die.
    确保指定的目录存在。如果没有，要么创建它，要么结束。
    返回值
*/
static int
check_dir_path(const char * const filepath, const char * const fp_desc, const unsigned char use_basename)
{
	//参数分别是 目录路径 目录描述 是否只使用基本名称
    struct stat     st;
    int             res = 0;
    char            tmp_path[MAX_PATH_LEN];
    char            *ndx;

    /*
     * FIXME:  We shouldn't use a hard-coded dir-separator here.
    */
    /* But first make sure we are using an absolute path.
    确保使用的是绝对路径
    不是绝对路径，则记录日志，返回0
    */
    if(*filepath != PATH_SEP)
    {
        log_msg(LOG_ERR,
            "Path '%s' is not absolute.", filepath
        );
        return 0;
    }

    /* If this is a file path that we want to use only the basename, strip
     * the trailing filename here.
    */
    //如果使用的是基本名称且filepath中存在PATH_SEP(也即'/')
    if(use_basename && ((ndx = strrchr(filepath, PATH_SEP)) != NULL))
		//将filename截断至分割符前并复制给tmp_path
        strlcpy(tmp_path, filepath, (ndx-filepath)+1);
    else
		//将filename复制给tmp_path
        strlcpy(tmp_path, filepath, sizeof(tmp_path));

    /* At this point, we should make the path is more than just the
     * PATH_SEP. If it is not, silently return.
    */

	//filepath的长度小于2（即只有一个目录分隔符），则返回1，表示目录路径有效
    if(strlen(tmp_path) < 2)
        return 1;

    /* Make sure we have a valid directory.
    */
    //stat用于获取文件或目录的元数据，返回值为0代表函数成功执行
    res = stat(tmp_path, &st);
    if(res != 0)
    {
        if(errno == ENOENT)
        {
            log_msg(LOG_WARNING,
                "%s directory: %s does not exist. Attempting to create it.",
                fp_desc, tmp_path
            );

            /* Directory does not exist, so attempt to create it.
            */
            //目录不存在，创建一个目录
            res = make_dir_path(tmp_path);
			//创建目录失败，记录日志，返回0
            if(res != 0)
            {
                log_msg(LOG_ERR,
                    "Unable to create %s directory: %s (error: %i)",
                    fp_desc, tmp_path, errno
                );
                return 0;
            }
			//创建成功
            log_msg(LOG_ERR,
                "Successfully created %s directory: %s", fp_desc, tmp_path
            );
        }
        else
        {
            log_msg(LOG_ERR,
                "Stat of %s returned error %i", tmp_path, errno
            );
            return 0;
        }
    }
    else
    {
        /* It is a file, but is it a directory?
        */
        if(! S_ISDIR(st.st_mode))
        {
            log_msg(LOG_ERR,
                "Specified %s directory: %s is NOT a directory", fp_desc, tmp_path
            );
            return 0;
        }
    }
    return 1;
}

//make_dir_path函数用于创建一个目录
static int
make_dir_path(const char * const run_dir)
{
    struct stat     st;
    int             res = 0;
    char            tmp_path[MAX_PATH_LEN];
    char            *ndx;

    strlcpy(tmp_path, run_dir, sizeof(tmp_path));

    /* Strip any trailing dir sep char.
    */
    chop_char(tmp_path, PATH_SEP);

    for(ndx = tmp_path+1; *ndx; ndx++)
    {
        if(*ndx == '/')
        {
            *ndx = '\0';

            /* Stat this part of the path to see if it is a valid directory.
             * If it does not exist, attempt to create it. If it does, and
             * it is a directory, go on. Otherwise, any other error cause it
             * to bail.
            */
            if(stat(tmp_path, &st) != 0)
            {
                if(errno == ENOENT)
                {
                    res = mkdir(tmp_path, S_IRWXU);
                    if(res != 0)
                        return res;

                    /* run stat() against the component since we just
                     * created it
                    */
                    if(stat(tmp_path, &st) != 0)
                    {
                        log_msg(LOG_ERR,
                            "Could not create component: %s of %s", tmp_path, run_dir
                        );
                        return(ENOTDIR);
                    }
                }
            }

            if(! S_ISDIR(st.st_mode))
            {
                log_msg(LOG_ERR,
                    "Component: %s of %s is NOT a directory", tmp_path, run_dir
                );
                return(ENOTDIR);
            }

            *ndx = '/';
        }
    }

    res = mkdir(tmp_path, S_IRWXU);

    return(res);
}

/* Become a daemon: fork(), start a new session, chdir "/",
 * and close unneeded standard filehandles.
*/
static void
daemonize_process(fko_srv_options_t * const opts)
{
    pid_t pid, old_pid;

    /* Reset the our umask
    */
    umask(0);

	//通过fork()创建一个子进程并让其成为新会话的首进程
    if ((pid = fork()) < 0)
    {
        perror("Unable to fork: ");
        clean_exit(opts, NO_FW_CLEANUP, EXIT_FAILURE);
    }
    else if (pid != 0) /* parent */
    {
        clean_exit(opts, NO_FW_CLEANUP, EXIT_SUCCESS);
    }

    /* Child process from here on out */

    /* Start a new session
    */
    setsid();

    /* Create the PID file (or be blocked by an existing one).
    */
    old_pid = write_pid_file(opts);
    if(old_pid > 0)
    {
        fprintf(stderr,
            "[*] An instance of fwknopd is already running: (PID=%i).\n", old_pid
        );
        clean_exit(opts, NO_FW_CLEANUP, EXIT_FAILURE);
    }
    else if(old_pid < 0)
    {
        fprintf(stderr,
                "[*] PID file error. The lock may not be effective.\n");
    }

    /* Chdir to the root of the filesystem
    */
    if ((chdir("/")) < 0) {
        perror("Could not chdir() to /: ");
        clean_exit(opts, NO_FW_CLEANUP, EXIT_FAILURE);
    }

    /* Close un-needed file handles
    */
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);

    return;
}

//将进程的PID写入PID文件
static int
write_pid_file(fko_srv_options_t *opts)
{
    pid_t   old_pid, my_pid;
    int     op_fd, lck_res, num_bytes;
    char    buf[PID_BUFLEN] = {0};

    /* Reset errno (just in case)
    */
    errno = 0;

    /* Open the PID file
    */
    //打开PID文件，O_WRONLY|O_CREAT是只写方式，S_IRUSR|S_IWUSR表示创建文件时的权限掩码
    op_fd = open(
        opts->config[CONF_FWKNOP_PID_FILE], O_WRONLY|O_CREAT, S_IRUSR|S_IWUSR
    );

    if(op_fd == -1)
    {
        perror("Error trying to open PID file: ");
        return -1;
    }

	//使用fcntl函数将文件描述符的关闭标志设置为FD_CLOEXEC，这样在执行后续的exec系列函数时，文件描述符将会被自动关闭。这样可以避免文件描述符泄露问题。
    if(fcntl(op_fd, F_SETFD, FD_CLOEXEC) == -1)
    {
        close(op_fd);
        perror("Unexpected error from fcntl: ");
        return -1;
    }

    /* Attempt to lock the PID file. If we get an EWOULDBLOCK
     * error, another instance already has the lock. So we grab
     * the pid from the existing lock file, complain and bail.

     F_TLOCK参数表示尝试获取锁，如果获取成功（返回值不为-1），则
     说明当前进程是第一个获取到锁的进程，可以继续执行后续操作。
     如果返回值为-1，并且errno为EAGAIN，表示锁已经被其他进程持有，
     函数将尝试读取已存在的PID，并将其作为返回值返回。如果返回值为-1，
     并且errno不为EAGAIN，则表示获取锁的过程中发生了错误。
    */
    lck_res = lockf(op_fd, F_TLOCK, 0);
    if(lck_res == -1)
    {
        close(op_fd);

        if(errno != EAGAIN)
        {
            perror("Unexpected error from lockf: ");
            return -1;
        }

        /* Look for an existing lock holder. If we get a pid return it.
        */
        old_pid = get_running_pid(opts);
        if(old_pid)
            return old_pid;

        /* Otherwise, consider it an error.
        */
        perror("Unable read existing PID file: ");
        return -1;
    }

    /* Write our PID to the file
    */
    //snprintf函数将当前进程的PID转换为字符串，并将其写入PID文件中。
    my_pid = getpid();
    snprintf(buf, PID_BUFLEN, "%i\n", my_pid);

    log_msg(LOG_DEBUG, "[+] Writing my PID (%i) to the lock file: %s",
        my_pid, opts->config[CONF_FWKNOP_PID_FILE]);

    num_bytes = write(op_fd, buf, strlen(buf));

    if(errno || num_bytes != strlen(buf))
        perror("Lock may not be valid. PID file write error: ");

    /* Sync/flush regardless...
    */
    fsync(op_fd);

    /* Put the lock file discriptor in out options struct so any
     * child processes we my spawn can close and release it.
    */
    opts->lock_fd = op_fd;

    return 0;
}

//获取正在运行fwknop进程的PID
static pid_t
get_running_pid(const fko_srv_options_t *opts)
{
    int     op_fd, is_err, bytes_read = 0;
    char    buf[PID_BUFLEN] = {0};
    pid_t   rpid            = 0;


    op_fd = open(opts->config[CONF_FWKNOP_PID_FILE], O_RDONLY);

    if(op_fd == -1)
    {
        if((opts->foreground != 0) && (opts->verbose != 0))
            perror("Error trying to open PID file: ");
        return(rpid);
    }

    if(verify_file_perms_ownership(opts->config[CONF_FWKNOP_PID_FILE], op_fd) != 1)
    {
        fprintf(stderr, "verify_file_perms_ownership() error\n");
        close(op_fd);
        return(rpid);
    }

    bytes_read = read(op_fd, buf, PID_BUFLEN);
    if (bytes_read > 0)
    {
        buf[PID_BUFLEN-1] = '\0';
        /* max pid value is configurable on Linux
        */
        rpid = (pid_t) strtol_wrapper(buf, 0, (2 << 22),
                NO_EXIT_UPON_ERR, &is_err);
        if(is_err != FKO_SUCCESS)
            rpid = 0;
    }
    else if (bytes_read < 0)
        perror("Error trying to read() PID file: ");

    close(op_fd);

    return(rpid);
}

#if HAVE_LIBFIU
//启用故障注入
static void
enable_fault_injections(fko_srv_options_t * const opts)
{
    if(opts->config[CONF_FAULT_INJECTION_TAG] != NULL)
    {
        if(opts->verbose)
            log_msg(LOG_INFO, "Enable fault injection tag: %s",
                    opts->config[CONF_FAULT_INJECTION_TAG]);
        if(fiu_init(0) != 0)
        {
            fprintf(stderr, "[*] Could not enable fault injection tag: %s\n",
                    opts->config[CONF_FAULT_INJECTION_TAG]);
            clean_exit(opts, NO_FW_CLEANUP, EXIT_FAILURE);
        }
        if (fiu_enable(opts->config[CONF_FAULT_INJECTION_TAG], 1, NULL, 0) != 0)
        {
            fprintf(stderr, "[*] Could not enable fault injection tag: %s\n",
                    opts->config[CONF_FAULT_INJECTION_TAG]);
            clean_exit(opts, NO_FW_CLEANUP, EXIT_FAILURE);
        }
    }
    return;
}
#endif

/***EOF***/
