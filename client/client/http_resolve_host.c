/* * */

#include "fwknop_common.h"
#include "utils.h"

#include <errno.h>

#ifdef WIN32
  #include <winsock2.h>
  #include <ws2tcpip.h>
#else
  #if HAVE_SYS_SOCKET_H
    #include <sys/socket.h>
  #endif
  #include <netdb.h>
  #include <sys/wait.h>
#endif

#if AFL_FUZZING
  #define AFL_SET_RESOLVE_HOST "192.168.12.123" /* 强制到不可路由IP */
#endif


/* 这段代码定义了一个名为 url的结构体。该结构体包含了三个成员变量：端口、主机和 路径 */
struct url
{
    char    port[MAX_PORT_STR_LEN+1];
    char    host[MAX_URL_HOST_LEN+1];
    char    path[MAX_URL_PATH_LEN+1];
};

/* 2023/7/20 15:29:56 */
static int
try_url(struct url *url, fko_cli_options_t *options)
{
    int     sock=-1, sock_success=0, res, error, http_buf_len, i;
    int     bytes_read = 0, position = 0;
    int     o1, o2, o3, o4;
    struct  addrinfo *result=NULL, *rp, hints;
    char    http_buf[HTTP_MAX_REQUEST_LEN]       = {0};
    char    http_response[HTTP_MAX_RESPONSE_LEN] = {0};
    char   *ndx;

#ifdef WIN32
    WSADATA wsa_data;

    /* Winsock需要初始化。。。 */
    res = WSAStartup( MAKEWORD(1,1), &wsa_data );
    if( res != 0 )
    {
        log_msg(LOG_VERBOSITY_ERROR, "Winsock initialization error %d", res );
        return(-1);
    }
#endif

    /* 构建我们的HTTP请求以解析外部IP（这类似于 */
    snprintf(http_buf, HTTP_MAX_REQUEST_LEN,
        "GET %s HTTP/1.1\r\nUser-Agent: %s\r\nAccept: */* \\r\n“ */
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

#if AFL_FUZZING
    /* 确保编译时不生成任何解析请求 */
    strlcpy(options->allow_ip_str, AFL_SET_RESOLVE_HOST,
            sizeof(options->allow_ip_str));
    log_msg(LOG_VERBOSITY_INFO,
                "\n[+] AFL fuzzing cycle, force IP resolution to: %s",
                options->allow_ip_str);

    return(1);
#endif

    error = getaddrinfo(url->host, url->port, &hints, &result);
    if (error != 0)
    {
        log_msg(LOG_VERBOSITY_ERROR, "error in getaddrinfo: %s", gai_strerror(error));
        return(-1);
    }

    for (rp = result; rp != NULL; rp = rp->ai_next) {
        sock = socket(rp->ai_family, rp->ai_socktype,
                rp->ai_protocol);
        if (sock < 0)
            continue;

        if ((error = (connect(sock, rp->ai_addr, rp->ai_addrlen) != -1)))
        {
            sock_success = 1;
            break;  /* 成功了 */
        }
        else /* 如果出现连接错误，请关闭打开的套接字 */
        {
#ifdef WIN32
            closesocket(sock);
#else
            close(sock);
#endif
        }

    }
    if(result != NULL)
        freeaddrinfo(result);

    if (! sock_success)
    {
        log_msg(LOG_VERBOSITY_ERROR, "resolve_ip_http: Could not create socket: ", strerror(errno));
        return(-1);
    }

    log_msg(LOG_VERBOSITY_DEBUG, "\nHTTP request: %s", http_buf);

    res = send(sock, http_buf, http_buf_len, 0);

    if(res < 0)
    {
        log_msg(LOG_VERBOSITY_ERROR, "resolve_ip_http: write error: ", strerror(errno));
    }
    else if(res != http_buf_len)
    {
        log_msg(LOG_VERBOSITY_WARNING,
            "[#] Warning: bytes sent (%i) not spa data length (%i).",
            res, http_buf_len
        );
    }

    do
    {
        memset(http_buf, 0x0, sizeof(http_buf));
        bytes_read = recv(sock, http_buf, sizeof(http_buf), 0);
        if ( bytes_read > 0 ) {
            if(position + bytes_read >= HTTP_MAX_RESPONSE_LEN)
                break;
            memcpy(&http_response[position], http_buf, bytes_read);
            position += bytes_read;
        }
    }
    while ( bytes_read > 0 );

    http_response[HTTP_MAX_RESPONSE_LEN-1] = '\0';

#ifdef WIN32
    closesocket(sock);
#else
    close(sock);
#endif

    log_msg(LOG_VERBOSITY_DEBUG, "\nHTTP response: %s", http_response);

    /* 移动到HTTP标头的末尾和内容的开头。 */
    ndx = strstr(http_response, "\r\n\r\n");
    if(ndx == NULL)
    {
        log_msg(LOG_VERBOSITY_ERROR, "Did not find the end of HTTP header.");
        return(-1);
    }
    ndx += 4;

    /* 沿着内容走一走，试图找到IP地址的末尾。 */
    for(i=0; i<MAX_IPV4_STR_LEN; i++) {
        if(! isdigit((int)(unsigned char)*(ndx+i)) && *(ndx+i) != '.')
            break;
    }

    /* 在第一个非数字和非点处终止。 */
    *(ndx+i) = '\0';

    /* 现在我们有了一个我们认为是IP地址字符串。我们制造 */
    if((sscanf(ndx, "%u.%u.%u.%u", &o1, &o2, &o3, &o4)) == 4
            && o1 >= 0 && o1 <= 255
            && o2 >= 0 && o2 <= 255
            && o3 >= 0 && o3 <= 255
            && o4 >= 0 && o4 <= 255)
    {
        strlcpy(options->allow_ip_str, ndx, sizeof(options->allow_ip_str));

        log_msg(LOG_VERBOSITY_INFO,
                    "\n[+] Resolved external IP (via http://%s%s) as: %s",
                    url->host,
                    url->path,
                    options->allow_ip_str);

        return(1);
    }
    else
    {
        log_msg(LOG_VERBOSITY_ERROR,
            "[-] From http://%s%s\n    Invalid IP (%s) in HTTP response:\n\n%s",
            url->host, url->path, ndx, http_response);
        return(-1);
    }
}

/* 2020年7月3日15:33:04 */
static int
parse_url(char *res_url, struct url* url)
{
    char *s_ndx, *e_ndx;
    int  tlen, tlen_offset, port, is_err;

    /* 如有必要，去掉https://或http://部分 */
    if(strncasecmp(res_url, "https://", 8) == 0)
        s_ndx = res_url + 8;
    else if(strncasecmp(res_url, "http://", 7) == 0)
        s_ndx = res_url + 7;
    else
        s_ndx = res_url;

    /* 如果指定了备用端口，请查找冒号。 */
    e_ndx = strchr(s_ndx, ':');
    if(e_ndx != NULL)
    {
        port = strtol_wrapper(e_ndx+1, 1, MAX_PORT, NO_EXIT_UPON_ERR, &is_err);
        if(is_err != FKO_SUCCESS)
        {
            log_msg(LOG_VERBOSITY_ERROR,
                "[*] resolve-url port value is invalid, must be in [%d-%d]",
                1, MAX_PORT);
            return(-1);
        }

        snprintf(url->port, sizeof(url->port)-1, "%u", port);

        /* 获取我们需要跳过端口部分的偏移量 */
        tlen_offset = strlen(url->port)+1;
    }
    else
    {
        strlcpy(url->port, "80", sizeof(url->port));
        tlen_offset = 0;
    }

    /* 去掉任何尾随斜杠 */
    if(res_url[strlen(res_url)-1] == '/')
        res_url[strlen(res_url)-1] = '\0';

    e_ndx = strchr(s_ndx, '/');
    if(e_ndx == NULL)
        tlen = strlen(s_ndx)+1;
    else
        tlen = (e_ndx-s_ndx)+1;

    tlen -= tlen_offset;

    if(tlen > MAX_URL_HOST_LEN)
    {
        log_msg(LOG_VERBOSITY_ERROR, "resolve-url hostname portion is too large.");
        return(-1);
    }
    strlcpy(url->host, s_ndx, tlen);

    if(e_ndx != NULL)
    {
        if(strlen(e_ndx) > MAX_URL_PATH_LEN)
        {
            log_msg(LOG_VERBOSITY_ERROR, "resolve-url path portion is too large.");
            return(-1);
        }

        strlcpy(url->path, e_ndx, sizeof(url->path));
    }
    else
    {
        /* 如果没有更具体的URL，则默认为“GET/” */
        strlcpy(url->path, "/", sizeof(url->path));
    }

    return(0);
}

int
resolve_ip_https(fko_cli_options_t *options)
{
    int     o1, o2, o3, o4, got_resp=0, i=0;
    char   *ndx, resp[MAX_IPV4_STR_LEN+1] = {0};
    struct  url url; /* 仅用于验证 */
    char    wget_ssl_cmd[MAX_URL_PATH_LEN] = {0};  /* 仅用于详细日志记录 */

#if HAVE_EXECVP
    char   *wget_argv[MAX_CMDLINE_ARGS]; /* 用于execvp（） */
    int     wget_argc=0;
    int     pipe_fd[2];
    pid_t   pid=0;
    FILE   *output;
    int     status, es = 0;
#else
    FILE *wget;
#endif

#if HAVE_EXECVP
    memset(wget_argv, 0x0, sizeof(wget_argv));
#endif
    memset(&url, 0x0, sizeof(url));

    if(options->wget_bin != NULL)
    {
        strlcpy(wget_ssl_cmd, options->wget_bin, sizeof(wget_ssl_cmd));
    }
    else
    {
#ifdef WGET_EXE
        strlcpy(wget_ssl_cmd, WGET_EXE, sizeof(wget_ssl_cmd));
#else
        log_msg(LOG_VERBOSITY_ERROR,
                "[*] Use --wget-cmd <path> to specify path to the wget command.");
        return(-1);
#endif
    }

    /* 看看我们是否应该更改默认的wget用户代理 */
    if(! options->use_wget_user_agent)
    {
        strlcat(wget_ssl_cmd, " -U ", sizeof(wget_ssl_cmd));
        strlcat(wget_ssl_cmd, options->http_user_agent, sizeof(wget_ssl_cmd));
    }

    /* 我们从wget的stdout中收集IP */
    strlcat(wget_ssl_cmd,
            " --secure-protocol=auto --quiet -O - ", sizeof(wget_ssl_cmd));

    if(options->resolve_url != NULL)
    {
        if(strncasecmp(options->resolve_url, "https", 5) != 0)
        {
            log_msg(LOG_VERBOSITY_ERROR,
                    "[-] Warning: IP resolution URL '%s' should begin with 'https://' in -R mode.",
                    options->resolve_url);
        }

        if(parse_url(options->resolve_url, &url) < 0)
        {
            log_msg(LOG_VERBOSITY_ERROR, "Error parsing resolve-url");
            return(-1);
        }
        /* 将原始URL添加到wget命令 */
        strlcat(wget_ssl_cmd, options->resolve_url, sizeof(wget_ssl_cmd));
    }
    else
    {
        /* 将默认URL添加到wget命令 */
        strlcat(wget_ssl_cmd, WGET_RESOLVE_URL_SSL, sizeof(wget_ssl_cmd));
    }

#if AFL_FUZZING
    /* 确保编译时不生成任何解析请求 */
    strlcpy(options->allow_ip_str, AFL_SET_RESOLVE_HOST,
            sizeof(options->allow_ip_str));
    log_msg(LOG_VERBOSITY_INFO,
                "\n[+] AFL fuzzing cycle, force IP resolution to: %s",
                options->allow_ip_str);

    return(1);
#endif

#if HAVE_EXECVP
    if(strtoargv(wget_ssl_cmd, wget_argv, &wget_argc) != 1)
    {
        log_msg(LOG_VERBOSITY_ERROR, "Error converting wget cmd str to argv");
        return(-1);
    }

    /* 我们驱动wget通过SSL解析外部IP。这可能不是 */
    if(pipe(pipe_fd) < 0)
    {
        log_msg(LOG_VERBOSITY_ERROR, "[*] pipe() error");
        free_argv(wget_argv, &wget_argc);
        return -1;
    }

    pid = fork();
    if (pid == 0)
    {
        close(pipe_fd[0]);
        dup2(pipe_fd[1], STDOUT_FILENO);
        dup2(pipe_fd[1], STDERR_FILENO);
        es = execvp(wget_argv[0], wget_argv);

        if(es == -1)
            log_msg(LOG_VERBOSITY_ERROR,
                    "[*] resolve_ip_https(): execvp() failed: %s",
                    strerror(errno));

        /* 只有当execvp（）出现问题时，我们才能在这里找到它， */
        exit(es);
    }
    else if(pid == -1)
    {
        log_msg(LOG_VERBOSITY_INFO, "[*] Could not fork() for wget.");
        free_argv(wget_argv, &wget_argc);
        return -1;
    }

    /* 只有父进程才能到达此处 */
    close(pipe_fd[1]);
    if ((output = fdopen(pipe_fd[0], "r")) != NULL)
    {
        if(fgets(resp, sizeof(resp), output) != NULL)
        {
            got_resp = 1;
        }
        fclose(output);
    }
    else
    {
        log_msg(LOG_VERBOSITY_INFO,
                "[*] Could not fdopen() pipe output file descriptor.");
        free_argv(wget_argv, &wget_argc);
        return -1;
    }

    waitpid(pid, &status, 0);

    free_argv(wget_argv, &wget_argc);

#else /* 退回到popen（） */
    wget = popen(wget_ssl_cmd, "r");
    if(wget == NULL)
    {
        log_msg(LOG_VERBOSITY_ERROR, "[*] Could not run cmd: %s",
                wget_ssl_cmd);
        return -1;
    }
    /* 应为一行wget输出，其中包含已解析的IP。 */
    if ((fgets(resp, sizeof(resp), wget)) != NULL)
    {
        got_resp = 1;
    }
    pclose(wget);
#endif

    if(got_resp)
    {
        ndx = resp;
        for(i=0; i<MAX_IPV4_STR_LEN; i++) {
            if(! isdigit((int)(unsigned char)*(ndx+i)) && *(ndx+i) != '.')
                break;
        }
        *(ndx+i) = '\0';

        if((sscanf(ndx, "%u.%u.%u.%u", &o1, &o2, &o3, &o4)) == 4
                && o1 >= 0 && o1 <= 255
                && o2 >= 0 && o2 <= 255
                && o3 >= 0 && o3 <= 255
                && o4 >= 0 && o4 <= 255)
        {
            strlcpy(options->allow_ip_str, ndx, sizeof(options->allow_ip_str));

            log_msg(LOG_VERBOSITY_INFO,
                        "\n[+] Resolved external IP (via '%s') as: %s",
                        wget_ssl_cmd, options->allow_ip_str);
            return 1;
        }
    }
    log_msg(LOG_VERBOSITY_ERROR,
        "[-] Could not resolve IP via: '%s'", wget_ssl_cmd);
    return -1;
}
//解析http
/* 这是一个C语言函数，用于通过HTTPS解析IP地址。函数接受一个名为选项的结构体指针作为参数，并返回一个整数。 */
int
resolve_ip_http(fko_cli_options_t *options)
{
    int     res;
    struct  url url;

    memset(&url, 0, sizeof(url));

    if(options->resolve_url != NULL)
    {
        /* 只有当用户强制使用非HTTPS时，我们才会输入此函数 */
        if(strncasecmp(options->resolve_url, "https", 5) == 0)
        {
            log_msg(LOG_VERBOSITY_ERROR,
                    "[*] https is not supported for --resolve-http-only.");
            return(-1);
        }

        if(parse_url(options->resolve_url, &url) < 0)
        {
            log_msg(LOG_VERBOSITY_ERROR, "Error parsing resolve-url");
            return(-1);
        }

        res = try_url(&url, options);

    } else {
        strlcpy(url.port, "80", sizeof(url.port));
        strlcpy(url.host, HTTP_RESOLVE_HOST, sizeof(url.host));
        strlcpy(url.path, HTTP_RESOLVE_URL, sizeof(url.path));

        res = try_url(&url, options);
        if(res != 1)
        {
            /* 尝试备份url（只需将主机切换到cipherdyne.com） */
            strlcpy(url.host, HTTP_BACKUP_RESOLVE_HOST, sizeof(url.host));

#ifndef WIN32
            sleep(2);
#endif
            res = try_url(&url, options);
        }
    }
    return(res);
}

/* **EOF** */
