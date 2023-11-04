/* * */


#include "spa_comm.h"
#include "utils.h"
/* 2020年7月3日15:40:08 */
static void
dump_transmit_options(const fko_cli_options_t *options)
{
    char proto_str[PROTOCOL_BUFSIZE] = {0};   /* 协议字符串 */

    proto_inttostr(options->spa_proto, proto_str, sizeof(proto_str));

    log_msg(LOG_VERBOSITY_INFO, "Generating SPA packet:");
    log_msg(LOG_VERBOSITY_INFO, "            protocol: %s", proto_str);

    if (options->spa_src_port)
        log_msg(LOG_VERBOSITY_INFO, "         source port: %d", options->spa_src_port);
    else
        log_msg(LOG_VERBOSITY_INFO, "         source port: <OS assigned>");

    log_msg(LOG_VERBOSITY_INFO, "    destination port: %d", options->spa_dst_port);
    log_msg(LOG_VERBOSITY_INFO, "             IP/host: %s", options->spa_server_str);

    return;
}

/* 用于生成标头校验和的函数。 */
/* 这是一个名为chksum的静态函数，用于计算校验和。 */
static unsigned short
chksum(unsigned short *buf, int nbytes)
{
    unsigned int   sum;
    unsigned short oddbyte;

    sum = 0;
    while (nbytes > 1)
    {
        sum += *buf++;
        nbytes -= 2;
    }

    if (nbytes == 1)
    {
        oddbyte = 0;
        *((unsigned short *) &oddbyte) = *(unsigned short *) buf;
        sum += oddbyte;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);

    return (unsigned short) ~sum;
}



/* 这是一个名为发送包裹tcp_or_udp的函数，用于发送SPA数据包。 */


//该函数是发送的不是原始的udp或者tcp的数据包
static int
send_spa_packet_tcp_or_udp(const char *spa_data, const int sd_len,
    const fko_cli_options_t *options)
{
    int     sock=-1, sock_success=0, res=0, error;
    struct  addrinfo *result=NULL, *rp, hints;
    char    port_str[MAX_PORT_STR_LEN+1] = {0};

    if (options->test)          //这里会判断是否开启了test，开启了就会直接打印日志，终止函数，这样主函数中的test代码就会执行
    {
        log_msg(LOG_VERBOSITY_NORMAL,
            "test mode enabled, SPA packet not actually sent.");
        return res;
    }

    memset(&hints, 0, sizeof(struct addrinfo));//用于将一块内存区域的值设置为指定的字节值。

    hints.ai_family   = AF_INET; /* 仅允许IPv4 */
   
    //如果是UDP，设置udp相关的
    /* 这段代码是根据给定的条件设置提示结构体中与套接字类型和协议相关的字段，以便在使用UDP协议发送SPA数据包时使用。 */
    if (options->spa_proto == FKO_PROTO_UDP)
    {
        /* 通过单个UDP数据包发送SPA数据包-这是 */
        hints.ai_socktype = SOCK_DGRAM;
        hints.ai_protocol = IPPROTO_UDP;
    }
    else
    {
        /* 通过已建立的TCP连接发送SPA数据包。 */
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;
    }

    //在提供的代码中，snprintf函数被用于将整数值options->spa_dst_port转换为字符串形式，
    //并将结果存储到port_str中。该函数保证不会超过MAX_PORT_STR_LEN限定的字符串长度。
    //通过该函数就可以获得string类型的目标端口号
    snprintf(port_str, MAX_PORT_STR_LEN+1, "%d", options->spa_dst_port);

#if AFL_FUZZING
    /* 确保永远不要在AFL模糊循环下发送SPA数据包 */
    log_msg(LOG_VERBOSITY_NORMAL,
        "AFL fuzzing enabled, SPA packet not actually sent.");
    return res;
#endif
    /* 这段代码使用获取地址信息函数根据给定的服务器地址和端口号获取与之对应的网络地址信息。 */
    error = getaddrinfo(options->spa_server_str, port_str, &hints, &result);

    if (error != 0)
    {
        log_msg(LOG_VERBOSITY_ERROR, "error in getaddrinfo: %s", gai_strerror(error));
        return -1;
    }
    /* 对于循环： */
    for (rp = result; rp != NULL; rp = rp->ai_next) {
        /* 应用--server-resolve-ipv4条件 */
        if(options->spa_server_resolve_ipv4)
        {
            //只会循环IPv4的协议族
            if(rp->ai_family != AF_INET)
            {
                log_msg(LOG_VERBOSITY_DEBUG, "Non-IPv4 resolution");
                continue;
            }
        }

        sock = socket(rp->ai_family, rp->ai_socktype,
                rp->ai_protocol);
        if (sock < 0)
            continue;

        /* 为UDP套接字调用连接函数的好处是： */
        /* 注意这里只要连接成功，就会退出循环 */
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
    //循环结束，释放空间
    if(result != NULL)
        freeaddrinfo(result);

    if (! sock_success) {
        log_msg(LOG_VERBOSITY_ERROR,
                "send_spa_packet_tcp_or_udp: Could not create socket: %s",
                strerror(errno));
        return -1;
    }
    //发送数据
    //这里可能是tcp也可能是udp，具体的形式，要看上面设置的协议，统一使用send函数就可以发送
    res = send(sock, spa_data, sd_len, 0);

    if(res < 0)
    {
        log_msg(LOG_VERBOSITY_ERROR, "send_spa_packet_tcp_or_udp: write error: ", strerror(errno));
    }
    else if(res != sd_len)
    {
        log_msg(LOG_VERBOSITY_WARNING,
            "[#] Warning: bytes sent (%i) not spa data length (%i).",
            res, sd_len
        );
    }

#ifdef WIN32
    closesocket(sock);
#else
    //最后释放socket
    close(sock);
#endif

    return(res);
}

/* 通过原始TCP数据包发送SPA数据。 */
//发送原始TCP数据包
/* 2023/7/20 15:46:43 */
static int
send_spa_packet_tcp_raw(const char *spa_data, const int sd_len,
    const struct sockaddr_in *saddr, const struct sockaddr_in *daddr,
    const fko_cli_options_t *options)
{
#ifdef WIN32
    log_msg(LOG_VERBOSITY_ERROR,
        "send_spa_packet_tcp_raw: raw packets are not yet supported.");
    return(-1);
#else
    int  sock, res = 0;
    char pkt_data[2048] = {0}; /* 对我们来说应该足够了 */

    struct iphdr  *iph  = (struct iphdr *) pkt_data;
    struct tcphdr *tcph = (struct tcphdr *) (pkt_data + sizeof (struct iphdr));

    int hdrlen = sizeof(struct iphdr) + sizeof(struct tcphdr);

    /* setsockopt的值。 */
    int         one     = 1;
    const int  *so_val  = &one;

    if (options->test)
    {
        log_msg(LOG_VERBOSITY_NORMAL,
            "test mode enabled, SPA packet not actually sent.");
        return res;
    }

    sock = socket (PF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0)
    {
        log_msg(LOG_VERBOSITY_ERROR, "send_spa_packet_tcp_raw: create socket: ", strerror(errno));
        return(sock);
    }

    /* 将水疗数据放在适当的位置。 */
    memcpy((pkt_data + hdrlen), spa_data, sd_len);

    /* 通过填充ip/tcp报头值来构造我们自己的报头， */
    iph->ihl        = 5;
    iph->version    = 4;
    iph->tos        = 0;
    /* 总大小为标头加有效负载 */
    iph->tot_len    = hdrlen + sd_len;
    /* 这里的值无关紧要 */
    srandom(time(NULL) ^ getuid() ^ (getgid() << 16) ^ getpid());
    iph->id         = random() & 0xffff;
    iph->frag_off   = 0;
    iph->ttl        = RAW_SPA_TTL;
    iph->protocol   = IPPROTO_TCP;
    iph->check      = 0;
    iph->saddr      = saddr->sin_addr.s_addr;
    iph->daddr      = daddr->sin_addr.s_addr;

    /* 现在TCP标头值。 */
    tcph->source    = saddr->sin_port;
    tcph->dest      = daddr->sin_port;
    tcph->seq       = htonl(1);
    tcph->ack_seq   = 0;
    tcph->doff      = 5;
    tcph->res1      = 0;
    /* TCP标志 */
    tcph->fin       = 0;
    tcph->syn       = 1;
    tcph->rst       = 0;
    tcph->psh       = 0;
    tcph->ack       = 0;
    tcph->urg       = 0;

    tcph->res2      = 0;
    tcph->window    = htons(32767);
    tcph->check     = 0;
    tcph->urg_ptr   = 0;

    /* 现在我们可以计算校验和了。 */
   //计算校验和
    iph->check = chksum((unsigned short *)pkt_data, iph->tot_len);

    /* 确保内核知道数据中包含标头，以便 */
   //保证内核知道头部包含在数据中，这样它就不会尝试将自己的头部插入数据包中
   //IP_HDRINCL选项可以让内核绕过协议栈，直接将数据包发送到网络上


    if (setsockopt (sock, IPPROTO_IP, IP_HDRINCL, so_val, sizeof(one)) < 0)
        log_msg(LOG_VERBOSITY_ERROR, "send_spa_packet_tcp_raw: setsockopt HDRINCL: ", strerror(errno));

    res = sendto (sock, pkt_data, iph->tot_len, 0,
        (struct sockaddr *)daddr, sizeof(*daddr));

    if(res < 0)
    {
        log_msg(LOG_VERBOSITY_ERROR, "send_spa_packet_tcp_raw: sendto error: ", strerror(errno));
    }
    else if(res != sd_len + hdrlen) /* 负责页眉？ */
    {
        log_msg(LOG_VERBOSITY_WARNING,
            "[#] Warning: bytes sent (%i) not spa data length (%i).",
            res, sd_len
        );
    }

    close(sock);

    return(res);

#endif /* ！WIN32 */
}

/* 通过原始UDP数据包发送SPA数据。 */
//发送原始UDP数据包
/* 这段代码是一个函数发送文件包udp_raw的实现，用于发送原始的UDP数据包。 */
static int
send_spa_packet_udp_raw(const char *spa_data, const int sd_len,
    const struct sockaddr_in *saddr, const struct sockaddr_in *daddr,
    const fko_cli_options_t *options)
{
#ifdef WIN32
    log_msg(LOG_VERBOSITY_ERROR,
        "send_spa_packet_udp_raw: raw packets are not yet supported.");
    return(-1);
#else
    int  sock, res = 0;
    char pkt_data[2048] = {0}; /* 对我们来说应该足够了 */

    struct iphdr  *iph  = (struct iphdr *) pkt_data;
    struct udphdr *udph = (struct udphdr *) (pkt_data + sizeof (struct iphdr));

    int hdrlen = sizeof(struct iphdr) + sizeof(struct udphdr);

    /* setsockopt的值。 */
    int         one     = 1;
    const int  *so_val  = &one;

    if (options->test)
    {
        log_msg(LOG_VERBOSITY_NORMAL,
            "test mode enabled, SPA packet not actually sent.");
        return res;
    }

    sock = socket (PF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0)
    {
        log_msg(LOG_VERBOSITY_ERROR, "send_spa_packet_udp_raw: create socket: ", strerror(errno));
        return(sock);
    }

    /* 将水疗数据放在适当的位置。 */
    memcpy((pkt_data + hdrlen), spa_data, sd_len);

    /* 通过填写ip/udp头值来构建我们自己的头， */
    iph->ihl        = 5;
    iph->version    = 4;
    iph->tos        = 0;
    /* 总大小为标头加有效负载 */
    iph->tot_len    = hdrlen + sd_len;
    /* 这里的值无关紧要 */
    srandom(time(NULL) ^ getuid() ^ (getgid() << 16) ^ getpid());
    iph->id         = random() & 0xffff;
    iph->frag_off   = 0;
    iph->ttl        = RAW_SPA_TTL;
    iph->protocol   = IPPROTO_UDP;
    iph->check      = 0;
    iph->saddr      = saddr->sin_addr.s_addr;
    iph->daddr      = daddr->sin_addr.s_addr;

    /* 现在UDP标头值。 */
    udph->source    = saddr->sin_port;
    udph->dest      = daddr->sin_port;
    udph->check     = 0;
    udph->len       = htons(sd_len + sizeof(struct udphdr));

    /* 现在我们可以计算校验和了。 */
    iph->check = chksum((unsigned short *)pkt_data, iph->tot_len);

    /* 确保内核知道数据中包含标头，以便 */
    if (setsockopt (sock, IPPROTO_IP, IP_HDRINCL, so_val, sizeof(one)) < 0)
        log_msg(LOG_VERBOSITY_ERROR, "send_spa_packet_udp_raw: setsockopt HDRINCL: ", strerror(errno));

    res = sendto (sock, pkt_data, iph->tot_len, 0,
        (struct sockaddr *)daddr, sizeof(*daddr));

    if(res < 0)
    {
        log_msg(LOG_VERBOSITY_ERROR, "send_spa_packet_udp_raw: sendto error: ", strerror(errno));
    }
    else if(res != sd_len + hdrlen) /* 负责页眉？ */
    {
        log_msg(LOG_VERBOSITY_WARNING,
            "[#] Warning: bytes sent (%i) not spa data length (%i).",
            res, sd_len
        );
    }

    close(sock);

    return(res);

#endif /* ！WIN32 */
}

/* 通过ICMP数据包发送SPA数据。 */
//发送ICMP数据包
/* 这段代码是用于通过ICMP协议发送SPA数据包的函数。下面是代码的执行流程： */
static int
send_spa_packet_icmp(const char *spa_data, const int sd_len,
    const struct sockaddr_in *saddr, const struct sockaddr_in *daddr,
    const fko_cli_options_t *options)
{
#ifdef WIN32
    log_msg(LOG_VERBOSITY_ERROR, "send_spa_packet_icmp: raw packets are not yet supported.");
    return(-1);
#else
    int res = 0, sock;
    char pkt_data[2048] = {0};

    struct iphdr  *iph    = (struct iphdr *) pkt_data;
    struct icmphdr *icmph = (struct icmphdr *) (pkt_data + sizeof (struct iphdr));

    int hdrlen = sizeof(struct iphdr) + sizeof(struct icmphdr);

    /* setsockopt的值。 */
    int         one     = 1;
    const int  *so_val  = &one;

    if (options->test)
    {
        log_msg(LOG_VERBOSITY_NORMAL,
            "test mode enabled, SPA packet not actually sent.");
        return res;
    }

    sock = socket (PF_INET, SOCK_RAW, IPPROTO_RAW);

    if (sock < 0)
    {
        log_msg(LOG_VERBOSITY_ERROR, "send_spa_packet_icmp: create socket: ", strerror(errno));
        return(sock);
    }

    /* 将水疗数据放在适当的位置。 */
    memcpy((pkt_data + hdrlen), spa_data, sd_len);

    /* 通过填写ip/icmp头值来构建我们自己的头， */
    iph->ihl        = 5;
    iph->version    = 4;
    iph->tos        = 0;
    /* 总大小为标头加有效负载 */
    iph->tot_len    = hdrlen + sd_len;
    /* 这里的值无关紧要 */
    srandom(time(NULL) ^ getuid() ^ (getgid() << 16) ^ getpid());
    iph->id         = random() & 0xffff;
    iph->frag_off   = 0;
    iph->ttl        = RAW_SPA_TTL;
    iph->protocol   = IPPROTO_ICMP;
    iph->check      = 0;
    iph->saddr      = saddr->sin_addr.s_addr;
    iph->daddr      = daddr->sin_addr.s_addr;

    /* 现在ICMP标头值。 */
    icmph->type     = options->spa_icmp_type;
    icmph->code     = options->spa_icmp_code;
    icmph->checksum = 0;

    if(icmph->type == ICMP_ECHO && icmph->code == 0)
    {
        icmph->un.echo.id       = htons(random() & 0xffff);
        icmph->un.echo.sequence = htons(1);
    }

    /* 现在我们可以计算校验和了。 */
    iph->check = chksum((unsigned short *)pkt_data, iph->tot_len);
    icmph->checksum = chksum((unsigned short *)icmph, sizeof(struct icmphdr) + sd_len);

    /* 确保内核知道数据中包含标头，以便 */
    if (setsockopt (sock, IPPROTO_IP, IP_HDRINCL, so_val, sizeof(one)) < 0)
        log_msg(LOG_VERBOSITY_ERROR, "send_spa_packet_icmp: setsockopt HDRINCL: ", strerror(errno));

    res = sendto (sock, pkt_data, iph->tot_len, 0,
        (struct sockaddr *)daddr, sizeof(*daddr));

    if(res < 0)
    {
        log_msg(LOG_VERBOSITY_ERROR, "send_spa_packet_icmp: sendto error: ", strerror(errno));
    }
    else if(res != sd_len + hdrlen) /* icmp标头的帐户 */
    {
        log_msg(LOG_VERBOSITY_WARNING, "[#] Warning: bytes sent (%i) not spa data length (%i).",
            res, sd_len);
    }

    close(sock);

    return(res);

#endif /* ！WIN32 */
}

/* 通过HTTP请求发送SPA数据包 */
/* 首先，函数开始时定义了一些变量。http_buf是用来存放HTTP请求内容的字符数组，初始化为全0spa_data_copy是用来保存拷贝的SPA数据的指针，初始时为空。 */
static int
send_spa_packet_http(const char *spa_data, const int sd_len,
    fko_cli_options_t *options)
{
    char http_buf[HTTP_MAX_REQUEST_LEN] = {0}, *spa_data_copy = NULL;
    char *ndx = options->http_proxy;
    int  i, proxy_port = 0, is_err;

    spa_data_copy = malloc(sd_len+1);
    if (spa_data_copy == NULL)
    {
        log_msg(LOG_VERBOSITY_ERROR, "[*] Fatal, could not allocate memory.");
        return -1;
    }
    memcpy(spa_data_copy, spa_data, sd_len+1);

    /* 对于HTTP请求（服务器 */
    for (i=0; i < sd_len; i++) {
        if (spa_data_copy[i] == '+') {
            spa_data_copy[i] = '-';
        }
        else if (spa_data_copy[i] == '/') {
            spa_data_copy[i] = '_';
        }
    }

    if(options->http_proxy[0] == 0x0)
    {
        snprintf(http_buf, HTTP_MAX_REQUEST_LEN,
            "GET /%s HTTP/1.1\r\nUser-Agent: %s\r\nAccept: */* \\r\n“ */
        );
    }
    else /* 我们正在通过HTTP代理发送SPA数据包 */
    {
        /* 如果主机名被指定为URL，则提取该主机名。事实上 */
        if(strncasecmp(ndx, "http://", 7) == 0)
            memmove(ndx, ndx+7, strlen(ndx)+1);

        /* 如果有冒号，则假定代理主机名或IP在左边 */
        ndx = strchr(options->http_proxy, ':');
        if(ndx)
        {
            *ndx = '\0';
            proxy_port = strtol_wrapper(ndx+1, 1, MAX_PORT, NO_EXIT_UPON_ERR, &is_err);
            if(is_err != FKO_SUCCESS)
            {
                log_msg(LOG_VERBOSITY_ERROR,
                    "[-] proxy port value is invalid, must be in [%d-%d]",
                    1, MAX_PORT);
                free(spa_data_copy);
                return -1;
            }
        }

        /* 如果我们有一个有效的端口值，请使用它。 */
        if(proxy_port)
            options->spa_dst_port = proxy_port;

        snprintf(http_buf, HTTP_MAX_REQUEST_LEN,
            "GET http://%s/%s HTTP/1.1\r\nUser-Agent: %s\r\nAccept: */* \\r\n“ */
        );
        strlcpy(options->spa_server_str, options->http_proxy,
                sizeof(options->spa_server_str));
    }
    free(spa_data_copy);

    if (options->test)
    {
        log_msg(LOG_VERBOSITY_INFO, "%s", http_buf);

        log_msg(LOG_VERBOSITY_NORMAL,
            "Test mode enabled, SPA packet not actually sent.");
        return 0;
    }

    /* 在AFL模糊模式下，以下功能不会发送 */
    return send_spa_packet_tcp_or_udp(http_buf, strlen(http_buf), options);
}

/* 用于发送SPA数据的函数。 */
//用于发送spa数据的函数
/* 这段代码是一个名为发送包裹的函数，用于发送SPA数据包。 */
//使用该函数可以封装前面的几种协议的函数
int
send_spa_packet(fko_ctx_t ctx, fko_cli_options_t *options)
{
    int                 res, sd_len;
    char               *spa_data;
    struct sockaddr_in  saddr, daddr;
    //字符串用于包含主机名的ip地址
    char                ip_str[INET_ADDRSTRLEN] = {0};  /* 用于包含主机名的ip地址的字符串 */ 
    //用于设置hints以解析主机名的结构
    struct addrinfo     hints;                          /* 用于设置提示以解析主机名的结构 */
#ifdef WIN32
    WSADATA wsa_data;
#endif

    /* 初始化提示缓冲区 */
    //初始化hints
    memset(&hints, 0 , sizeof(hints));

    /* 点击此处获取我们的水疗数据。 */
    res = fko_get_spa_data(ctx, &spa_data);

    if(res != FKO_SUCCESS)
    {
        log_msg(LOG_VERBOSITY_ERROR,
            "send_spa_packet: Error #%i from fko_get_spa_data: %s",
            res, fko_errstr(res)
        );
        return(-1);
    }

    sd_len = strlen(spa_data);

#ifdef WIN32
    /* Winsock需要初始化。。。 */
    res = WSAStartup( MAKEWORD(1,1), &wsa_data );
    if( res != 0 )
    {
        log_msg(LOG_VERBOSITY_ERROR, "Winsock initialization error %d", res );
        return(-1);
    }
#endif

    errno = 0;
    
    dump_transmit_options(options);

    if (options->spa_proto == FKO_PROTO_TCP || options->spa_proto == FKO_PROTO_UDP)
    {
        res = send_spa_packet_tcp_or_udp(spa_data, sd_len, options);
    }
    else if (options->spa_proto == FKO_PROTO_HTTP)
    {
        res = send_spa_packet_http(spa_data, sd_len, options);
    }
    else if (options->spa_proto == FKO_PROTO_TCP_RAW
            || options->spa_proto == FKO_PROTO_UDP_RAW
            || options->spa_proto == FKO_PROTO_ICMP)
    {
        memset(&saddr, 0, sizeof(saddr));
        memset(&daddr, 0, sizeof(daddr));

        saddr.sin_family = AF_INET;
        daddr.sin_family = AF_INET;

        /* 设置源地址和端口 */
        if (options->spa_src_port)
            saddr.sin_port = htons(options->spa_src_port);
        else
            saddr.sin_port = INADDR_ANY;

        if (options->spoof_ip_src_str[0] != 0x00) {
            saddr.sin_addr.s_addr = inet_addr(options->spoof_ip_src_str);
        } else
            saddr.sin_addr.s_addr = INADDR_ANY;  /* 违约 */

        if (saddr.sin_addr.s_addr == -1)
        {
            log_msg(LOG_VERBOSITY_ERROR, "Could not set source IP.");
            return -1;
        }

        /* 设置目标端口 */
        daddr.sin_port = htons(options->spa_dst_port);

        /* 设置目标地址。我们使用默认协议来解决 */
        hints.ai_family = AF_INET;

#if AFL_FUZZING
        /* 确保永远不要在AFL模糊循环下发送SPA数据包 */
        log_msg(LOG_VERBOSITY_NORMAL,
            "AFL fuzzing enabled, SPA packet not actually sent.");
        return res;
#endif

        if (resolve_dst_addr(options->spa_server_str,
                    &hints, ip_str, sizeof(ip_str), options) != 0)
        {
            log_msg(LOG_VERBOSITY_ERROR, "[*] Unable to resolve %s as an ip address",
                    options->spa_server_str);
            return -1;
        }
        else;

        daddr.sin_addr.s_addr = inet_addr(ip_str);

        if (options->spa_proto == FKO_PROTO_TCP_RAW)
        {
            res = send_spa_packet_tcp_raw(spa_data, sd_len, &saddr, &daddr, options);
        }
        else if (options->spa_proto == FKO_PROTO_UDP_RAW)
        {
            res = send_spa_packet_udp_raw(spa_data, sd_len, &saddr, &daddr, options);
        }
        else
        {
            res = send_spa_packet_icmp(spa_data, sd_len, &saddr, &daddr, options);
        }
    }
    else
    {
        /* --DSS XXX：我们在这里真正想做什么？ */
        log_msg(LOG_VERBOSITY_ERROR, "%i is not a valid or supported protocol.",
            options->spa_proto);
        res = -1;
    }

    return res;
}

/* 将SPA数据包数据写入文件系统的函数 */
//将SPA数据写入文件
/* 2023/7/20 16:28:35 */
int write_spa_packet_data(fko_ctx_t ctx, const fko_cli_options_t *options)
{
    FILE   *fp;
    char   *spa_data;
    int     res;

    res = fko_get_spa_data(ctx, &spa_data);

    if(res != FKO_SUCCESS)
    {
        log_msg(LOG_VERBOSITY_ERROR,
            "write_spa_packet_data: Error #%i from fko_get_spa_data: %s",
            res, fko_errstr(res)
        );

        return(-1);
    }

    if (options->save_packet_file_append)
    {
        fp = fopen(options->save_packet_file, "a");
    }
    else
    {
        unlink(options->save_packet_file);
        fp = fopen(options->save_packet_file, "w");
    }

    if(fp == NULL)
    {
        log_msg(LOG_VERBOSITY_ERROR, "write_spa_packet_data: ", strerror(errno));
        return(-1);
    }

    fprintf(fp, "%s\n",
        (spa_data == NULL) ? "<NULL>" : spa_data);

    fclose(fp);

    return(0);
}

/* **EOF** */
