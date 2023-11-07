
#include "common.h"
#include "spanop_common.h"
#include "utils.h"
#ifndef WIN32
#include <arpa/inet.h>
#endif

static void *get_in_addr(struct sockaddr *sa);

/* * */
typedef struct ztn_protocol
{
    const char  str[PROTOCOL_BUFSIZE];      /* ！<表示ZTN库的协议值的字符串 */
    int         val;                        /* ！<根据ZTN库的协议值 */
} ztn_protocol_t;

static ztn_protocol_t ztn_protocol_array[] =
{
    { "udpraw", ZTN_PROTO_UDP_RAW   },
    { "udp",    ZTN_PROTO_UDP       },
    { "tcpraw", ZTN_PROTO_TCP_RAW   },
    { "tcp",    ZTN_PROTO_TCP       },
    { "icmp",   ZTN_PROTO_ICMP      },
    { "http",   ZTN_PROTO_HTTP      }
};

int
verify_file_perms_ownership(const char *file, int fd)
{
    int res = 1;

#if HAVE_FSTAT && HAVE_STAT
    struct stat st;

    /* spa客户端处理的每个文件都应该拥有 */
    if((fd >= 0 && fstat(fd, &st) == 0) || stat(file, &st) == 0)
    {
        /* 确保它是一个常规文件 */
        if(S_ISREG(st.st_mode) != 1 && S_ISLNK(st.st_mode) != 1)
        {
            log_msg(LOG_VERBOSITY_ERROR,
                "[-] file: %s is not a regular file or symbolic link.",
                file
            );
            /* 当我们开始强制执行而不仅仅是警告 */
        }

        if((st.st_mode & (S_IRWXU|S_IRWXG|S_IRWXO)) != (S_IRUSR|S_IWUSR))
        {
            log_msg(LOG_VERBOSITY_ERROR,
                "[-] file: %s permissions should only be user read/write (0600, -rw-------)",
                file
            );
            /* 当我们开始强制执行而不仅仅是警告 */
        }

        if(st.st_uid != getuid())
        {
            log_msg(LOG_VERBOSITY_ERROR, "[-] file: %s not owned by current effective user id",
                file);
            /* 当我们开始强制执行而不仅仅是警告 */
        }
    }
    else
    {
        /* 如果路径不存在，则返回，否则返回 */
        if(errno != ENOENT)
        {
            log_msg(LOG_VERBOSITY_ERROR, "[-] stat() against file: %s returned: %s",
                file, strerror(errno));
            res = 0;
        }
    }
#endif

    return res;
}

/* * */
static void *
get_in_addr(struct sockaddr *sa)
{
  if (sa->sa_family == AF_INET)
  {
    return &(((struct sockaddr_in*)sa)->sin_addr);
  }

  else
  {
    return &(((struct sockaddr_in6*)sa)->sin6_addr);
  }
}

/* * */
int
resolve_dst_addr(const char *dns_str, struct addrinfo *hints,
        char *ip_str, size_t ip_bufsize, ztn_cli_options_t *opts)
{
    int                 error;      /* 函数错误返回代码 */
    struct addrinfo    *result;     /* getaddrinfo（）的结果 */
    struct addrinfo    *rp;         /* getaddrinfo（）返回的链表的元素 */
#if WIN32 && WINVER <= 0x0600
	struct sockaddr_in *in;
	char			   *win_ip;
#else
    struct sockaddr_in *sai_remote; /* 作为sockaddr_in结构的远程主机信息 */
#endif

    /* 尝试解析主机名 */
    error = getaddrinfo(dns_str, NULL, hints, &result);
    if (error != 0)
        fprintf(stderr, "resolve_dst_addr() : %s\n", gai_strerror(error));

    else
    {
        error = 1;

        /* 浏览addrinfo结构的链接列表 */
        for (rp = result; rp != NULL; rp = rp->ai_next)
        {
            /* 应用--server-resolve-ipv4条件 */
            if(opts->spa_server_resolve_ipv4)
            {
                if(rp->ai_family != AF_INET)
                {
                    log_msg(LOG_VERBOSITY_DEBUG, "Non-IPv4 resolution");
                    continue;
                }
            }

            memset(ip_str, 0, ip_bufsize);
#if WIN32 && WINVER <= 0x0600
			/* 在较旧的Windows系统上（Vista之前的任何系统？）， */
			in = (struct sockaddr_in*)(rp->ai_addr);
			win_ip = inet_ntoa(in->sin_addr);

			if (win_ip != NULL && (strlcpy(ip_str, win_ip, ip_bufsize) > 0))
#else
            sai_remote = (struct sockaddr_in *)get_in_addr((struct sockaddr *)(rp->ai_addr));
            if (inet_ntop(rp->ai_family, sai_remote, ip_str, ip_bufsize) != NULL)
#endif
            {
                error = 0;
                break;
            }
            else
                log_msg(LOG_VERBOSITY_ERROR, "resolve_dst_addr() : inet_ntop (%d) - %s",
                        errno, strerror(errno));
        }

        /* 从getaddrinfo（）释放我们的结果 */
        freeaddrinfo(result);
    }

    return error;
}

/* * */
short
proto_inttostr(int proto, char *proto_str, size_t proto_size)
{
    short           proto_error = -1;
    unsigned char   ndx_proto;          /* ztn_procol_t结构的索引 */

    /* 初始化协议字符串 */
    memset(proto_str, 0, proto_size);

    /* 查看ztn_procol_array以找到正确的协议 */
    for (ndx_proto = 0 ; ndx_proto < ARRAY_SIZE(ztn_protocol_array) ; ndx_proto++)
    {
        /* 如果协议匹配，就抓住它 */
        if (ztn_protocol_array[ndx_proto].val == proto)
        {
            strlcpy(proto_str, ztn_protocol_array[ndx_proto].str, proto_size);
            proto_error = 0;
            break;
        }
    }

    return proto_error;

}

/* * */
short
proto_strtoint(const char *pr_str)
{
    unsigned char   ndx_proto;          /* ztn_procol_t结构的索引 */
    int             proto_int = -1;     /* 协议整数值 */

    /* 查看ztn_procol_array以找到正确的协议 */
    for (ndx_proto = 0 ; ndx_proto < ARRAY_SIZE(ztn_protocol_array) ; ndx_proto++)
    {
        /* 如果协议匹配，就抓住它 */
        if (strcasecmp(pr_str, ztn_protocol_array[ndx_proto].str) == 0)
        {
            proto_int = ztn_protocol_array[ndx_proto].val;
            break;
        }
    }

    return proto_int;
}

/* **EOF** */
