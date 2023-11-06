
#ifndef UTILS_H
#define UTILS_H

#if HAVE_CONFIG_H
  #include "config.h"
#endif

#include <sys/types.h>
#ifdef WIN32
  #include <winsock2.h>
  #include <ws2tcpip.h>
#else
  #if HAVE_SYS_SOCKET_H
    #include <sys/socket.h>
  #endif
  #include <netdb.h>
#endif

#define PROTOCOL_BUFSIZE    16      /*最大的协议字符串长度（例如TCP）*/
#define FD_INVALID          -1
#define FD_IS_VALID(x)      ((x)>=0)


//检测文件所有权
int     verify_file_perms_ownership(const char *file, int fd);
//解析目标地址
int     resolve_dst_addr(const char *dns_str, struct addrinfo *hints,
            char *ip_str, size_t ip_bufsize, fko_cli_options_t *opts);
//int -> str
short   proto_inttostr(int proto, char *proto_str, size_t proto_size);
//str -> int
short   proto_strtoint(const char *pr_str);

#endif  /* UTILS_H */
