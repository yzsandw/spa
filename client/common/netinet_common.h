
#ifndef NETINET_COMMON_H
#define NETINET_COMMON_H

#ifdef WIN32
  #include <winsock2.h>
  #include <ws2tcpip.h>
#else
  #if HAVE_SYS_SOCKET_H
    #include <sys/socket.h>
  #endif
  #if HAVE_NETDB_H
    #include <netdb.h>
  #endif
  #if HAVE_NETINET_IN_H
    #include <netinet/in.h>
  #endif
  #if PLATFORM_NETBSD || PLATFORM_OPENBSD  /* 对于autoconf-net/if.h困难 */
    #include <net/if.h>
    #include <net/ethertypes.h>
    #include <netinet/if_ether.h>
    #ifndef ETHER_IS_VALID_LEN
      #define ETHER_IS_VALID_LEN(x) \
        ((x) >= ETHER_MIN_LEN && (x) <= ETHER_MAX_LEN)
    #endif
  #endif
  #if HAVE_ARPA_INET_H
    #include <arpa/inet.h>
  #endif
  #if HAVE_NET_ETHERNET_H
    #include <net/ethernet.h>
  #elif HAVE_SYS_ETHERNET_H
    #include <sys/ethernet.h> /* 似乎就是Solaris的用武之地。 */
    /* 可能还需要在此处定义ETHER_IS_VALID_LEN */
    #ifndef ETHER_IS_VALID_LEN
      #define ETHER_IS_VALID_LEN(x) \
        ((x) >= ETHERMIN && (x) <= ETHERMAX)
    #endif
  #endif
#endif

/* 我们将推出我们自己的包头结构。 */

/* IP标头 */
struct iphdr
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
    unsigned int ihl:4;
    unsigned int version:4;
#elif __BYTE_ORDER == __BIG_ENDIAN
    unsigned int version:4;
    unsigned int ihl:4;
#else
  #error       "Please fix <bits/endian.h>"
#endif
    unsigned char tos;
    unsigned short tot_len;
    unsigned short id;
    unsigned short frag_off;
    unsigned char ttl;
    unsigned char protocol;
    unsigned short check;
    unsigned int saddr;
    unsigned int daddr;
};

/* TCP标头 */
struct tcphdr
{
    unsigned short source;
    unsigned short dest;
    unsigned int seq;
    unsigned int ack_seq;
#if __BYTE_ORDER == __LITTLE_ENDIAN
    unsigned short res1:4;
    unsigned short doff:4;
    unsigned short fin:1;
    unsigned short syn:1;
    unsigned short rst:1;
    unsigned short psh:1;
    unsigned short ack:1;
    unsigned short urg:1;
    unsigned short res2:2;
#elif __BYTE_ORDER == __BIG_ENDIAN
    unsigned short doff:4;
    unsigned short res1:4;
    unsigned short res2:2;
    unsigned short urg:1;
    unsigned short ack:1;
    unsigned short psh:1;
    unsigned short rst:1;
    unsigned short syn:1;
    unsigned short fin:1;
#else
  #error "Adjust your <bits/endian.h> defines"
#endif
    unsigned short window;
    unsigned short check;
    unsigned short urg_ptr;
};

/* UDP标头 */
struct udphdr {
    unsigned short source;              /* 源端口 */
    unsigned short dest;                /* 目的港 */
    unsigned short len;                 /* udp长度 */
    unsigned short check;               /* udp校验和 */
};

/* ICMP标头 */
struct icmphdr
{
    unsigned char type;                 /* 消息类型 */
    unsigned char code;                 /* 类型子代码 */
    unsigned short checksum;
    union
    {
        struct
        {
            unsigned short  id;
            unsigned short  sequence;
        } echo;                         /* 回波数据报 */
        unsigned int    gateway;        /* 网关地址 */
        struct
        {
            unsigned short  __notused;
            unsigned short  mtu;
        } frag;                         /* 路径mtu发现 */
    } un;
};

#define ICMP_ECHOREPLY          0   /* 回显答复 */
#define ICMP_DEST_UNREACH       3   /* 无法访问目标 */
#define ICMP_SOURCE_QUENCH      4   /* 源淬火 */
#define ICMP_REDIRECT           5   /* 重定向（更改路由） */
#define ICMP_ECHO               8   /* 回显请求 */
#define ICMP_TIME_EXCEEDED      11  /* 超过的时间 */
#define ICMP_PARAMETERPROB      12  /* 参数问题 */
#define ICMP_TIMESTAMP          13  /* 时间戳请求 */
#define ICMP_TIMESTAMPREPLY     14  /* 时间戳回复 */
#define ICMP_INFO_REQUEST       15  /* 信息请求 */
#define ICMP_INFO_REPLY         16  /* 信息回复 */
#define ICMP_ADDRESS            17  /* 地址掩码请求 */
#define ICMP_ADDRESSREPLY       18  /* 地址掩码答复 */

#endif  /* NETINET_COMMON_H */
