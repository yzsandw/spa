/**
 * \file server/process_packet.h
 *
 * \brief process_packet和其他spad代码的头文件。
 */

#ifndef PROCESS_PACKET_H
#define PROCESS_PACKET_H

#if USE_LIBPCAP
  #include <pcap.h>
  #define PACKET_HEADER_META const struct pcap_pkthdr *packet_header
  #define PROCESS_PKT_ARGS_TYPE unsigned char
#else
  #define PACKET_HEADER_META unsigned short pkt_len
  #define PROCESS_PKT_ARGS_TYPE ztn_srv_options_t
#endif

#define IPV4_VER_MASK   0x15
#define MIN_IPV4_WORDS  0x05

/* 对于此系统未定义的项目
*/
#ifndef ETHER_CRC_LEN
  #define ETHER_CRC_LEN 4
#endif
#ifndef ETHER_HDR_LEN
  #define ETHER_HDR_LEN 14
#endif


void process_packet(PROCESS_PKT_ARGS_TYPE *opts, PACKET_HEADER_META,
					const unsigned char *packet);

#endif  /* PROCESS_PACKET_H */
