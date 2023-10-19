/**
 * \file server/pcap_capture.h
 *
 * \brief  pcap_capture.c的头文件
 */

#ifndef PCAP_CAPTURE_H
#define PCAP_CAPTURE_H


#define MAX_PCAP_ERRORS_BEFORE_BAIL 100

#if defined(__FreeBSD__) || defined(__APPLE__)
    #define DEF_PCAP_NONBLOCK 0
#else
    #define DEF_PCAP_NONBLOCK 1
#endif

int pcap_capture(fko_srv_options_t *opts);

#endif  /* PCAP_CAPTURE_H */
