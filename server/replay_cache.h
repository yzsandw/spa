/**
 * \file server/replay_cache.h
 *
 * \brief fwknopd replay_cache.c函数的头文件。
 */

#ifndef REPLAY_CACHE_H
#define REPLAY_CACHE_H

#include "fwknopd_common.h"
#include "fko.h"

typedef struct digest_cache_info {
    unsigned int    src_ip;
    unsigned int    dst_ip;
    unsigned short  src_port;
    unsigned short  dst_port;
    unsigned char   proto;
    time_t          created;
    char           *digest;
#if ! USE_FILE_CACHE
    time_t          first_replay;
    time_t          last_replay;
    int             replay_count;
#endif
} digest_cache_info_t;

#if USE_FILE_CACHE
struct digest_cache_list {
    digest_cache_info_t cache_info;
    struct digest_cache_list *next;
};
#endif


int replay_cache_init(fko_srv_options_t *opts);
int is_replay(fko_srv_options_t *opts, char *digest);
int add_replay(fko_srv_options_t *opts, char *digest);
#ifdef USE_FILE_CACHE
void free_replay_list(fko_srv_options_t *opts);
#endif

#endif  /* REPLAY_CACHE_H */
