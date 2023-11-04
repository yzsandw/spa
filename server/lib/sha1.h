
#ifndef SHA1_H
#define SHA1_H 1

#include "common.h"

#ifdef WIN32
  #define BYTEORDER 1234
#endif

/* 截断到32位--在32位计算机上应该是null操作 */
#ifndef TRUNC32
  #define TRUNC32(x)  ((x) & 0xffffffffL)
#endif

#define SHA1_BLOCKSIZE      64
#define SHA1_BLOCK_LEN      SHA1_BLOCKSIZE
#define SHA1_DIGEST_LEN     20
#define SHA1_DIGEST_STR_LEN (SHA1_DIGEST_LEN * 2 + 1)
#define SHA1_B64_LEN        27

typedef struct {
    uint32_t    digest[8];
    uint32_t    count_lo, count_hi;
    uint8_t     data[SHA1_BLOCKSIZE];
    int         local;
} SHA1_INFO;

/* SHA1原型。 */
void sha1_init(SHA1_INFO *sha1_info);
void sha1_update(SHA1_INFO *sha1_info, uint8_t *buffer, int count);
void sha1_final(uint8_t digest[SHA1_DIGEST_LEN], SHA1_INFO *sha1_info);

#endif /* SHA1_H */
