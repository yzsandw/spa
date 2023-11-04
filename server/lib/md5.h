
#ifndef MD5_H
#define MD5_H 1

#include "common.h"

#define MD5_BLOCK_LEN       64
#define MD5_DIGEST_LEN      16
#define MD5_DIGEST_STR_LEN  (MD5_DIGEST_LEN * 2 + 1)
#define MD5_B64_LEN         22

typedef struct _MD5Context {
        uint32_t buf[4];
        uint32_t bits[2];
        unsigned char in[64];
} MD5Context;

void MD5Init(MD5Context*);
void MD5Update(MD5Context *ctx, unsigned char *buf, unsigned len);
void MD5Final(unsigned char digest[16], MD5Context *ctx);
void MD5Transform(uint32_t buf[4], uint32_t in[16]);

#endif /* MD5_H */

/* **EOF** */
