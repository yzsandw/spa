
#include "md5.h"
#include "ztn_common.h"

#if BYTEORDER == 1234
  #define byteReverse(buf, len)    /* 没有什么 */
#elif BYTEORDER == 4321
  /* 注意：这段代码在little-endian机器上是无害的。 */
  void byteReverse(unsigned char *buf, unsigned longs)
  {
      uint32_t t;
      do {
          t = (uint32_t) ((unsigned) buf[3] << 8 | buf[2]) << 16 |
              ((unsigned) buf[1] << 8 | buf[0]);
          *(uint32_t *) buf = t;
          buf += 4;
      } while (--longs);
  }
#else
  #define byteReverse(buf, len)    /* 没有什么 */
  #ifndef WIN32
    #warning Undetermined or unsupported Byte Order... We will try LITTLE_ENDIAN
  #endif
#endif

/* *启动MD5累加。将位计数设置为0，将缓冲区设置为神秘 */
void
MD5Init(MD5Context *ctx)
{
    ctx->buf[0] = 0x67452301;
    ctx->buf[1] = 0xefcdab89;
    ctx->buf[2] = 0x98badcfe;
    ctx->buf[3] = 0x10325476;

    ctx->bits[0] = 0;
    ctx->bits[1] = 0;
}

/* 更新上下文以反映另一个缓冲区已满的串联 */
void
MD5Update(MD5Context *ctx, unsigned char *buf, unsigned len)
{
    uint32_t t;

    /* 更新位计数 */
    t = ctx->bits[0];
    if ((ctx->bits[0] = t + ((uint32_t) len << 3)) < t)
    ctx->bits[1]++;     /* 从低到高进位 */
    ctx->bits[1] += len >> 29;

    t = (t >> 3) & 0x3f;    /* shsInfo->数据中已存在的字节数 */

    /* 处理任何前导的奇数大小的块 */
    if (t) {
        unsigned char *p = (unsigned char *) ctx->in + t;

        t = 64 - t;

        if (len < t) {
            memcpy(p, buf, len);
            return;
        }

        memcpy(p, buf, t);
        byteReverse(ctx->in, 16);
        MD5Transform(ctx->buf, (uint32_t *) ctx->in);
        buf += t;
        len -= t;
    }

    /* 以64字节块处理数据 */
    while (len >= 64) {
        memcpy(ctx->in, buf, 64);
        byteReverse(ctx->in, 16);
        MD5Transform(ctx->buf, (uint32_t *) ctx->in);
        buf += 64;
        len -= 64;
    }

    /* 处理任何剩余的数据字节。 */
    memcpy(ctx->in, buf, len);
}

/* 最终封装-使用位模式填充到64字节边界 */
void
MD5Final(unsigned char digest[16], MD5Context *ctx)
{
    unsigned count;
    unsigned char *p;

    /* 计算字节数mod 64 */
    count = (ctx->bits[0] >> 3) & 0x3F;

    /* 将填充的第一个字符设置为0x80。这是安全的，因为有 */
    p = ctx->in + count;
    *p++ = 0x80;

    /* 生成64字节所需的填充字节 */
    count = 64 - 1 - count;

    /* 填充到56 mod 64 */
    if (count < 8) {
        /* 两组填充：将第一个块填充为64字节 */
        memset(p, 0, count);
        byteReverse(ctx->in, 16);
        MD5Transform(ctx->buf, (uint32_t *) ctx->in);

        /* 现在用56个字节填充下一个块 */
        memset(ctx->in, 0, 56);
    } else {
        /* 将块填充到56字节 */
        memset(p, 0, count - 8);
    }

    byteReverse(ctx->in, 14);

    /* 以位为单位的附加长度和变换 */
    memcpy(&(ctx->in[56]), &(ctx->bits[0]), sizeof(uint32_t));
    memcpy(&(ctx->in[60]), &(ctx->bits[1]), sizeof(uint32_t));

    MD5Transform(ctx->buf, (uint32_t *) ctx->in);
    byteReverse((unsigned char *) ctx->buf, 4);
    memcpy(digest, ctx->buf, 16);

    memset(ctx, 0, sizeof(*ctx));        /* 以防敏感 */
}


/* 四大核心功能 */
#define F1(x, y, z) (z ^ (x & (y ^ z)))
#define F2(x, y, z) F1(z, x, y)
#define F3(x, y, z) (x ^ y ^ z)
#define F4(x, y, z) (y ^ (x | ~z))

/* 这是MD5算法的核心步骤。 */
#define MD5STEP(f, w, x, y, z, data, s) \
    ( w += f(x, y, z) + data,  w = w<<s | w>>(32-s),  w += x )

/* MD5算法的核心，这将现有的MD5哈希更改为 */
void
MD5Transform(uint32_t buf[4], uint32_t in[16])
{
    register uint32_t a, b, c, d;

    a = buf[0];
    b = buf[1];
    c = buf[2];
    d = buf[3];

    MD5STEP(F1, a, b, c, d, in[0]  + 0xd76aa478, 7);
    MD5STEP(F1, d, a, b, c, in[1]  + 0xe8c7b756, 12);
    MD5STEP(F1, c, d, a, b, in[2]  + 0x242070db, 17);
    MD5STEP(F1, b, c, d, a, in[3]  + 0xc1bdceee, 22);
    MD5STEP(F1, a, b, c, d, in[4]  + 0xf57c0faf, 7);
    MD5STEP(F1, d, a, b, c, in[5]  + 0x4787c62a, 12);
    MD5STEP(F1, c, d, a, b, in[6]  + 0xa8304613, 17);
    MD5STEP(F1, b, c, d, a, in[7]  + 0xfd469501, 22);
    MD5STEP(F1, a, b, c, d, in[8]  + 0x698098d8, 7);
    MD5STEP(F1, d, a, b, c, in[9]  + 0x8b44f7af, 12);
    MD5STEP(F1, c, d, a, b, in[10] + 0xffff5bb1, 17);
    MD5STEP(F1, b, c, d, a, in[11] + 0x895cd7be, 22);
    MD5STEP(F1, a, b, c, d, in[12] + 0x6b901122, 7);
    MD5STEP(F1, d, a, b, c, in[13] + 0xfd987193, 12);
    MD5STEP(F1, c, d, a, b, in[14] + 0xa679438e, 17);
    MD5STEP(F1, b, c, d, a, in[15] + 0x49b40821, 22);

    MD5STEP(F2, a, b, c, d, in[1]  + 0xf61e2562, 5);
    MD5STEP(F2, d, a, b, c, in[6]  + 0xc040b340, 9);
    MD5STEP(F2, c, d, a, b, in[11] + 0x265e5a51, 14);
    MD5STEP(F2, b, c, d, a, in[0]  + 0xe9b6c7aa, 20);
    MD5STEP(F2, a, b, c, d, in[5]  + 0xd62f105d, 5);
    MD5STEP(F2, d, a, b, c, in[10] + 0x02441453, 9);
    MD5STEP(F2, c, d, a, b, in[15] + 0xd8a1e681, 14);
    MD5STEP(F2, b, c, d, a, in[4]  + 0xe7d3fbc8, 20);
    MD5STEP(F2, a, b, c, d, in[9]  + 0x21e1cde6, 5);
    MD5STEP(F2, d, a, b, c, in[14] + 0xc33707d6, 9);
    MD5STEP(F2, c, d, a, b, in[3]  + 0xf4d50d87, 14);
    MD5STEP(F2, b, c, d, a, in[8]  + 0x455a14ed, 20);
    MD5STEP(F2, a, b, c, d, in[13] + 0xa9e3e905, 5);
    MD5STEP(F2, d, a, b, c, in[2]  + 0xfcefa3f8, 9);
    MD5STEP(F2, c, d, a, b, in[7]  + 0x676f02d9, 14);
    MD5STEP(F2, b, c, d, a, in[12] + 0x8d2a4c8a, 20);

    MD5STEP(F3, a, b, c, d, in[5]  + 0xfffa3942, 4);
    MD5STEP(F3, d, a, b, c, in[8]  + 0x8771f681, 11);
    MD5STEP(F3, c, d, a, b, in[11] + 0x6d9d6122, 16);
    MD5STEP(F3, b, c, d, a, in[14] + 0xfde5380c, 23);
    MD5STEP(F3, a, b, c, d, in[1]  + 0xa4beea44, 4);
    MD5STEP(F3, d, a, b, c, in[4]  + 0x4bdecfa9, 11);
    MD5STEP(F3, c, d, a, b, in[7]  + 0xf6bb4b60, 16);
    MD5STEP(F3, b, c, d, a, in[10] + 0xbebfbc70, 23);
    MD5STEP(F3, a, b, c, d, in[13] + 0x289b7ec6, 4);
    MD5STEP(F3, d, a, b, c, in[0]  + 0xeaa127fa, 11);
    MD5STEP(F3, c, d, a, b, in[3]  + 0xd4ef3085, 16);
    MD5STEP(F3, b, c, d, a, in[6]  + 0x04881d05, 23);
    MD5STEP(F3, a, b, c, d, in[9]  + 0xd9d4d039, 4);
    MD5STEP(F3, d, a, b, c, in[12] + 0xe6db99e5, 11);
    MD5STEP(F3, c, d, a, b, in[15] + 0x1fa27cf8, 16);
    MD5STEP(F3, b, c, d, a, in[2]  + 0xc4ac5665, 23);

    MD5STEP(F4, a, b, c, d, in[0]  + 0xf4292244, 6);
    MD5STEP(F4, d, a, b, c, in[7]  + 0x432aff97, 10);
    MD5STEP(F4, c, d, a, b, in[14] + 0xab9423a7, 15);
    MD5STEP(F4, b, c, d, a, in[5]  + 0xfc93a039, 21);
    MD5STEP(F4, a, b, c, d, in[12] + 0x655b59c3, 6);
    MD5STEP(F4, d, a, b, c, in[3]  + 0x8f0ccc92, 10);
    MD5STEP(F4, c, d, a, b, in[10] + 0xffeff47d, 15);
    MD5STEP(F4, b, c, d, a, in[1]  + 0x85845dd1, 21);
    MD5STEP(F4, a, b, c, d, in[8]  + 0x6fa87e4f, 6);
    MD5STEP(F4, d, a, b, c, in[15] + 0xfe2ce6e0, 10);
    MD5STEP(F4, c, d, a, b, in[6]  + 0xa3014314, 15);
    MD5STEP(F4, b, c, d, a, in[13] + 0x4e0811a1, 21);
    MD5STEP(F4, a, b, c, d, in[4]  + 0xf7537e82, 6);
    MD5STEP(F4, d, a, b, c, in[11] + 0xbd3af235, 10);
    MD5STEP(F4, c, d, a, b, in[2]  + 0x2ad7d2bb, 15);
    MD5STEP(F4, b, c, d, a, in[9]  + 0xeb86d391, 21);

    buf[0] += a;
    buf[1] += b;
    buf[2] += c;
    buf[3] += d;
}

/* **EOF** */
