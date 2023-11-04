/* * */

/* 作者：Aaron D.Gifford-http://www.aarongifford.com/ */
#ifndef __SHA2_H__
#define __SHA2_H__

#ifdef __cplusplus
extern "C" {
#endif

#include "common.h"

/* *从系统标头导入u_intXX_t size_t类型定义。你 */
#include <sys/types.h>

#if HAVE_INTTYPES_H
  #define SHA2_USE_INTTYPES_H
#endif

#ifdef SHA2_USE_INTTYPES_H
  #include <inttypes.h>
#endif /* SHA2_USE_INTTYPES_H */

/* 请确保我们将其保持在上面的检查之下。 */
#ifdef WIN32
  #define SHA2_USE_INTTYPES_H 1
#endif

/* **SHA-256/384/512各种长度定义********************** */
#define SHA256_BLOCK_LEN        64
#define SHA256_DIGEST_LEN       32
#define SHA256_DIGEST_STR_LEN   (SHA256_DIGEST_LEN * 2 + 1)
#define SHA256_B64_LEN          43

#define SHA384_BLOCK_LEN        128
#define SHA384_DIGEST_LEN       48
#define SHA384_DIGEST_STR_LEN   (SHA384_DIGEST_LEN * 2 + 1)
#define SHA384_B64_LEN          64

#define SHA512_BLOCK_LEN        128
#define SHA512_DIGEST_LEN       64
#define SHA512_DIGEST_STR_LEN   (SHA512_DIGEST_LEN * 2 + 1)
#define SHA512_B64_LEN          86


/* **SHA-256/384/512上下文结构****************************** */
/* 注意：如果您的体系结构没有定义u_intXX_t类型或 */
#if 0
typedef unsigned char u_int8_t;		/* 1字节（8位） */
typedef unsigned int u_int32_t;		/* 4字节（32位） */
typedef unsigned long long u_int64_t;	/* 8字节（64位） */
#endif
/* *大多数BSD系统已经定义了u_intXX_t类型，Linux也是如此。 */
#ifdef SHA2_USE_INTTYPES_H

typedef struct _SHA256_CTX {
	uint32_t	state[8];
	uint64_t	bitcount;
	uint8_t	buffer[SHA256_BLOCK_LEN];
} SHA256_CTX;
typedef struct _SHA512_CTX {
	uint64_t	state[8];
	uint64_t	bitcount[2];
	uint8_t	buffer[SHA512_BLOCK_LEN];
} SHA512_CTX;

#else /* SHA2_USE_INTTYPES_H */

typedef struct _SHA256_CTX {
	u_int32_t	state[8];
	u_int64_t	bitcount;
	u_int8_t	buffer[SHA256_BLOCK_LEN];
} SHA256_CTX;
typedef struct _SHA512_CTX {
	u_int64_t	state[8];
	u_int64_t	bitcount[2];
	u_int8_t	buffer[SHA512_BLOCK_LEN];
} SHA512_CTX;

#endif /* SHA2_USE_INTTYPES_H */

typedef SHA512_CTX SHA384_CTX;


/* **SHA-256/384/512功能原型***************************** */
#ifndef NOPROTO
#ifdef SHA2_USE_INTTYPES_H

void SHA256_Init(SHA256_CTX *);
void SHA256_Update(SHA256_CTX*, const uint8_t*, size_t);
void SHA256_Final(uint8_t[SHA256_DIGEST_LEN], SHA256_CTX*);

void SHA384_Init(SHA384_CTX*);
void SHA384_Update(SHA384_CTX*, const uint8_t*, size_t);
void SHA384_Final(uint8_t[SHA384_DIGEST_LEN], SHA384_CTX*);

void SHA512_Init(SHA512_CTX*);
void SHA512_Update(SHA512_CTX*, const uint8_t*, size_t);
void SHA512_Final(uint8_t[SHA512_DIGEST_LEN], SHA512_CTX*);

#else /* SHA2_USE_INTTYPES_H */

void SHA256_Init(SHA256_CTX *);
void SHA256_Update(SHA256_CTX*, const u_int8_t*, size_t);
void SHA256_Final(u_int8_t[SHA256_DIGEST_LEN], SHA256_CTX*);

void SHA384_Init(SHA384_CTX*);
void SHA384_Update(SHA384_CTX*, const u_int8_t*, size_t);
void SHA384_Final(u_int8_t[SHA384_DIGEST_LEN], SHA384_CTX*);

void SHA512_Init(SHA512_CTX*);
void SHA512_Update(SHA512_CTX*, const u_int8_t*, size_t);
void SHA512_Final(u_int8_t[SHA512_DIGEST_LEN], SHA512_CTX*);

#endif /* SHA2_USE_INTTYPES_H */

#else /* NOPROTO */

void SHA256_Init();
void SHA256_Update();
void SHA256_Final();

void SHA384_Init();
void SHA384_Update();
void SHA384_Final();

void SHA512_Init();
void SHA512_Update();
void SHA512_Final();

#endif /* NOPROTO */

#ifdef	__cplusplus
}
#endif /* __cplusplus */

#endif /* __SHA2_H__ */
