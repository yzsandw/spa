
#ifndef DIGEST_H
#define DIGEST_H 1

#include "md5.h"
#include "sha1.h"
#include "sha2.h"
#include "sha3.h"

/* 尺寸计算宏 */
#define MD_HEX_SIZE(x) x * 2

void md5(unsigned char* out, unsigned char* in, size_t size);
void md5_base64(char* out, unsigned char* in, size_t size);
void sha1(unsigned char* out, unsigned char* in, size_t size);
void sha1_base64(char* out, unsigned char* in, size_t size);
void sha256(unsigned char* out, unsigned char* in, size_t size);
void sha256_base64(char* out, unsigned char* in, size_t size);
void sha384(unsigned char* out, unsigned char* in, size_t size);
void sha384_base64(char* out, unsigned char* in, size_t size);
void sha512(unsigned char* out, unsigned char* in, size_t size);
void sha512_base64(char* out, unsigned char* in, size_t size);
void sha3_256(unsigned char* out, unsigned char* in, size_t size);
void sha3_256_base64(char* out, unsigned char* in, size_t size);
void sha3_512(unsigned char* out, unsigned char* in, size_t size);
void sha3_512_base64(char* out, unsigned char* in, size_t size);

#endif /* 摘要_ */

/* **EOF** */
