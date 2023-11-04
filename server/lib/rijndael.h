
/* *Rijndael是一个128/192/256位分组密码，接受的密钥大小为 */
#ifndef RIJNDAEL_H
#define RIJNDAEL_H 1

#include "common.h"

/* 其他块大小和密钥长度也是可能的，但在 */
#define RIJNDAEL_BLOCKSIZE 16
#define RIJNDAEL_KEYSIZE   32
#define RIJNDAEL_MIN_KEYSIZE 16
#define RIJNDAEL_MAX_KEYSIZE 32
#define SALT_LEN 8

#define     MODE_ECB        1    /* 我们是在欧洲央行模式下加密吗？ */
#define     MODE_CBC        2    /* 我们是在CBC模式下加密吗？ */
#define     MODE_CFB        3    /* 我们是在128位CFB模式下加密吗？ */
#define     MODE_PCBC       4    /* 我们是在PCBC模式下加密吗？ */
#define     MODE_OFB        5    /* 我们是在128位OFB模式下加密吗？ */
#define     MODE_CTR        6    /* 我们是在计数器模式下加密吗？ */

/* 允许大小为128<=位<=256的密钥 */

typedef struct {
  uint32_t keys[60];		/* 密钥调度的最大大小 */
  uint32_t ikeys[60];		/* 倒键时间表 */
  int nrounds;			/* 用于我们的密钥大小的回合数 */
  int mode;			    /* 加密模式 */
  /* 由DSS添加 */
  uint8_t key[RIJNDAEL_MAX_KEYSIZE];
  uint8_t iv[RIJNDAEL_BLOCKSIZE];
  uint8_t salt[SALT_LEN];
} RIJNDAEL_context;

/* * */
void
rijndael_setup(RIJNDAEL_context *ctx,
    const size_t keysize, const uint8_t *key);

/* *rijndael_encrypt（） */

void
rijndael_encrypt(RIJNDAEL_context *context,
		 const uint8_t *plaintext,
		 uint8_t *ciphertext);

/* *rijndael_decrypt（） */

void
rijndael_decrypt(RIJNDAEL_context *context,
		 const uint8_t *ciphertext,
		 uint8_t *plaintext);

/* 以上下文中指定的模式加密明文块 */
void
block_encrypt(RIJNDAEL_context *ctx, uint8_t *input, int inputlen,
	      uint8_t *output, uint8_t *iv);

/* 以上下文中指定的模式解密明文块 */
void
block_decrypt(RIJNDAEL_context *ctx, uint8_t *input, int inputlen,
	      uint8_t *output, uint8_t *iv);

#endif /* RIJNDAEL_H */
