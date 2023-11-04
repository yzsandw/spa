
#ifndef CIPHER_FUNCS_H
#define CIPHER_FUNCS_H 1

#include "rijndael.h"
#include "gpgme_funcs.h"

/* 为给定的输入数据提供预测的加密数据大小 */
#define PREDICT_ENCSIZE(x) (1+(x>>4)+(x&0xf?1:0))<<4

void get_random_data(unsigned char *data, const size_t len);
size_t rij_encrypt(unsigned char *in, size_t len,
    const char *key, const int key_len,
    unsigned char *out, int encryption_mode);
size_t rij_decrypt(unsigned char *in, size_t len,
    const char *key, const int key_len,
    unsigned char *out, int encryption_mode);
int add_salted_str(fko_ctx_t ctx);
int add_gpg_prefix(fko_ctx_t ctx);

#endif /* 密码_FUNCS_H */

/* **EOF** */
