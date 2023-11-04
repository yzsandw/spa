
#ifndef HMAC_H
#define HMAC_H 1

#include "digest.h"

#define MAX_DIGEST_BLOCK_LEN    SHA3_256_BLOCK_LEN /* *<最长的块长度来自SHA3_256 */
/* * */
int hmac_md5(const char *msg, const unsigned int msg_len,
        unsigned char *hmac, const char *hmac_key, const int hmac_key_len);
/* * */
int hmac_sha1(const char *msg, const unsigned int msg_len,
        unsigned char *hmac, const char *hmac_key, const int hmac_key_len);
/* * */
int hmac_sha256(const char *msg, const unsigned int msg_len,
        unsigned char *hmac, const char *hmac_key, const int hmac_key_len);
/* * */
int hmac_sha384(const char *msg, const unsigned int msg_len,
        unsigned char *hmac, const char *hmac_key, const int hmac_key_len);
/* * */
int hmac_sha512(const char *msg, const unsigned int msg_len,
        unsigned char *hmac, const char *hmac_key, const int hmac_key_len);
/* * */
int hmac_sha3_256(const char *msg, const unsigned int msg_len,
        unsigned char *hmac, const char *hmac_key, const int hmac_key_len);
/* * */
int hmac_sha3_512(const char *msg, const unsigned int msg_len,
        unsigned char *hmac, const char *hmac_key, const int hmac_key_len);

#endif /* HMAC.H */

/* **EOF** */
