
#ifndef BASE64_H
#define BASE64_H 1

/* 原型 */
int b64_encode(unsigned char *in, char *out, int in_len);
int b64_decode(const char *in, unsigned char *out);
void strip_b64_eq(char *data);

#endif /* BASE64_H */

/* **EOF** */
