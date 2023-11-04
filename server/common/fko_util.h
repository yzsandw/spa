
#ifndef FKO_UTIL_H
#define FKO_UTIL_H 1

#include "fko.h"

#define MAX_CMDLINE_ARGS   30    /* ！<应该绰绰有余 */
#define MAX_ARGS_LINE_LEN  1024
#define MAX_HOSTNAME_LEN    70

/* 功能原型 */
int     is_valid_encoded_msg_len(const int len);
int     is_valid_pt_msg_len(const int len);
int     is_valid_ipv4_addr(const char * const ip_str, const int len);
int     is_valid_hostname(const char * const hostname_str, const int len);
int     is_base64(const unsigned char * const buf, const unsigned short int len);
void    hex_dump(const unsigned char *data, const int size);
int     enc_mode_strtoint(const char *enc_mode_str);
short   enc_mode_inttostr(int enc_mode, char* enc_mode_str, size_t enc_mode_size);
int     strtol_wrapper(const char * const str, const int min,
            const int max, const int exit_upon_err, int *is_err);
short   digest_strtoint(const char *dt_str);
short   digest_inttostr(int digest, char* digest_str, size_t digest_size);
short   hmac_digest_strtoint(const char *dt_str);
short   hmac_digest_inttostr(int digest, char* digest_str, size_t digest_size);
int     constant_runtime_cmp(const char *a, const char *b, int len);
void    chop_whitespace(char *buf);
int     zero_free(char *buf, int len);
int     zero_buf(char *buf, int len);

const char * enc_type_inttostr(const int type);
const char * msg_type_inttostr(const int type);

void  chop_newline(char *str);
void  chop_char(char *str, const char chop);
void  chop_spaces(char *str);

/* * */
int   count_characters(const char *str, const char match, int len);

int   strtoargv(const char * const args_str, char **argv_new, int *argc_new);
void  free_argv(char **argv_new, int *argc_new);

int   ipv4_resolve(const char *dns_str, char *ip_str);
#if !HAVE_STRLCAT
size_t  strlcat(char *dst, const char *src, size_t siz);
#endif

#if !HAVE_STRLCPY
size_t  strlcpy(char *dst, const char *src, size_t siz);
#endif

#if defined(WIN32) || !defined(HAVE_STRNDUP)
char * strndup( const char * s, size_t len );
#endif

int     dump_ctx_to_buffer(fko_ctx_t ctx, char *dump_buf, size_t dump_buf_len);

#include <sys/types.h>
#ifdef WIN32
  #include <winsock2.h>
  #include <ws2tcpip.h>
#else
  #if HAVE_SYS_SOCKET_H
    #include <sys/socket.h>
  #endif
  #include <netdb.h>
#endif

#endif /* FKO_UTIL.H */

/* **EOF** */
