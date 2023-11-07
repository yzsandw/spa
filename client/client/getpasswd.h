/**
 * \file client/getpasswd.h
 *
 * \brief Header file for getpasswd.c.
 */


#ifndef GETPASSWD_H
#define GETPASSWD_H

/* Prototypes
*/
char* getpasswd(const char *prompt, int fd);

/* This can be used to acquire an encryption key or HMAC key
*/
int get_key_file(char *key, int *key_len, const char *key_file,
    ztn_ctx_t ctx, const ztn_cli_options_t *options);

#endif  /* GETPASSWD_H */
