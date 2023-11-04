
#ifndef GPGME_FUNCS_H
#define GPGME_FUNCS_H 1

#if HAVE_LIBGPGME
  #include <gpgme.h>
#endif

#include "fko.h"

int gpgme_encrypt(fko_ctx_t ctx, unsigned char *in, size_t len, const char *pw, unsigned char **out, size_t *out_len);
int gpgme_decrypt(fko_ctx_t ctx, unsigned char *in, size_t len, const char *pw, unsigned char **out, size_t *out_len);
#if HAVE_LIBGPGME
  int get_gpg_key(fko_ctx_t fko_ctx, gpgme_key_t *mykey, const int signer);
#endif

#endif /* GPGME_FUNCS.H */

/* **EOF** */
