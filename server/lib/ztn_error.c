
#include "ztn_common.h"
#include "ztn.h"

#if HAVE_LIBGPGME
  #include <gpgme.h>
#endif

const char*
ztn_errstr(const int err_code)
{
    switch (err_code)
    {
        /* 起始基准ZTN错误 */
        case ZTN_SUCCESS:
            return("Success");

        case ZTN_ERROR_CTX_NOT_INITIALIZED:
            return("ZTN Context is not initialized");

        case ZTN_ERROR_MEMORY_ALLOCATION:
            return("Unable to allocate memory");

        case ZTN_ERROR_FILESYSTEM_OPERATION:
            return("Read/write bytes mismatch");

        case ZTN_ERROR_INVALID_DATA:
            return("Args contain invalid data");

        case ZTN_ERROR_INVALID_DATA_CLIENT_TIMEOUT_NEGATIVE:
            return("Args contain invalid data: ZTN_ERROR_INVALID_DATA_CLIENT_TIMEOUT_NEGATIVE");

        case ZTN_ERROR_INVALID_DATA_DECODE_MSGLEN_VALIDFAIL:
            return("Args contain invalid data: ZTN_ERROR_INVALID_DATA_DECODE_MSGLEN_VALIDFAIL");

        case ZTN_ERROR_INVALID_DATA_DECODE_NON_ASCII:
            return("Args contain invalid data: ZTN_ERROR_INVALID_DATA_DECODE_NON_ASCII");

        case ZTN_ERROR_INVALID_DATA_DECODE_LT_MIN_FIELDS:
            return("Args contain invalid data: ZTN_ERROR_INVALID_DATA_DECODE_LT_MIN_FIELDS");

        case ZTN_ERROR_INVALID_DATA_DECODE_GT_MAX_FIELDS:
            return("Args contain invalid data: ZTN_ERROR_INVALID_DATA_DECODE_GT_MAX_FIELDS");

        case ZTN_ERROR_INVALID_DATA_DECODE_WRONG_NUM_FIELDS:
            return("Args contain invalid data: ZTN_ERROR_INVALID_DATA_DECODE_WRONG_NUM_FIELDS");

        case ZTN_ERROR_INVALID_DATA_DECODE_ENC_MSG_LEN_MT_T_SIZE:
            return("Args contain invalid data: ZTN_ERROR_INVALID_DATA_DECODE_ENC_MSG_LEN_MT_T_SIZE");

        case ZTN_ERROR_INVALID_DATA_DECODE_RAND_MISSING:
            return("Args contain invalid data: ZTN_ERROR_INVALID_DATA_DECODE_RAND_MISSING");

        case ZTN_ERROR_INVALID_DATA_DECODE_USERNAME_MISSING:
            return("Args contain invalid data: ZTN_ERROR_INVALID_DATA_DECODE_USERNAME_MISSING");

        case ZTN_ERROR_INVALID_DATA_DECODE_USERNAME_TOOBIG:
            return("Args contain invalid data: ZTN_ERROR_INVALID_DATA_DECODE_USERNAME_TOOBIG");

        case ZTN_ERROR_INVALID_DATA_DECODE_USERNAME_DECODEFAIL:
            return("Args contain invalid data: ZTN_ERROR_INVALID_DATA_DECODE_USERNAME_DECODEFAIL");

        case ZTN_ERROR_INVALID_DATA_DECODE_USERNAME_VALIDFAIL:
            return("Args contain invalid data: ZTN_ERROR_INVALID_DATA_DECODE_USERNAME_VALIDFAIL");

        case ZTN_ERROR_INVALID_DATA_DECODE_TIMESTAMP_MISSING:
            return("Args contain invalid data: ZTN_ERROR_INVALID_DATA_DECODE_TIMESTAMP_MISSING");

        case ZTN_ERROR_INVALID_DATA_DECODE_TIMESTAMP_TOOBIG:
            return("Args contain invalid data: ZTN_ERROR_INVALID_DATA_DECODE_TIMESTAMP_TOOBIG");

        case ZTN_ERROR_INVALID_DATA_DECODE_TIMESTAMP_DECODEFAIL:
            return("Args contain invalid data: ZTN_ERROR_INVALID_DATA_DECODE_TIMESTAMP_DECODEFAIL");

        case ZTN_ERROR_INVALID_DATA_DECODE_VERSION_MISSING:
            return("Args contain invalid data: ZTN_ERROR_INVALID_DATA_DECODE_VERSION_MISSING");

        case ZTN_ERROR_INVALID_DATA_DECODE_VERSION_TOOBIG:
            return("Args contain invalid data: ZTN_ERROR_INVALID_DATA_DECODE_VERSION_TOOBIG");

        case ZTN_ERROR_INVALID_DATA_DECODE_MSGTYPE_MISSING:
            return("Args contain invalid data: ZTN_ERROR_INVALID_DATA_DECODE_MSGTYPE_MISSING");

        case ZTN_ERROR_INVALID_DATA_DECODE_MSGTYPE_TOOBIG:
            return("Args contain invalid data: ZTN_ERROR_INVALID_DATA_DECODE_MSGTYPE_TOOBIG");

        case ZTN_ERROR_INVALID_DATA_DECODE_MSGTYPE_DECODEFAIL:
            return("Args contain invalid data: ZTN_ERROR_INVALID_DATA_DECODE_MSGTYPE_DECODEFAIL");

        case ZTN_ERROR_INVALID_DATA_DECODE_MESSAGE_MISSING:
            return("Args contain invalid data: ZTN_ERROR_INVALID_DATA_DECODE_MESSAGE_MISSING");

        case ZTN_ERROR_INVALID_DATA_DECODE_MESSAGE_TOOBIG:
            return("Args contain invalid data: ZTN_ERROR_INVALID_DATA_DECODE_MESSAGE_TOOBIG");

        case ZTN_ERROR_INVALID_DATA_DECODE_MESSAGE_DECODEFAIL:
            return("Args contain invalid data: ZTN_ERROR_INVALID_DATA_DECODE_MESSAGE_DECODEFAIL");

        case ZTN_ERROR_INVALID_DATA_DECODE_MESSAGE_VALIDFAIL:
            return("Args contain invalid data: ZTN_ERROR_INVALID_DATA_DECODE_MESSAGE_VALIDFAIL");

        case ZTN_ERROR_INVALID_DATA_DECODE_ACCESS_VALIDFAIL:
            return("Args contain invalid data: ZTN_ERROR_INVALID_DATA_DECODE_ACCESS_VALIDFAIL");

        case ZTN_ERROR_INVALID_DATA_DECODE_NATACCESS_MISSING:
            return("Args contain invalid data: ZTN_ERROR_INVALID_DATA_DECODE_NATACCESS_MISSING");

        case ZTN_ERROR_INVALID_DATA_DECODE_NATACCESS_TOOBIG:
            return("Args contain invalid data: ZTN_ERROR_INVALID_DATA_DECODE_NATACCESS_TOOBIG");

        case ZTN_ERROR_INVALID_DATA_DECODE_NATACCESS_DECODEFAIL:
            return("Args contain invalid data: ZTN_ERROR_INVALID_DATA_DECODE_NATACCESS_DECODEFAIL");

        case ZTN_ERROR_INVALID_DATA_DECODE_NATACCESS_VALIDFAIL:
            return("Args contain invalid data: ZTN_ERROR_INVALID_DATA_DECODE_NATACCESS_VALIDFAIL");

        case ZTN_ERROR_INVALID_DATA_DECODE_SRVAUTH_MISSING:
            return("Args contain invalid data: ZTN_ERROR_INVALID_DATA_DECODE_SRVAUTH_MISSING");

        case ZTN_ERROR_INVALID_DATA_DECODE_SRVAUTH_DECODEFAIL:
            return("Args contain invalid data: ZTN_ERROR_INVALID_DATA_DECODE_SRVAUTH_DECODEFAIL");

        case ZTN_ERROR_INVALID_DATA_DECODE_SPA_EXTRA_TOOBIG:
            return("Args contain invalid data: ZTN_ERROR_INVALID_DATA_DECODE_SPA_EXTRA_TOOBIG");

        case ZTN_ERROR_INVALID_DATA_DECODE_EXTRA_TOOBIG:
            return("Args contain invalid data: ZTN_ERROR_INVALID_DATA_DECODE_EXTRA_TOOBIG");

        case ZTN_ERROR_INVALID_DATA_DECODE_EXTRA_DECODEFAIL:
            return("Args contain invalid data: ZTN_ERROR_INVALID_DATA_DECODE_EXTRA_DECODEFAIL");

        case ZTN_ERROR_INVALID_DATA_DECODE_TIMEOUT_MISSING:
            return("Args contain invalid data: ZTN_ERROR_INVALID_DATA_DECODE_TIMEOUT_MISSING");

        case ZTN_ERROR_INVALID_DATA_DECODE_TIMEOUT_TOOBIG:
            return("Args contain invalid data: ZTN_ERROR_INVALID_DATA_DECODE_TIMEOUT_TOOBIG");

        case ZTN_ERROR_INVALID_DATA_DECODE_TIMEOUT_VALIDFAIL:
            return("Args contain invalid data: ZTN_ERROR_INVALID_DATA_DECODE_TIMEOUT_VALIDFAIL");

        case ZTN_ERROR_INVALID_DATA_DECODE_TIMEOUT_DECODEFAIL:
            return("Args contain invalid data: ZTN_ERROR_INVALID_DATA_DECODE_TIMEOUT_DECODEFAIL");

        case ZTN_ERROR_INVALID_DATA_ENCODE_MESSAGE_TOOBIG:
            return("Args contain invalid data: ZTN_ERROR_INVALID_DATA_ENCODE_MESSAGE_TOOBIG");

        case ZTN_ERROR_INVALID_DATA_ENCODE_MSGLEN_VALIDFAIL:
            return("Args contain invalid data: ZTN_ERROR_INVALID_DATA_ENCODE_MSGLEN_VALIDFAIL");

        case ZTN_ERROR_INVALID_DATA_ENCODE_DIGEST_VALIDFAIL:
            return("Args contain invalid data: ZTN_ERROR_INVALID_DATA_ENCODE_DIGEST_VALIDFAIL");

        case ZTN_ERROR_INVALID_DATA_ENCODE_DIGEST_TOOBIG:
            return("Args contain invalid data: ZTN_ERROR_INVALID_DATA_ENCODE_DIGEST_TOOBIG");

        case ZTN_ERROR_INVALID_DATA_ENCODE_NOTBASE64:
            return("Args contain invalid data: ZTN_ERROR_INVALID_DATA_ENCODE_NOTBASE64");

        case ZTN_ERROR_INVALID_DATA_ENCRYPT_MSGLEN_VALIDFAIL:
            return("Args contain invalid data: ZTN_ERROR_INVALID_DATA_ENCRYPT_MSGLEN_VALIDFAIL");

        case ZTN_ERROR_INVALID_DATA_ENCRYPT_DIGESTLEN_VALIDFAIL:
            return("Args contain invalid data: ZTN_ERROR_INVALID_DATA_ENCRYPT_DIGESTLEN_VALIDFAIL");

        case ZTN_ERROR_INVALID_DATA_ENCRYPT_PTLEN_VALIDFAIL:
            return("Args contain invalid data: ZTN_ERROR_INVALID_DATA_ENCRYPT_PTLEN_VALIDFAIL");

        case ZTN_ERROR_INVALID_DATA_ENCRYPT_RESULT_MSGLEN_VALIDFAIL:
            return("Args contain invalid data: ZTN_ERROR_INVALID_DATA_ENCRYPT_RESULT_MSGLEN_VALIDFAIL");

        case ZTN_ERROR_INVALID_DATA_ENCRYPT_CIPHERLEN_DECODEFAIL:
            return("Args contain invalid data: ZTN_ERROR_INVALID_DATA_ENCRYPT_CIPHERLEN_DECODEFAIL");

        case ZTN_ERROR_INVALID_DATA_ENCRYPT_CIPHERLEN_VALIDFAIL:
            return("Args contain invalid data: ZTN_ERROR_INVALID_DATA_ENCRYPT_CIPHERLEN_VALIDFAIL");

        case ZTN_ERROR_INVALID_DATA_ENCRYPT_DECRYPTED_MESSAGE_MISSING:
            return("Args contain invalid data: ZTN_ERROR_INVALID_DATA_ENCRYPT_DECRYPTED_MESSAGE_MISSING");

        case ZTN_ERROR_INVALID_DATA_ENCRYPT_DECRYPTED_MSGLEN_VALIDFAIL:
            return("Args contain invalid data: ZTN_ERROR_INVALID_DATA_ENCRYPT_DECRYPTED_MSGLEN_VALIDFAIL");

        case ZTN_ERROR_INVALID_DATA_ENCRYPT_GPG_MESSAGE_VALIDFAIL:
            return("Args contain invalid data: ZTN_ERROR_INVALID_DATA_ENCRYPT_GPG_MESSAGE_VALIDFAIL");

        case ZTN_ERROR_INVALID_DATA_ENCRYPT_GPG_DIGEST_VALIDFAIL:
            return("Args contain invalid data: ZTN_ERROR_INVALID_DATA_ENCRYPT_GPG_DIGEST_VALIDFAIL");

        case ZTN_ERROR_INVALID_DATA_ENCRYPT_GPG_MSGLEN_VALIDFAIL:
            return("Args contain invalid data: ZTN_ERROR_INVALID_DATA_ENCRYPT_GPG_MSGLEN_VALIDFAIL");

        case ZTN_ERROR_INVALID_DATA_ENCRYPT_GPG_RESULT_MSGLEN_VALIDFAIL:
            return("Args contain invalid data: ZTN_ERROR_INVALID_DATA_ENCRYPT_GPG_RESULT_MSGLEN_VALIDFAIL");

        case ZTN_ERROR_INVALID_DATA_ENCRYPT_GPG_CIPHER_DECODEFAIL:
            return("Args contain invalid data: ZTN_ERROR_INVALID_DATA_ENCRYPT_GPG_CIPHER_DECODEFAIL");

        case ZTN_ERROR_INVALID_DATA_ENCRYPT_GPG_ENCODEDMSG_NULL:
            return("Args contain invalid data: ZTN_ERROR_INVALID_DATA_ENCRYPT_GPG_ENCODEDMSG_NULL");

        case ZTN_ERROR_INVALID_DATA_ENCRYPT_GPG_ENCODEDMSGLEN_VALIDFAIL:
            return("Args contain invalid data: ZTN_ERROR_INVALID_DATA_ENCRYPT_GPG_ENCODEDMSGLEN_VALIDFAIL");

        case ZTN_ERROR_INVALID_DATA_ENCRYPT_TYPE_VALIDFAIL:
            return("Args contain invalid data: ZTN_ERROR_INVALID_DATA_ENCRYPT_TYPE_VALIDFAIL");

        case ZTN_ERROR_INVALID_DATA_ENCRYPT_MODE_VALIDFAIL:
            return("Args contain invalid data: ZTN_ERROR_INVALID_DATA_ENCRYPT_MODE_VALIDFAIL");

        case ZTN_ERROR_INVALID_DATA_ENCRYPT_TYPE_UNKNOWN:
            return("Args contain invalid data: ZTN_ERROR_INVALID_DATA_ENCRYPT_TYPE_UNKNOWN");

        case ZTN_ERROR_INVALID_DATA_FUNCS_NEW_ENCMSG_MISSING:
            return("Args contain invalid data: ZTN_ERROR_INVALID_DATA_FUNCS_NEW_ENCMSG_MISSING");

        case ZTN_ERROR_INVALID_DATA_FUNCS_NEW_MSGLEN_VALIDFAIL:
            return("Args contain invalid data: ZTN_ERROR_INVALID_DATA_FUNCS_NEW_MSGLEN_VALIDFAIL");

        case ZTN_ERROR_INVALID_DATA_FUNCS_GEN_KEYLEN_VALIDFAIL:
            return("Args contain invalid data: ZTN_ERROR_INVALID_DATA_FUNCS_GEN_KEYLEN_VALIDFAIL");

        case ZTN_ERROR_INVALID_DATA_FUNCS_GEN_HMACLEN_VALIDFAIL:
            return("Args contain invalid data: ZTN_ERROR_INVALID_DATA_FUNCS_GEN_HMACLEN_VALIDFAIL");

        case ZTN_ERROR_INVALID_DATA_FUNCS_GEN_KEY_ENCODEFAIL:
            return("Args contain invalid data: ZTN_ERROR_INVALID_DATA_FUNCS_GEN_KEY_ENCODEFAIL");

        case ZTN_ERROR_INVALID_DATA_FUNCS_GEN_HMAC_ENCODEFAIL:
            return("Args contain invalid data: ZTN_ERROR_INVALID_DATA_FUNCS_GEN_HMAC_ENCODEFAIL");

        case ZTN_ERROR_INVALID_DATA_FUNCS_SET_MSGLEN_VALIDFAIL:
            return("Args contain invalid data: ZTN_ERROR_INVALID_DATA_FUNCS_SET_MSGLEN_VALIDFAIL");

        case ZTN_ERROR_INVALID_DATA_HMAC_MSGLEN_VALIDFAIL:
            return("Args contain invalid data: ZTN_ERROR_INVALID_DATA_HMAC_MSGLEN_VALIDFAIL");

        case ZTN_ERROR_INVALID_DATA_HMAC_ENCMSGLEN_VALIDFAIL:
            return("Args contain invalid data: ZTN_ERROR_INVALID_DATA_HMAC_ENCMSGLEN_VALIDFAIL");

        case ZTN_ERROR_INVALID_DATA_HMAC_COMPAREFAIL:
            return("Args contain invalid data: ZTN_ERROR_INVALID_DATA_HMAC_COMPAREFAIL");

        case ZTN_ERROR_INVALID_DATA_HMAC_TYPE_VALIDFAIL:
            return("Args contain invalid data: ZTN_ERROR_INVALID_DATA_HMAC_TYPE_VALIDFAIL");

        case ZTN_ERROR_INVALID_DATA_HMAC_LEN_VALIDFAIL:
            return("Args contain invalid data: ZTN_ERROR_INVALID_DATA_HMAC_LEN_VALIDFAIL");

        case ZTN_ERROR_INVALID_DATA_MESSAGE_PORT_MISSING:
            return("Args contain invalid data: ZTN_ERROR_INVALID_DATA_MESSAGE_PORT_MISSING");

        case ZTN_ERROR_INVALID_DATA_MESSAGE_TYPE_VALIDFAIL:
            return("Args contain invalid data: ZTN_ERROR_INVALID_DATA_MESSAGE_TYPE_VALIDFAIL");

        case ZTN_ERROR_INVALID_DATA_MESSAGE_EMPTY:
            return("Args contain invalid data: ZTN_ERROR_INVALID_DATA_MESSAGE_EMPTY");

        case ZTN_ERROR_INVALID_DATA_MESSAGE_CMD_MISSING:
            return("Args contain invalid data: ZTN_ERROR_INVALID_DATA_MESSAGE_CMD_MISSING");

        case ZTN_ERROR_INVALID_DATA_MESSAGE_ACCESS_MISSING:
            return("Args contain invalid data: ZTN_ERROR_INVALID_DATA_MESSAGE_ACCESS_MISSING");

        case ZTN_ERROR_INVALID_DATA_MESSAGE_NAT_MISSING:
            return("Args contain invalid data: ZTN_ERROR_INVALID_DATA_MESSAGE_NAT_MISSING");

        case ZTN_ERROR_INVALID_DATA_MESSAGE_PORTPROTO_MISSING:
            return("Args contain invalid data: ZTN_ERROR_INVALID_DATA_MESSAGE_PORTPROTO_MISSING");

        case ZTN_ERROR_INVALID_DATA_NAT_EMPTY:
            return("Args contain invalid data: ZTN_ERROR_INVALID_DATA_NAT_EMPTY");

        case ZTN_ERROR_INVALID_DATA_RAND_LEN_VALIDFAIL:
            return("Args contain invalid data: ZTN_ERROR_INVALID_DATA_RAND_LEN_VALIDFAIL");

        case ZTN_ERROR_INVALID_DATA_SRVAUTH_MISSING:
            return("Args contain invalid data: ZTN_ERROR_INVALID_DATA_SRVAUTH_MISSING");

        case ZTN_ERROR_INVALID_DATA_TIMESTAMP_VALIDFAIL:
            return("Args contain invalid data: ZTN_ERROR_INVALID_DATA_TIMESTAMP_VALIDFAIL");

        case ZTN_ERROR_INVALID_DATA_USER_MISSING:
            return("Args contain invalid data: ZTN_ERROR_INVALID_DATA_USER_MISSING");

        case ZTN_ERROR_INVALID_DATA_USER_FIRSTCHAR_VALIDFAIL:
            return("Args contain invalid data: ZTN_ERROR_INVALID_DATA_USER_FIRSTCHAR_VALIDFAIL");

        case ZTN_ERROR_INVALID_DATA_USER_REMCHAR_VALIDFAIL:
            return("Args contain invalid data: ZTN_ERROR_INVALID_DATA_USER_REMCHAR_VALIDFAIL");

        case ZTN_ERROR_INVALID_DATA_UTIL_STRTOL_LT_MIN:
            return("Args contain invalid data: ZTN_ERROR_INVALID_DATA_UTIL_STRTOL_LT_MIN");

        case ZTN_ERROR_INVALID_DATA_UTIL_STRTOL_GT_MAX:
            return("Args contain invalid data: ZTN_ERROR_INVALID_DATA_UTIL_STRTOL_GT_MAX");

        case ZTN_ERROR_DATA_TOO_LARGE:
            return("Value or Size of the data exceeded the max allowed");

        case ZTN_ERROR_INVALID_KEY_LEN:
            return("Invalid key length");

        case ZTN_ERROR_USERNAME_UNKNOWN:
            return("Unable to determine username");

        case ZTN_ERROR_INCOMPLETE_SPA_DATA:
            return("Missing or incomplete SPA data");

        case ZTN_ERROR_MISSING_ENCODED_DATA:
            return("There is no encoded data to process");

        case ZTN_ERROR_INVALID_DIGEST_TYPE:
            return("Invalid digest type");

        case ZTN_ERROR_INVALID_ALLOW_IP:
            return("Invalid allow IP address in the SPA message data");

        case ZTN_ERROR_INVALID_SPA_COMMAND_MSG:
            return("Invalid SPA command message format");

        case ZTN_ERROR_INVALID_SPA_ACCESS_MSG:
            return("Invalid SPA access message format");

        case ZTN_ERROR_INVALID_SPA_NAT_ACCESS_MSG:
            return("Invalid SPA nat_access message format");

        case ZTN_ERROR_INVALID_ENCRYPTION_TYPE:
            return("Invalid encryption type");

        case ZTN_ERROR_WRONG_ENCRYPTION_TYPE:
            return("Wrong or inappropriate encryption type for this operation");

        case ZTN_ERROR_DECRYPTION_SIZE:
            return("Unexpected or invalid size for decrypted data");

        case ZTN_ERROR_DECRYPTION_FAILURE:
            return("Decryption failed or decrypted data is invalid");

        case ZTN_ERROR_DIGEST_VERIFICATION_FAILED:
            return("The computed digest did not match the digest in the spa data");

        case ZTN_ERROR_INVALID_HMAC_KEY_LEN:
            return("Invalid HMAC key length");

        case ZTN_ERROR_UNSUPPORTED_HMAC_MODE:
            return("Unsupported HMAC mode (default: SHA256)");

        case ZTN_ERROR_UNSUPPORTED_FEATURE:
            return("Unsupported or unimplemented feature or function");

        case ZTN_ERROR_ZERO_OUT_DATA:
            return("Could not zero out sensitive data");

        case ZTN_ERROR_UNKNOWN:
            return("Unknown/Unclassified error");

#if HAVE_LIBGPGME
        /* 启动GPGME相关错误 */
        case ZTN_ERROR_MISSING_GPG_KEY_DATA:
            return("Missing GPG key data (signer or recipient not set)");

        case ZTN_ERROR_GPGME_NO_OPENPGP:
            return("This GPGME implementation does not support OpenPGP");

        case ZTN_ERROR_GPGME_CONTEXT:
            return("Unable to create GPGME context");

        case ZTN_ERROR_GPGME_PLAINTEXT_DATA_OBJ:
            return("Error creating the plaintext data object");

        case ZTN_ERROR_GPGME_SET_PROTOCOL:
            return("Unable to set GPGME to use OpenPGP protocol");

        case ZTN_ERROR_GPGME_CIPHER_DATA_OBJ:
            return("Error creating the encrypted data data object");

        case ZTN_ERROR_GPGME_BAD_PASSPHRASE:
            return("The GPG passphrase was not valid");

        case ZTN_ERROR_GPGME_ENCRYPT_SIGN:
            return("Error during the encrypt and sign operation");

        case ZTN_ERROR_GPGME_CONTEXT_SIGNER_KEY:
            return("Unable to create GPGME context for the signer key");

        case ZTN_ERROR_GPGME_SIGNER_KEYLIST_START:
            return("Error from signer keylist start operation");

        case ZTN_ERROR_GPGME_SIGNER_KEY_NOT_FOUND:
            return("The key for the given signer was not found");

        case ZTN_ERROR_GPGME_SIGNER_KEY_AMBIGUOUS:
            return("Ambiguous name/id for the signer key (multiple matches)");

        case ZTN_ERROR_GPGME_ADD_SIGNER:
            return("Error adding the signer key to the gpgme context");

        case ZTN_ERROR_GPGME_CONTEXT_RECIPIENT_KEY:
            return("Unable to create GPGME context for the recipient key");

        case ZTN_ERROR_GPGME_RECIPIENT_KEYLIST_START:
            return("Error from signer keylist start operation");

        case ZTN_ERROR_GPGME_RECIPIENT_KEY_NOT_FOUND:
            return("The key for the given recipient was not found");

        case ZTN_ERROR_GPGME_RECIPIENT_KEY_AMBIGUOUS:
            return("Ambiguous name/id for the recipient key (multiple matches)");

        case ZTN_ERROR_GPGME_DECRYPT_FAILED:
            return("Decryption operation failed");

        case ZTN_ERROR_GPGME_DECRYPT_UNSUPPORTED_ALGORITHM:
            return("Decryption operation failed due to unsupported algorithm");

        case ZTN_ERROR_GPGME_BAD_GPG_EXE:
            return("Unable to stat the given GPG executable");

        case ZTN_ERROR_GPGME_BAD_HOME_DIR:
            return("Unable to stat the given GPG home directory");

        case ZTN_ERROR_GPGME_SET_HOME_DIR:
            return("Unable to set the given GPG home directory");

        case ZTN_ERROR_GPGME_NO_SIGNATURE:
            return("Missing GPG signature");

        case ZTN_ERROR_GPGME_BAD_SIGNATURE:
            return("Bad GPG signature");

        case ZTN_ERROR_GPGME_SIGNATURE_VERIFY_DISABLED:
            return("Trying to check signature with verification disabled");

#endif /* HAVE_LIBGPGME */
    }

#if !HAVE_LIBGPGME
    if(err_code > GPGME_ERR_START && err_code < ZTN_LAST_ERROR)
        return("GPG-related error code given, but GPG is not supported");
#endif

    return("Undefined Error");
}

const char*
ztn_gpg_errstr(ztn_ctx_t ctx)
{
#if HAVE_LIBGPGME

    /* 必须初始化 */
    if(!CTX_INITIALIZED(ctx))
        return("");

    if(ctx->gpg_err)
        return(gpgme_strerror(ctx->gpg_err));
#endif /* HAVE_LIBGPGME */

    return("");
}

/* **EOF** */
