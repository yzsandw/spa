
#ifndef FKO_H
#define FKO_H 1

#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef WIN32
  #ifdef DLL_EXPORTS
    #define DLL_API __declspec(dllexport)
  #else
	#ifdef DLL_IMPORTS
		#define DLL_API __declspec(dllimport)
	#else
		#define DLL_API
	#endif
  #endif
#else
  #define DLL_API
#endif

/* 常规参数 */
#define FKO_PROTOCOL_VERSION "3.0.0" /* *<fwknop协议版本 */

/* * */

/* FKO_COMMAND_MSG：表示命令消息，对应整数值 0 */
typedef enum {
    FKO_COMMAND_MSG = 0, /* *<命令消息 */
    FKO_ACCESS_MSG, /* *<访问消息 */
    FKO_NAT_ACCESS_MSG,  /* *<NAT访问消息 */
    FKO_CLIENT_TIMEOUT_ACCESS_MSG, /* *<访问消息超时 */
    FKO_CLIENT_TIMEOUT_NAT_ACCESS_MSG, /* *<NAT访问超时 */
    FKO_LOCAL_NAT_ACCESS_MSG, /* *<本地NAT访问 */
    FKO_CLIENT_TIMEOUT_LOCAL_NAT_ACCESS_MSG, /* *<本地NAT访问超时 */
    FKO_LAST_MSG_TYPE /* *<始终将此作为最后一个 */
} fko_message_type_t;

/* * */

/* FKO_edigest_INVALID_DATA：表示无效的摘要类型，对应整数值 -1. */
typedef enum {
    FKO_DIGEST_INVALID_DATA = -1, /* *<摘要类型无效 */
    FKO_DIGEST_UNKNOWN = 0, /* *<未知摘要类型 */
    FKO_DIGEST_MD5, /* *<MD5摘要类型 */
    FKO_DIGEST_SHA1, /* *＜SHA1摘要类型 */
    FKO_DIGEST_SHA256, /* *＜SHA256摘要类型 */
    FKO_DIGEST_SHA384, /* *<SHA384摘要类型 */
    FKO_DIGEST_SHA512, /* *＜SHA512摘要类型 */
    FKO_DIGEST_SHA3_256, /* *＜SHA3 256摘要类型 */
    FKO_DIGEST_SHA3_512, /* *＜SHA3 512摘要类型 */
    FKO_LAST_DIGEST_TYPE /* *<始终将此作为最后一个 */
} fko_digest_type_t;

/* * */
/* FKO_HMAC_INVALID_DATA：表示无效的 HMAC类型，对应整数值 -1. */
typedef enum {
    FKO_HMAC_INVALID_DATA = -1, /* *<HMAC类型无效 */
    FKO_HMAC_UNKNOWN = 0, /* *<未知HMAC类型 */
    FKO_HMAC_MD5, /* *<MD5 HMAC类型 */
    FKO_HMAC_SHA1, /* *<SHA1 HMAC类型 */
    FKO_HMAC_SHA256, /* *<SHA256 HMAC类型 */
    FKO_HMAC_SHA384, /* *<SHA384 HMAC类型 */
    FKO_HMAC_SHA512, /* *<SHA512 HMAC类型 */
    FKO_HMAC_SHA3_256, /* *<SHA3 256 HMAC类型 */
    FKO_HMAC_SHA3_512, /* *<SHA3 512 HMAC类型 */
    FKO_LAST_HMAC_MODE /* *<始终将此作为最后一个 */
} fko_hmac_type_t;

/* * */
/* FKO_ENCRYPTION_ivalid_DATA：表示无效的加密类型，对应整数值 -1. */
typedef enum {
    FKO_ENCRYPTION_INVALID_DATA = -1, /* *<加密类型无效 */
    FKO_ENCRYPTION_UNKNOWN = 0, /* *<未知加密类型 */
    FKO_ENCRYPTION_RIJNDAEL, /* *<AES加密类型 */
    FKO_ENCRYPTION_GPG, /* *<GPG加密类型 */
    FKO_LAST_ENCRYPTION_TYPE /* *<始终将此作为最后一个 */
} fko_encryption_type_t;

/* * */
/* FKO_ec_MODE_UNKNOWN：未知的加密模式。 */
typedef enum {
    FKO_ENC_MODE_UNKNOWN = 0, /* *<未知加密模式 */
    FKO_ENC_MODE_ECB, /* *<电子代码簿加密模式 */
    FKO_ENC_MODE_CBC, /* *<密码块链接加密模式 */
    FKO_ENC_MODE_CFB, /* *<密码反馈加密模式 */
    FKO_ENC_MODE_PCBC, /* *<Propagating Cipher Block Chaining加密模式 */
    FKO_ENC_MODE_OFB, /* *<输出反馈加密模式 */
    FKO_ENC_MODE_CTR, /* *<计数器加密模式 */
    FKO_ENC_MODE_ASYMMETRIC,  /* *<使用GPG时的占位符 */
    FKO_ENC_MODE_CBC_LEGACY_IV,  /* *<对于旧的零填充策略 */
    FKO_LAST_ENC_MODE /* *<始终将此作为最后一个 */
} fko_encryption_mode_t;

/* * */
typedef enum {
    FKO_SUCCESS = 0, /* *<成功 */
    FKO_ERROR_CTX_NOT_INITIALIZED, /* *<FKO上下文未初始化 */
    FKO_ERROR_MEMORY_ALLOCATION, /* *<无法分配内存 */
    FKO_ERROR_FILESYSTEM_OPERATION, /* *<读/写字节不匹配 */

    /* 无效数据错误 */
    FKO_ERROR_INVALID_DATA, /* *＜Args包含无效数据 */
    FKO_ERROR_INVALID_DATA_CLIENT_TIMEOUT_NEGATIVE, /* *＜Args包含无效数据：FKO_ERROR_invalid_data_CLIENT_TIMEOUT_NEGIVE */
    FKO_ERROR_INVALID_DATA_DECODE_MSGLEN_VALIDFAIL, /* *<参数包含无效数据：FKO_ERROR_invalid_data_DECODE_MSGLEN_VALIDFAIL */
    FKO_ERROR_INVALID_DATA_DECODE_NON_ASCII, /* *<参数包含无效数据：FKO_ERROR_invalid_data_DECODE_NON_ASCII */
    FKO_ERROR_INVALID_DATA_DECODE_LT_MIN_FIELDS, /* *<参数包含无效数据：FKO_ERROR_invalid_data_DECODE_LT_MIN_FIELDS */
    FKO_ERROR_INVALID_DATA_DECODE_GT_MAX_FIELDS, /* *<参数包含无效数据：FKO_ERROR_invalid_data_DECODE_GT_MAX_FIELDS */
    FKO_ERROR_INVALID_DATA_DECODE_WRONG_NUM_FIELDS, /* *<参数包含无效数据：FKO_ERROR_invalid_data_DECODE_WRONG_NUM_FIELDS */
    FKO_ERROR_INVALID_DATA_DECODE_ENC_MSG_LEN_MT_T_SIZE, /* *<参数包含无效数据：FKO_ERROR_invalid_data_DECODE_ENC_MSG_LEN_MT_SIZE */
    FKO_ERROR_INVALID_DATA_DECODE_RAND_MISSING, /* *<参数包含无效数据：FKO_ERROR_invalid_data_DECODE_RAND_MISSING */
    FKO_ERROR_INVALID_DATA_DECODE_USERNAME_MISSING, /* *<参数包含无效数据：FKO_ERROR_invalid_data_DECODE_USERNAME_MISSING */
    FKO_ERROR_INVALID_DATA_DECODE_USERNAME_TOOBIG, /* *<参数包含无效数据：FKO_ERROR_invalid_data_DECODE_USERNAME_TOOBIG */
    FKO_ERROR_INVALID_DATA_DECODE_USERNAME_DECODEFAIL, /* *<参数包含无效数据：FKO_ERROR_invalid_data_DECODE_USERNAME_DECODEFAIL */
    FKO_ERROR_INVALID_DATA_DECODE_USERNAME_VALIDFAIL, /* *<参数包含无效数据：FKO_ERROR_invalid_data_DECODE_USERNAME_VALIDFAIL */
    FKO_ERROR_INVALID_DATA_DECODE_TIMESTAMP_MISSING, /* *<参数包含无效数据：FKO_ERROR_invalid_data_DECODE_TIMESTAMP_MISSING */
    FKO_ERROR_INVALID_DATA_DECODE_TIMESTAMP_TOOBIG, /* *＜参数包含无效数据：FKO_ERROR_invalid_data_DECODE_TIMESTAMP_TOOBIG */
    FKO_ERROR_INVALID_DATA_DECODE_TIMESTAMP_DECODEFAIL, /* *<参数包含无效数据：FKO_ERROR_invalid_data_DECODE_TIMESTAMP_DECODEFAIL */
    FKO_ERROR_INVALID_DATA_DECODE_VERSION_MISSING, /* *<参数包含无效数据：FKO_ERROR_invalid_data_DECODE_VERSION_MISSING */
    FKO_ERROR_INVALID_DATA_DECODE_VERSION_TOOBIG, /* *<参数包含无效数据：FKO_ERROR_invalid_data_DECODE_VERSION_TOOBIG */
    FKO_ERROR_INVALID_DATA_DECODE_MSGTYPE_MISSING, /* *<参数包含无效数据：FKO_ERROR_invalid_data_DECODE_MSGTYPE_MISSING */
    FKO_ERROR_INVALID_DATA_DECODE_MSGTYPE_TOOBIG, /* *<参数包含无效数据：FKO_ERROR_invalid_data_DECODE_MSGTYPE_TOOBIG */
    FKO_ERROR_INVALID_DATA_DECODE_MSGTYPE_DECODEFAIL, /* *<参数包含无效数据：FKO_ERROR_invalid_data_DECODE_MSGTYPE_DECODEFAIL */
    FKO_ERROR_INVALID_DATA_DECODE_MESSAGE_MISSING, /* *<参数包含无效数据：FKO_ERROR_invalid_data_DECODE_MESSAGE_MISSING */
    FKO_ERROR_INVALID_DATA_DECODE_MESSAGE_TOOBIG, /* *＜参数包含无效数据：FKO_ERROR_invalid_data_DECODE_MESSAGE_TOOBIG */
    FKO_ERROR_INVALID_DATA_DECODE_MESSAGE_DECODEFAIL, /* *<参数包含无效数据：FKO_ERROR_invalid_data_DECODE_MESSAGE_DECODEFAIL */
    FKO_ERROR_INVALID_DATA_DECODE_MESSAGE_VALIDFAIL, /* *<参数包含无效数据：FKO_ERROR_invalid_data_DECODE_MESSAGE_VALIDFAIL */
    FKO_ERROR_INVALID_DATA_DECODE_ACCESS_VALIDFAIL, /* *<参数包含无效数据：FKO_ERROR_invalid_data_DECODE_ACCESS_VALIDFAIL */
    FKO_ERROR_INVALID_DATA_DECODE_NATACCESS_MISSING, /* *<参数包含无效数据：FKO_ERROR_invalid_data_DECODE_NAMETACCESS_MISSING */
    FKO_ERROR_INVALID_DATA_DECODE_NATACCESS_TOOBIG, /* *<参数包含无效数据：FKO_ERROR_invalid_data_DECODE_NAMETACCESS_TOOBIG */
    FKO_ERROR_INVALID_DATA_DECODE_NATACCESS_DECODEFAIL, /* *<参数包含无效数据：FKO_ERROR_invalid_data_DECODE_NAMETACCESS_DECODEFAIL */
    FKO_ERROR_INVALID_DATA_DECODE_NATACCESS_VALIDFAIL, /* *<参数包含无效数据：FKO_ERROR_invalid_data_DECODE_NAMETACCESS_VALIDFAIL */
    FKO_ERROR_INVALID_DATA_DECODE_SRVAUTH_MISSING, /* *<参数包含无效数据：FKO_ERROR_invalid_data_DECODE_SRVAUTH_MISSING */
    FKO_ERROR_INVALID_DATA_DECODE_SRVAUTH_DECODEFAIL, /* *<参数包含无效数据：FKO_ERROR_invalid_data_DECODE_SRVAUTH_DECODEFAIL */
    FKO_ERROR_INVALID_DATA_DECODE_SPA_EXTRA_TOOBIG, /* *<参数包含无效数据：FKO_ERROR_invalid_data_DECODE_SPA_EXTRA_TOOBIG */
    FKO_ERROR_INVALID_DATA_DECODE_EXTRA_TOOBIG, /* *＜参数包含无效数据：FKO_ERROR_invalid_data_DECODE_EXTRA_TOOBIG */
    FKO_ERROR_INVALID_DATA_DECODE_EXTRA_DECODEFAIL, /* *<参数包含无效数据：FKO_ERROR_invalid_data_DECODE_EXTRA_DECODEFAIL */
    FKO_ERROR_INVALID_DATA_DECODE_TIMEOUT_MISSING, /* *<参数包含无效数据：FKO_ERROR_invalid_data_DECODE_TIMEOUT_MISSING */
    FKO_ERROR_INVALID_DATA_DECODE_TIMEOUT_TOOBIG, /* *＜参数包含无效数据：FKO_ERROR_invalid_data_DECODE_TIMEOUT_TOOBIG */
    FKO_ERROR_INVALID_DATA_DECODE_TIMEOUT_VALIDFAIL, /* *<参数包含无效数据：FKO_ERROR_invalid_data_DECODE_TIMEOUT_VALIDFAIL */
    FKO_ERROR_INVALID_DATA_DECODE_TIMEOUT_DECODEFAIL, /* *<参数包含无效数据：FKO_ERROR_invalid_data_DECODE_TIMEOUT_DECODEFAIL */
    FKO_ERROR_INVALID_DATA_ENCODE_MESSAGE_TOOBIG, /* *<Args包含无效数据：FKO_ERROR_invalid_data_ENCODE_MESSAGE_TOOBIG */
    FKO_ERROR_INVALID_DATA_ENCODE_MSGLEN_VALIDFAIL, /* *<参数包含无效数据：FKO_ERROR_invalid_data_ENCODE_MSGLEN_VALIDFAIL */
    FKO_ERROR_INVALID_DATA_ENCODE_DIGEST_VALIDFAIL, /* *<参数包含无效数据：FKO_ERROR_invalid_data_ENCODE_DIGEST_VALIDFAIL */
    FKO_ERROR_INVALID_DATA_ENCODE_DIGEST_TOOBIG, /* *<Args包含无效数据：FKO_ERROR_invalid_data_ENCODE_DIGEST_TOOBIG */
    FKO_ERROR_INVALID_DATA_ENCODE_NOTBASE64, /* *<Args包含无效数据：FKO_ERROR_invalid_data_ENCODE_NOTBASE64 */
    FKO_ERROR_INVALID_DATA_ENCRYPT_MSGLEN_VALIDFAIL, /* *<参数包含无效数据：FKO_ERROR_invalid_data_ENCRYPT_MSGLEN_VALIDFAIL */
    FKO_ERROR_INVALID_DATA_ENCRYPT_DIGESTLEN_VALIDFAIL, /* *<参数包含无效数据：FKO_ERROR_invalid_data_ENCRYPT_DIGESTLEN_VALIDFAIL */
    FKO_ERROR_INVALID_DATA_ENCRYPT_PTLEN_VALIDFAIL, /* *<参数包含无效数据：FKO_ERROR_invalid_data_ENCRYPT_PTLEN_VALIDFAIL */
    FKO_ERROR_INVALID_DATA_ENCRYPT_RESULT_MSGLEN_VALIDFAIL, /* *<参数包含无效数据：FKO_ERROR_invalid_data_ENCRYPT_RESULT_MSGLEN_VALIDFAIL */
    FKO_ERROR_INVALID_DATA_ENCRYPT_CIPHERLEN_DECODEFAIL, /* *<参数包含无效数据：FKO_ERROR_invalid_data_ENCRYPT_CIPHERLEN_DECODEFAIL */
    FKO_ERROR_INVALID_DATA_ENCRYPT_CIPHERLEN_VALIDFAIL, /* *<参数包含无效数据：FKO_ERROR_invalid_data_ENCRYPT_CIPHERLEN_VALIDFAIL */
    FKO_ERROR_INVALID_DATA_ENCRYPT_DECRYPTED_MESSAGE_MISSING, /* *<参数包含无效数据：FKO_ERROR_invalid_data_ENCRYPT_DECRYPTED_MESSAGE_ISSING */
    FKO_ERROR_INVALID_DATA_ENCRYPT_DECRYPTED_MSGLEN_VALIDFAIL, /* *<参数包含无效数据：FKO_ERROR_invalid_data_ENCRYPT_DECRYPTED_MSGLEN_VALIDFAIL */
    FKO_ERROR_INVALID_DATA_ENCRYPT_GPG_MESSAGE_VALIDFAIL, /* *<参数包含无效数据：FKO_ERROR_invalid_data_ENCRYPT_GPG_MESSAGE_VALIDFAIL */
    FKO_ERROR_INVALID_DATA_ENCRYPT_GPG_DIGEST_VALIDFAIL, /* *<参数包含无效数据：FKO_ERROR_invalid_data_ENCRYPT_GPG_DIGEST_VALIDFAIL */
    FKO_ERROR_INVALID_DATA_ENCRYPT_GPG_MSGLEN_VALIDFAIL, /* *<参数包含无效数据：FKO_ERROR_invalid_data_ENCRYPT_GPG_MSGLEN_VALIDFAIL */
    FKO_ERROR_INVALID_DATA_ENCRYPT_GPG_RESULT_MSGLEN_VALIDFAIL, /* *<参数包含无效数据：FKO_ERROR_invalid_data_ENCRYPT_GPG_RESULT_MSGLEN_VALIDFAIL */
    FKO_ERROR_INVALID_DATA_ENCRYPT_GPG_CIPHER_DECODEFAIL, /* *<参数包含无效数据：FKO_ERROR_invalid_data_ENCRYPT_GPG_CIPHER_DECODEFAIL */
    FKO_ERROR_INVALID_DATA_ENCRYPT_GPG_ENCODEDMSG_NULL, /* *<参数包含无效数据：FKO_ERROR_invalid_data_ENCRYPT_GPG_ENCODEDMSG_NULL */
    FKO_ERROR_INVALID_DATA_ENCRYPT_GPG_ENCODEDMSGLEN_VALIDFAIL, /* *<参数包含无效数据：FKO_ERROR_invalid_data_ENCRYPT_GPG_ENCODEDMSGLEN_VALIDFAIL */
    FKO_ERROR_INVALID_DATA_ENCRYPT_TYPE_VALIDFAIL, /* *<参数包含无效数据：FKO_ERROR_invalid_data_ENCRYPT_TYPE_VALIDFAIL */
    FKO_ERROR_INVALID_DATA_ENCRYPT_MODE_VALIDFAIL, /* *<参数包含无效数据：FKO_ERROR_invalid_data_ENCRYPT_MODE_VALIDFAIL */
    FKO_ERROR_INVALID_DATA_ENCRYPT_TYPE_UNKNOWN, /* *<参数包含无效数据：FKO_ERROR_invalid_data_ENCRYPT_TYPE_UNKNOWN */
    FKO_ERROR_INVALID_DATA_FUNCS_NEW_ENCMSG_MISSING, /* *<参数包含无效数据：FKO_ERROR_invalid_data_FUNCS_NEW_ENCMSG_MISSING */
    FKO_ERROR_INVALID_DATA_FUNCS_NEW_MSGLEN_VALIDFAIL, /* *<参数包含无效数据：FKO_ERROR_invalid_data_FUNCS_NEW_MSGLEN_VALIDFAIL */
    FKO_ERROR_INVALID_DATA_FUNCS_GEN_KEYLEN_VALIDFAIL, /* *<参数包含无效数据：FKO_ERROR_invalid_data_FUNCS_GEN_KEYLEN_VALIDFAIL */
    FKO_ERROR_INVALID_DATA_FUNCS_GEN_HMACLEN_VALIDFAIL, /* *<参数包含无效数据：FKO_ERROR_invalid_data_FUNCS_GEN_HMACLEN_VALIDFAIL */
    FKO_ERROR_INVALID_DATA_FUNCS_GEN_KEY_ENCODEFAIL, /* *<参数包含无效数据：FKO_ERROR_invalid_data_FUNCS_GEN_KEY_ENCODEFAIL */
    FKO_ERROR_INVALID_DATA_FUNCS_GEN_HMAC_ENCODEFAIL, /* *<参数包含无效数据：FKO_ERROR_invalid_data_FUNCS_GEN_HMAC_ENCODEFAIL */
    FKO_ERROR_INVALID_DATA_FUNCS_SET_MSGLEN_VALIDFAIL, /* *<参数包含无效数据：FKO_ERROR_invalid_data_FUNCS_SET_MSGLEN_VALIDFAIL */
    FKO_ERROR_INVALID_DATA_HMAC_MSGLEN_VALIDFAIL, /* *<参数包含无效数据：FKO_ERROR_invalid_data_HMAC_MSGLEN_VALIDFAIL */
    FKO_ERROR_INVALID_DATA_HMAC_ENCMSGLEN_VALIDFAIL, /* *<参数包含无效数据：FKO_ERROR_invalid_data_HMAC_ENCMSGLEN_VALIDFAIL */
    FKO_ERROR_INVALID_DATA_HMAC_COMPAREFAIL, /* *＜Args包含无效数据：FKO_ERROR_invalid_data_HMAC_COMPAREFAIL */
    FKO_ERROR_INVALID_DATA_HMAC_TYPE_VALIDFAIL, /* *<参数包含无效数据：FKO_ERROR_invalid_data_HMAC_TYPE_VALIDFAIL */
    FKO_ERROR_INVALID_DATA_HMAC_LEN_VALIDFAIL, /* *<参数包含无效数据：FKO_ERROR_invalid_data_HMAC_LEN_VALIDFAIL */
    FKO_ERROR_INVALID_DATA_MESSAGE_PORT_MISSING, /* *<参数包含无效数据：FKO_ERROR_invalid_data_MESSAGE_PORT_MISSING */
    FKO_ERROR_INVALID_DATA_MESSAGE_TYPE_VALIDFAIL, /* *<参数包含无效数据：FKO_ERROR_invalid_data_MESSAGE_TYPE_VALIDFAIL */
    FKO_ERROR_INVALID_DATA_MESSAGE_EMPTY, /* *<参数包含无效数据：FKO_ERROR_invalid_data_MESSAGE_EMPTY */
    FKO_ERROR_INVALID_DATA_MESSAGE_CMD_MISSING, /* *<参数包含无效数据：FKO_ERROR_invalid_data_MESSAGE_CMD_MISSING */
    FKO_ERROR_INVALID_DATA_MESSAGE_ACCESS_MISSING, /* *<参数包含无效数据：FKO_ERROR_invalid_data_MESSAGE_ACCESS_MISSING */
    FKO_ERROR_INVALID_DATA_MESSAGE_NAT_MISSING, /* *<参数包含无效数据：FKO_ERROR_invalid_data_MESSAGE_NAMET_MISSING */
    FKO_ERROR_INVALID_DATA_MESSAGE_PORTPROTO_MISSING, /* *<参数包含无效数据：FKO_ERROR_invalid_data_MESSAGE_PORTPROTO_MISSING */
    FKO_ERROR_INVALID_DATA_NAT_EMPTY, /* *<参数包含无效数据：FKO_ERROR_invalid_data_NAMET_EMPTY */
    FKO_ERROR_INVALID_DATA_RAND_LEN_VALIDFAIL, /* *<参数包含无效数据：FKO_ERROR_invalid_data_RAND_LEN_VALIDFAIL */
    FKO_ERROR_INVALID_DATA_SRVAUTH_MISSING, /* *<参数包含无效数据：FKO_ERROR_invalid_data_SRVAUTH_MISSING */
    FKO_ERROR_INVALID_DATA_TIMESTAMP_VALIDFAIL, /* *<参数包含无效数据：FKO_ERROR_invalid_data_TIMESTAMP_VALIDFAIL */
    FKO_ERROR_INVALID_DATA_USER_MISSING, /* *<参数包含无效数据：FKO_ERROR_invalid_data_USER_MISSING */
    FKO_ERROR_INVALID_DATA_USER_FIRSTCHAR_VALIDFAIL, /* *<参数包含无效数据：FKO_ERROR_invalid_data_USER_FIRSTCHAR_VALIDFAIL */
    FKO_ERROR_INVALID_DATA_USER_REMCHAR_VALIDFAIL, /* *<参数包含无效数据：FKO_ERROR_invalid_data_USER_REMCHAR_VALIDFAIL */
    FKO_ERROR_INVALID_DATA_UTIL_STRTOL_LT_MIN, /* *<参数包含无效数据：FKO_ERROR_invalid_data_UTIL_STRTOL_LT_MIN */
    FKO_ERROR_INVALID_DATA_UTIL_STRTOL_GT_MAX, /* *<参数包含无效数据：FKO_ERROR_invalid_data_UTIL_STRTOL_GT_MAX */

    FKO_ERROR_DATA_TOO_LARGE, /* *<数据的值或大小超过了允许的最大值 */
    FKO_ERROR_INVALID_KEY_LEN, /* *<密钥长度无效 */
    FKO_ERROR_USERNAME_UNKNOWN, /* *<无法确定用户名 */
    FKO_ERROR_INCOMPLETE_SPA_DATA, /* *<SPA数据缺失或不完整 */
    FKO_ERROR_MISSING_ENCODED_DATA, /* *<没有要处理的编码数据 */
    FKO_ERROR_INVALID_DIGEST_TYPE, /* *<摘要类型无效 */
    FKO_ERROR_INVALID_ALLOW_IP, /* *<SPA消息数据中的允许IP地址无效 */
    FKO_ERROR_INVALID_SPA_COMMAND_MSG, /* *<无效的SPA命令消息格式 */
    FKO_ERROR_INVALID_SPA_ACCESS_MSG, /* *<无效的SPA访问消息格式 */
    FKO_ERROR_INVALID_SPA_NAT_ACCESS_MSG, /* *<无效的SPA nat_access消息格式 */
    FKO_ERROR_INVALID_ENCRYPTION_TYPE, /* *<加密类型无效 */
    FKO_ERROR_WRONG_ENCRYPTION_TYPE, /* *<此操作的加密类型错误或不合适 */
    FKO_ERROR_DECRYPTION_SIZE, /* *<解密数据的大小意外或无效 */
    FKO_ERROR_DECRYPTION_FAILURE, /* *<解密失败或解密的数据无效 */
    FKO_ERROR_DIGEST_VERIFICATION_FAILED, /* *<计算的摘要与spa数据中的摘要不匹配 */
    FKO_ERROR_INVALID_HMAC_KEY_LEN, /* *<HMAC密钥长度无效 */
    FKO_ERROR_UNSUPPORTED_HMAC_MODE, /* *<不支持的HMAC模式（默认值：SHA256） */
    FKO_ERROR_UNSUPPORTED_FEATURE, /* *<不支持或未实现的功能 */
    FKO_ERROR_ZERO_OUT_DATA, /* *<无法将敏感数据清零 */
    FKO_ERROR_UNKNOWN, /* *<未知/未分类错误 */

    /* 启动GPGME相关错误（注意：不要放置非GPG相关错误 */
    GPGME_ERR_START, /* *<不是真正的错误，GPG错误开始的标记 */
    FKO_ERROR_MISSING_GPG_KEY_DATA, /* *<缺少GPG密钥数据（未设置签名者或收件人） */
    FKO_ERROR_GPGME_NO_OPENPGP, /* *＜此GPGME实现不支持OpenPGP */
    FKO_ERROR_GPGME_CONTEXT, /* *<无法创建GPGME上下文 */
    FKO_ERROR_GPGME_PLAINTEXT_DATA_OBJ, /* *<创建明文数据对象时出错 */
    FKO_ERROR_GPGME_SET_PROTOCOL, /* *<无法将GPGME设置为使用OpenPGP协议 */
    FKO_ERROR_GPGME_CIPHER_DATA_OBJ, /* *<创建加密数据数据对象时出错 */
    FKO_ERROR_GPGME_BAD_PASSPHRASE, /* *<GPG密码短语无效 */
    FKO_ERROR_GPGME_ENCRYPT_SIGN, /* *<加密和签名操作期间出错 */
    FKO_ERROR_GPGME_CONTEXT_SIGNER_KEY, /* *<无法为签名者密钥创建GPGME上下文 */
    FKO_ERROR_GPGME_SIGNER_KEYLIST_START, /* *<签名者密钥列表启动操作出错 */
    FKO_ERROR_GPGME_SIGNER_KEY_NOT_FOUND, /* *<找不到给定签名者的密钥 */
    FKO_ERROR_GPGME_SIGNER_KEY_AMBIGUOUS, /* *<签名者密钥的名称/id不明确（多个匹配项） */
    FKO_ERROR_GPGME_ADD_SIGNER, /* *<将签名者密钥添加到gpgme上下文时出错 */
    FKO_ERROR_GPGME_CONTEXT_RECIPIENT_KEY, /* *<无法为收件人密钥创建GPGME上下文 */
    FKO_ERROR_GPGME_RECIPIENT_KEYLIST_START, /* *<签名者密钥列表启动操作出错 */
    FKO_ERROR_GPGME_RECIPIENT_KEY_NOT_FOUND, /* *<找不到给定收件人的密钥 */
    FKO_ERROR_GPGME_RECIPIENT_KEY_AMBIGUOUS, /* *<收件人密钥的名称/id不明确（多个匹配项） */
    FKO_ERROR_GPGME_DECRYPT_FAILED, /* *<解密操作失败 */
    FKO_ERROR_GPGME_DECRYPT_UNSUPPORTED_ALGORITHM, /* *<由于算法不受支持，解密操作失败 */
    FKO_ERROR_GPGME_BAD_GPG_EXE, /* *<无法统计给定的GPG可执行文件 */
    FKO_ERROR_GPGME_BAD_HOME_DIR, /* *<无法统计给定的GPG主目录 */
    FKO_ERROR_GPGME_SET_HOME_DIR, /* *<无法设置给定的GPG主目录 */
    FKO_ERROR_GPGME_NO_SIGNATURE, /* *<缺少GPG签名 */
    FKO_ERROR_GPGME_BAD_SIGNATURE, /* *<错误的GPG签名 */
    FKO_ERROR_GPGME_SIGNATURE_VERIFY_DISABLED, /* *<尝试在禁用验证的情况下检查签名 */

    FKO_LAST_ERROR /* *<不是真正的错误，必须是枚举的最后一个 */
} fko_error_codes_t;

/* *如果给定的错误代码是与gpg相关的错误，则返回true的宏。 */
#define IS_GPG_ERROR(x) (x > GPGME_ERR_START && x < FKO_LAST_ERROR)

/* 常规默认值 */
#define FKO_DEFAULT_MSG_TYPE     FKO_ACCESS_MSG
#define FKO_DEFAULT_DIGEST       FKO_DIGEST_SHA256
#define FKO_DEFAULT_ENCRYPTION   FKO_ENCRYPTION_RIJNDAEL
#define FKO_DEFAULT_ENC_MODE     FKO_ENC_MODE_CBC
#define FKO_DEFAULT_KEY_LEN      0
#define FKO_DEFAULT_HMAC_KEY_LEN 0
#define FKO_DEFAULT_HMAC_MODE    FKO_HMAC_SHA256

/* 在某些加密方案上定义一致的前缀或salt。 */
#define B64_RIJNDAEL_SALT "U2FsdGVkX1"
#define B64_RIJNDAEL_SALT_STR_LEN 10

#define B64_GPG_PREFIX "hQ"
#define B64_GPG_PREFIX_STR_LEN 2

/* 指定是否允许libfko调用exit（） */
#define EXIT_UPON_ERR 1
#define NO_EXIT_UPON_ERR 0

/* 上下文包含全局状态和配置选项，如 */
struct fko_context;
typedef struct fko_context *fko_ctx_t;

/* 一些gpg特定的数据类型和常量。 */
#if HAVE_LIBGPGME

enum {
    FKO_GPG_NO_SIG_VERIFY_SIGS  = 0x01,
    FKO_GPG_ALLOW_BAD_SIG       = 0x02,
    FKO_GPG_NO_SIG_INFO         = 0x04,
    FKO_GPG_ALLOW_EXPIRED_SIG   = 0x08,
    FKO_GPG_ALLOW_REVOKED_SIG   = 0x10
};

#define FKO_GPG_GOOD_SIGSUM     3

#endif /* HAVE_LIBGPGME */

/* 功能原型 */

/* 一般API调用 */

/* * */
DLL_API int fko_new(fko_ctx_t *ctx);


/* * */
DLL_API int fko_new_with_data(fko_ctx_t *ctx, const char * const enc_msg,
    const char * const dec_key, const int dec_key_len, int encryption_mode,
    const char * const hmac_key, const int hmac_key_len, const int hmac_type);

/* * */
DLL_API int fko_destroy(fko_ctx_t ctx);

/* * */
DLL_API int fko_spa_data_final(fko_ctx_t ctx, const char * const enc_key,
    const int enc_key_len, const char * const hmac_key, const int hmac_key_len);

/* 设置上下文数据函数 */

/* * */
DLL_API int fko_set_rand_value(fko_ctx_t ctx, const char * const val);

/* * */
DLL_API int fko_set_username(fko_ctx_t ctx, const char * const spoof_user);

/* * */
DLL_API int fko_set_timestamp(fko_ctx_t ctx, const int offset);

/* * */
DLL_API int fko_set_spa_message_type(fko_ctx_t ctx, const short msg_type);

/* * */
DLL_API int fko_set_spa_message(fko_ctx_t ctx, const char * const msg_string);

/* * */
DLL_API int fko_set_spa_nat_access(fko_ctx_t ctx, const char * const nat_access);

/* * */
DLL_API int fko_set_spa_server_auth(fko_ctx_t ctx, const char * const server_auth);

/* * */
DLL_API int fko_set_spa_client_timeout(fko_ctx_t ctx, const int timeout);

/* * */
DLL_API int fko_set_spa_digest_type(fko_ctx_t ctx, const short digest_type);

/* * */
DLL_API int fko_set_spa_digest(fko_ctx_t ctx);

/* * */
DLL_API int fko_set_raw_spa_digest_type(fko_ctx_t ctx, const short raw_digest_type);

/* * */
DLL_API int fko_set_raw_spa_digest(fko_ctx_t ctx);

/* * */
DLL_API int fko_set_spa_encryption_type(fko_ctx_t ctx, const short encrypt_type);

/* * */
DLL_API int fko_set_spa_encryption_mode(fko_ctx_t ctx, const int encrypt_mode);

/* * */
DLL_API int fko_set_spa_data(fko_ctx_t ctx, const char * const enc_msg);

#if AFL_FUZZING
DLL_API int fko_afl_set_spa_data(fko_ctx_t ctx, const char * const enc_msg,
        const int enc_msg_len);
#endif

/* * */
DLL_API int fko_set_spa_hmac_type(fko_ctx_t ctx, const short hmac_type);

/* 数据处理和杂项实用程序功能 */

/* * */
DLL_API const char* fko_errstr(const int err_code);

/* * */
DLL_API int fko_encryption_type(const char * const enc_data);

/* * */
DLL_API int fko_key_gen(char * const key_base64, const int key_len,
        char * const hmac_key_base64, const int hmac_key_len,
        const int hmac_type);

/* * */
DLL_API int fko_base64_encode(unsigned char * const in, char * const out, int in_len);

/* * */
DLL_API int fko_base64_decode(const char * const in, unsigned char *out);


/* * */
DLL_API int fko_encode_spa_data(fko_ctx_t ctx);

/* * */
DLL_API int fko_decode_spa_data(fko_ctx_t ctx);

/* * */
DLL_API int fko_encrypt_spa_data(fko_ctx_t ctx, const char * const enc_key,
    const int enc_key_len);

/* * */
DLL_API int fko_decrypt_spa_data(fko_ctx_t ctx, const char * const dec_key,
    const int dec_key_len);

/* * */
DLL_API int fko_verify_hmac(fko_ctx_t ctx, const char * const hmac_key,
    const int hmac_key_len);

/* * */
DLL_API int fko_set_spa_hmac(fko_ctx_t ctx, const char * const hmac_key,
    const int hmac_key_len);

/* * */
DLL_API int fko_get_spa_hmac(fko_ctx_t ctx, char **enc_data);


/* * */
DLL_API int fko_get_encoded_data(fko_ctx_t ctx, char **enc_data);

#if FUZZING_INTERFACES
DLL_API int fko_set_encoded_data(fko_ctx_t ctx, const char * const encoded_msg,
        const int msg_len, const int do_digest, const int digest_type);
#endif

/* 获取上下文数据函数 */

/* * */
DLL_API int fko_get_rand_value(fko_ctx_t ctx, char **rand_val);

/* * */
DLL_API int fko_get_username(fko_ctx_t ctx, char **username);

/* * */
DLL_API int fko_get_timestamp(fko_ctx_t ctx, time_t *ts);

/* * */
DLL_API int fko_get_spa_message_type(fko_ctx_t ctx, short *spa_msg);

/* * */
DLL_API int fko_get_spa_message(fko_ctx_t ctx, char **spa_message);

/* * */
DLL_API int fko_get_spa_nat_access(fko_ctx_t ctx, char **nat_access);

/* * */
DLL_API int fko_get_spa_server_auth(fko_ctx_t ctx, char **server_auth);

/* * */
DLL_API int fko_get_spa_client_timeout(fko_ctx_t ctx, int *client_timeout);

/* * */
DLL_API int fko_get_spa_digest_type(fko_ctx_t ctx, short *spa_digest_type);

/* * */
DLL_API int fko_get_raw_spa_digest_type(fko_ctx_t ctx, short *raw_spa_digest_type);

/* * */
DLL_API int fko_get_spa_hmac_type(fko_ctx_t ctx, short *spa_hmac_type);

/* * */
DLL_API int fko_get_spa_digest(fko_ctx_t ctx, char **spa_digest);

/* * */
DLL_API int fko_get_raw_spa_digest(fko_ctx_t ctx, char **raw_spa_digest);

/* * */
DLL_API int fko_get_spa_encryption_type(fko_ctx_t ctx, short *spa_enc_type);

/* * */
DLL_API int fko_get_spa_encryption_mode(fko_ctx_t ctx, int *spa_enc_mode);

/* * */
DLL_API int fko_get_spa_data(fko_ctx_t ctx, char **spa_data);


/* * */
DLL_API int fko_get_version(fko_ctx_t ctx, char **version);

/* GPG相关功能 */

/* * */
DLL_API int fko_set_gpg_exe(fko_ctx_t ctx, const char * const gpg_exe);

/* * */
DLL_API int fko_get_gpg_exe(fko_ctx_t ctx, char **gpg_exe);


/* * */
DLL_API int fko_set_gpg_recipient(fko_ctx_t ctx, const char * const recip);

/* * */
DLL_API int fko_get_gpg_recipient(fko_ctx_t ctx, char **recip);

/* * */
DLL_API int fko_set_gpg_signer(fko_ctx_t ctx, const char * const signer);

/* * */
DLL_API int fko_get_gpg_signer(fko_ctx_t ctx, char **signer);

/* * */
DLL_API int fko_set_gpg_home_dir(fko_ctx_t ctx, const char * const gpg_home_dir);

/* * */
DLL_API int fko_get_gpg_home_dir(fko_ctx_t ctx, char **gpg_home_dir);


/* * */
DLL_API const char* fko_gpg_errstr(fko_ctx_t ctx);


/* * */
DLL_API int fko_set_gpg_signature_verify(fko_ctx_t ctx,
    const unsigned char val);

/* * */
DLL_API int fko_get_gpg_signature_verify(fko_ctx_t ctx,
    unsigned char * const val);

/* * */
DLL_API int fko_set_gpg_ignore_verify_error(fko_ctx_t ctx,
    const unsigned char val);

/* * */
DLL_API int fko_get_gpg_ignore_verify_error(fko_ctx_t ctx,
    unsigned char * const val);


/* * */
DLL_API int fko_get_gpg_signature_id(fko_ctx_t ctx, char **sig_id);

/* * */
DLL_API int fko_get_gpg_signature_fpr(fko_ctx_t ctx, char **sig_fpr);

/* * */
DLL_API int fko_get_gpg_signature_summary(fko_ctx_t ctx, int *sigsum);

/* * */
DLL_API int fko_get_gpg_signature_status(fko_ctx_t ctx, int *sigstat);


/* * */
DLL_API int fko_gpg_signature_id_match(fko_ctx_t ctx, const char * const id,
    unsigned char * const result);

/* * */
DLL_API int fko_gpg_signature_fpr_match(fko_ctx_t ctx, const char * const fpr,
    unsigned char * const result);

#ifdef __cplusplus
}
#endif

#ifdef HAVE_C_UNIT_TESTS
int register_ts_fko_decode(void);
int register_ts_hmac_test(void);
int register_ts_digest_test(void);
int register_ts_aes_test(void);
int register_utils_test(void);
int register_base64_test(void);
#endif

#endif /* FKO.H */

/* **EOF** */
