
#ifndef FKO_LIMITS_H
#define FKO_LIMITS_H 1

/* 我们允许fko上下文错误消息缓冲区有多少空间。 */
#define MAX_FKO_ERR_MSG_SIZE        128

/* 定义一些限制（--DSS XXX：这些尺寸需要审查） */
#define MAX_SPA_ENCRYPTED_SIZE     1500
#define MAX_SPA_CMD_LEN            1400
#define MAX_SPA_USERNAME_SIZE        64
#define MAX_SPA_MESSAGE_SIZE        256
#define MAX_SPA_NAT_ACCESS_SIZE     128
#define MAX_SPA_SERVER_AUTH_SIZE     64
#define MAX_SPA_TIMESTAMP_SIZE       12
#define MAX_SPA_VERSION_SIZE          8 /* 12.34.56 */
#define MAX_SPA_MESSAGE_TYPE_SIZE     2

#define MIN_SPA_ENCODED_MSG_SIZE     36 /* 有点武断 */
#define MAX_SPA_ENCODED_MSG_SIZE     MAX_SPA_ENCRYPTED_SIZE

#define MIN_SPA_PLAINTEXT_MSG_SIZE   MIN_SPA_ENCODED_MSG_SIZE
#define MAX_SPA_PLAINTEXT_MSG_SIZE   MAX_SPA_ENCODED_MSG_SIZE

#define MIN_GNUPG_MSG_SIZE          400
#define MIN_SPA_FIELDS                6
#define MAX_SPA_FIELDS                9

#define MAX_IPV4_STR_LEN             16
#define MIN_IPV4_STR_LEN              7

#define MAX_PROTO_STR_LEN             4  /* tcp，udp，icmp */
#define MAX_PORT_STR_LEN              5
#define MAX_PORT                  65535

/* 杂项。 */
#define FKO_ENCODE_TMP_BUF_SIZE    1024
#define FKO_RAND_VAL_SIZE            16

#endif /* FKO_LIMITS_H */

/* **EOF** */
