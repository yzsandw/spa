
#ifndef ZTN_STATE_H
#define ZTN_STATE_H 1

/* 一般状态标志位值。 */
typedef enum {
    ZTN_CTX_SET                 = 1,        /* 初始化ctx时设置 */
    ZTN_DATA_MODIFIED           = 1 << 1,
    ZTN_STATE_RESERVED_2        = 1 << 2,
    STATE_RESERVED_3            = 1 << 3,
    STATE_RESERVED_4            = 1 << 4,
    STATE_RESERVED_5            = 1 << 5,
    ZTN_SPA_MSG_TYPE_MODIFIED   = 1 << 6,
    ZTN_CTX_SET_2               = 1 << 7,   /* 初始化ctx时设置 */
    STATE_RESERVED_8            = 1 << 8,
    STATE_RESERVED_9            = 1 << 9,
    STATE_RESERVED_10           = 1 << 10,
    STATE_RESERVED_11           = 1 << 11,
    ZTN_DIGEST_TYPE_MODIFIED    = 1 << 12,
    ZTN_ENCRYPT_TYPE_MODIFIED   = 1 << 13,
    STATE_RESERVED_14           = 1 << 14,
    ZTN_BACKWARD_COMPATIBLE     = 1 << 15,
    ZTN_ENCRYPT_MODE_MODIFIED   = 1 << 16,
    ZTN_HMAC_MODE_MODIFIED      = 1 << 17
} ztn_state_flags_t;

/* 这与ctx->初始值一起使用，作为 */
#define ZTN_CTX_INITIALIZED  (ZTN_CTX_SET|ZTN_CTX_SET_2)

#define ZTN_SET_CTX_INITIALIZED(ctx) \
    (ctx->state |= (ZTN_CTX_INITIALIZED))

#define ZTN_CLEAR_CTX_INITIALIZED(ctx) \
    (ctx->state &= (0xffff & ~ZTN_CTX_INITIALIZED))

/* 合并所有已修改的SPA数据标志。 */
#define ZTN_SPA_DATA_MODIFIED ( \
    ZTN_DATA_MODIFIED | ZTN_SPA_MSG_TYPE_MODIFIED \
      | ZTN_DIGEST_TYPE_MODIFIED | ZTN_ENCRYPT_TYPE_MODIFIED )

/* 如果自 */
#define ZTN_IS_SPA_DATA_MODIFIED(ctx) (ctx->state & ZTN_SPA_DATA_MODIFIED)

/* 清除所有SPA数据修改标志。这通常在 */
#define ZTN_CLEAR_SPA_DATA_MODIFIED(ctx) \
    (ctx->state &= (0xffff & ~ZTN_SPA_DATA_MODIFIED))

/* 用于确定ctx初始化状态的宏。 */
#define CTX_INITIALIZED(ctx) (ctx != NULL && ctx->initval == ZTN_CTX_INITIALIZED)

#endif /* ZTN_STATE_H */

/* **EOF** */
