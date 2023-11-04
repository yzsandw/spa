
#ifndef FKO_STATE_H
#define FKO_STATE_H 1

/* 一般状态标志位值。 */
typedef enum {
    FKO_CTX_SET                 = 1,        /* 初始化ctx时设置 */
    FKO_DATA_MODIFIED           = 1 << 1,
    FKO_STATE_RESERVED_2        = 1 << 2,
    STATE_RESERVED_3            = 1 << 3,
    STATE_RESERVED_4            = 1 << 4,
    STATE_RESERVED_5            = 1 << 5,
    FKO_SPA_MSG_TYPE_MODIFIED   = 1 << 6,
    FKO_CTX_SET_2               = 1 << 7,   /* 初始化ctx时设置 */
    STATE_RESERVED_8            = 1 << 8,
    STATE_RESERVED_9            = 1 << 9,
    STATE_RESERVED_10           = 1 << 10,
    STATE_RESERVED_11           = 1 << 11,
    FKO_DIGEST_TYPE_MODIFIED    = 1 << 12,
    FKO_ENCRYPT_TYPE_MODIFIED   = 1 << 13,
    STATE_RESERVED_14           = 1 << 14,
    FKO_BACKWARD_COMPATIBLE     = 1 << 15,
    FKO_ENCRYPT_MODE_MODIFIED   = 1 << 16,
    FKO_HMAC_MODE_MODIFIED      = 1 << 17
} fko_state_flags_t;

/* 这与ctx->初始值一起使用，作为 */
#define FKO_CTX_INITIALIZED  (FKO_CTX_SET|FKO_CTX_SET_2)

#define FKO_SET_CTX_INITIALIZED(ctx) \
    (ctx->state |= (FKO_CTX_INITIALIZED))

#define FKO_CLEAR_CTX_INITIALIZED(ctx) \
    (ctx->state &= (0xffff & ~FKO_CTX_INITIALIZED))

/* 合并所有已修改的SPA数据标志。 */
#define FKO_SPA_DATA_MODIFIED ( \
    FKO_DATA_MODIFIED | FKO_SPA_MSG_TYPE_MODIFIED \
      | FKO_DIGEST_TYPE_MODIFIED | FKO_ENCRYPT_TYPE_MODIFIED )

/* 如果自 */
#define FKO_IS_SPA_DATA_MODIFIED(ctx) (ctx->state & FKO_SPA_DATA_MODIFIED)

/* 清除所有SPA数据修改标志。这通常在 */
#define FKO_CLEAR_SPA_DATA_MODIFIED(ctx) \
    (ctx->state &= (0xffff & ~FKO_SPA_DATA_MODIFIED))

/* 用于确定ctx初始化状态的宏。 */
#define CTX_INITIALIZED(ctx) (ctx != NULL && ctx->initval == FKO_CTX_INITIALIZED)

#endif /* FKO_STATE_H */

/* **EOF** */
