/**
 * \file server/replay_cache.c
 *
 * \brief 缓存数据包以检测重放攻击
 *
 *          提供检查可能的重放攻击的函数，
 *          通过使用先前看到的摘要的缓存。 
 *          默认情况下，此缓存是一个简单的文件，
 *          但可以配置成使用dbm解决方案（ndbm或以ndbm兼容模式的gdbm文件）
 *          来存储先前接收到的SPA数据包的摘要。
 */


#include "replay_cache.h"
#include "log_msg.h"
#include "fwknopd_errors.h"
#include "utils.h"

#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>

#if HAVE_LIBGDBM
  #include <gdbm.h>

  #define MY_DBM_FETCH(d, k)        gdbm_fetch(d, k)
  #define MY_DBM_STORE(d, k, v, m)  gdbm_store(d, k, v, m)
  #define MY_DBM_STRERROR(x)        gdbm_strerror(x)
  #define MY_DBM_CLOSE(d)           gdbm_close(d)

  #define MY_DBM_REPLACE            GDBM_REPLACE
  #define MY_DBM_INSERT             GDBM_INSERT

#elif HAVE_LIBNDBM
  #include <ndbm.h>

  #define MY_DBM_FETCH(d, k)        dbm_fetch(d, k)
  #define MY_DBM_STORE(d, k, v, m)  dbm_store(d, k, v, m)
  #define MY_DBM_STRERROR(x)        strerror(x)
  #define MY_DBM_CLOSE(d)           dbm_close(d)

  #define MY_DBM_REPLACE            DBM_REPLACE
  #define MY_DBM_INSERT             DBM_INSERT

#else
  #if ! USE_FILE_CACHE
    #error "File cache method disabled, and No GDBM or NDBM header file found. WTF?"
  #endif
#endif

#if HAVE_SYS_SOCKET_H
  #include <sys/socket.h>
#endif
#include <arpa/inet.h>

#include <fcntl.h>

#define DATE_LEN 18
#define MAX_DIGEST_SIZE 64

/* 通过重命名来轮换摘要文件。
*/
static void
rotate_digest_cache_file(fko_srv_options_t *opts)
{
#ifdef NO_DIGEST_CACHE
    log_msg(LOG_WARNING, "Digest cache not supported. Nothing to rotate.");
#else
    int         res;
    char       *new_file = NULL;

    log_msg(LOG_INFO, "Rotating digest cache file.");

#if USE_FILE_CACHE
    new_file = calloc(1, strlen(opts->config[CONF_DIGEST_FILE])+5);
#else
    new_file = calloc(1, strlen(opts->config[CONF_DIGEST_DB_FILE])+5);
#endif

    if(new_file == NULL)
    {
        log_msg(LOG_ERR, "rotate_digest_cache_file: Memory allocation error.");
        clean_exit(opts, NO_FW_CLEANUP, EXIT_FAILURE);
    }

    /* 新文件名只是原文件名后加上 '-old'。
    */
#if USE_FILE_CACHE
    strlcpy(new_file, opts->config[CONF_DIGEST_FILE],
        strlen(opts->config[CONF_DIGEST_FILE])+5);
    strlcat(new_file, "-old",
            strlen(opts->config[CONF_DIGEST_FILE])+5);
#else
    strlcpy(new_file, opts->config[CONF_DIGEST_DB_FILE],
        strlen(opts->config[CONF_DIGEST_DB_FILE])+5);
    strlcat(new_file, "-old",
            strlen(opts->config[CONF_DIGEST_DB_FILE])+5);
#endif

#if USE_FILE_CACHE
    res = rename(opts->config[CONF_DIGEST_FILE], new_file);
#else
    res = rename(opts->config[CONF_DIGEST_DB_FILE], new_file);
#endif

    if(res < 0)
        log_msg(LOG_ERR, "Unable to rename digest file: %s to %s: %s",
#if USE_FILE_CACHE
            opts->config[CONF_DIGEST_FILE], new_file, strerror(errno)
#else
            opts->config[CONF_DIGEST_DB_FILE], new_file, strerror(errno)
#endif
        );
#endif /* NO_DIGEST_CACHE */

    free(new_file);
    return;
}

static void
replay_warning(fko_srv_options_t *opts, digest_cache_info_t *digest_info)
{
    char        src_ip[INET_ADDRSTRLEN+1] = {0};
    char        orig_src_ip[INET_ADDRSTRLEN+1] = {0};
    char        created[DATE_LEN] = {0};

#if ! USE_FILE_CACHE
    char        first[DATE_LEN] = {0}, last[DATE_LEN] = {0};
#endif

    /* 将IP地址转换为人类可读的形式。
    */
    inet_ntop(AF_INET, &(opts->spa_pkt.packet_src_ip),
        src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(digest_info->src_ip), orig_src_ip, INET_ADDRSTRLEN);

#if ! USE_FILE_CACHE
    /* 标记最后的重放时间。
    */
    digest_info->last_replay = time(NULL);

    /* 增加重放次数并检查是否是第一次。
    */
    if(++(digest_info->replay_count) == 1)
    {
        /* 这是第一次重放，所以将其设置为与最后一次重放相同
        */
        digest_info->first_replay = digest_info->last_replay;
    }

    strftime(first, DATE_LEN, "%D %H:%M:%S", localtime(&(digest_info->first_replay)));
    strftime(last, DATE_LEN, "%D %H:%M:%S", localtime(&(digest_info->last_replay)));
#endif

    strftime(created, DATE_LEN, "%D %H:%M:%S", localtime(&(digest_info->created)));

    log_msg(LOG_WARNING,
        "Replay detected from source IP: %s, "
        "Destination proto/port: %d/%d, "
        "Original source IP: %s, "
        "Original dst proto/port: %d/%d, "
#if USE_FILE_CACHE
        "Entry created: %s",
#else
        "Entry created: %s, "
        "First replay: %s, "
        "Last replay: %s, "
        "Replay count: %i",
#endif
        src_ip,
        opts->spa_pkt.packet_proto,
        opts->spa_pkt.packet_dst_port,
        orig_src_ip,
        digest_info->proto,
        digest_info->dst_port,
#if USE_FILE_CACHE
        created
#else
        created,
        first,
        last,
        digest_info->replay_count
#endif
    );

    return;
}

#if USE_FILE_CACHE
static int
replay_file_cache_init(fko_srv_options_t *opts)
{
    FILE           *digest_file_ptr = NULL;
    unsigned int    num_lines = 0, digest_ctr = 0;
    char            line_buf[MAX_LINE_LEN]    = {0};
    char            src_ip[INET_ADDRSTRLEN+1] = {0};
    char            dst_ip[INET_ADDRSTRLEN+1] = {0};
    long int        time_tmp;
    int             digest_file_fd = -1;
    char            digest_header[] = "# <digest> <proto> <src_ip> <src_port> <dst_ip> <dst_port> <time>\n";

    struct digest_cache_list *digest_elm = NULL;

    /* 如果文件存在，将之前的SPA摘要导入到缓存列表中。
    */
    if (access(opts->config[CONF_DIGEST_FILE], F_OK) == 0)
    {
        /* 检查权限
        */
        if (access(opts->config[CONF_DIGEST_FILE], R_OK|W_OK) != 0)
        {
            log_msg(LOG_WARNING, "Digest file '%s' exists but: '%s'",
                opts->config[CONF_DIGEST_FILE], strerror(errno));
            return(-1);
        }
    }
    else
    {
        /* 若文件尚不存在，即第一个成功的SPA数据包摘要被写入磁盘时创建该文件。
        */
        digest_file_fd = open(opts->config[CONF_DIGEST_FILE],
                O_WRONLY|O_CREAT|O_EXCL, S_IRUSR|S_IWUSR);

        if (digest_file_fd == -1)
        {
            log_msg(LOG_WARNING, "Could not create digest cache: %s: %s",
                opts->config[CONF_DIGEST_FILE], strerror(errno));
            return(-1);
        }
        else
        {
            if(write(digest_file_fd, digest_header, strlen(digest_header))
                    != strlen(digest_header)) {
                log_msg(LOG_WARNING,
                    "Did not write expected number of bytes to digest cache: %s",
                    opts->config[CONF_DIGEST_FILE]);
            }
            close(digest_file_fd);

            return(0);
        }
    }

    /* 文件存在，并且我们有访问权限 - 创建内存中的摘要缓存。
    */
    if ((digest_file_ptr = fopen(opts->config[CONF_DIGEST_FILE], "r")) == NULL)
    {
        log_msg(LOG_WARNING, "Could not open digest cache: %s: %s",
            opts->config[CONF_DIGEST_FILE], strerror(errno));
        return(-1);
    }

#if HAVE_FILENO
    if(verify_file_perms_ownership(opts->config[CONF_DIGEST_FILE], fileno(digest_file_ptr)) != 1)
#else
    if(verify_file_perms_ownership(opts->config[CONF_DIGEST_FILE], -1) != 1)
#endif
    {
        fclose(digest_file_ptr);
        return(-1);
    }

    /* 行格式：
     * <摘要> <协议> <源IP> <源端口> <目标IP> <目标端口> <时间>
     * <digest> <proto> <src_ip> <src_port> <dst_ip> <dst_port> <time>
     * 示例：
     * 7XgadOyqv0tF5xG8uhg2iIrheeNKglCWKmxQDgYP1dY 17 127.0.0.1 40305 127.0.0.1 62201 1313283481
    */
    while ((fgets(line_buf, MAX_LINE_LEN, digest_file_ptr)) != NULL)
    {
        num_lines++;
        line_buf[MAX_LINE_LEN-1] = '\0';

        if(IS_EMPTY_LINE(line_buf[0]))
            continue;

        /* Initialize a digest cache list element, and add it into the list if
         * valid.
         * 初始化一个摘要缓存列表元素，并将其添加到列表中，如果有效。
        */
        if ((digest_elm = calloc(1, sizeof(struct digest_cache_list))) == NULL)
        {
            log_msg(LOG_ERR, "[*] Could not allocate digest list element");
            continue;
        }
        if ((digest_elm->cache_info.digest = calloc(1, MAX_DIGEST_SIZE+1)) == NULL)
        {
            free(digest_elm);
            log_msg(LOG_ERR, "[*] Could not allocate digest string");
            continue;
        }
        src_ip[0] = '\0';
        dst_ip[0] = '\0';

        if(sscanf(line_buf, "%64s %hhu %16s %hu %16s %hu %ld",
            digest_elm->cache_info.digest,  /* %64s, buffer size is MAX_DIGEST_SIZE+1 */
            &(digest_elm->cache_info.proto),
            src_ip,  /* %16s, buffer size is INET_ADDRSTRLEN+1 */
            &(digest_elm->cache_info.src_port),
            dst_ip,  /* %16s, buffer size is INET_ADDRSTRLEN+1 */
            &(digest_elm->cache_info.dst_port),
            &time_tmp) != 7)
        {
            log_msg(LOG_INFO,
                "*Skipping invalid digest file entry in %s at line %i.\n - %s",
                opts->config[CONF_DIGEST_FILE], num_lines, line_buf
            );
            free(digest_elm->cache_info.digest);
            free(digest_elm);
            continue;
        }
        digest_elm->cache_info.created = time_tmp;


        if (inet_pton(AF_INET, src_ip, &(digest_elm->cache_info.src_ip)) != 1)
        {
            free(digest_elm->cache_info.digest);
            free(digest_elm);
            continue;
        }

        if (inet_pton(AF_INET, dst_ip, &(digest_elm->cache_info.dst_ip)) != 1)
        {
            free(digest_elm->cache_info.digest);
            free(digest_elm);
            continue;
        }

        digest_elm->next   = opts->digest_cache;
        opts->digest_cache = digest_elm;
        digest_ctr++;

        if(opts->verbose > 3)
            log_msg(LOG_DEBUG,
                "DIGEST FILE: %s, VALID LINE: %s",
                opts->config[CONF_DIGEST_FILE], line_buf
            );

    }

    fclose(digest_file_ptr);

    return(digest_ctr);
}

#else /* 使用文件缓存。 */

/* 检查重放DBM文件是否存在，如果不存在则创建它。返回DB条目的数量，或在出现错误时返回-1。
*/
static int
replay_db_cache_init(fko_srv_options_t *opts)
{
#ifdef NO_DIGEST_CACHE
    return(-1);
#else

#ifdef HAVE_LIBGDBM
    GDBM_FILE   rpdb;
#elif HAVE_LIBNDBM
    DBM        *rpdb;
    datum       db_ent;
#endif

    datum       db_key, db_next_key;
    int         db_count = 0;

#ifdef HAVE_LIBGDBM
    rpdb = gdbm_open(
        opts->config[CONF_DIGEST_DB_FILE], 512, GDBM_WRCREAT, S_IRUSR|S_IWUSR, 0
    );
#elif HAVE_LIBNDBM
    rpdb = dbm_open(
        opts->config[CONF_DIGEST_DB_FILE], O_RDWR|O_CREAT, S_IRUSR|S_IWUSR
    );
#endif

    if(!rpdb)
    {
        log_msg(LOG_ERR,
            "Unable to open digest cache file: '%s': %s",
            opts->config[CONF_DIGEST_DB_FILE],
            MY_DBM_STRERROR(errno)
        );

        return(-1);
    }

#ifdef HAVE_LIBGDBM
    db_key = gdbm_firstkey(rpdb);

    while (db_key.dptr != NULL)
    {
        db_count++;
        db_next_key = gdbm_nextkey(rpdb, db_key);
        free(db_key.dptr);
        db_key = db_next_key;
    }
#elif HAVE_LIBNDBM
    for (db_key = dbm_firstkey(rpdb); db_ent.dptr != NULL; db_key = dbm_nextkey(rpdb))
        db_count++;
#endif

    MY_DBM_CLOSE(rpdb);

    return(db_count);
#endif /* 使用文件缓存*/
}
#endif /* 没有摘要缓存 */

#if USE_FILE_CACHE
static int
is_replay_file_cache(fko_srv_options_t *opts, char *digest)
{
    int         digest_len = 0;

    struct digest_cache_list *digest_list_ptr = NULL;

    digest_len = strlen(digest);

    /* 检查SPA数据包摘要的缓存。
    */
    for (digest_list_ptr = opts->digest_cache;
            digest_list_ptr != NULL;
            digest_list_ptr = digest_list_ptr->next) {

        if (constant_runtime_cmp(digest_list_ptr->cache_info.digest,
                    digest, digest_len) == 0) {

            replay_warning(opts, &(digest_list_ptr->cache_info));

            return(SPA_MSG_REPLAY);
        }
    }
    return(SPA_MSG_SUCCESS);
}

static int
add_replay_file_cache(fko_srv_options_t *opts, char *digest)
{
    FILE       *digest_file_ptr = NULL;
    int         digest_len = 0;
    char        src_ip[INET_ADDRSTRLEN+1] = {0};
    char        dst_ip[INET_ADDRSTRLEN+1] = {0};

    struct digest_cache_list *digest_elm = NULL;

    digest_len = strlen(digest);

    if ((digest_elm = calloc(1, sizeof(struct digest_cache_list))) == NULL)
    {
        log_msg(LOG_WARNING, "Error calloc() returned NULL for digest cache element",
            fko_errstr(SPA_MSG_ERROR));

        return(SPA_MSG_ERROR);
    }
    if ((digest_elm->cache_info.digest = calloc(1, digest_len+1)) == NULL)
    {
        log_msg(LOG_WARNING, "Error calloc() returned NULL for digest cache string",
            fko_errstr(SPA_MSG_ERROR));
        free(digest_elm);
        return(SPA_MSG_ERROR);
    }

    strlcpy(digest_elm->cache_info.digest, digest, digest_len+1);
    digest_elm->cache_info.proto    = opts->spa_pkt.packet_proto;
    digest_elm->cache_info.src_ip   = opts->spa_pkt.packet_src_ip;
    digest_elm->cache_info.dst_ip   = opts->spa_pkt.packet_dst_ip;
    digest_elm->cache_info.src_port = opts->spa_pkt.packet_src_port;
    digest_elm->cache_info.dst_port = opts->spa_pkt.packet_dst_port;
    digest_elm->cache_info.created = time(NULL);

    /* 首先，将摘要添加到内存列表的开头
    */
    digest_elm->next = opts->digest_cache;
    opts->digest_cache = digest_elm;

    /* 现在，将摘要写入磁盘。
    */
    if ((digest_file_ptr = fopen(opts->config[CONF_DIGEST_FILE], "a")) == NULL)
    {
        log_msg(LOG_WARNING, "Could not open digest cache: %s: %s",
            opts->config[CONF_DIGEST_FILE], strerror(errno));
        return(SPA_MSG_DIGEST_CACHE_ERROR);
    }

    inet_ntop(AF_INET, &(digest_elm->cache_info.src_ip),
        src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(digest_elm->cache_info.dst_ip),
        dst_ip, INET_ADDRSTRLEN);
    fprintf(digest_file_ptr, "%s %d %s %d %s %d %d\n",
        digest,
        digest_elm->cache_info.proto,
        src_ip,
        (int) digest_elm->cache_info.src_port,
        dst_ip,
        digest_elm->cache_info.dst_port,
        (int) digest_elm->cache_info.created);

    fclose(digest_file_ptr);

    return(SPA_MSG_SUCCESS);
}
#endif /* 使用文件缓存。 */

#if !USE_FILE_CACHE
static int
is_replay_dbm_cache(fko_srv_options_t *opts, char *digest)
{
#ifdef NO_DIGEST_CACHE
    return 0;
#else

#ifdef HAVE_LIBGDBM
    GDBM_FILE   rpdb;
#elif HAVE_LIBNDBM
    DBM        *rpdb;
#endif
    datum       db_key, db_ent;

    int         digest_len, res = SPA_MSG_SUCCESS;

    digest_len = strlen(digest);

    db_key.dptr = digest;
    db_key.dsize = digest_len;

    /* 检查数据库中是否存在这个键
    */
#ifdef HAVE_LIBGDBM
    rpdb = gdbm_open(
         opts->config[CONF_DIGEST_DB_FILE], 512, GDBM_WRCREAT, S_IRUSR|S_IWUSR, 0
    );
#elif HAVE_LIBNDBM
    rpdb = dbm_open(opts->config[CONF_DIGEST_DB_FILE], O_RDWR, 0);
#endif

    if(!rpdb)
    {
        log_msg(LOG_WARNING, "Error opening digest_cache: '%s': %s",
            opts->config[CONF_DIGEST_DB_FILE],
            MY_DBM_STRERROR(errno)
        );

        return(SPA_MSG_DIGEST_CACHE_ERROR);
    }

    db_ent = MY_DBM_FETCH(rpdb, db_key);

    /* 如果数据不为null，我们有一个匹配。否则，我们将此条目添加到缓存中
    */
    if(db_ent.dptr != NULL)
    {
        replay_warning(opts, (digest_cache_info_t *)db_ent.dptr);

        /* Save it back to the digest cache
        */
        if(MY_DBM_STORE(rpdb, db_key, db_ent, MY_DBM_REPLACE) != 0)
            log_msg(LOG_WARNING, "Error updating entry in digest_cache: '%s': %s",
                opts->config[CONF_DIGEST_DB_FILE],
                MY_DBM_STRERROR(errno)
            );

#ifdef HAVE_LIBGDBM
        free(db_ent.dptr);
#endif
        res = SPA_MSG_REPLAY;
    }

    MY_DBM_CLOSE(rpdb);

    return(res);
#endif /*  没有摘要缓存 */
}

static int
add_replay_dbm_cache(fko_srv_options_t *opts, char *digest)
{
#ifdef NO_DIGEST_CACHE
    return 0;
#else

#ifdef HAVE_LIBGDBM
    GDBM_FILE   rpdb;
#elif HAVE_LIBNDBM
    DBM        *rpdb;
#endif
    datum       db_key, db_ent;

    int         digest_len, res = SPA_MSG_SUCCESS;

    digest_cache_info_t dc_info;

    digest_len = strlen(digest);

    db_key.dptr = digest;
    db_key.dsize = digest_len;

    /* 检查数据库中是否存在这个键
    */
#ifdef HAVE_LIBGDBM
    rpdb = gdbm_open(
         opts->config[CONF_DIGEST_DB_FILE], 512, GDBM_WRCREAT, S_IRUSR|S_IWUSR, 0
    );
#elif HAVE_LIBNDBM
    rpdb = dbm_open(opts->config[CONF_DIGEST_DB_FILE], O_RDWR, 0);
#endif

    if(!rpdb)
    {
        log_msg(LOG_WARNING, "Error opening digest_cache: '%s': %s",
            opts->config[CONF_DIGEST_DB_FILE],
            MY_DBM_STRERROR(errno)
        );

        return(SPA_MSG_DIGEST_CACHE_ERROR);
    }

    db_ent = MY_DBM_FETCH(rpdb, db_key);

    /* 如果数据为null，表示有一个新条目
    */
    if(db_ent.dptr == NULL)
    {
        /* 这是一个需要添加到缓存中的新SPA数据包
        */
        dc_info.src_ip   = opts->spa_pkt.packet_src_ip;
        dc_info.dst_ip   = opts->spa_pkt.packet_dst_ip;
        dc_info.src_port = opts->spa_pkt.packet_src_port;
        dc_info.dst_port = opts->spa_pkt.packet_dst_port;
        dc_info.proto    = opts->spa_pkt.packet_proto;
        dc_info.created  = time(NULL);
        dc_info.first_replay = dc_info.last_replay = dc_info.replay_count = 0;

        db_ent.dsize    = sizeof(digest_cache_info_t);
        db_ent.dptr     = (char*)&(dc_info);

        if(MY_DBM_STORE(rpdb, db_key, db_ent, MY_DBM_INSERT) != 0)
        {
            log_msg(LOG_WARNING, "Error adding entry digest_cache: %s",
                MY_DBM_STRERROR(errno)
            );

            res = SPA_MSG_DIGEST_CACHE_ERROR;
        }

        res = SPA_MSG_SUCCESS;
    }
    else
        res = SPA_MSG_DIGEST_CACHE_ERROR;

    MY_DBM_CLOSE(rpdb);

    return(res);
#endif /* 没有摘要缓存 */
}
#endif /* 使用文件缓存 */

#if USE_FILE_CACHE
/* 释放重放列表的内存
*/
void
free_replay_list(fko_srv_options_t *opts)
{
    struct digest_cache_list *digest_list_ptr = NULL, *digest_tmp = NULL;

#ifdef NO_DIGEST_CACHE
    return;
#endif

#if AFL_FUZZING
    if(opts->afl_fuzzing)
        return;
#endif

    if (opts->digest_cache == NULL)
        return;

    digest_list_ptr = opts->digest_cache;
    while (digest_list_ptr != NULL)
    {
        digest_tmp = digest_list_ptr->next;
        if (digest_list_ptr->cache_info.digest != NULL
                && digest_list_ptr->cache_info.digest[0] != '\0')
        {
            free(digest_list_ptr->cache_info.digest);
        }
        free(digest_list_ptr);
        digest_list_ptr = digest_tmp;
    }

    return;
}
#endif

int
replay_cache_init(fko_srv_options_t *opts)
{
#ifdef NO_DIGEST_CACHE
    return(-1);
#else

    /* 如果指定了轮换，执行它
    */
    if(opts->rotate_digest_cache)
        rotate_digest_cache_file(opts);

#if USE_FILE_CACHE
    return replay_file_cache_init(opts);
#else
    return replay_db_cache_init(opts);
#endif

#endif /* 没有摘要缓存 */
}

int
add_replay(fko_srv_options_t *opts, char *digest)
{
#ifdef NO_DIGEST_CACHE
    return(-1);
#else

    if(digest == NULL)
    {
        log_msg(LOG_WARNING, "NULL digest passed into add_replay()");
        return(SPA_MSG_DIGEST_CACHE_ERROR);
    }

#if USE_FILE_CACHE
    return add_replay_file_cache(opts, digest);
#else
    return add_replay_dbm_cache(opts, digest);
#endif
#endif /* 没有摘要缓存 */
}

/* 获取一个fko上下文，提取摘要并将其用作用于检查重放数据库（摘要缓存）的键。
*/
int
is_replay(fko_srv_options_t *opts, char *digest)
{
#ifdef NO_DIGEST_CACHE
    return(-1);
#else

#if USE_FILE_CACHE
    return is_replay_file_cache(opts, digest);
#else
    return is_replay_dbm_cache(opts, digest);
#endif
#endif /* 没有摘要缓存 */
}

/***EOF***/
