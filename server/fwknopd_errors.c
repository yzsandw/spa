/**
 * \file server/fwknopd_errors.c
 *
 * \brief fwknopd的错误消息函数
 */


#include "fwknopd_common.h"
#include "fwknopd_errors.h"

/* 返回一个描述给定错误代码含义的字符串
*/
static const char*
fwknopd_errstr(const int err_code)
{
    switch (err_code)
    {
        case 0:
            return("Success");

        case SPA_MSG_BAD_DATA:
            return("Data is not a valid SPA message format");

        case SPA_MSG_LEN_TOO_SMALL:
            return("Not enough data to be a valid SPA message");

        case SPA_MSG_NOT_SPA_DATA:
            return("Data is not an SPA message");

        case SPA_MSG_HTTP_NOT_ENABLED:
            return("SPA via HTTP request, but ENABLE_SPA_OVER_HTTP is not set");

        case SPA_MSG_FKO_CTX_ERROR:
            return("Error creating FKO context for incoming data.");

        case SPA_MSG_DIGEST_ERROR:
            return("Unable to retrieve digest from the SPA data.");

        case SPA_MSG_DIGEST_CACHE_ERROR:
            return("Error trying to access the digest.cache file");

        case SPA_MSG_REPLAY:
            return("Detected SPA message replay");

        case SPA_MSG_TOO_OLD:
            return("SPA message timestamp is outside the allowable window");

        case SPA_MSG_ACCESS_DENIED:
            return("SPA message did not pass access checks");

        case SPA_MSG_COMMAND_ERROR:
            return("An error occurred while executing an SPA command message");

        case SPA_MSG_NOT_SUPPORTED:
            return("Unsupported SPA message operation");

        case SPA_MSG_ERROR:
            return("General SPA message processing error");

        case FW_RULE_ADD_ERROR:
            return("An error occurred while tring to add a firewall rule");

        case FW_RULE_DELETE_ERROR:
            return("An error occurred while tring to delete a firewall rule");

        case FW_RULE_UNKNOWN_ERROR:
            return("Unknown/unclassified firewall rule processing error");
    }

    return("Undefined/unknown fwknopd Error");
}

/* 尝试确定错误代码类型并发送相应的响应。基本上，如果它不是fwknopd错误代码，就假定它是libfko的错误。
*/
const char*
get_errstr(const int err_code)
{
    if(! IS_FWKNOPD_ERROR(err_code))
        return(fko_errstr(err_code));

    return(fwknopd_errstr(err_code));
}

/* 打印所有服务器错误（来自server/fwknopd_errors.c）到标准输出 
*/
void
dump_server_errors(void)
{
    int i;
    for (i=SPA_MSG_BAD_DATA; i<=SPA_MSG_ERROR; i++)
    {
        fprintf(stdout, "err code: %d, err string: '%s'\n",
                i, fwknopd_errstr(i));
    }
    for (i=FW_RULE_ADD_ERROR; i<=FW_RULE_UNKNOWN_ERROR; i++)
    {
        fprintf(stdout, "err code: %d, err string: '%s'\n",
                i, fwknopd_errstr(i));
    }
    fflush(stdout);
    return;
}

/***EOF***/
