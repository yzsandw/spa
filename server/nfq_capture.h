/**
 * \file server/nfq_capture.h
 *
 * \brief nfq_capture.c的头文件
 */


#ifndef NFQ_CAPTURE_H
#define NFQ_CAPTURE_H


#define MAX_NFQ_ERRORS_BEFORE_BAIL 100

/* 原型
*/
int nfq_capture(fko_srv_options_t *opts);

#endif  /* NFQ_CAPTURE_H */
