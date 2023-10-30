/**
 * \file server/sig_handler.h
 *
 * \brief sig_handler函数和数据的头文件。
 */

#ifndef SIG_HANDLER_H
#define SIG_HANDLER_H

#include <signal.h>

extern sig_atomic_t got_signal;

extern sig_atomic_t got_sighup;
extern sig_atomic_t got_sigint;
extern sig_atomic_t got_sigterm;
extern sig_atomic_t got_sigusr1;
extern sig_atomic_t got_sigusr2;
extern sig_atomic_t got_sigchld;

void sig_handler(int sig);
int set_sig_handlers(void);
int sig_do_stop(void);

#endif /* SIG_HANDLER_H */

/***EOF***/
