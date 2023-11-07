
#ifndef SPA_COMM_H
#define SPA_COMM_H

#include "spanop_common.h"
#include "netinet_common.h"


int send_spa_packet(ztn_ctx_t ctx, ztn_cli_options_t *options);
int write_spa_packet_data(ztn_ctx_t ctx, const ztn_cli_options_t *options);

#endif  /* SPA_COMM_H */
