
#ifndef SPA_COMM_H
#define SPA_COMM_H

#include "fwknop_common.h"
#include "netinet_common.h"


int send_spa_packet(fko_ctx_t ctx, fko_cli_options_t *options);
int write_spa_packet_data(fko_ctx_t ctx, const fko_cli_options_t *options);

#endif  /* SPA_COMM_H */
