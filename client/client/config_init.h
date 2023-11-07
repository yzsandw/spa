
#ifndef CONFIG_INIT_H
#define CONFIG_INIT_H

#include <getopt.h>
#include <sys/stat.h>

#define CONF_VAR_IS(n, v) (strcmp(n, v) == 0)

void config_init(ztn_cli_options_t *options, int argc, char **argv);
void usage(void);

#ifdef HAVE_C_UNIT_TESTS
int register_ts_config_init(void);
#endif

#endif /* CONFIG_INIT_H */

/***EOF***/
