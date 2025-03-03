#ifndef ARGS_H
#define ARGS_H

#include <netinet/in.h>
#define MAX_LEN_IPV4 15

int  parse_port(int argc, char **argv, in_port_t *port_var);
int  parse_addr(int argc, char **argv, in_port_t *port_var, char *ipv4);
void print_usage_client(void);

#endif
