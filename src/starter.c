#include "../include/args.h"
#include "../include/socket.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DEFAULT_PORT 8080

int main(int argc, char **argv)
{
    in_port_t          sm_port;
    char               ipv4[MAX_LEN_IPV4 + 2];
    int                err;
    struct sockaddr_in sm_addr;
    // int                server_fd;
    // int                ret;

    sm_port = DEFAULT_PORT;

    if(parse_addr(argc, argv, &sm_port, ipv4))
    {
        exit(EXIT_FAILURE);
    }

    if(setup_addr(ipv4, &sm_addr, sm_port, &err) != 0)
    {
        fprintf(stderr, "Invalid ipv4 address- %s\n", strerror(err));
        print_usage_client();
        exit(EXIT_FAILURE);
    }
}
