#include "../include/args.h"
#include "../include/server_manager.h"
#include "../include/socket.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DEFAULT_PORT 8080

// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
static volatile sig_atomic_t running = 1;

void handle_signal(int signal);

int main(int argc, char **argv)
{
    in_port_t          sm_port;
    char               ipv4[MAX_LEN_IPV4 + 2];
    int                err;
    struct sockaddr_in sm_addr;
    int                sock_fd;
    int                ret;

    sm_port = DEFAULT_PORT;
    ret     = 0;
    signal(SIGINT, handle_signal);

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

    sock_fd = socket(sm_addr.sin_family, SOCK_STREAM, 0);    // NOLINT(android-cloexec-socket)
    if(sock_fd == -1)
    {
        fprintf(stderr, "Error calling socket()\n");
        exit(EXIT_FAILURE);
    }

    if(server_manager_connect(sock_fd, &sm_addr, &running))
    {
        goto end;    // SIGINT received
    }

    server_loop(sock_fd);    // temp, needs to capture return value

    while(running)
    {
    }

    printf("Server starter closing...\n");
end:
    return ret;
}

void handle_signal(int signal)
{
    if(signal == SIGINT)
    {
        running = 0;
    }
}
