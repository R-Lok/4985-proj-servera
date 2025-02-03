#include "../include/args.h"
#include "../include/socket.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DEFAULT_PORT 8000    // default port if no port arg is

// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
static volatile sig_atomic_t running = 1;    // Global flag for whether the server is running, changed by signal handler

void handle_signal(int signal);

int main(int argc, char **argv)
{
    in_port_t          port;
    struct sockaddr_in addr;
    int                err;
    int                sock_fd;

    port = DEFAULT_PORT;
    signal(SIGINT, handle_signal);

    if(parse_port(argc, argv, &port) != 0)    // parse the port from command line args
    {
        exit(EXIT_FAILURE);
    }

    if(setup_addr(&addr, port, &err))    // set up address structs for socket setup
    {
        fprintf(stderr, "Error setting up sockaddr_in %s", strerror(err));
        exit(EXIT_FAILURE);
    }

    sock_fd = setup_socket(&addr, &err);    // sets up the socket, prepares it to listen

    if(sock_fd == -1)
    {
        fprintf(stderr, "Error setting up socket %s", strerror(err));
        exit(EXIT_FAILURE);
    }

    if(set_socket_nonblock(sock_fd, &err))    // set socket to non-blocking
    {
        fprintf(stdout, "Error setting socket to non-blocking - %s\n", strerror(err));
        exit(EXIT_FAILURE);
    }

    printf("Server running on port %u...\n", port);

    handle_connections(sock_fd, &addr, &running);

    return EXIT_SUCCESS;
}

void handle_signal(int signal)
{
    if(signal == SIGINT)
    {
        running = 0;
    }
}
