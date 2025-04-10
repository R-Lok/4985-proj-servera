#include "../include/args.h"
#include "../include/protocol.h"
#include "../include/server_manager.h"
#include "../include/socket.h"
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define DEFAULT_PORT 8000    // default port if no port arg is

// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
static volatile sig_atomic_t running = 1;    // Global flag for whether the server is running, changed by signal handler

void handle_signal(int signal);

/*
    Main server entry point. Parses port argument, sets up and starts a non-blocking server socket,
    then enters the connection handling loop.

    @param
    argc: Argument count
    argv: Argument values

    @return
    EXIT_SUCCESS or EXIT_FAILURE
 */
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

    if(setup_addr("0.0.0.0", &addr, port, &err))    // set up address structs for socket setup
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

    // Attempt to connect to server manager

    handle_connections(sock_fd, &addr, &running);
    close(sock_fd);
    return EXIT_SUCCESS;
}

/*
    Handles SIGINT to shut down the server.

    @param
    signal: The received signal
 */
void handle_signal(int signal)
{
    if(signal == SIGINT)
    {
        running = 0;
    }
}
