#include "../include/user.h"
#include <../include/socket.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAX_PENDING_CONNECTIONS 10    // max backlogged connections
#define MAX_CONNECTED_CLIENTS 1024    // max number of connected clients (can change to dynamic resize later if required)
#define POLL_TIMEOUT 500              // time to wait for each poll call

static void remove_pollfd(struct pollfd *clients, nfds_t index, nfds_t num_clients);
static void handle_disconnect_events(ServerData *sd);
static int  handle_pollins(const ServerData *sd);

int setup_addr(struct sockaddr_in *my_addr, in_port_t port, int *err)
{
    const char *addr = "0.0.0.0";    // Listen to all incoming connections on all availalbe network interfaces

    memset(my_addr, 0, sizeof(struct sockaddr_in));

    my_addr->sin_family = AF_INET;
    my_addr->sin_port   = htons(port);

    if(inet_pton(AF_INET, addr, &(my_addr->sin_addr)) != 1)
    {
        *err = EINVAL;
        return 1;
    }
    return 0;
}

int setup_socket(struct sockaddr_in *my_addr, int *err)
{
    int socket_fd;

    socket_fd = socket(my_addr->sin_family, SOCK_STREAM, 0);    // NOLINT(android-cloexec-socket)

    if(socket_fd == -1)
    {
        *err = errno;
        return -1;
    }

    if(bind(socket_fd, (struct sockaddr *)my_addr, sizeof(struct sockaddr_in)) != 0)
    {
        *err = errno;
        goto fail;
    }

    if(listen(socket_fd, MAX_PENDING_CONNECTIONS))
    {
        *err = errno;
        goto fail;
    }

    return socket_fd;
fail:
    close(socket_fd);
    return -1;
}

int set_socket_nonblock(int socket_fd, int *err)
{
    int flags;
    flags = fcntl(socket_fd, F_GETFL, 0);
    if(flags == -1)
    {
        *err = errno;
        return 1;
    }

    if(fcntl(socket_fd, F_SETFL, flags | O_NONBLOCK) == -1)
    {
        *err = errno;
        return 1;
    }
    return 0;
}

// This function is really long, I will probably try to abstract it later, but most of the length is due to setting things up, locking, error handling
int handle_connections(int sock_fd, struct sockaddr_in *addr, const volatile sig_atomic_t *running)
{
    int        ret;
    ServerData sd;

    sd.num_clients = 0;
    ret            = EXIT_SUCCESS;

    sd.clients = (struct pollfd *)calloc(MAX_CONNECTED_CLIENTS, sizeof(struct pollfd));
    if(sd.clients == NULL)
    {
        fprintf(stderr, "clients calloc failed in accept_connections\n");
        return 1;
    }

    sd.fd_map = (SessionUser *)calloc(MAX_CONNECTED_CLIENTS + 4, sizeof(SessionUser));    // plus 4 as stdin,stdout,stderr,server manager takes up 4 fd's
    if(sd.fd_map == NULL)
    {
        fprintf(stderr, "fd_map calloc failed in accept_connections\n");
        free(sd.clients);
        return 1;
    }

    while(*running == 1)
    {
        int       client_fd;
        socklen_t sock_len;
        int       poll_res;

        sock_len  = (socklen_t)sizeof(struct sockaddr_in);
        client_fd = accept(sock_fd, (struct sockaddr *)addr, &sock_len);

        if(client_fd == -1)    // if accept call failed
        {
            if(errno != EINTR && errno != EAGAIN && errno != ECONNABORTED)    // if it's none of the acceptable errors, exit
            {
                fprintf(stderr, "accept() error\n");
                ret = 1;
                break;
            }
        }
        else
        {
            sd.clients[sd.num_clients].fd     = client_fd;
            sd.clients[sd.num_clients].events = POLLIN | POLLERR | POLLHUP;    // set to listen to POLLIN(data in socket) and hangup/disconnect
            sd.num_clients++;                                                  // increment num of clients
        }

        poll_res = poll(sd.clients, sd.num_clients, POLL_TIMEOUT);
        if(poll_res == -1)    // if poll() had an error:
        {
            if(errno != EINTR)
            {
                fprintf(stderr, "poll() error\n");
                ret = EXIT_FAILURE;
                break;
            }
        }
        handle_disconnect_events(&sd);    // goes through array to check for disconnects

        handle_pollins(&sd);
        // if(check_pollins(&sd))
        // {
        //     ret = EXIT_FAILURE;
        //     break;
        // }
    }
    // close all remaining client fds - need to consider - will there be server message sent to clients
    // indicating the server is shutting down? (future consideration)
    for(nfds_t i = 0; i < sd.num_clients; i++)
    {
        close(sd.clients[i].fd);
    }
    free(sd.clients);
    free(sd.fd_map);
    return ret;
}

static void remove_pollfd(struct pollfd *clients, nfds_t index, nfds_t num_clients)
{
    if(close(clients[index].fd) == -1)
    {
        // if fail to close, can't really do anything about it anyways but print - unless we want to keep trying to close it?
        fprintf(stderr, "Failed to close client socket - %s\n", strerror(errno));
    }
    // copy fd of last element in array to this index. Set fd of the (previously) last element to -1 (poll ignores -1)
    clients[index].fd           = clients[num_clients - 1].fd;
    clients[num_clients - 1].fd = -1;
}

static void handle_disconnect_events(ServerData *sd)
{
    for(nfds_t i = 0; i < sd->num_clients; i++)
    {
        // Check if POLLERR or POLLHUP occurred
        if(sd->clients[i].revents & POLLERR || sd->clients[i].revents & POLLHUP)
        {
            const int fd = sd->clients[i].fd;
            printf("Error/Hangup occurred on fd %d\n - removing client..\n", sd->clients[i].fd);

            // close file descriptor, set uid to 0 (not logged in), zero out username
            close(fd);
            sd->fd_map[fd].uid = 0;
            memset(sd->fd_map[fd].username, 0, sizeof(sd->fd_map[fd].username));

            remove_pollfd(sd->clients, i, sd->num_clients);
            sd->num_clients--;
        }
    }
}

static int handle_pollins(const ServerData *sd)
{
    for(nfds_t i = 0; i < sd->num_clients; i++)
    {
        if(sd->clients[i].revents & POLLIN)
        {
            // Function to handle the fd
        }
    }
    return 0;
}
