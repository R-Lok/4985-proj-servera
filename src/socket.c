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
#define POLL_TIMEOUT 1000             // time to wait for each poll call

static void remove_pollfd(struct pollfd *clients, nfds_t index, nfds_t num_clients);
static int  handle_disconnect_events(struct pollfd *clients, nfds_t *num_clients, pthread_rwlock_t *rwlock);

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

int accept_connections(int sock_fd, struct sockaddr_in *addr, const volatile sig_atomic_t *running)
{
    atomic_uint      num_threads;
    struct pollfd   *clients;
    nfds_t           num_clients;
    int              ret;
    pthread_rwlock_t rwlock;

    num_clients = 0;
    ret         = EXIT_SUCCESS;
    atomic_store(&num_threads, 0);

    clients = (struct pollfd *)calloc(MAX_CONNECTED_CLIENTS, sizeof(struct pollfd));
    if(clients == NULL)
    {
        fprintf(stderr, "calloc failed in accept_connections\n");
        return 1;
    }

    if(pthread_rwlock_init(&rwlock, NULL) != 0)
    {
        perror("pthread_rwlock_init failed");
        free(clients);
        return 1;
    }

    while(*running)
    {
        int       client_fd;
        socklen_t sock_len;
        int       poll_res;

        sock_len  = (socklen_t)sizeof(struct sockaddr_in);
        client_fd = accept(sock_fd, (struct sockaddr *)addr, &sock_len);

        if(client_fd == -1)
        {
            if(errno != EINTR && errno != EAGAIN && errno != ECONNABORTED)
            {
                fprintf(stderr, "accept() error\n");
                ret = 1;
                break;
            }
        }
        else
        {
            clients[num_clients].fd     = client_fd;
            clients[num_clients].events = POLLIN | POLLERR | POLLHUP;    // set to listen to POLLIN(data in socket) and hangup/disconnect
            num_clients++;
        }

        poll_res = poll(clients, num_clients, POLL_TIMEOUT);
        if(poll_res == -1)
        {
            fprintf(stderr, "poll() error\n");
            ret = EXIT_FAILURE;
            break;
        }

        if(handle_disconnect_events(clients, &num_clients, &rwlock))
        {
            ret = EXIT_FAILURE;
            break;
        }
    }

    while(atomic_load(&num_threads) == 0)
    {
    }

    for(nfds_t i = 0; i < num_clients; i++)
    {
        close(clients[i].fd);
    }

    free(clients);

    return ret;
    // atomic_fetch_add(&num_threads, 1);
}

static void remove_pollfd(struct pollfd *clients, nfds_t index, nfds_t num_clients)
{
    if(close(clients[index].fd) == -1)
    {
        fprintf(stderr, "Failed to close client socket - %s\n", strerror(errno));
    }
    clients[index].fd           = clients[num_clients - 1].fd;
    clients[num_clients - 1].fd = -1;
}

static int handle_disconnect_events(struct pollfd *clients, nfds_t *num_clients, pthread_rwlock_t *rwlock)
{
    int wlock_res;

    wlock_res = pthread_rwlock_wrlock(rwlock);
    if(wlock_res != 0)
    {
        fprintf(stderr, "r/w lock wrlock error\n %s\n", strerror(errno));
        return 1;
    }

    for(nfds_t i = 0; i < *num_clients; i++)
    {
        // Check if POLLERR or POLLHUP occurred
        if(clients[i].revents & POLLERR || clients[i].revents & POLLHUP)
        {
            printf("Error/Hangup occurred on fd %d\n - removing client..\n", clients[i].fd);
            remove_pollfd(clients, i, *num_clients);
            num_clients--;
        }
    }

    wlock_res = pthread_rwlock_unlock(rwlock);
    if(wlock_res != 0)
    {
        fprintf(stderr, "r/w lock unlock error\n %s\n", strerror(errno));
        return 1;
    }

    return 0;
}
