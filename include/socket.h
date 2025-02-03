#ifndef SOCKET_H
#define SOCKET_H
#include <netinet/in.h>
#include <signal.h>
#include <sys/socket.h>

int setup_addr(struct sockaddr_in *my_addr, in_port_t port, int *err);
int setup_socket(struct sockaddr_in *my_addr, int *err);
int set_socket_nonblock(int socket_fd, int *err);
int accept_connections(int sock_fd, struct sockaddr_in *addr, const volatile sig_atomic_t *running);

#endif
