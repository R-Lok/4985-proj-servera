#ifndef SERVER_MANAGER_H
#define SERVER_MANAGER_H

#include <netinet/in.h>
#include <stdint.h>

#define SERVER_MANAGER_UP "127.0.0.1"
#define SERVER_MANAGER_PORT 9000

int  server_manager_connect(int *sock_fd);
void server_manager_disconnect(int sock_fd);
int  send_user_count(int sock_fd, uint32_t user_count);

#endif    // SERVER_MANAGER_H
