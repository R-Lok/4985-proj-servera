#ifndef SERVER_MANAGER_H
#define SERVER_MANAGER_H

#include <netinet/in.h>
#include <signal.h>
#include <stdint.h>

#define SERVER_MANAGER_UP "127.0.0.1"
#define SERVER_MANAGER_PORT 9000

#define SERVER_MANAGER_HEADER_SIZE 4

typedef struct
{
    // cppcheck-suppress unusedStructMember
    uint8_t packet_type;
    // cppcheck-suppress unusedStructMember
    uint8_t protocol_ver;
    // cppcheck-suppress unusedStructMember
    uint16_t payload_len;
} ServerManagerHeader;

int  server_manager_connect(int sock_fd, const struct sockaddr_in *sm_addr, const volatile sig_atomic_t *running);
void server_manager_disconnect(int sock_fd);
int  send_user_count(int sock_fd, uint16_t user_count);
int  server_loop(int sm_fd);
int  retrieve_sm_fd(int *sm_fd_holder);
int  create_sm_diagnostic_thread(pthread_t *thread, int sm_fd, uint16_t *user_count_ptr, const volatile sig_atomic_t *running);
int  start_server(pid_t *server_pid, int fd);
int  stop_server(pid_t *server_pid, int fd);
int  send_svr_online(int fd);
int  send_svr_offline(int fd);
int  handle_sm_packet(int sock_fd);
int  read_sm_header(int sock_fd, ServerManagerHeader *header);

#endif    // SERVER_MANAGER_H
