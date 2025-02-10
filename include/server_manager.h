#ifndef SERVER_MANAGER_H
#define SERVER_MANAGER_H

#include <netinet/in.h>
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

int  server_manager_connect(void);
void server_manager_disconnect(int sock_fd);
int  send_user_count(int sock_fd, uint16_t user_count);

#endif    // SERVER_MANAGER_H
