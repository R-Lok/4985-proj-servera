#include "../include/server_manager.h"
#include "../include/io.h"
#include "../include/protocol.h"
#include "../include/socket.h"
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void pickle_server_manager_header(char *arr, const ServerManagerHeader *hd);

int server_manager_connect(void)
{
    struct sockaddr_in server_manager_addr;
    int                err;
    const char        *sm_ipv4 = "127.0.0.1";    // change depending on sm ipv4 address
    int                sock_fd;

    // Function from socket.h to set up sm address
    if(setup_addr(sm_ipv4, &server_manager_addr, SERVER_MANAGER_PORT, &err) != 0)
    {
        fprintf(stderr, "Error settng up server manager address");
        return -1;
    }

    // Create and connect to socket
    sock_fd = socket(server_manager_addr.sin_family, SOCK_STREAM, 0);    // NOLINT(android-cloexec-socket)
    if(sock_fd == -1)
    {
        fprintf(stderr, "Error calling socket()\n");
        return -1;
    }
    if(connect(sock_fd, (struct sockaddr *)&server_manager_addr, sizeof(server_manager_addr)) == -1)
    {
        fprintf(stderr, "Error connecting to server manager\n");
        close(sock_fd);
        return -1;
    }
    return sock_fd;
}

void server_manager_disconnect(int sock_fd)
{
    if(sock_fd >= 0)
    {
        close(sock_fd);
    }
}

int send_user_count(int sock_fd, uint16_t user_count)
{
    ServerManagerHeader smh;
    char               *header;
    char               *payload;
    char               *message;
    int                 ret;
    uint16_t user_count_network_order;
    PayloadField        pf;

    ret = 0;

    // Construct the header
    smh.packet_type  = USR_COUNT;    // packet for user count
    smh.protocol_ver = 1;            // protocol version
    smh.payload_len  = (uint16_t)(sizeof(user_count) + EXTRA_BYTES_FOR_BER_AND_LENGTH);

    // Allocate space for header
    header = (char *)malloc(SERVER_MANAGER_HEADER_SIZE);
    if(header == NULL)
    {
        fprintf(stderr, "Error allocating header for user count\n");
        return 1;
    }

    // Encode header
    pickle_server_manager_header(header, &smh);

    user_count_network_order = htons(user_count);
    // Fill payload
    pf.data            = &user_count_network_order;
    pf.ber_tag         = P_INTEGER;
    pf.data_size_bytes = sizeof(user_count);

    payload = construct_payload(&pf, 1, smh.payload_len);
    if(payload == NULL)
    {
        ret = 1;
        goto free_header;
    }

    // Construct message
    message = construct_message(header, payload, SERVER_MANAGER_HEADER_SIZE, smh.payload_len);
    if(message == NULL)
    {
        ret = 1;
        goto free_payload;
    }

    // Send the message
    if(write_fully(sock_fd, message, (size_t)(SERVER_MANAGER_HEADER_SIZE + smh.payload_len)) == WRITE_ERROR)
    {
        fprintf(stderr, "Error sending user count to server manager\n");
        ret = 1;
    }

    // Cleanup
    free(message);
free_payload:
    free(payload);
free_header:
    free(header);
    return ret;
}

void pickle_server_manager_header(char *arr, const ServerManagerHeader *hd)
{
    const uint16_t host_order_payload_len = htons(hd->payload_len);

    *(uint8_t *)arr         = hd->packet_type;
    *((uint8_t *)(arr + 1)) = hd->protocol_ver;
    memcpy(arr + 2, &host_order_payload_len, sizeof(host_order_payload_len));
}
