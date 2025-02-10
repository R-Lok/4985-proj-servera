#include "../include/server_manager.h"
#include "../include/io.h"
#include "../include/protocol.h"
#include "../include/socket.h"
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int server_manager_connect(int *sock_fd)
{
    struct sockaddr_in server_manager_addr;
    int                err;

    // Function from socket.h to set up sm address
    if(setup_addr(&server_manager_addr, SERVER_MANAGER_PORT, &err) != 0)
    {
        fprintf(stderr, "Error settng up server manager address");
        return -1;
    }

    // Create and connect to socket
    *sock_fd = setup_socket(&server_manager_addr, &err);
    if(*sock_fd == -1)
    {
        fprintf(stderr, "Error connecting to server manager");
        return -1;
    }

    return 0;
}

void server_manager_disconnect(int sock_fd)
{
    if(sock_fd >= 0)
    {
        close(sock_fd);
    }
}

int send_user_count(int sock_fd, uint32_t user_count)
{
    HeaderData   hd;
    char        *header;
    char        *payload;
    char        *message;
    int          ret;
    PayloadField pf;

    ret = 0;

    // Construct the header
    hd.packet_type  = USR_COUNT;    // packet for user count
    hd.protocol_ver = 1;            // protocol version
    hd.sender_id    = 0;            // system message
    hd.payload_len  = (uint16_t)(sizeof(user_count) + EXTRA_BYTES_FOR_BER_AND_LENGTH);

    // Allocate space for header
    header = (char *)malloc(HEADER_SIZE);
    if(header == NULL)
    {
        fprintf(stderr, "Error allocating header for user count\n");
        return 1;
    }

    // Encode header
    pickle_header(header, &hd);

    // Fill payload
    pf.data            = &user_count;
    pf.ber_tag         = P_INTEGER;
    pf.data_size_bytes = sizeof(user_count);

    payload = construct_payload(&pf, 1, hd.payload_len);
    if(payload == NULL)
    {
        ret = 1;
        goto free_header;
    }

    // Construct message
    message = construct_message(header, payload, HEADER_SIZE, hd.payload_len);
    if(message == NULL)
    {
        ret = 1;
        goto free_payload;
    }

    // Send the message
    if(write_fully(sock_fd, message, HEADER_SIZE + hd.payload_len) == WRITE_ERROR)
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
