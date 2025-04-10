#include "../include/protocol.h"
#include "../include/db.h"
#include "../include/io.h"
#include "../include/request_handlers.h"
#include "../include/server_manager.h"
#include "../include/user.h"
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define POLL_TIMEOUT 500    // time to wait for each poll call
#define DB_BUFFER 16        // buffer for db names in char arrays

void extract_header(const char *buffer, HeaderData *header);
int  is_valid_header(const HeaderData *header);
int  is_valid_version(uint8_t protocol_ver);
int  is_valid_packet_type(uint8_t packet_type);

char *malloc_payload_buffer(uint16_t payload_len);
int   handle_read_request_res(int res, int fd);

static void remove_pollfd(struct pollfd *clients, nfds_t index, nfds_t num_clients);
static int  handle_new_client(int client_fd, ServerData *sd);
static void handle_disconnect_events(ServerData *sd);
static int  handle_pollins(ServerData *sd);

/*
    Extracts header fields from a raw byte buffer into a HeaderData struct.

    @param
    buffer: Raw header buffer
    header: Pointer to HeaderData to populate
*/
void extract_header(const char *buffer, HeaderData *header)
{
    header->packet_type  = (uint8_t)buffer[0];    // no converting to host order as one byte only
    header->protocol_ver = (uint8_t)buffer[1];    // same here

    memcpy(&(header->sender_id), buffer + 2, sizeof(uint16_t));
    memcpy(&(header->payload_len), buffer + 4, sizeof(uint16_t));

    header->sender_id   = ntohs(header->sender_id);
    header->payload_len = ntohs(header->payload_len);
}

/*
    Validates the protocol version and packet type of a header.

    @param
    header: Pointer to the HeaderData to validate

    @return
    1 if valid, 0 if invalid
*/
int is_valid_header(const HeaderData *header)
{
    if(is_valid_version(header->protocol_ver) && is_valid_packet_type(header->packet_type))
    {
        return 1;
    }
    return 0;
}

/*
    Checks if the given protocol version is supported.

    @param
    protocol_ver: Protocol version to validate

    @return
    1 if valid, 0 if invalid
*/
int is_valid_version(uint8_t protocol_ver)
{
    return protocol_ver <= PROTOCOL_VERSION;
}

/*
    Checks if the given packet type is one of the supported types.

    @param
    packet_type: Packet type to validate

    @return
    1 if valid, 0 if invalid
*/
int is_valid_packet_type(uint8_t packet_type)
{
    switch(packet_type)
    {
        case ACC_LOGIN:
        case ACC_CREATE:
        case ACC_LOGOUT:
        case CHT_SEND:
            return 1;
        default:
            return 0;
    }
}

/*
    Sends a SYS_ERROR packet to the specified file descriptor with an error code and message.

    @param
    fd: Destination file descriptor
    err_code: Error code to send
    err_msg: Error message to send

    @return
    0 on success, 1 on failure
*/
int send_sys_error(int fd, uint8_t err_code, const char *err_msg)
{
    HeaderData   hd;
    char        *header;
    char        *payload;
    char        *message;
    PayloadField payload_fields[2];
    size_t       err_msg_len;
    int          ret;
    char        *temp_err_msg;

    ret         = 0;
    err_msg_len = strlen(err_msg);

    // Filling in struct data, so we can use it to construct the serialized header array.
    hd.packet_type  = SYS_ERROR;
    hd.protocol_ver = PROTOCOL_VERSION;
    hd.sender_id    = SYSTEM_ID;
    hd.payload_len  = (uint16_t)(err_msg_len + sizeof(err_code) + ((size_t)EXTRA_BYTES_FOR_BER_AND_LENGTH * 2));    //* 2 as two fields in payload

    header = (char *)malloc(HEADER_SIZE);
    if(header == NULL)
    {
        fprintf(stderr, "malloc error\n");
        return 1;
    }

    // Use HeaderData struct to fill in the serialized Header array.
    pickle_header(header, &hd);
    temp_err_msg = (char *)malloc(err_msg_len + 1);
    if(temp_err_msg == NULL)
    {
        fprintf(stderr, "malloc() err\n");
        goto payload_fail;
    }
    strncpy(temp_err_msg, err_msg, err_msg_len);    // We need to copy the err_msg into a char *, as it is a const char *, which we cannot use (compiler cries)

    // Fill in the payload fields. SYS error has two fields, so fill in two PayloadField structs. (order matters - has to match protocol)
    payload_fields[0].data            = &err_code;
    payload_fields[0].data_size_bytes = sizeof(err_code);
    payload_fields[0].ber_tag         = P_ENUMERATED;
    payload_fields[1].data            = temp_err_msg;
    payload_fields[1].data_size_bytes = err_msg_len;
    payload_fields[1].ber_tag         = P_UTF8STRING;

    // Payload here means the body of the request
    payload = construct_payload(payload_fields, 2, hd.payload_len);
    if(payload == NULL)
    {
        ret = 1;
        goto payload_fail;
    }

    // Message = Header + Payload
    message = construct_message(header, payload, HEADER_SIZE, hd.payload_len);
    if(message == NULL)
    {
        ret = 1;
        goto message_fail;
    }

    if(write_fully(fd, message, (size_t)HEADER_SIZE + hd.payload_len) == WRITE_ERROR)
    {
        fprintf(stderr, "Error sending sys error\n");
        ret = 1;
    }

    free(message);
message_fail:
    free(payload);
payload_fail:
    free(temp_err_msg);
    free(header);
    return ret;
}

/*
    Sends a SYS_SUCCESS packet to confirm successful handling of a specific request type.

    @param
    fd: Destination file descriptor
    packet_type: Type of packet being acknowledged

    @return
    0 on success, 1 on failure
*/
int send_sys_success(int fd, uint8_t packet_type)
{
    HeaderData   hd;
    char        *header;
    char        *payload;
    char        *message;
    int          ret;
    PayloadField pf;

    ret = 0;

    // Filling in struct data, so we can use it to construct the serialized header array.
    hd.packet_type  = SYS_SUCCESS;
    hd.protocol_ver = PROTOCOL_VERSION;
    hd.sender_id    = SYSTEM_ID;
    hd.payload_len  = (uint16_t)(sizeof(packet_type) + ((size_t)EXTRA_BYTES_FOR_BER_AND_LENGTH));

    header = (char *)malloc(HEADER_SIZE);
    if(header == NULL)
    {
        fprintf(stderr, "malloc error\n");
        return 1;
    }

    // Use HeaderData struct to fill in the serialized Header array.
    pickle_header(header, &hd);

    // Fill in the payload fields. SYS error has two fields, so fill in two PayloadField structs. (order matters - has to match protocol)
    pf.data            = &packet_type;
    pf.ber_tag         = P_ENUMERATED;
    pf.data_size_bytes = sizeof(packet_type);

    // Payload here means the body of the request
    payload = construct_payload(&pf, 1, hd.payload_len);
    if(payload == NULL)
    {
        ret = 1;
        goto payload_fail;
    }

    // Message = Header + Payload
    message = construct_message(header, payload, HEADER_SIZE, hd.payload_len);
    if(message == NULL)
    {
        ret = 1;
        goto message_fail;
    }

    if(write_fully(fd, message, (size_t)HEADER_SIZE + hd.payload_len) == WRITE_ERROR)
    {
        fprintf(stderr, "Error sending sys success\n");
        ret = 1;
    }

    free(message);
message_fail:
    free(payload);
payload_fail:
    free(header);
    return ret;
}

/*
    Serializes a HeaderData struct into a byte array for transmission.

    @param
    arr: Destination buffer for serialized header
    hd: Pointer to HeaderData struct
*/
void pickle_header(char *arr, const HeaderData *hd)
{
    const uint16_t host_order_sender_id   = htons(hd->sender_id);
    const uint16_t host_order_payload_len = htons(hd->payload_len);

    *(uint8_t *)arr         = hd->packet_type;
    *((uint8_t *)(arr + 1)) = hd->protocol_ver;

    memcpy(arr + 2, &host_order_sender_id, sizeof(host_order_sender_id));
    memcpy(arr + 4, &host_order_payload_len, sizeof(host_order_payload_len));
}

/*MAKE SURE THE PAYLOAD_FIELDS ELEMENTS ARE IN THE SAME ORDER AS LISTED IN THE PROTOCOL!
ALSO MAKE SURE THAT payload_len ACCOUNTS FOR THE BYTES NEEDED BY THE BER TAG + BER LENGTH */
/*
    Constructs a payload from an array of PayloadField structs.

    @param
    payload_fields: Array of fields to include in the payload
    num_fields: Number of fields in the array
    payload_len: Total length of the payload

    @return
    Pointer to the constructed payload, or NULL on failure
*/
char *construct_payload(PayloadField *payload_fields, size_t num_fields, size_t payload_len)
{
    // I'm just iterating through all the PayloadField structs, and writing them into the payload buffer.
    // This works regardless of data type cause the struct uses a void pointer to point to the data. It makes this function reuseable.
    char *payload;
    char *payload_ptr_copy;

    payload = (char *)malloc(payload_len);
    if(payload == NULL)
    {
        fprintf(stderr, "malloc error - construct_payload\n");
        return NULL;
    }
    payload_ptr_copy = payload;

    for(size_t i = 0; i < num_fields; i++)
    {
        *(payload++) = (char)payload_fields[i].ber_tag;
        *(payload++) = (char)payload_fields[i].data_size_bytes;
        memcpy(payload, payload_fields[i].data, payload_fields[i].data_size_bytes);
        payload += payload_fields[i].data_size_bytes;
    }
    return payload_ptr_copy;
}

/*
    Combines a header and payload into a full message

    @param
    header: Pointer to the serialized header
    payload: Pointer to the serialized payload
    header_len: Length of the header in bytes
    payload_len: Length of the payload in bytes

    @return
    Pointer to the combined message, or NULL on failure
*/
char *construct_message(const char *header, const char *payload, size_t header_len, size_t payload_len)
{
    char *msg;
    msg = (char *)malloc(header_len + payload_len);
    if(msg == NULL)
    {
        fprintf(stderr, "malloc error - construct_message\n");
        return NULL;
    }

    memcpy(msg, header, header_len);
    memcpy(msg + header_len, payload, payload_len);

    return msg;
}

/*
    Handles a single client request by reading, validating, and dispatching the request.

    @param
    fd: File descriptor for the client socket
    server_data: Pointer to the server state

    @return
    1 on internal error, 0 otherwise
*/
int handle_fd(int fd, ServerData *server_data)
{
    int            ret;
    char           header_buffer[HEADER_SIZE];
    char          *payload_buffer;
    int            read_header_result;
    int            read_payload_result;
    int            res;
    HeaderData     hd;
    RequestHandler handler;
    HandlerArgs    ha;

    payload_buffer = NULL;

    read_header_result = read_fully(fd, header_buffer, HEADER_SIZE);

    res = handle_read_request_res(read_header_result, fd);
    if(res == CLIENT_DISCONNECTED || res == TIMEOUT)
    {
        if(res == CLIENT_DISCONNECTED)
        {
            close(fd);
        }
        return 0;
    }
    if(res == 1)
    {
        return 1;
    }

    extract_header(header_buffer, &hd);

    if(hd.payload_len != 0)    // Only run this logic if payload length is not 0 (there is payload)
    {
        payload_buffer = malloc_payload_buffer(hd.payload_len);
        if(payload_buffer == NULL)
        {
            return 1;
        }

        read_payload_result = read_fully(fd, payload_buffer, hd.payload_len);
        if(handle_read_request_res(read_payload_result, fd))
        {
            ret = 1;
            goto bad_req;
        }
    }
    // printf("Checking header..\n");
    if(is_valid_header(&hd) == 0)
    {
        fprintf(stderr, "invalid header received\n");
        send_sys_error(fd, P_BAD_REQUEST, P_BAD_REQUEST_MSG);
        ret = 0;
        goto bad_req;
    }
    printf("packet type: %u\n", hd.packet_type);

    handler = get_handler_function(hd.packet_type);
    if(handler == NULL)
    {
        fprintf(stdout, "Sending P_BAD_REQUEST - Bad Packet Type\n");
        send_sys_error(fd, P_BAD_REQUEST, P_BAD_REQUEST_MSG);
        ret = 0;
        goto bad_req;
    }
    ha.hd             = &hd;
    ha.payload_buffer = payload_buffer;
    ha.sd             = server_data;
    ret               = handler(&ha, fd);

bad_req:
    if(payload_buffer)
    {
        free(payload_buffer);
    }
    return ret;
}

/*
    Allocates a buffer for reading the payload.

    @param
    payload_len: Length of the payload to allocate

    @return
    Pointer to the allocated buffer, or NULL on failure
*/
char *malloc_payload_buffer(uint16_t payload_len)
{
    char *buffer;

    buffer = (char *)malloc(payload_len);
    if(buffer == NULL)
    {
        fprintf(stderr, "malloc_payload_buffer error\n");
        return NULL;
    }
    return buffer;
}

/*
    Handles the result of a read operation and sends appropriate system error messages.

    @param
    res: Result code from read_fully
    fd: File descriptor to send response to

    @return
    0 on success, 1 on write error, 2 if client disconnected, 3 if timeout
*/
int handle_read_request_res(int res, int fd)
{
    if(res == TIMEOUT)
    {
        if(send_sys_error(fd, P_TIMEOUT, P_TIMEOUT_MSG))
        {
            return 1;
        }
        return 3;
    }
    if(res == READ_ERROR)
    {
        send_sys_error(fd, P_SERVER_FAILURE, P_SERVER_FAILURE_MSG);
        return 1;
    }
    if(res == CLIENT_DISCONNECTED)
    {
        return 2;
    }
    return 0;
}

/*
    Sends a login success message to the client with the assigned user ID.

    @param
    fd: File descriptor to write to
    uid: User ID to include in the payload

    @return
    0 on success, 1 on failure
*/
int send_login_success(int fd, uint16_t uid)
{
    HeaderData   hd;
    char        *header;
    char        *payload;
    char        *message;
    int          ret;
    PayloadField pf;
    uint16_t     network_order_uid;

    ret = 0;

    // Filling in struct data, so we can use it to construct the serialized header array.
    hd.packet_type  = ACC_LOGIN_SUCCESS;
    hd.protocol_ver = PROTOCOL_VERSION;
    hd.sender_id    = SYSTEM_ID;
    hd.payload_len  = (uint16_t)(sizeof(uid) + ((size_t)EXTRA_BYTES_FOR_BER_AND_LENGTH));

    header = (char *)malloc(HEADER_SIZE);
    if(header == NULL)
    {
        fprintf(stderr, "malloc error\n");
        return 1;
    }

    // Use HeaderData struct to fill in the serialized Header array.
    pickle_header(header, &hd);

    network_order_uid = htons(uid);
    // Fill in the payload fields. SYS error has two fields, so fill in two PayloadField structs. (order matters - has to match protocol)
    pf.data            = &network_order_uid;
    pf.ber_tag         = P_INTEGER;
    pf.data_size_bytes = sizeof(uid);

    // Payload here means the body of the request
    payload = construct_payload(&pf, 1, hd.payload_len);
    if(payload == NULL)
    {
        ret = 1;
        goto payload_fail;
    }

    // Message = Header + Payload
    message = construct_message(header, payload, HEADER_SIZE, hd.payload_len);
    if(message == NULL)
    {
        ret = 1;
        goto message_fail;
    }

    if(write_fully(fd, message, (size_t)HEADER_SIZE + hd.payload_len) == WRITE_ERROR)
    {
        fprintf(stderr, "Error sending sys error\n");
        ret = 1;
    }

    free(message);
message_fail:
    free(payload);
payload_fail:
    free(header);
    return ret;
}

/*
    Sends a chat received acknowledgment to the client.

    @param
    fd: File descriptor to write to
    sender_id: ID of the user who sent the message

    @return
    0 on success, 1 on failure
*/
int send_cht_received(int fd, uint16_t sender_id)
{
    HeaderData hd;
    char       header[HEADER_SIZE];

    hd.packet_type  = CHT_RECEIVED;
    hd.protocol_ver = PROTOCOL_VERSION;
    hd.sender_id    = sender_id;
    hd.payload_len  = 0;

    pickle_header(header, &hd);

    if(write_fully(fd, header, (size_t)HEADER_SIZE) == WRITE_ERROR)
    {
        fprintf(stderr, "Error sending cht_received\n");
        return 1;
    }
    return 0;
}

/*
    Handles new client connections and incoming data.

    @param
    sock_fd: Server socket file descriptor
    addr: Pointer to the server address struct
    running: Flag to control server loop execution

    @return
    0 on success, non-zero on failure
*/
int handle_connections(int sock_fd, struct sockaddr_in *addr, volatile sig_atomic_t *running)
{
    int        ret;
    int        sm_fd;
    ServerData sd;
    char       user_db_filename[DB_BUFFER];
    char       metadata_db_filename[DB_BUFFER];
    pthread_t  thread;

    strcpy(user_db_filename, "user_db");
    strcpy(metadata_db_filename, "metadata_db");

    sd.num_clients  = 0;
    sd.num_messages = 0;
    ret             = EXIT_SUCCESS;

    sd.user_db     = dbm_open(user_db_filename, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    sd.metadata_db = dbm_open(metadata_db_filename, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

    if(sd.metadata_db == NULL || sd.user_db == NULL)
    {
        fprintf(stderr, "Failed to open one or both dbs\n");
        return 1;
    }

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

    if(retrieve_sm_fd(&sm_fd))
    {
        fprintf(stderr, "failed to retrieve server manager fd\n");
        free(sd.clients);
        free(sd.fd_map);
        return 1;
    }
    printf("smfd: %d\n", sm_fd);

    if(create_sm_diagnostic_thread(&thread, sm_fd, &sd.num_clients, &sd.num_messages, running))
    {
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
                ret = EXIT_FAILURE;
                break;
            }
        }
        else
        {
            printf("Accepted client %d\n", client_fd);
            if(handle_new_client(client_fd, &sd))
            {
                close(client_fd);
            }
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
        if(handle_pollins(&sd) == 1)
        {
            *running = 0;
            ret      = EXIT_FAILURE;
        }
    }
    *running = 0;
    pthread_cancel(thread);                       // Kill the thread sending the diagnostic messages
    for(nfds_t i = 0; i < sd.num_clients; i++)    // close all remaining client fds - need to consider - will there be server message sent to clients
    {
        close(sd.clients[i].fd);
    }
    free(sd.clients);
    free(sd.fd_map);

    dbm_close(sd.user_db);
    dbm_close(sd.metadata_db);
    printf("Exiting handle_connections..\n");
    fflush(stdout);
    return ret;
}

/*
    Removes a pollfd entry by replacing it with the last active client and clearing the last entry.

    @param
    clients: Array of pollfd structs
    index: Index of the client to remove
    num_clients: Total number of connected clients
*/
static void remove_pollfd(struct pollfd *clients, nfds_t index, nfds_t num_clients)
{
    // copy fd of last element in array to this index. Set fd of the (previously) last element to -1 (poll ignores -1)
    clients[index].fd      = clients[num_clients - 1].fd;
    clients[index].revents = clients[num_clients - 1].revents;
    clients[index].events  = clients[num_clients - 1].events;

    clients[num_clients - 1].fd      = -1;
    clients[num_clients - 1].revents = 0;
    clients[num_clients - 1].events  = 0;
}

/*
    Handles disconnection events by closing client sockets and cleaning up associated session data.

    @param
    sd: Pointer to ServerData containing client and session information
*/
static void handle_disconnect_events(ServerData *sd)
{
    for(nfds_t i = 0; i < sd->num_clients; i++)
    {
        // Check if POLLERR or POLLHUP occurred OR the file descriptor was closed somewhere deeper in the program.
        if(sd->clients[i].revents & POLLERR || sd->clients[i].revents & POLLHUP || sd->clients[i].revents & POLLNVAL)
        {
            const int fd = sd->clients[i].fd;
            if(sd->clients[i].revents & POLLHUP)
            {
                close(sd->clients[i].fd);
            }
            printf("Error/Hangup occurred on fd %d\n - removing client..\n", sd->clients[i].fd);

            // close file descriptor, set uid to 0 (not logged in), zero out username
            sd->fd_map[fd].uid = 0;
            memset(sd->fd_map[fd].username, 0, sizeof(sd->fd_map[fd].username));

            remove_pollfd(sd->clients, i, sd->num_clients);
            sd->num_clients--;
        }
    }
}

/*
    Processes POLLIN events for all connected clients and handles incoming data.

    @param
    sd: Pointer to ServerData containing client and session information

    @return
    1 if a fatal error occurred during handling, 0 otherwise
*/
static int handle_pollins(ServerData *sd)
{
    // printf("handling pollins\n");
    for(nfds_t i = 0; i < sd->num_clients; i++)
    {
        if(sd->clients[i].revents & POLLIN)
        {
            if(handle_fd(sd->clients[i].fd, sd) == 1)
            {
                return 1;
            }
            sd->clients[i].revents = 0;
        }
    }
    return 0;
}

/*
    Registers a new client by setting the file descriptor to non-blocking and adding it to the clients array.

    @param
    client_fd: File descriptor of the new client
    sd: Pointer to ServerData to store client info

    @return
    0 on success, 1 on failure
*/
static int handle_new_client(int client_fd, ServerData *sd)
{
    int err;
    if(set_socket_nonblock(client_fd, &err))
    {
        fprintf(stderr, "Failed to set client_fd to non-blocking - %s\n", strerror(err));
        return 1;
    }
    sd->clients[sd->num_clients].fd     = client_fd;
    sd->clients[sd->num_clients].events = POLLIN | POLLERR | POLLHUP | POLLNVAL;    // set to listen to POLLIN(data in socket) and hangup/disconnect
    sd->num_clients++;                                                              // increment num of clients
    return 0;
}
