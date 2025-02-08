#include "../include/protocol.h"
#include "../include/io.h"
#include "../include/request_handlers.h"
#include "../include/user.h"
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void  extract_header(const char *buffer, HeaderData *header);
int   is_valid_header(const HeaderData *header);
int   is_valid_version(uint8_t protocol_ver);
int   is_valid_packet_type(uint8_t packet_type);
void  pickle_header(char *arr, const HeaderData *hd);
char *construct_payload(PayloadField *payload_fields, size_t num_fields, size_t payload_len);
char *construct_message(const char *header, const char *payload, size_t header_len, size_t payload_len);
char *malloc_payload_buffer(uint16_t payload_len);
int   handle_read_request_res(int res, int fd);

void extract_header(const char *buffer, HeaderData *header)
{
    header->packet_type  = (uint8_t)buffer[0];    // no converting to host order as one byte only
    header->protocol_ver = (uint8_t)buffer[1];    // same here

    memcpy(&(header->sender_id), buffer + 2, sizeof(uint16_t));
    memcpy(&(header->payload_len), buffer + 4, sizeof(uint16_t));

    header->sender_id   = ntohs(header->sender_id);
    header->payload_len = ntohs(header->payload_len);
}

int is_valid_header(const HeaderData *header)
{
    if(is_valid_version(header->protocol_ver) && is_valid_packet_type(header->packet_type))
    {
        return 1;
    }
    return 0;
}

int is_valid_version(uint8_t protocol_ver)
{
    return protocol_ver <= PROTOCOL_VERSION;
}

int is_valid_packet_type(uint8_t packet_type)
{
    switch(packet_type)
    {
        case ACC_LOGIN:
        case ACC_CREATE:
        case ACC_LOGOUT:
            return 1;
        default:
            return 0;
    }
}

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
    payload_fields[0].ber_tag         = P_INTEGER;
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

    if(write_fully(fd, message, (size_t)HEADER_SIZE + hd.payload_len) == WRITE_ERROR)    // need to also handle TIMEOUT (send sys error to indicate timeout)
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

// int send_sys_success(int fd, uint8_t packet_type) {
//     HeaderData hd;
// }

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
char *construct_payload(PayloadField *payload_fields, size_t num_fields, size_t payload_len)
{
    // This function may be hard to wrap your head around - I'm just iterating through all the PayloadField structs, and writing them into the
    // payload buffer. This works regardless of data type cause the struct uses a void pointer to point to the data. It makes this function reuseable.
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

// Combines header and payload to make the full message
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

// In the works, it's pretty much complete but the handler function pointer needs work to ensure all message types are covered.
int handle_fd(int fd, ServerData *server_data)
{
    int            ret;
    char           header_buffer[HEADER_SIZE];
    char          *payload_buffer;
    int            read_header_result;
    int            read_payload_result;
    HeaderData     hd;
    RequestHandler handler;
    HandlerArgs    ha;

    read_header_result = read_fully(fd, header_buffer, HEADER_SIZE);
    if(handle_read_request_res(read_header_result, fd))
    {
        ret = 1;
        goto end;
    }

    extract_header(header_buffer, &hd);
    if(is_valid_header(&hd) == 0)
    {
        send_sys_error(fd, P_BAD_REQUEST, P_BAD_REQUEST_MSG);
    }

    payload_buffer = malloc_payload_buffer(hd.payload_len);
    if(payload_buffer == NULL)
    {
        return 1;
    }

    read_payload_result = read_fully(fd, payload_buffer, hd.payload_len);
    if(handle_read_request_res(read_payload_result, fd))
    {
        ret = 1;
        goto end;
    }
    printf("packet type: %u\n", hd.packet_type);
    handler = get_handler_function(hd.packet_type);
    if(handler == NULL)
    {
        // fprintf(stdout, "Sending P_BAD_REQUEST - Bad Packet Type\n"); //comment out if not debugging
        send_sys_error(fd, P_BAD_REQUEST, P_BAD_REQUEST_MSG);
        ret = 0;
        goto bad_req;
    }
    ha.hd             = &hd;
    ha.payload_buffer = payload_buffer;
    ha.sd             = server_data;
    ret               = handler(&ha, fd);

bad_req:
    free(payload_buffer);
end:
    return ret;
}

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

int handle_read_request_res(int res, int fd)
{
    if(res == TIMEOUT)
    {    // error handling here a bit dodgy, revisit later
        if(send_sys_error(fd, P_TIMEOUT, P_TIMEOUT_MSG))
        {
            return 1;
        }
    }
    if(res == READ_ERROR)
    {
        send_sys_error(fd, P_SERVER_FAILURE, P_SERVER_FAILURE_MSG);
        return 1;
    }
    return 0;
}
