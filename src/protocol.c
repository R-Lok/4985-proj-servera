#include "../include/protocol.h"
#include "../include/io.h"
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void  extract_header(const char *buffer, HeaderData *header);
int   is_valid_header(const HeaderData *header);
int   is_valid_version(uint8_t protocol_ver);
int   is_valid_packet_type(uint8_t packet_type);
int   send_sys_error(int fd, uint8_t err_code, char *err_msg);
void  pickle_header(char *arr, const HeaderData *hd);
char *construct_payload(PayloadField *payload_fields, size_t num_fields, size_t payload_len);
char *construct_message(const char *header, const char *payload, size_t header_len, size_t payload_len);

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
    if(is_valid_version(header->protocol_ver) || is_valid_packet_type(header->packet_type))
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

int send_sys_error(int fd, uint8_t err_code, char *err_msg)
{
    HeaderData   hd;
    char        *header;
    char        *payload;
    char        *message;
    PayloadField payload_fields[2];
    size_t       err_msg_len;
    int          ret;

    ret             = 0;
    err_msg_len     = strlen(err_msg);
    hd.packet_type  = SYS_ERROR;
    hd.protocol_ver = PROTOCOL_VERSION;
    hd.sender_id    = SYSTEM_ID;
    hd.payload_len  = (uint16_t)(err_msg_len + sizeof(err_code));

    header = (char *)malloc(HEADER_SIZE);
    if(header == NULL)
    {
        fprintf(stderr, "malloc error\n");
        return 1;
    }

    pickle_header(header, &hd);

    payload_fields[0].data            = &err_code;
    payload_fields[0].data_size_bytes = sizeof(err_code);
    payload_fields[1].data            = err_msg;
    payload_fields[1].data_size_bytes = err_msg_len;

    payload = construct_payload(payload_fields, 2, hd.payload_len);
    if(payload == NULL)
    {
        ret = 1;
        goto payload_fail;
    }

    message = construct_message(header, payload, HEADER_SIZE, hd.payload_len);
    if(message == NULL)
    {
        ret = 1;
        goto message_fail;
    }

    if(write_fully(fd, message, (size_t)HEADER_SIZE + hd.payload_len))
    {
        fprintf(stderr, "Error sending sys error\n");
        ret = 1;
    }

    free(message);
    printf("%d", fd);
message_fail:
    free(payload);
payload_fail:
    free(header);
    return ret;
}

void pickle_header(char *arr, const HeaderData *hd)
{
    const uint16_t host_order_sender_id   = htons(hd->sender_id);
    const uint16_t host_order_payload_len = htons(hd->payload_len);

    *(uint8_t *)arr         = hd->packet_type;
    *((uint8_t *)(arr + 1)) = hd->protocol_ver;

    memcpy(arr + 2, &host_order_sender_id, sizeof(host_order_sender_id));
    memcpy(arr + 4, &host_order_payload_len, sizeof(host_order_payload_len));
}

char *construct_payload(PayloadField *payload_fields, size_t num_fields, size_t payload_len)
{
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
        memcpy(payload, payload_fields[i].data, payload_fields[i].data_size_bytes);
        payload += payload_fields[i].data_size_bytes;
    }
    return payload_ptr_copy;
}

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
