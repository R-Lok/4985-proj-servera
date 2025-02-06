#include "../include/protocol.h"
#include <arpa/inet.h>
#include <string.h>

void extract_header(const char *buffer, HeaderData *header);
int  is_valid_header(const HeaderData *header);
int  is_valid_version(uint8_t protocol_ver);
int  is_valid_packet_type(uint8_t packet_type);

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
