#include "../include/protocol.h"
#include <arpa/inet.h>
#include <string.h>

void extract_header(const char *buffer, HeaderData *header);

void extract_header(const char *buffer, HeaderData *header)
{
    header->packet_type  = (uint8_t)buffer[0];    // no converting to host order as one byte only
    header->protocol_ver = (uint8_t)buffer[1];    // same here

    memcpy(&(header->sender_id), buffer + 2, sizeof(uint16_t));
    memcpy(&(header->payload_len), buffer + 4, sizeof(uint16_t));

    header->sender_id   = ntohs(header->sender_id);
    header->payload_len = ntohs(header->payload_len);
}
