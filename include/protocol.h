#ifndef PROTOCOL_H
#define PROTOCOL_H

#include "../include/user.h"
#include <inttypes.h>
#include <stddef.h>

#define PROTOCOL_VERSION 1
#define SYSTEM_ID 0
#define EXTRA_BYTES_FOR_BER_AND_LENGTH 2

/*Header size in bytes*/
#define HEADER_SIZE 6

/*Client and Server Packet types*/
// #define SYS_SUCCESS 0
#define SYS_ERROR 1
#define ACC_LOGIN 10    // User request to log in
// #define ACC_LOGIN_SUCCESS 11 //System response that log in was successful
#define ACC_LOGOUT 12    // User request to log out
#define ACC_CREATE 13

/*Server-Client Error codes*/
// #define P_INVALID_USER_ID 11
// #define P_INVALID_AUTH_INFO 12
// #define P_USER_EXISTS 13 //If signing up with taken name
#define P_SERVER_FAILURE 21    // if server has error and cannot fulfill the request
#define P_BAD_REQUEST 31
#define P_TIMEOUT 32

#define P_BAD_REQUEST_MSG "Bad Request"
#define P_TIMEOUT_MSG "Request Timed"
#define P_SERVER_FAILURE_MSG "Server Error"

/*BER Tags (P prefix to not confuse with any C reserved keywords)*/
// #define P_BOOLEAN 1
#define P_INTEGER 2
// #define P_NULL 5
// #define P_ENUMERATED 10
#define P_UTF8STRING 12

// #define P_SEQUENCE 16
// #define P_PRINTABLESTRING 19
// #define P_UTC_TIME 23
// #define P_GENERALIZED_TIME 24

#define PAYLOAD_READ_BUF_SIZE 1024

typedef struct
{
    // cppcheck-suppress unusedStructMember
    uint8_t packet_type;
    // cppcheck-suppress unusedStructMember
    uint8_t protocol_ver;
    // cppcheck-suppress unusedStructMember
    uint16_t sender_id;
    // cppcheck-suppress unusedStructMember
    uint16_t payload_len;
} HeaderData;

typedef struct
{
    // cppcheck-suppress unusedStructMember
    uint8_t ber_tag;
    // cppcheck-suppress unusedStructMember
    size_t data_size_bytes;
    // cppcheck-suppress unusedStructMember
    void *data;
} PayloadField;

int handle_fd(int fd, ServerData *server_data);
int send_sys_error(int fd, uint8_t err_code, const char *err_msg);

#endif
