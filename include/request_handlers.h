#ifndef REQUEST_HANDLERS_H
#define REQUEST_HANDLERS_H
#include "../include/protocol.h"
#include "../include/user.h"

typedef struct
{
    // cppcheck-suppress unusedStructMember
    ServerData *sd;
    // cppcheck-suppress unusedStructMember
    HeaderData *hd;
    // cppcheck-suppress unusedStructMember
    char *payload_buffer;
} HandlerArgs;

// Function pointer for handler functions
typedef int (*RequestHandler)(HandlerArgs *, int);

RequestHandler get_handler_function(uint8_t packet_type);

#endif
