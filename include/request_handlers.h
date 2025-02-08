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

// THIS TYPEDEF WILL GET CHANGED, CURRENTLY CANNOT COVER ALL REQUEST TYPES AS COMPILER CRIES ABOUT WHETHER ServerData * is const or not.
typedef int (*RequestHandler)(HandlerArgs *, int);

RequestHandler get_handler_function(uint8_t packet_type);

#endif
