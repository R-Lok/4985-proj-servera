#ifndef REQUEST_HANDLERS_H
#define REQUEST_HANDLERS_H
#include "../include/protocol.h"
#include "../include/user.h"

// THIS TYPEDEF WILL GET CHANGED, CURRENTLY CANNOT COVER ALL REQUEST TYPES AS COMPILER CRIES ABOUT WHETHER ServerData * is const or not.
typedef int (*RequestHandler)(const ServerData *, const HeaderData *, char *);

RequestHandler get_handler_function(uint8_t packet_type);

#endif
