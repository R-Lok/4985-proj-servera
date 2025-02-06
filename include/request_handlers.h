#ifndef REQUEST_HANDLERS_H
#define REQUEST_HANDLERS_H
#include "../include/protocol.h"
#include "../include/user.h"

typedef int (*RequestHandler)(const ServerData *, const HeaderData *, char *);
RequestHandler get_handler_function(uint8_t packet_type);

#endif
