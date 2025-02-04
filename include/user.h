#ifndef USER_H
#define USER_H
#include <inttypes.h>
#include <pthread.h>
#include <poll.h>

#define MAX_USERNAME_LENGTH 33 //including \0 terminator

typedef struct
{
    char username[MAX_USERNAME_LENGTH];
    uint32_t uid;
} SessionUser;

typedef struct 
{
    struct pollfd *clients;
    SessionUser *fd_map;
    nfds_t num_clients;
    
} ServerData;


#endif
