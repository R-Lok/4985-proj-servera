#ifndef USER_H
#define USER_H
#include <inttypes.h>
#include <pthread.h>
#include <poll.h>

#define MAX_USERNAME_LENGTH 32

typedef struct
{
    char username[MAX_USERNAME_LENGTH];
    uint32_t uid;
    uint8_t  processing;
} SessionUser;

typedef struct 
{
    struct pollfd *clients;
    SessionUser *fd_map;
    pthread_rwlock_t rwlock;
    nfds_t num_clients;
    
} ServerData;


#endif
