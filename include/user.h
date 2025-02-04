#ifndef USER_H
#define USER_H
#include <inttypes.h>
#include <poll.h>
#include <pthread.h>

#define MAX_USERNAME_LENGTH 33    // including \0 terminator

typedef struct
{
    // cppcheck-suppress unusedStructMember
    char username[MAX_USERNAME_LENGTH];
    // cppcheck-suppress unusedStructMember
    uint32_t uid;
} SessionUser;

typedef struct
{
    // cppcheck-suppress unusedStructMember
    struct pollfd *clients;
    // cppcheck-suppress unusedStructMember
    SessionUser *fd_map;
    // cppcheck-suppress unusedStructMember
    nfds_t num_clients;

} ServerData;

#endif
