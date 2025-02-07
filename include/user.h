#ifndef USER_H
#define USER_H
#include <inttypes.h>
#include <poll.h>
#include <pthread.h>

#define MAX_USERNAME_LENGTH 33    // including \0 terminator

typedef struct    // This struct is the elements of the fd_map in ServerData. Each holds a user's name and uid AFTER they logged in.
{
    // cppcheck-suppress unusedStructMember
    char username[MAX_USERNAME_LENGTH];    // This should be zero'd out (all nul terminators) if not logged in
    // cppcheck-suppress unusedStructMember
    uint32_t uid;    // This should be 0, if they are not logged in.
} SessionUser;

typedef struct
{
    // cppcheck-suppress unusedStructMember
    struct pollfd *clients;    // Array of pollfd's. ALL connected clients regardless if they are logged in or not.
    // cppcheck-suppress unusedStructMember
    SessionUser *fd_map;    // A map containing all the connected clients. We the file descriptor as the index to this array. So we can tie each fd to
                            // a specific username and uid.
    // cppcheck-suppress unusedStructMember
    nfds_t num_clients;    // Just tracking the number of connected clients (don't have to be logged in)

} ServerData;

#endif
