#ifndef IO_H
#define IO_H
#include <inttypes.h>
#include <stddef.h>

#define FULLY_READ 0
#define FULLY_WRITTEN 0
#define WRITE_ERROR 1
#define READ_ERROR 1
#define CLIENT_DISCONNECTED 2
#define TIMEOUT 3

int read_fully(int fd, char *buffer, size_t bytes_to_read);
int write_fully(int fd, const char *buffer, size_t bytes_to_write);

#endif
