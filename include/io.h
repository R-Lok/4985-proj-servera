#ifndef IO_H
#define IO_H
#include <inttypes.h>

int read_fully(int fd, char *buffer, uint32_t bytes_to_read);

#endif