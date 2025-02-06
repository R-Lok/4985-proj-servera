#include "../include/io.h"
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define TIMEOUT_DURATION 50    // ms
#define MS_PER_SECOND 1000

int read_fully(int fd, char *buffer, size_t bytes_to_read)
{
    clock_t start_tick;
    size_t  tread;
    tread      = 0;
    start_tick = clock();

    while(tread != bytes_to_read)
    {
        ssize_t nread;
        clock_t current_tick;
        double  elapsed_time_ms;

        current_tick    = clock();
        elapsed_time_ms = (double)(current_tick - start_tick) * MS_PER_SECOND / CLOCKS_PER_SEC;
        if(elapsed_time_ms > TIMEOUT_DURATION)
        {
            return TIMEOUT;
        }
        nread = read(fd, buffer + tread, bytes_to_read - tread);
        if(nread == -1)
        {
            if(errno == EINTR || errno == EAGAIN)
            {
                continue;
            }
            fprintf(stderr, "read() error - %s\n", strerror(errno));
            return READ_ERROR;
        }

        if(nread == 0 && bytes_to_read != tread)
        {
            return CLIENT_DISCONNECTED;
        }

        tread += (size_t)nread;
    }
    return FULLY_READ;
}

int write_fully(int fd, const char *buffer, size_t bytes_to_write)
{
    clock_t start_tick;
    size_t  twrote;
    twrote     = 0;
    start_tick = clock();

    while(twrote != bytes_to_write)
    {
        ssize_t nwrote;
        clock_t current_tick;
        double  elapsed_time_ms;

        current_tick    = clock();
        elapsed_time_ms = (double)(current_tick - start_tick) * MS_PER_SECOND / CLOCKS_PER_SEC;
        if(elapsed_time_ms > TIMEOUT_DURATION)
        {
            return TIMEOUT;
        }

        nwrote = write(fd, buffer + twrote, bytes_to_write - twrote);
        if(nwrote == -1)
        {
            if(errno == EINTR || errno == EAGAIN)
            {
                continue;
            }
            if(errno == EPIPE || errno == ECONNRESET)
            {
                return CLIENT_DISCONNECTED;
            }
            fprintf(stderr, "write() error - %s\n", strerror(errno));
            return WRITE_ERROR;
        }
        twrote += (size_t)nwrote;
    }
    return FULLY_WRITTEN;
}
