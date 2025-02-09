#include "../include/io.h"
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

// in ms, can lower. Timeout exists cause imagine: client states their payload is 20 bytes in header, but actually
// 18 bytes. We would get stuck on read forever if we do not time out their request.
#define TIMEOUT_DURATION 100
#define MS_PER_SECOND 1000

int read_fully(int fd, char *buffer, size_t bytes_to_read)
{
    clock_t start_tick;
    size_t  tread;
    tread      = 0;
    start_tick = clock();    // Start the timer. We are measuring using clock ticks. It doesn't matter if the timeout is EXACTLY 100ms.

    while(tread != bytes_to_read)
    {
        ssize_t nread;
        clock_t current_tick;
        double  elapsed_time_ms;

        current_tick    = clock();    // Get current tick.
        elapsed_time_ms = (double)(current_tick - start_tick) * MS_PER_SECOND / CLOCKS_PER_SEC;
        if(elapsed_time_ms > TIMEOUT_DURATION)    // If beyond timeout, then return TIMEOUT.
        {
            printf("Timed Out\n");
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

        if(nread == 0 && bytes_to_read != tread)    // If we read EOF even though we expected to read more bytes.
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
    start_tick = clock();    // Same time out idea as above. But in this case, in case the client's kernel buffer for the socket is full for too long.

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
