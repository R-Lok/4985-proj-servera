#include "../include/io.h"
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

// in ms, can lower. Timeout exists cause imagine: client states their payload is 20 bytes in header, but actually
// 18 bytes. We would get stuck on read forever if we do not time out their request.
#define TIMEOUT_DURATION 6000
#define MS_PER_SECOND 1000

/*
    Reads a specified number of bytes from a file descriptor with timeout handling.

    @param
    fd: File descriptor to read from
    buffer: Buffer to store the read data
    bytes_to_read: Number of bytes to read

    @return
    FULLY_READ on success, TIMEOUT or error code on failure
*/
int read_fully(int fd, char *buffer, size_t bytes_to_read)
{
    clock_t start_tick;
    size_t  tread;
    // printf("wanting to read %zu bytes\n", bytes_to_read);
    tread      = 0;
    start_tick = clock();    // Start the timer. We are measuring using clock ticks. It doesn't matter if the timeout is EXACTLY 100ms.

    while(tread != bytes_to_read)
    {
        ssize_t nread;
        clock_t current_tick;
        double  elapsed_time_ms;

        // printf("read %zu bytes\n", tread);
        current_tick    = clock();    // Get current tick.
        elapsed_time_ms = (double)(current_tick - start_tick) * MS_PER_SECOND / CLOCKS_PER_SEC;
        if(elapsed_time_ms > TIMEOUT_DURATION)    // If beyond timeout, then return TIMEOUT.
        {
            printf("Timed Out fd:%d | elapsed time: %f\n", fd, elapsed_time_ms);
            return TIMEOUT;
        }
        nread = read(fd, buffer + tread, bytes_to_read - tread);
        if(nread == -1)
        {
            if(errno == EINTR || errno == EAGAIN)
            {
                continue;
            }
            if(errno == EBADF)
            {
                return CLIENT_DISCONNECTED;
            }
            fprintf(stderr, "read() error - %s\n", strerror(errno));
            return READ_ERROR;
        }

        if(nread == 0)    // If we read EOF even though we expected to read more bytes.
        {
            // printf("cd\n");
            return CLIENT_DISCONNECTED;
        }

        tread += (size_t)nread;
    }
    return FULLY_READ;
}

/*
    Writes a specified number of bytes to a file descriptor with timeout handling.

    @param
    fd: File descriptor to write to
    buffer: Buffer containing data to write
    bytes_to_write: Number of bytes to write

    @return
    FULLY_WRITTEN on success, TIMEOUT or error code on failure
*/
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
