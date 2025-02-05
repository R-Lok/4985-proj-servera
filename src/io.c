#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include "../include/io.h"

#define FULLY_READ 0
#define READ_ERROR 1
#define CLIENT_DISCONNECTED 2
#define TIMEOUT 3
#define TIMEOUT_DURATION 50 //ms
#define MS_PER_SECOND 1000

int read_fully(int fd, char *buffer, uint32_t bytes_to_read) {

    clock_t start_tick;
    size_t tread;
    tread = 0;
    start_tick = clock();

    while(tread != bytes_to_read) {
        
        ssize_t nread;
        clock_t current_tick;
        double elapsed_time_ms;

        nread = read(fd, buffer + tread, bytes_to_read - tread);
        if(nread == -1) {
            if (errno == EINTR) {
                continue;
            }
            fprintf(strerror, "read() error - %s", strerror(errno));
            return READ_ERROR;
        }

        if(nread == 0 && bytes_to_read != tread) {
            return CLIENT_DISCONNECTED;
        }

        current_tick = clock();
        elapsed_time_ms = (double)(current_tick - start_tick) * MS_PER_SECOND / CLOCKS_PER_SEC;
        if(elapsed_time_ms > TIMEOUT_DURATION) {
            return TIMEOUT;
        }
        tread += (size_t)nread;
    }
    return 0;
}