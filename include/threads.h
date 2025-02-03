#ifndef THREADS_H
#define THREADS_H
#include "./user.h"
#include <poll.h>

void * handle_fd(void *thread_args);

#endif