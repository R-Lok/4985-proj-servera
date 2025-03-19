#include "../include/args.h"
#include "../include/server_manager.h"
#include "../include/socket.h"
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define DEFAULT_PORT 8080

// set sys err (check this function for header building)
// get server manager running on computer and use wireshark
// no payload so don't need to combine messages
// use pickle header

// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
static volatile sig_atomic_t running = 1;
// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
static int *pipe_write_end;
void        handle_signal(int signal);
void        sigchld_handler(int sig);

int main(int argc, char **argv)
{
    in_port_t          sm_port;
    char               ipv4[MAX_LEN_IPV4 + 2];
    int                err;
    struct sockaddr_in sm_addr;
    int                sock_fd;
    int                ret;

    struct sigaction sa;
    static int       child_pipe[2];

    memset(&sa, 0, sizeof(sa));

#if defined(__clang__)
    #pragma clang diagnostic push
    #pragma clang diagnostic ignored "-Wdisabled-macro-expansion"
#endif
    sa.sa_handler = sigchld_handler;
#if defined(__clang__)
    #pragma clang diagnostic pop
#endif

    sa.sa_flags = SA_RESTART;
    sigaction(SIGCHLD, &sa, NULL);

    sm_port = DEFAULT_PORT;
    ret     = 0;
    signal(SIGINT, handle_signal);

    if(parse_addr(argc, argv, &sm_port, ipv4))
    {
        exit(EXIT_FAILURE);
    }

    if(setup_addr(ipv4, &sm_addr, sm_port, &err) != 0)
    {
        fprintf(stderr, "Invalid ipv4 address- %s\n", strerror(err));
        print_usage_client();
        exit(EXIT_FAILURE);
    }

    sock_fd = socket(sm_addr.sin_family, SOCK_STREAM, 0);    // NOLINT(android-cloexec-socket)
    if(sock_fd == -1)
    {
        fprintf(stderr, "Error calling socket()\n");
        exit(EXIT_FAILURE);
    }

    if(pipe2(child_pipe, O_CLOEXEC | O_NONBLOCK) == -1)
    {
        perror("Error creating pipe");
        exit(EXIT_FAILURE);
    }
    pipe_write_end = &child_pipe[1];
    if(server_manager_connect(sock_fd, &sm_addr, &running))
    {
        goto end;    // SIGINT received
    }

    server_loop(sock_fd, child_pipe[0]);    // temp, needs to capture return value

    printf("Server starter closing...\n");
end:
    close(child_pipe[0]);
    close(child_pipe[1]);
    return ret;
}

void handle_signal(int signal)
{
    if(signal == SIGINT)
    {
        running = 0;
    }
}

void sigchld_handler(int sig)
{
    (void)sig;

    // Write dummy byte to notify poll
    write(*pipe_write_end, "x", 1);

    // Clean up the zombie process
    while(waitpid(-1, NULL, WNOHANG) > 0)
    {
    }
}
