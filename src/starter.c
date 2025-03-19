#include "../include/args.h"
#include "../include/protocol.h"
#include "../include/server_manager.h"
#include "../include/socket.h"
#include <errno.h>
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
static volatile sig_atomic_t ss_running = 1;
// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
static int *pipe_write_end;
void        handle_signal(int signal);
void        sigchld_handler(int sig);
void        server_loop(int sm_fd, int pipe_read_end);

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
    if(server_manager_connect(sock_fd, &sm_addr, &ss_running))
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
        ss_running = 0;
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

void server_loop(int sm_fd, int pipe_read_end)
{
    char          fd_string[MAX_CONNECTED_CLIENTS + 4];
    struct pollfd fds[2];
    pid_t         server_pid = -1;    // tracking server process ID
    fds[0].fd                = sm_fd;
    fds[0].events            = POLLIN;
    fds[1].fd                = pipe_read_end;
    fds[1].events            = POLLIN;

    // int  child_id;g

    // int  child_exists;
    printf("Inside server loop\n");
    snprintf(fd_string, sizeof(fd_string), "%d", sm_fd);
    setenv("SM_FD", fd_string, 1);
    // Need to wrap in some sort of loop here to read from server manager, if start -> exec the server, if stop -> kill the child (milestone3)
    // but don't fork a server is child already exists, and if stopping but not server -> no effect

    while(ss_running)
    {
        int poll_count = poll(fds, 2, -1);
        if(poll_count == -1)
        {
            if(errno == EINTR)
            {
                continue;
            }
            perror("poll() failed");
            continue;
        }

        if(fds[0].revents & POLLIN)
        {
            int packet_type = handle_sm_packet(sm_fd);

            if(packet_type == -1)
            {
                fprintf(stderr, "Connection lost, shutting down server starter...\n");
                break;
            }
            switch(packet_type)
            {
                case SVR_START:
                    printf("SVR_START received\n");
                    start_server(&server_pid, sm_fd);
                    break;
                case SVR_STOP:
                    printf("SVR_STOP received\n");
                    stop_server(&server_pid, sm_fd);
                    break;
                default:
                    printf("unknown packet type %d\n", packet_type);
                    break;
            }
        }

        if(fds[1].revents & POLLIN)
        {
            char dummy;
            read(fds[1].fd, &dummy, 1);
            printf("child process detected as terminated\n");
            if(waitpid(server_pid, NULL, WNOHANG) > 0)
            {
                send_svr_offline(sm_fd);
                server_pid = -1;
            }
        }
    }

    // child_id = fork();
    // if(child_id == -1)
    // {
    //     fprintf(stderr, "fork() failed\n");
    //     return 1;
    // }
    // if(child_id == 0)
    // {
    //     execl(SERVER_PATH, SERVER_PROG_NAME, PORT_FLAG, SERVER_PORT, NULL);
    //     printf("exec failed\n");
    //     exit(1);    // exec failed;
    // }
    // else
    // {
    //     server_pid = child_id;
    //     // child_exists = 1;
    //     // printf("child exist: %d | child id = %d \n", child_exists, child_id);
    // }
}
