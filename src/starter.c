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

#define DEFAULT_SM_PORT 9000

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
int         server_loop(int sm_fd, int pipe_read_end);
int         set_cloexec(int fd);

/*
    Initializes signal handling, connects to the server manager, and starts the control loop.

    @param
    argc: Number of command-line arguments
    argv: Array of command-line argument strings

    @return
    0 on success, 1 on failure
*/
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

    sm_port = DEFAULT_SM_PORT;
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

    if(pipe(child_pipe) == -1)    // NOLINT(android-cloexec-pipe)
    {
        perror("Error creating pipe");
        exit(EXIT_FAILURE);
    }
    if(set_cloexec(child_pipe[0]) || set_cloexec(child_pipe[1]))
    {
        fprintf(stderr, "Failed to set pipes to CLOEXEC\n");
        exit(EXIT_FAILURE);
    }

    pipe_write_end = &child_pipe[1];
    sock_fd        = server_manager_connect(&sm_addr, &ss_running);
    if(sock_fd == -1 || sock_fd == 0)
    {
        ret = 1;
        goto end;    // SIGINT received, or error creating socket
    }

    ret = server_loop(sock_fd, child_pipe[0]);    // temp, needs to capture return value

    printf("Server starter closing...\n");
end:
    close(child_pipe[0]);
    close(child_pipe[1]);
    return ret;
}

/*
    Handles SIGINT by updating the running flag to terminate the program.

    @param
    signal: Signal number received
*/
void handle_signal(int signal)
{
    if(signal == SIGINT)
    {
        ss_running = 0;
    }
}

/*
    Handles SIGCHLD to clean up terminated child processes and notify the main loop.

    @param
    sig: Signal number received
*/
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

/*
    Runs the main control loop to manage server start/stop commands and child process events.

    @param
    sm_fd: Socket connected to the server manager
    pipe_read_end: Read end of the pipe used for SIGCHLD notifications

    @return
    0 on normal exit, 1 on connection loss
*/
int server_loop(int sm_fd, int pipe_read_end)
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
            perror("poll() failed");
            if(errno == EINTR)
            {
                continue;
            }
            ss_running = 0;
            break;
        }

        if(fds[0].revents & POLLIN)
        {
            int packet_type = handle_sm_packet(sm_fd);

            if(packet_type == -1)
            {
                if(server_pid != -1)
                {    // kill child if exists
                    kill(server_pid, SIGINT);
                }
                fprintf(stderr, "Connection lost, shutting down server starter...\n");
                return 1;
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
    return 0;
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

/*
    Sets the FD_CLOEXEC flag on a file descriptor to close it during exec.

    @param
    fd: File descriptor to modify

    @return
    0 on success, 1 on failure
*/
int set_cloexec(int fd)
{
    int flags = fcntl(fd, F_GETFD);    // Get current flags
    if(flags == -1)
    {
        perror("failed to retrieve fd flags");
        return 1;
    }

    if(fcntl(fd, F_SETFD, flags | FD_CLOEXEC) == -1)
    {    // Set FD_CLOEXEC
        perror("failed to set fd flags");
        return 1;
    }
    return 0;
}
