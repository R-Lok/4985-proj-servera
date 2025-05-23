#include "../include/server_manager.h"
#include "../include/io.h"
#include "../include/protocol.h"
#include "../include/socket.h"
#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#define SERVER_PATH "./build/main"
#define SERVER_PROG_NAME "main"
#define SERVER_PORT "8000"
#define PORT_FLAG "-p"

#define DIAGNOSTIC_DELAY 10

typedef struct
{
    int                          fd;
    uint16_t                    *usr_count_ptr;
    uint32_t                    *msg_count_ptr;
    const volatile sig_atomic_t *running;
} ThreadArgs;

void pickle_server_manager_header(char *arr, const ServerManagerHeader *hd);

void *thread_send_usrcount(void *args);

/*
    Attempts to connect to the server manager, retrying until successful or termination is requested.

    @param
    sm_addr: Pointer to sockaddr_in struct with server manager address
    running: Flag used to check if the program should keep running

    @return
    Connected socket file descriptor on success, -1 on failure
*/
int server_manager_connect(const struct sockaddr_in *sm_addr, const volatile sig_atomic_t *running)
{
    const uint8_t RETRY_TIME = 5;
    int           sock_fd;

    sock_fd = socket(sm_addr->sin_family, SOCK_STREAM, 0);    // NOLINT(android-cloexec-socket)
    if(sock_fd == -1)
    {
        fprintf(stderr, "Error calling socket() in server_manager_connect\n");
        return -1;
    }
    while(*running == 1)
    {
        printf("Attempting to connect to server manager..\n");
        if(connect(sock_fd, (const struct sockaddr *)sm_addr, sizeof(*(sm_addr))) == 0)
        {
            return sock_fd;
        }
        close(sock_fd);
        sock_fd = socket(sm_addr->sin_family, SOCK_STREAM, 0);    // NOLINT(android-cloexec-socket)
        if(sock_fd == -1)
        {
            fprintf(stderr, "Error calling socket() in server_manager_connect\n");
            return -1;
        }
        sleep(RETRY_TIME);
    }
    return sock_fd;
}

/*
    Closes the socket connection to the server manager if it's valid.

    @param
    sock_fd: Socket file descriptor to close
*/
void server_manager_disconnect(int sock_fd)
{
    if(sock_fd >= 0)
    {
        close(sock_fd);
    }
}

/*
    Sends the current user count and message count to the server manager.

    @param
    sock_fd: Socket file descriptor for the server manager
    user_count: Number of connected users
    msg_count: Number of messages sent

    @return
    0 on success, 1 on error
*/
int send_user_count(int sock_fd, uint16_t user_count, uint32_t msg_count)    // named sender user count, but also includes the message count
{
    ServerManagerHeader smh;
    char               *header;
    char               *payload;
    char               *message;
    int                 ret;
    uint16_t            user_count_network_order;
    uint32_t            msg_count_network_order;
    PayloadField        payload_fields[2];

    ret = 0;

    // Construct the header
    smh.packet_type  = SVR_Diagnostic;                                                                                         // packet for user count
    smh.protocol_ver = PROTOCOL_VERSION;                                                                                       // protocol version
    smh.payload_len  = (uint16_t)(sizeof(user_count) + sizeof(msg_count) + (uint32_t)(EXTRA_BYTES_FOR_BER_AND_LENGTH * 2));    // 2 fields

    // Allocate space for header
    header = (char *)malloc(SERVER_MANAGER_HEADER_SIZE);
    if(header == NULL)
    {
        fprintf(stderr, "Error allocating header for user count\n");
        return 1;
    }

    // Encode header
    pickle_server_manager_header(header, &smh);

    user_count_network_order = htons(user_count);
    msg_count_network_order  = htonl(msg_count);
    // Fill payload
    payload_fields[0].data            = &user_count_network_order;
    payload_fields[0].ber_tag         = P_INTEGER;
    payload_fields[0].data_size_bytes = sizeof(user_count);
    payload_fields[1].data            = &msg_count_network_order;
    payload_fields[1].ber_tag         = P_INTEGER;
    payload_fields[1].data_size_bytes = sizeof(msg_count);

    payload = construct_payload(payload_fields, 2, smh.payload_len);
    if(payload == NULL)
    {
        ret = 1;
        goto free_header;
    }

    // Construct message
    message = construct_message(header, payload, SERVER_MANAGER_HEADER_SIZE, smh.payload_len);
    if(message == NULL)
    {
        ret = 1;
        goto free_payload;
    }

    // Send the message
    if(write_fully(sock_fd, message, (size_t)(SERVER_MANAGER_HEADER_SIZE + smh.payload_len)) == WRITE_ERROR)
    {
        fprintf(stderr, "Error sending user count to server manager\n");
        ret = 1;
    }

    // Cleanup
    free(message);
free_payload:
    free(payload);
free_header:
    free(header);
    return ret;
}

/*
    Serializes a ServerManagerHeader struct into a byte array.

    @param
    arr: Buffer to store the serialized header
    hd: Pointer to the ServerManagerHeader struct to serialize
*/
void pickle_server_manager_header(char *arr, const ServerManagerHeader *hd)
{
    const uint16_t host_order_payload_len = htons(hd->payload_len);

    *(uint8_t *)arr         = hd->packet_type;
    *((uint8_t *)(arr + 1)) = hd->protocol_ver;
    memcpy(arr + 2, &host_order_payload_len, sizeof(host_order_payload_len));
}

// int server_loop(int sm_fd, int pipe_read_end)
// {
//     char          fd_string[MAX_CONNECTED_CLIENTS + 4];
//     struct pollfd fds[2];
//     pid_t         server_pid = -1;    // tracking server process ID
//     fds[0].fd                = sm_fd;
//     fds[0].events            = POLLIN;
//     fds[1].fd                = pipe_read_end;
//     fds[1].events            = POLLIN;
//
//     // int  child_id;g
//
//     // int  child_exists;
//     printf("Inside server loop\n");
//     snprintf(fd_string, sizeof(fd_string), "%d", sm_fd);
//     setenv("SM_FD", fd_string, 1);
//     // Need to wrap in some sort of loop here to read from server manager, if start -> exec the server, if stop -> kill the child (milestone3)
//     // but don't fork a server is child already exists, and if stopping but not server -> no effect
//
//     while(running)
//     {
//         int poll_count = poll(fds, 2, -1);
//         if(poll_count == -1)
//         {
//             if(errno == EINTR)
//             {
//                 continue;
//             }
//             perror("poll() failed");
//             continue;
//         }
//
//         if(fds[0].revents & POLLIN)
//         {
//             int packet_type = handle_sm_packet(sm_fd);
//             switch(packet_type)
//             {
//                 case SVR_START:
//                     printf("SVR_START received\n");
//                     start_server(&server_pid, sm_fd);
//                     break;
//                 case SVR_STOP:
//                     printf("SVR_STOP received\n");
//                     stop_server(&server_pid, sm_fd);
//                     break;
//                 default:
//                     printf("unknown packet type %d\n", packet_type);
//                     break;
//             }
//         }
//
//         if(fds[1].revents & POLLIN)
//         {
//             char dummy;
//             read(fds[1].fd, &dummy, 1);
//             printf("child process detected as terminated\n");
//             if(waitpid(server_pid, NULL, WNOHANG) > 0)
//             {
//                 send_svr_offline(sm_fd);
//                 server_pid = -1;
//             }
//         }
//     }
//
//     // child_id = fork();
//     // if(child_id == -1)
//     // {
//     //     fprintf(stderr, "fork() failed\n");
//     //     return 1;
//     // }
//     // if(child_id == 0)
//     // {
//     //     execl(SERVER_PATH, SERVER_PROG_NAME, PORT_FLAG, SERVER_PORT, NULL);
//     //     printf("exec failed\n");
//     //     exit(1);    // exec failed;
//     // }
//     // else
//     // {
//     //     server_pid = child_id;
//     //     // child_exists = 1;
//     //     // printf("child exist: %d | child id = %d \n", child_exists, child_id);
//     // }
// }

/*
    Retrieves the server manager file descriptor from the SM_FD environment variable.

    @param
    sm_fd_holder: Pointer to where the file descriptor should be stored

    @return
    0 on success, -1 on failure
*/
int retrieve_sm_fd(int *sm_fd_holder)
{
    const int   BASE_TEN = 10;
    const char *env_val  = getenv("SM_FD");
    if(env_val != NULL)
    {
        char *endptr;
        *sm_fd_holder = (int)strtol(env_val, &endptr, BASE_TEN);
        if(*endptr != '\0')
        {
            return -1;    // ENV VAR INVALID <- shouldnt happen
        }
        return 0;
    }
    return -1;    // ENV VAR missing
}

/*
    Creates a thread that periodically sends diagnostic data (user and message count) to the server manager.

    @param
    thread: Pointer to the pthread_t to store the thread ID
    sm_fd: File descriptor for the server manager
    user_count_ptr: Pointer to the current user count
    msg_count_ptr: Pointer to the current message count
    running: Flag to indicate if the thread should continue running

    @return
    0 on success, 1 on failure
*/
int create_sm_diagnostic_thread(pthread_t *thread, int sm_fd, uint16_t *user_count_ptr, uint32_t *msg_count_ptr, const volatile sig_atomic_t *running)
{
    ThreadArgs *ta = (ThreadArgs *)malloc(sizeof(ThreadArgs));
    if(!ta)
    {
        fprintf(stderr, "Memory allocation failed\n");
        return 1;
    }
    ta->fd            = sm_fd;
    ta->usr_count_ptr = user_count_ptr;
    ta->msg_count_ptr = msg_count_ptr;
    ta->running       = running;

    if(pthread_create(thread, NULL, thread_send_usrcount, (void *)ta))
    {
        fprintf(stderr, "error creating thread\n");
        return 1;
    }
    return 0;
}

/*
    Thread function that sends diagnostic data to the server manager at regular intervals.

    @param
    args: Pointer to a ThreadArgs struct containing file descriptor, counters, and running flag

*/
void *thread_send_usrcount(void *args)
{
    ThreadArgs *ta;

    ta = (ThreadArgs *)args;

    while((*ta->running) == 1)
    {
        // printf("Thread running...\n");
        send_user_count(ta->fd, *ta->usr_count_ptr, *ta->msg_count_ptr);
        sleep(DIAGNOSTIC_DELAY);
    }
    printf("Thread exiting...%d\n", *ta->running);
    free(ta);
    return NULL;
}

/*
    Starts the server process if it's not already running.

    @param
    server_pid: Pointer to the PID of the server process
    fd: File descriptor for communicating with the server manager

    @return
    0 on success, 1 on failure
*/
int start_server(pid_t *server_pid, int fd)
{
    if(*server_pid > 0)
    {
        printf("Server already running with PID: %d\n", *server_pid);
        send_svr_online(fd);
        return 0;
    }

    *server_pid = fork();
    if(*server_pid == -1)
    {
        perror("Failed to fork server process");
        return 1;
    }

    if(*server_pid == 0)    // Child process
    {
        execl(SERVER_PATH, SERVER_PROG_NAME, PORT_FLAG, SERVER_PORT, NULL);
        perror("Failed to start server");
        exit(EXIT_FAILURE);    // Only reached if execl() fails
    }

    printf("Server started with PID %d\n", *server_pid);
    send_svr_online(fd);
    return 0;
}

/*
    Stops the running server process, if any.

    @param
    server_pid: Pointer to the PID of the server process
    fd: File descriptor for communicating with the server manager

    @return
    0 on success, 1 on failure
*/
int stop_server(pid_t *server_pid, int fd)
{
    printf("stopping with PID %d\n", *server_pid);
    if(*server_pid > 0)
    {
        printf("stopping server with PID: %d\n", *server_pid);

        if(kill(*server_pid, SIGINT) == 0)
        {
            waitpid(*server_pid, NULL, 0);
            printf("server stopped successfully.\n");
            send_svr_offline(fd);
        }
        else
        {
            send_svr_online(fd);
            perror("failed to stop server");
            return 1;
        }
        *server_pid = -1;
    }
    else
    {
        printf("no server to stop\n");
        send_svr_offline(fd);
    }
    return 0;
}

/*
    Sends a SVR_ONLINE message to the server manager.

    @param
    fd: File descriptor for the server manager connection

    @return
    0 on success, 1 on failure
*/
int send_svr_online(int fd)
{
    ServerManagerHeader hd;
    char               *header;

    hd.packet_type  = SVR_ONLINE;
    hd.protocol_ver = PROTOCOL_VERSION;
    hd.payload_len  = 0;

    header = (char *)malloc(SERVER_MANAGER_HEADER_SIZE);
    if(header == NULL)
    {
        fprintf(stderr, "Memory allocation failed\n");
        return 1;
    }

    pickle_server_manager_header(header, &hd);

    if(write_fully(fd, header, (size_t)(SERVER_MANAGER_HEADER_SIZE + hd.payload_len)) == WRITE_ERROR)
    {
        fprintf(stderr, "Error sending SVR_Online message\n");
        free(header);
        return 1;
    }

    free(header);
    return 0;
}

/*
    Sends a SVR_OFFLINE message to the server manager.

    @param
    fd: File descriptor for the server manager connection

    @return
    0 on success, 1 on failure
*/
int send_svr_offline(int fd)
{
    ServerManagerHeader hd;
    char               *header;

    hd.packet_type  = SVR_OFFLINE;
    hd.protocol_ver = PROTOCOL_VERSION;
    hd.payload_len  = 0;

    header = (char *)malloc(SERVER_MANAGER_HEADER_SIZE);
    if(header == NULL)
    {
        fprintf(stderr, "Memory allocation failed\n");
        return 1;
    }

    pickle_server_manager_header(header, &hd);

    if(write_fully(fd, header, (size_t)(SERVER_MANAGER_HEADER_SIZE + hd.payload_len)) == WRITE_ERROR)
    {
        fprintf(stderr, "Error sending SVR_Online message\n");
        free(header);
        return 1;
    }

    free(header);
    return 0;
}

/*
    Reads and unpacks a ServerManagerHeader from the socket.

    @param
    sock_fd: Socket file descriptor to read from
    header: Pointer to ServerManagerHeader to populate

    @return
    0 on success, -1 if connection closed or error occurs
*/
int read_sm_header(int sock_fd, ServerManagerHeader *header)
{
    char buffer[SERVER_MANAGER_HEADER_SIZE];
    int  read_res;

    read_res = read_fully(sock_fd, buffer, SERVER_MANAGER_HEADER_SIZE);

    if(read_res == 2)    // consider also handling the other error returns
    {
        fprintf(stderr, "Connection closed by server manager\n");
        return -1;
    }

    // Unpack the header
    header->packet_type  = (uint8_t)buffer[0];
    header->protocol_ver = (uint8_t)buffer[1];
    memcpy(&header->payload_len, buffer + 2, sizeof(header->payload_len));
    header->payload_len = ntohs(header->payload_len);    // Convert from network byte order

    return 0;
}

/*
    Reads a packet from the server manager and returns its type.

    @param
    sock_fd: Socket file descriptor to read from

    @return
    Packet type on success, -1 on failure
*/
int handle_sm_packet(int sock_fd)
{
    ServerManagerHeader header;
    if(read_sm_header(sock_fd, &header) == -1)
    {
        fprintf(stderr, "Failed to read header\n");
        return -1;
    }
    return header.packet_type;
}
