#include "../include/server_manager.h"
#include "../include/io.h"
#include "../include/protocol.h"
#include "../include/socket.h"
#include <arpa/inet.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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
    const volatile sig_atomic_t *running;
} ThreadArgs;

void pickle_server_manager_header(char *arr, const ServerManagerHeader *hd);

void *thread_send_usrcount(void *args);

int server_manager_connect(int sock_fd, const struct sockaddr_in *sm_addr, const volatile sig_atomic_t *running)
{
    const uint8_t RETRY_TIME = 5;
    int           connected;
    int           ret = 1;
    connected         = 0;
    while(*running == 1 && connected == 0)
    {
        printf("Attempting to connect to server manager..\n");
        if(connect(sock_fd, (const struct sockaddr *)sm_addr, sizeof(*(sm_addr))) == 0)
        {
            connected = 1;
            ret       = 0;
        }
        else
        {
            sleep(RETRY_TIME);
        }
    }
    return ret;
}

void server_manager_disconnect(int sock_fd)
{
    if(sock_fd >= 0)
    {
        close(sock_fd);
    }
}

int send_user_count(int sock_fd, uint16_t user_count)
{
    ServerManagerHeader smh;
    char               *header;
    char               *payload;
    char               *message;
    int                 ret;
    uint16_t            user_count_network_order;
    PayloadField        pf;

    ret = 0;

    // Construct the header
    smh.packet_type  = USR_COUNT;    // packet for user count
    smh.protocol_ver = 1;            // protocol version
    smh.payload_len  = (uint16_t)(sizeof(user_count) + EXTRA_BYTES_FOR_BER_AND_LENGTH);

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
    // Fill payload
    pf.data            = &user_count_network_order;
    pf.ber_tag         = P_INTEGER;
    pf.data_size_bytes = sizeof(user_count);

    payload = construct_payload(&pf, 1, smh.payload_len);
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

void pickle_server_manager_header(char *arr, const ServerManagerHeader *hd)
{
    const uint16_t host_order_payload_len = htons(hd->payload_len);

    *(uint8_t *)arr         = hd->packet_type;
    *((uint8_t *)(arr + 1)) = hd->protocol_ver;
    memcpy(arr + 2, &host_order_payload_len, sizeof(host_order_payload_len));
}

int server_loop(int sm_fd)
{
    int  child_id;
    char fd_string[MAX_CONNECTED_CLIENTS + 4];
    // int  child_exists;
    snprintf(fd_string, sizeof(fd_string), "%d", sm_fd);
    setenv("SM_FD", fd_string, 1);
    // Need to wrap in some sort of loop here to read from server manager, if start -> exec the server, if stop -> kill the child (milestone3)
    // but don't fork a server is child already exists, and if stopping but not server -> no effect

    child_id = fork();
    if(child_id == -1)
    {
        fprintf(stderr, "fork() failed\n");
        return 1;
    }
    if(child_id == 0)
    {
        execl(SERVER_PATH, SERVER_PROG_NAME, PORT_FLAG, SERVER_PORT, NULL);
        printf("exec failed\n");
        exit(1);    // exec failed;
    }
    else
    {
        // child_exists = 1;
        // printf("child exist: %d | child id = %d \n", child_exists, child_id);
    }

    return 0;
}

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

int create_sm_diagnostic_thread(pthread_t *thread, int sm_fd, uint16_t *user_count_ptr, const volatile sig_atomic_t *running)
{
    ThreadArgs *ta = (ThreadArgs *)malloc(sizeof(ThreadArgs));
    if(!ta)
    {
        fprintf(stderr, "Memory allocation failed\n");
        return 1;
    }
    ta->fd            = sm_fd;
    ta->usr_count_ptr = user_count_ptr;
    ta->running       = running;

    if(pthread_create(thread, NULL, thread_send_usrcount, (void *)ta))
    {
        fprintf(stderr, "error creating thread\n");
        return 1;
    }
    return 0;
}

void *thread_send_usrcount(void *args)
{
    ThreadArgs *ta;

    ta = (ThreadArgs *)args;

    while((*ta->running) == 1)
    {
        // printf("Thread running...\n");
        send_user_count(ta->fd, *ta->usr_count_ptr);
        sleep(DIAGNOSTIC_DELAY);
    }
    printf("Thread exiting...%d\n", *ta->running);
    free(ta);
    return NULL;
}
