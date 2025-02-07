#include "../include/request_handlers.h"
#include "../include/protocol.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int handle_login(HandlerArgs *args);
int handle_logout(HandlerArgs *args);
int handle_acc_create(HandlerArgs *args);

RequestHandler get_handler_function(uint8_t packet_type)
{
    if(packet_type == ACC_LOGIN)
    {
        return handle_login;
    }
    return NULL;
    // switch(packet_type)
    // {
    //     case ACC_LOGIN:
    //         return handle_login;
    //     // case ACC_LOGOUT:
    //     //     return handle_logout;
    //     // case ACC_CREATE:
    //     //     return handle_acc_create;
    //     default:
    //         return NULL;
    // }
}

// This will get rewritten - was only written so we could test with a client group - it successfully printed out the username and password.
int handle_login(HandlerArgs *args)
{
    uint8_t name_len;
    uint8_t pass_len;
    char   *name;
    char   *password;
    int     ret;

    ret = 0;
    printf("BER: %u\n", (uint8_t)*(args->payload_buffer));
    ++args->payload_buffer;
    name_len = *((uint8_t *)(args->payload_buffer));    // skip ber tag
    name     = (char *)malloc((size_t)name_len + 1);    //+1 for nul termination
    if(name == NULL)
    {
        fprintf(stderr, "malloc() err\n");
        ret = 1;
        goto name_fail;
    }
    args->payload_buffer++;
    memcpy(name, args->payload_buffer, name_len);
    name[name_len] = '\0';
    args->payload_buffer += name_len;

    ++args->payload_buffer;
    pass_len = *((uint8_t *)(args->payload_buffer));    // skip ber tag
    printf("pass length: %u\n", pass_len);
    password = (char *)malloc((size_t)pass_len + 1);
    if(password == NULL)
    {
        fprintf(stderr, "malloc() err\n");
        ret = 1;
        goto password_fail;
    }
    ++args->payload_buffer;
    printf("first char of pass: %c\n", *args->payload_buffer);
    memcpy(password, args->payload_buffer, pass_len);
    password[pass_len] = '\0';

    printf("%s : %s\n", name, password);

    printf("%u, %u\n", args->sd->num_clients, args->hd->packet_type);

    free(password);
password_fail:
    free(name);
name_fail:
    return ret;
}

// int handle_logout(ServerData *sd, HeaderData *hd, char *payload_buffer)
// {
//     return 0;
// }

// int handle_acc_create(ServerData *sd, HeaderData *hd, char *payload_buffer)
// {
//     return 0;
// }
