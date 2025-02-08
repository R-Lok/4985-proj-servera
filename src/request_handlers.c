#include "../include/request_handlers.h"
#include "../include/protocol.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define NAME_BUFFER_SIZE 256
#define PASSWORD_BUFFER_SIZE 256

int handle_login(HandlerArgs *args, int fd);
int handle_logout(HandlerArgs *args, int fd);
int handle_acc_create(HandlerArgs *args, int fd);

int extract_login_fields(uint16_t reported_payload_length, char *p_buffer, char *name, char *password);

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

int handle_login(HandlerArgs *args, int fd)
{
    char username[NAME_BUFFER_SIZE];
    char password[PASSWORD_BUFFER_SIZE];
    int  extract_res;
    int  ret;

    ret = 0;

    extract_res = extract_login_fields(args->hd->payload_len, args->payload_buffer, username, password);
    if(extract_res == 1 || extract_res == 2)
    {
        send_sys_error(fd, P_BAD_REQUEST, P_BAD_REQUEST_MSG);
        return 0;    // ok error, client had bad request
    }

    printf("%s:%s\n", username, password);    // remove this later;

    // call try_login() - this function would do DB calls for the username (key), if nothing returned, or value (password) does not match, error
    // try_login would also be responsible for updating sd->fd_map
    // if try_login error, send sys_error, else send sys_success

    return ret;
}

int extract_login_fields(uint16_t reported_payload_length, char *p_buffer, char *name, char *password)
{
    const int SUCCESS                 = 0;
    const int INCORRECT_FIELD_TYPE    = 1;
    const int PAYLOAD_LENGTH_MISMATCH = 2;
    int       payload_length_sum;
    uint8_t   name_len;
    uint8_t   password_len;

    payload_length_sum = 0;
    // Check BER to be UTF8STRING
    if(*p_buffer++ != P_UTF8STRING)
    {    // shift to length after check
        return INCORRECT_FIELD_TYPE;
    }

    name_len = *((uint8_t *)(p_buffer));                 // get name_length
    payload_length_sum += *((uint8_t *)(p_buffer++));    // increment sum and move ptr to first char of name
    if(payload_length_sum > reported_payload_length)
    {
        return PAYLOAD_LENGTH_MISMATCH;
    }
    memcpy(name, p_buffer, name_len);
    name[name_len] = '\0';

    p_buffer += name_len;    // increment ptr to next BER tag
    if(*p_buffer++ != P_UTF8STRING)
    {    // check and move pointer
        return INCORRECT_FIELD_TYPE;
    }

    password_len = *((uint8_t *)(p_buffer));
    payload_length_sum += *((uint8_t *)(p_buffer++));    // increment to first char of password;
    if(payload_length_sum > reported_payload_length)
    {
        return PAYLOAD_LENGTH_MISMATCH;
    }

    memcpy(password, p_buffer, password_len);
    password[password_len] = '\0';

    return SUCCESS;
}

// This will get rewritten - was only written so we could test with a client group - it successfully printed out the username and password.
// int handle_login(HandlerArgs *args, int fd)
// {
//     uint8_t name_len;
//     uint8_t pass_len;
//     char   *name;
//     char   *password;
//     int     ret;

//     ret = 0;
//     printf("BER: %u\n", (uint8_t)*(args->payload_buffer));
//     ++args->payload_buffer;
//     name_len = *((uint8_t *)(args->payload_buffer));    // skip ber tag
//     name     = (char *)malloc((size_t)name_len + 1);    //+1 for nul termination
//     if(name == NULL)
//     {
//         fprintf(stderr, "malloc() err\n");
//         ret = 1;
//         goto name_fail;
//     }
//     args->payload_buffer++;
//     memcpy(name, args->payload_buffer, name_len);
//     name[name_len] = '\0';
//     args->payload_buffer += name_len;

//     ++args->payload_buffer;
//     pass_len = *((uint8_t *)(args->payload_buffer));    // skip ber tag
//     printf("pass length: %u\n", pass_len);
//     password = (char *)malloc((size_t)pass_len + 1);
//     if(password == NULL)
//     {
//         fprintf(stderr, "malloc() err\n");
//         ret = 1;
//         goto password_fail;
//     }
//     ++args->payload_buffer;
//     printf("first char of pass: %c\n", *args->payload_buffer);
//     memcpy(password, args->payload_buffer, pass_len);
//     password[pass_len] = '\0';

//     printf("%s : %s\n", name, password);

//     printf("%u, %u\n", args->sd->num_clients, args->hd->packet_type);

//     free(password);
// password_fail:
//     free(name);
// name_fail:
//     return ret;
// }

// int handle_logout(ServerData *sd, HeaderData *hd, char *payload_buffer)
// {
//     return 0;
// }

// int handle_acc_create(ServerData *sd, HeaderData *hd, char *payload_buffer)
// {
//     return 0;
// }
