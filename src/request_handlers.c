#include "../include/request_handlers.h"
#include "../include/protocol.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define NAME_BUFFER_SIZE 256
#define PASSWORD_BUFFER_SIZE 256

int handle_login(HandlerArgs *args, int fd);
int handle_logout(HandlerArgs *args, int fd);
int handle_acc_create(HandlerArgs *args, int fd);

// int extract_login_fields(uint16_t reported_payload_length, char *p_buffer, char *name, char *password);

int extract_field(char **payload_ptr, void *buffer, uint16_t *byte_threshold, uint8_t ber_tag);

int      extract_user_pass(char *payload_buffer, char *username, char *password, uint16_t *remaining_bytes);
int      try_acc_create(DBM *user_db, DBM *metadata_db, const char *username, const char *password);
int      check_user_exists(DBM *user_db, const char *username);
uint32_t increment_uid(DBM *metadata_db);
int      insert_new_user(DBM *user_db, const char *username, const char *password, uint32_t uid);

RequestHandler get_handler_function(uint8_t packet_type)
{
    switch(packet_type)
    {
        case ACC_LOGIN:
            return handle_login;
        // case ACC_LOGOUT:
        //     return handle_logout;
        case ACC_CREATE:
            return handle_acc_create;
        default:
            return NULL;
    }
}

int handle_login(HandlerArgs *args, int fd)
{
    char     username[NAME_BUFFER_SIZE];
    char     password[PASSWORD_BUFFER_SIZE];
    int      ret;
    uint16_t remaining_bytes;

    remaining_bytes = args->hd->payload_len;

    ret = 0;

    if(extract_user_pass(args->payload_buffer, username, password, &remaining_bytes))
    {
        send_sys_error(fd, P_BAD_REQUEST, P_BAD_REQUEST_MSG);
        return 0;    // not system error, ok
    }

    printf("login:%s:%s | remaining bytes: %u\n", username, password, remaining_bytes);    // remove this later;

    // call try_login() - this function would do DB calls for the username (key), if nothing returned, or value (password) does not match, error
    // try_login would also be responsible for updating sd->fd_map
    // if try_login error, send sys_error, else send sys_success

    return ret;
}

int handle_acc_create(HandlerArgs *args, int fd)
{
    char     username[NAME_BUFFER_SIZE];
    char     password[PASSWORD_BUFFER_SIZE];
    int      ret;
    uint16_t remaining_bytes;

    remaining_bytes = args->hd->payload_len;

    ret = 0;

    if(extract_user_pass(args->payload_buffer, username, password, &remaining_bytes))
    {
        send_sys_error(fd, P_BAD_REQUEST, P_BAD_REQUEST_MSG);
        return 0;    // not system error, ok
    }

    printf("acc create:%s:%s | remaining bytes: %u\n", username, password, remaining_bytes);    // remove this later;

    // call try_acc_create() -> first check if key (username) already exists, if it does, return some err number,
    // also consider empty passwords (nothing - maybe store password as just 1 NUL byte? or maybe return error? not sure - will have to discuss with clients)
    // if ok to create that account, create the account and return 0 (success)
    // send sys_success on successful creation, sys_error on failure (username already taken)

    return ret;
}

/**
 * Issue with handling logouts is that the main poll loop is already polling for disconnect events, the fd might be cleaned up
 * before this request is even read. I'll think about it more in milestone 2. There should be no major issues even with the current
 * design apart from maybe the fd_map position not being cleaned to NUL and 0.
 */
int handle_logout(HandlerArgs *args, int fd)
{
    // Check sender id matches the actual id stored in the fd_map
    if(args->hd->sender_id == args->sd->fd_map[fd].uid)
    {    // consider adding some kind of handling if it doesnt match?
        // set name to all NUL chars
        memset(args->sd->fd_map[fd].username, 0, sizeof(args->sd->fd_map[fd].username));
        // set uid of that position in the map as 0
        args->sd->fd_map[fd].uid = 0;
        // Close the file descriptor as they have logged out
        close(fd);    // consider if this needs further error handling.
    }
    return 0;
}

/**
 * This extracts specifically two fields from the payload: username followed by password (for login/acc create)
 */
int extract_user_pass(char *payload_buffer, char *username, char *password, uint16_t *remaining_bytes)
{
    if(extract_field(&payload_buffer, username, remaining_bytes, P_UTF8STRING))
    {
        return 1;    // bad request
    }

    if(extract_field(&payload_buffer, password, remaining_bytes, P_UTF8STRING))
    {
        return 1;    // bad request
    }
    return 0;
}

/**
 * This function extracts ONE payload field into the passed in buffer. You need to provide the ber_tag
 * so that it can check if the ber_tag in the payload is what you expected. The byte_threshold is essentially
 * how many remaining expected bytes are there (you are making sure the payload doesn't actually have more data than
 * the header reported). It can also detect if you are trying to read a string and will append the NUL terminator for you
 * if you provided the P_UTF8STRING ber_tag.
 *
 * If you are unsure how to incorporate this into a handle_xxxx function and the setup it requires, read handle_login/extract_user_pass
 * functions to get an idea of what the calling function needs in order to make use of the payload length checking.
 */
int extract_field(char **payload_ptr, void *buffer, uint16_t *byte_threshold, uint8_t ber_tag)
{
    const int SUCCESS                 = 0;
    const int INCORRECT_FIELD_TYPE    = 1;
    const int PAYLOAD_LENGTH_MISMATCH = 2;
    char     *buffer_ptr;
    uint8_t   data_len;

    buffer_ptr = (char *)buffer;

    if(**payload_ptr != (char)ber_tag)
    {
        return INCORRECT_FIELD_TYPE;
    }
    (*payload_ptr)++;

    data_len = *(uint8_t *)(*payload_ptr);
    (*payload_ptr)++;

    if(data_len > *byte_threshold - 2)
    {
        return PAYLOAD_LENGTH_MISMATCH;
    }

    memcpy(buffer_ptr, *payload_ptr, data_len);

    *payload_ptr += data_len;

    if(ber_tag == P_UTF8STRING)
    {
        buffer_ptr[data_len] = '\0';
    }

    *byte_threshold = (uint16_t)(*byte_threshold - data_len - 2);

    return SUCCESS;
}

int try_acc_create(DBM *user_db, DBM *metadata_db, const char *username, const char *password)
{
    const int USERNAME_TAKEN = 1;
    const int DB_ERROR       = 2;

    int      user_exists_res;
    uint32_t uid;

    user_exists_res = check_user_exists(user_db, username);
    if(user_exists_res == 1)
    {
        return USERNAME_TAKEN;
    }

    uid = increment_uid(metadata_db);
    if(uid == 0)
    {
        return DB_ERROR;
    }

    if(insert_new_user(user_db, username, password, uid))
    {
        return DB_ERROR;
    }

    return 0;
}

int check_user_exists(DBM *user_db, const char *username)
{
    const int   USER_EXISTS    = 1;
    const int   USER_NOT_EXIST = 0;
    const_datum key_datum;
    datum       result;

    key_datum = MAKE_CONST_DATUM(username);

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Waggregate-return"
    result = dbm_fetch(user_db, *(datum *)&key_datum);
#pragma GCC diagnostic pop

    if(result.dptr == NULL)
    {
        return USER_NOT_EXIST;
    }
    return USER_EXISTS;
}

uint32_t increment_uid(DBM *metadata_db)
{
    const uint32_t FIRST_UID = 1;
    const uint32_t ERROR     = 0;
    const char    *key       = "numusers";
    uint32_t       uid;

    if(retrieve_uint32(metadata_db, key, &uid) == -1)
    {    // no previous "numusers" entry
        if(store_uint32(metadata_db, key, FIRST_UID) == -1)
        {                    // set numusers to 1
            return ERROR;    // if storing has error
        }
        return FIRST_UID;    // return 1, first user to register
    }

    uid++;    // increment the retrieved number

    if(store_uint32(metadata_db, key, uid) == -1)
    {                    // store incremented number
        return ERROR;    // if storing has error
    }
    return uid;    // returned the incremented uid to assign to the user
}

int insert_new_user(DBM *user_db, const char *username, const char *password, uint32_t uid)
{
    char       *serialized_data;
    char       *shift_ptr;
    int         result;
    const_datum key;
    datum       value;

    serialized_data = (char *)malloc((strlen(password) + 1) + sizeof(uint32_t));
    if(serialized_data == NULL)
    {
        return -1;    // malloc error;
    }
    shift_ptr = serialized_data;

    memcpy(shift_ptr, &uid, sizeof(uid));                 // serialize uid into the array
    shift_ptr += sizeof(uid);                             // shift ptr to empty byte
    memcpy(shift_ptr, password, strlen(password) + 1);    // serialize password + NUL terminator

    key.dptr    = username;
    key.dsize   = strlen(username) + 1;    // include nul terminator
    value.dptr  = serialized_data;
    value.dsize = sizeof(uid) + strlen(password) + 1;

    result = dbm_store(user_db, *(datum *)&key, value, DBM_INSERT);
    free(serialized_data);
    return result;
}

// Below function is obsolete but i will keep it here for now for reference in the future.
//  int extract_login_fields(uint16_t reported_payload_length, char *p_buffer, char *name, char *password)
//  {
//      const int SUCCESS                 = 0;
//      const int INCORRECT_FIELD_TYPE    = 1;
//      const int PAYLOAD_LENGTH_MISMATCH = 2;
//      int       payload_length_sum;
//      uint8_t   name_len;
//      uint8_t   password_len;

//     payload_length_sum = 0;
//     // Check BER to be UTF8STRING
//     if(*p_buffer++ != P_UTF8STRING)
//     {    // shift to length after check
//         return INCORRECT_FIELD_TYPE;
//     }

//     name_len = *((uint8_t *)(p_buffer));                 // get name_length
//     payload_length_sum += *((uint8_t *)(p_buffer++));    // increment sum and move ptr to first char of name
//     if(payload_length_sum > reported_payload_length)
//     {
//         return PAYLOAD_LENGTH_MISMATCH;
//     }
//     memcpy(name, p_buffer, name_len);
//     name[name_len] = '\0';

//     p_buffer += name_len;    // increment ptr to next BER tag
//     if(*p_buffer++ != P_UTF8STRING)
//     {    // check and move pointer
//         return INCORRECT_FIELD_TYPE;
//     }

//     password_len = *((uint8_t *)(p_buffer));
//     payload_length_sum += *((uint8_t *)(p_buffer++));    // increment to first char of password;
//     if(payload_length_sum > reported_payload_length)
//     {
//         return PAYLOAD_LENGTH_MISMATCH;
//     }

//     memcpy(password, p_buffer, password_len);
//     password[password_len] = '\0';

//     return SUCCESS;
// }

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
