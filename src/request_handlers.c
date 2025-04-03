#include "../include/request_handlers.h"
#include "../include/io.h"
#include "../include/protocol.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define NAME_BUFFER_SIZE 256
#define TIMESTAMP_BUFFER_SIZE 128
#define MESSAGE_BUFFER_SIZE 512
#define PASSWORD_BUFFER_SIZE 256

int handle_login(HandlerArgs *args, int fd);
int handle_logout(HandlerArgs *args, int fd);
int handle_acc_create(HandlerArgs *args, int fd);
int handle_chat(HandlerArgs *args, int fd);
int extract_chat_fields(const HeaderData *hd, char *payload_buffer, char *timestamp_buf, char *message_buf, char *usr_buf);
int is_valid_timestamp(const char *timestamp);

// int extract_login_fields(uint16_t reported_payload_length, char *p_buffer, char *name, char *password);

int extract_field(char **payload_ptr, void *buffer, uint16_t *byte_threshold, uint8_t ber_tag);

int      extract_user_pass(char *payload_buffer, char *username, char *password, uint16_t *remaining_bytes);
int      try_acc_create(DBM *user_db, DBM *metadata_db, const char *username, const char *password);
int      check_user_exists(DBM *user_db, const char *username);
uint16_t increment_uid(DBM *metadata_db);
int      insert_new_user(DBM *user_db, const char *username, const char *password, uint16_t uid);
int      try_login(DBM *user_db, SessionUser *fd_map, int fd, const char *username, const char *password);

RequestHandler get_handler_function(uint8_t packet_type)
{
    switch(packet_type)
    {
        case ACC_LOGIN:
            return handle_login;
        case ACC_LOGOUT:
            return handle_logout;
        case ACC_CREATE:
            printf("selecting handle_acc_create\n");
            return handle_acc_create;
        case CHT_SEND:
            return handle_chat;
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

    printf("login:%s:%s | remaining bytes: %u | fd:%d\n", username, password, remaining_bytes, fd);    // remove this later;

    // call try_login() - this function would do DB calls for the username (key), if nothing returned, or value (password) does not match, error
    // try_login would also be responsible for updating sd->fd_map
    // if try_login error, send sys_error, else send sys_success
    if(try_login(args->sd->user_db, args->sd->fd_map, fd, username, password) == 0)
    {
        printf("Login success: %s | session info: uid:%u, socket:%d\n", args->sd->fd_map[fd].username, args->sd->fd_map[fd].uid, fd);    // send LOGIN SUCCESS packet
        send_login_success(fd, args->sd->fd_map[fd].uid);
    }
    else
    {
        printf("invalid auth\n");    // send sys_error
        send_sys_error(fd, P_INVALID_AUTH_INFO, P_INVALID_AUTH_INFO_MSG);
    }

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
    // if ok to create that account, create the account and return 0 (success)
    // send sys_success on successful creation, sys_error on failure (username already taken)
    if(try_acc_create(args->sd->user_db, args->sd->metadata_db, username, password))
    {
        printf("username taken\n");
        send_sys_error(fd, P_USER_EXISTS, P_USER_EXISTS_MSG);    // needs error handling
    }
    else
    {
        printf("account created\n");
        send_sys_success(fd, ACC_CREATE);
        // needs error handling
    }

    return ret;
}

/**
 * Issue with handling logouts is that the main poll loop is already polling for disconnect events, the fd might be cleaned up
 * before this request is even read.
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
        close(fd);
    }
    else
    {
        send_sys_error(fd, P_BAD_REQUEST, P_BAD_REQUEST_MSG);
        close(fd);    // Close their socket for attempting to log someone else out (assume malicious)
    }
    return 0;
}

/**
 * This extracts specifically two fields from the payload: username followed by password (for login/acc create)
 * NEEDS ERROR HANDLING FOR EMPTY PASSWORD MAYBE? - Will need to discuss with client groups perhaps - how would they even send an "empty" password?
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
    uint16_t uid;

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

uint16_t increment_uid(DBM *metadata_db)
{
    const uint16_t FIRST_UID = 1;
    const uint16_t ERROR     = 0;
    const char    *key       = "numusers";
    uint16_t       uid;

    if(retrieve_uint16(metadata_db, key, &uid) == -1)
    {    // no previous "numusers" entry
        if(store_uint16(metadata_db, key, FIRST_UID) == -1)
        {                    // set numusers to 1
            return ERROR;    // if storing has error
        }
        return FIRST_UID;    // return 1, first user to register
    }

    uid++;    // increment the retrieved number

    if(store_uint16(metadata_db, key, uid) == -1)
    {                    // store incremented number
        return ERROR;    // if storing has error
    }
    return uid;    // returned the incremented uid to assign to the user
}

int insert_new_user(DBM *user_db, const char *username, const char *password, uint16_t uid)
{
    char       *serialized_data;
    char       *shift_ptr;
    int         result;
    const_datum key;
    datum       value;

    serialized_data = (char *)malloc((strlen(password) + 1) + sizeof(uid));
    if(serialized_data == NULL)
    {
        return -1;    // malloc error;
    }
    shift_ptr = serialized_data;

    memcpy(shift_ptr, &uid, sizeof(uid));                 // serialize uid into the array
    shift_ptr += sizeof(uid);                             // shift ptr to empty byte
    memcpy(shift_ptr, password, strlen(password) + 1);    // serialize password + NUL terminator

    key.dptr    = username;
    key.dsize   = (datum_size)(strlen(username) + 1);    // include nul terminator
    value.dptr  = serialized_data;
    value.dsize = (datum_size)(sizeof(uid) + strlen(password) + 1);

    result = dbm_store(user_db, *(datum *)&key, value, DBM_INSERT);
    free(serialized_data);
    return result;
}

int try_login(DBM *user_db, SessionUser *fd_map, int fd, const char *username, const char *password)
{
    const int INVALID_AUTH = 1;
    // const int SERVER_ERROR = 2;
    char     retrieved_pass[PASSWORD_BUFFER_SIZE + 1];
    uint16_t retrieved_uid;
    datum    result;

    const_datum key;

    key = MAKE_CONST_DATUM(username);

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Waggregate-return"
    result = dbm_fetch(user_db, *(datum *)&key);
#pragma GCC diagnostic pop

    if(result.dptr == NULL)
    {
        return INVALID_AUTH;    // user doesnt exist
    }
    memcpy(&retrieved_uid, result.dptr, sizeof(retrieved_uid));

#ifdef __APPLE__
    strlcpy(retrieved_pass, (char *)result.dptr + sizeof(retrieved_uid), (size_t)result.dsize - sizeof(retrieved_uid));
#else
    strlcpy(retrieved_pass, result.dptr + sizeof(retrieved_uid), (size_t)result.dsize - sizeof(retrieved_uid));
#endif

    if(strcmp(password, retrieved_pass) != 0)
    {
        return INVALID_AUTH;    // wrong password
    }
    strlcpy(fd_map[fd].username, username, sizeof(fd_map[fd].username));
    fd_map[fd].uid = retrieved_uid;
    return 0;
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

int handle_chat(HandlerArgs *args, int fd)
{
    char        timestamp_buf[TIMESTAMP_BUFFER_SIZE];
    char        message_buf[MESSAGE_BUFFER_SIZE];
    char        username_buf[NAME_BUFFER_SIZE];
    char        header[HEADER_SIZE];
    char       *message;
    const char *payload_dup = args->payload_buffer;

    if(extract_chat_fields(args->hd, args->payload_buffer, timestamp_buf, message_buf, username_buf))
    {
        fprintf(stderr, "extract_chat_fields\n");
        send_sys_error(fd, P_BAD_REQUEST, P_BAD_REQUEST_MSG);
        return 0;
    }

    if(strcmp(username_buf, args->sd->fd_map[fd].username) != 0)
    {
        fprintf(stderr, "username not match\n");
        send_sys_error(fd, P_BAD_REQUEST, P_BAD_REQUEST_MSG);
        return 0;
    }

    pickle_header(header, args->hd);
    message = construct_message(header, payload_dup, HEADER_SIZE, args->hd->payload_len);
    if(message == NULL)
    {
        return 1;
    }

    for(nfds_t i = 0; i < args->sd->num_clients; i++)
    {
        int curr_client = args->sd->clients[i].fd;

        if(args->sd->fd_map[curr_client].uid != 0)
        {
            if(write_fully(curr_client, message, (size_t)HEADER_SIZE + args->hd->payload_len) == WRITE_ERROR)    // consider handling the other error types (not server errors)
            {
                fprintf(stderr, "Error forwarding chat message\n");
                free(message);
                return 1;
            }
        }
    }
    args->sd->num_messages++;

    free(message);
    return 0;
}

int extract_chat_fields(const HeaderData *hd, char *payload_buffer, char *timestamp_buf, char *message_buf, char *usr_buf)
{
    uint16_t byte_threshold;

    byte_threshold = hd->payload_len;

    if(extract_field(&payload_buffer, timestamp_buf, &byte_threshold, P_GENERALIZED_TIME))
    {
        return 1;    // bad request
    }

    if(is_valid_timestamp(timestamp_buf) == 0)
    {
        return 1;
    }

    if(extract_field(&payload_buffer, message_buf, &byte_threshold, P_UTF8STRING))
    {
        return 1;
    }

    if(extract_field(&payload_buffer, usr_buf, &byte_threshold, P_UTF8STRING))
    {
        return 1;
    }
    return 0;
}

int is_valid_timestamp(const char *timestamp)
{
    struct tm time = {0};
    char     *endptr;

    endptr = strptime(timestamp, "%Y%m%d%H%M%S", &time);
    if(endptr == NULL)
    {
        return 0;    // String does not contain timestamp
    }

    if(mktime(&time) == -1)
    {
        return 0;    // Impossible date
    }

    if(*endptr == 'Z')    // check if ending with Z
    {
        endptr++;
    }
    else
    {
        return 0;    // if not ending with Z, not formatted correctly
    }

    if(*endptr != '\0')
    {
        return 0;    // Reject extra characters after 'Z'
    }

    return 1;    // Valid timestamp
}
