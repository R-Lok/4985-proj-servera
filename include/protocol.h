#ifndef PROTOCOL_H
#define PROTOCOL_H

/*Client and Server Packet types*/
// #define SYS_SUCCESS 0
// #define SYS_ERROR 1
// #define ACC_LOGIN 10 //User request to log in
// #define ACC_LOGIN_SUCCESS 11 //System response that log in was successful
// #define ACC_LOGOUT 12 //User request to log out
// #define ACC_CREATE 13

/*Server-Client Error codes*/
// #define INVALID_USER_ID 11
// #define INVALID_AUTH_INFO 12
// #define USER_EXISTS 13 //If signing up with taken name
// #define SERVER_FAILURE 21 //if server has error and cannot fulfill the request

/*BER Tags (P prefix to not confuse with any C reserved keywords)*/
// #define P_BOOLEAN 1
// #define P_INTEGER 2
// #define P_NULL 5
// #define P_ENUMERATED 10
// #define P_UTF8STRING 12
// #define P_SEQUENCE 16
// #define P_PRINTABLESTRING 19
// #define P_UTC_TIME 23
// #define P_GENERALIZED_TIME 24

#endif
