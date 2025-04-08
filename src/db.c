#include "../include/db.h"
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
    Stores a string value in the database under the given key.

    @param
    db: Pointer to the DBM database
    key: Key to store the value under
    value: String value to store

    @return
    0 on success, non-zero on failure
*/
int store_string(DBM *db, const char *key, const char *value)
{
    const_datum key_datum   = MAKE_CONST_DATUM(key);
    const_datum value_datum = MAKE_CONST_DATUM(value);

    return dbm_store(db, *(datum *)&key_datum, *(datum *)&value_datum, DBM_REPLACE);
}

/*
    Stores a 16-bit unsigned integer in the database under the given key.

    @param
    db: Pointer to the DBM database
    key: Key to store the value under
    value: 16-bit unsigned integer to store

    @return
    0 on success, non-zero on failure
*/
int store_uint16(DBM *db, const char *key, uint16_t value)
{
    const_datum key_datum = MAKE_CONST_DATUM(key);
    datum       value_datum;
    int         result;

    value_datum.dptr = (char *)malloc(TO_SIZE_T(sizeof(uint16_t)));

    if(value_datum.dptr == NULL)
    {
        return -1;
    }

    memcpy(value_datum.dptr, &value, sizeof(uint16_t));
    value_datum.dsize = sizeof(uint16_t);

    result = dbm_store(db, *(datum *)&key_datum, value_datum, DBM_REPLACE);

    free(value_datum.dptr);
    return result;
}

/*
    Retrieves a string from the database by key.

    @param
    db: Pointer to the DBM database
    key: Key associated with the value to retrieve

    @return
    String value on success, NULL on failure
*/
char *retrieve_string(DBM *db, const char *key)
{
    const_datum key_datum;
    datum       result;
    char       *retrieved_str;

    key_datum = MAKE_CONST_DATUM(key);

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Waggregate-return"
    result = dbm_fetch(db, *(datum *)&key_datum);
#pragma GCC diagnostic pop

    if(result.dptr == NULL)
    {
        return NULL;
    }

    retrieved_str = (char *)malloc(TO_SIZE_T(result.dsize));

    if(!retrieved_str)
    {
        return NULL;
    }

    memcpy(retrieved_str, result.dptr, TO_SIZE_T(result.dsize));

    return retrieved_str;
}

/*
    Retrieves a uint16_t from the database by key.

    @param
    db: Pointer to the DBM database
    key: Key associated with the value to retrieve
    result: Output pointer to store the retrieved value

    @return
    0 on success, -1 on failure
*/
int retrieve_uint16(DBM *db, const char *key, uint16_t *result)
{
    datum       fetched;
    const_datum key_datum = MAKE_CONST_DATUM(key);

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Waggregate-return"
    fetched = dbm_fetch(db, *(datum *)&key_datum);
#pragma GCC diagnostic pop

    if(fetched.dptr == NULL || fetched.dsize != sizeof(uint16_t))
    {
        return -1;
    }

    memcpy(result, fetched.dptr, sizeof(uint16_t));

    return 0;
}
