#include "../include/db.h"
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int store_string(DBM *db, const char *key, const char *value)
{
    const_datum key_datum   = MAKE_CONST_DATUM(key);
    const_datum value_datum = MAKE_CONST_DATUM(value);

    return dbm_store(db, *(datum *)&key_datum, *(datum *)&value_datum, DBM_REPLACE);
}

int store_int(DBM *db, const char *key, int value)
{
    const_datum key_datum = MAKE_CONST_DATUM(key);
    datum       value_datum;
    int         result;

    value_datum.dptr = (char *)malloc(TO_SIZE_T(sizeof(int)));

    if(value_datum.dptr == NULL)
    {
        return -1;
    }

    memcpy(value_datum.dptr, &value, sizeof(int));
    value_datum.dsize = sizeof(int);

    result = dbm_store(db, *(datum *)&key_datum, value_datum, DBM_REPLACE);

    free(value_datum.dptr);
    return result;
}

// **Function to retrieve a string**
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

// **Function to retrieve an integer**
int retrieve_int(DBM *db, const char *key, int *result)
{
    datum       fetched;
    const_datum key_datum = MAKE_CONST_DATUM(key);

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Waggregate-return"
    fetched = dbm_fetch(db, *(datum *)&key_datum);
#pragma GCC diagnostic pop

    if(fetched.dptr == NULL || fetched.dsize != sizeof(int))
    {
        return -1;
    }

    memcpy(result, fetched.dptr, sizeof(int));

    return 0;
}
