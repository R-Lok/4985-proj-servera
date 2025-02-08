#ifndef DB_H
#define DB_H
#include <ndbm.h>

#ifdef __APPLE__
typedef size_t datum_size;
#else
typedef int datum_size;
#endif

#define TO_SIZE_T(x) ((size_t)(x))

typedef struct
{
    // cppcheck-suppress unusedStructMember
    const void *dptr;
    // cppcheck-suppress unusedStructMember
    datum_size dsize;
} const_datum;

#define MAKE_CONST_DATUM(str) ((const_datum){(str), (datum_size)strlen(str) + 1})
int   store_string(DBM *db, const char *key, const char *value);
int   store_int(DBM *db, const char *key, int value);
char *retrieve_string(DBM *db, const char *key);
int   retrieve_int(DBM *db, const char *key, int *result);

#endif
