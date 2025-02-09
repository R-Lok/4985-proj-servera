#ifndef DB_H
#define DB_H
#include <inttypes.h>
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
int   store_uint8(DBM *db, const char *key, uint8_t value);
char *retrieve_string(DBM *db, const char *key);
int   retrieve_uint8(DBM *db, const char *key, uint8_t *result);

#endif
