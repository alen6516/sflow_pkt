#ifndef UTIL_H
#define UTIL_H

#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>

typedef unsigned char  u8;
typedef unsigned short u16;
typedef unsigned int   u32;
typedef unsigned long  u64;

/*
 * calloc for type TYPE
 * specify allocate size by size, if size == 0, then use sizeof(TYPE)
 * exit() if fail to allocate
 */
#define CALLOC_EXIT_ON_FAIL(TYPE, ptr, size) ({                         \
    ptr = (TYPE *) calloc(1, ((size) == 0) ? sizeof(TYPE) : (size));    \
    if (NULL == ptr) {                                                  \
        printf("Calloc fail\n");                                        \
        err_exit(MALLOC_FAIL);                                          \
    }                                                                   \
})


typedef enum {
    DEFAULT_FAIL = 1,
    MALLOC_FAIL,
    PARSE_ARG_FAIL,
    CONNECT_FAIL
} fail_e;


static inline void err_exit(fail_e reason)
{
    switch (reason) {
        case DEFAULT_FAIL:
            break;
        case MALLOC_FAIL:
            printf("malloc fail, exit\n");
            break;
        case PARSE_ARG_FAIL:
            printf("parse arg fail, exit\n");
            break;
        case CONNECT_FAIL:
            printf("connect fail, exit\n");
            break;
        default:
            printf("no such fail reason\n");
            break;
    }
    exit(1);
}

#endif
