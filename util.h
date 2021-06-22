#ifndef UTIL_H
#define UTIL_H

#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>

typedef unsigned char  u8;
typedef unsigned short u16;
typedef unsigned int   u32;
typedef unsigned long  u64;

#define SIZE_OF_ARR(arr) ((int)(sizeof(arr)/sizeof(arr[0])))

// simple debug print
#ifdef DEBUG
#define debug_printf(...) ((    \
        printf(__VA_ARGS__);    \
})
#else
#define debug_printf(...)
#endif

// when condition occur, we must exit, but we don't want to
#define ASSERT_WARN(con, msg) do {                      \
    if (!!(con)==0) {                                   \
        printf("[ASSERT WARN] %s", (msg))               \
    }                                                   \
} while (0)

// when condition occur, we must exit immidiately
#define ASSERT_EXIT(con, msg) do {                      \
    if (!!(con)==0) {                                   \
        printf("[ASSERT EXIT] %s\n", msg);              \
        exit(-1);                                       \
    }                                                   \
} while(0)


// error enum
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

#define CALLOC_EXIT_ON_FAIL(TYPE, ptr, size) do {       \
    ptr = (TYPE*) calloc(                               \
            ((size) == 0) ? sizeof(TYPE) : (size),      \
            1);                                         \
    if (!ptr) {                                         \
        err_exit(MALLOC_FAIL);                          \
    }                                                   \
} while(0)
#endif
