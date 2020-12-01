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

#endif
