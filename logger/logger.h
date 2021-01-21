#ifndef LOGGER_H
#define LOGGER_H

#include <stdio.h>
#include <stdarg.h>
#include <stdint.h>
#include <string.h>

#define LOGGER_FILE "../log.txt"
#define FILE_LINE_SIZE 40 // file.c: 900
#define MODE_SIZE 10      // "[WARN] "
#define MSG_SIZE 100      // msg body 


typedef enum {
    INFO_MODE = 0,
    DEBUG_MODE,
    CHECK_MODE,
    WARN_MODE,
    ERROR_MODE
} LOG_MODE;


typedef struct __logger {
    LOG_MODE mode;
    FILE* log_file;
    unsigned char is_file_line_on :1,
                  spare:           7;
} LOGGER;

#define LOGGER_CALLOC() (logger_t*)calloc(1, sizeof(logger_t))

extern LOGGER logger;

int init_logger(const char*);

void _log(const char*, unsigned long, LOG_MODE, const char *, va_list);


//void INFO(const char *format, ...);
//void DEBUG(const char *format, ...);
//void CHECK(const char *format, ...);
//void WARN(const char *format, ...);
//void ERROR(const char *format, ...);

#define INFO(format, ...)  _log(__FILE__, __LINE__, INFO_MODE, format, __VA_ARGS__)
#define DEBUG(format, ...) _log(__FILE__, __LINE__, DEBUG_MODE, format, __VA_ARGS__)
#define CHECK(format, ...) _log(__FILE__, __LINE__, CHECK_MODE, format, __VA_ARGS__)
#define WARN(format, ...)  _log(__FILE__, __LINE__, WARN_MODE, format, __VA_ARGS__)
#define ERROR(format, ...) _log(__FILE__, __LINE__, ERROR_MODE, format, __VA_ARGS__)

#endif
