#pragma once

#include <inttypes.h>
#include <stdlib.h>

typedef uint64_t    u64;
typedef uint32_t    u32;
typedef uint16_t    u16;
typedef uint8_t     u8;
typedef int64_t     s64;
typedef int32_t     s32;
typedef int16_t     s16;
typedef int8_t      s8;

typedef enum svc_err_t {
    ERR_OK          = 0,
    ERR_OPTS        = 1,
    ERR_INVALID     = 2,
} svc_err;

#define handle_error(string) do { \
        perror((string)); \
        exit(1); } while(0)
