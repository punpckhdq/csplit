#pragma once

#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifdef WIN32
#include <direct.h>
#else
#include <sys/stat.h>
#include <errno.h>
#include <linux/limits.h>
#endif

#ifdef WIN32
#define PACKED_STRUCT(_name) __pragma(pack(1)) struct _name
#define PACKED_UNION(_name) __pragma(pack(1)) union _name
#define NORETURN __declspec(noreturn)
#define mkdir(_path, _mode) _mkdir(_path)
#else
#define PACKED_STRUCT(_name) struct __attribute__((packed, aligned(1)))  _name
#define PACKED_UNION(_name) union __attribute__((packed, aligned(1))) _name
#define NORETURN __attribute__((noreturn))
#define _MAX_PATH PATH_MAX
#define __min(x, y) (((x) < (y)) ? (x) : (y))
#define __max(x, y) (((x) > (y)) ? (x) : (y))
#endif

#define COUNTOF(_x) (sizeof(_x)/sizeof(_x[0]))

#define STRINGIFY(x) STRINGIFY2(x)
#define STRINGIFY2(x) #x

struct contrib {
    uint32_t file_offset;
    uint32_t size;
    uint32_t flags;
    uint32_t module_index;
    uint32_t selection;
};

struct module {
    uint32_t index;
    char name[1024];
};

struct reloc {
    uint32_t source_file_offset;
    uint32_t target_file_offset;
    int32_t target_addend;
    bool is_relative;
};

struct split {
    uint32_t file_offset;
    char name[1024];
};

struct symbol {
    uint32_t file_offset;
    uint32_t flags;
    bool local;
    char name[1024];
};
