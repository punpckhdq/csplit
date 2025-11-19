#pragma once

#include <assert.h>
#include <direct.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define PACKED __pragma(pack(1))
#define NORETURN __declspec(noreturn)

#define COUNTOF(_x) (sizeof(_x)/sizeof(_x[0]))

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
