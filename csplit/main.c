#include "csplit.h"
#include "cJSON.h"

enum exitCode {
    EXIT_USAGE = EXIT_FAILURE,
    EXIT_INVALID_MODULE,
    EXIT_FILE_IO,
    EXIT_MALLOC_FAILED,
    EXIT_OOB,
    EXIT_INVALID_JSON,
};

// packed file data (sorry big-endian users)

PACKED
struct COFFFileHeader {
    uint16_t machine;
    uint16_t number_of_sections;
    uint32_t time_date_stamp;
    uint32_t pointer_to_symbol_table;
    uint32_t number_of_symbols;
    uint16_t size_of_optional_header;
    uint16_t characteristics;
};

PACKED
struct COFFSectionHeader {
    char name[8];
    uint32_t virtual_size;
    uint32_t virtual_address;
    uint32_t size_of_raw_data;
    uint32_t pointer_to_raw_data;
    uint32_t pointer_to_relocations;
    uint32_t pointer_to_line_numbers;
    uint16_t number_of_relocations;
    uint16_t number_of_line_numbers;
    uint32_t characteristics;
};

PACKED
struct COFFRelocation {
    uint32_t virtual_address;
    uint32_t symbol_table_index;
    uint16_t type;
};

PACKED
union COFFSymbolName {
    char name[8];
    struct {
        uint32_t zeroes;
        uint32_t offset;
    } extension;
};

PACKED
union COFFSymbol {
    struct {
        union COFFSymbolName name;
        uint32_t value;
        uint16_t section_number;
        uint16_t type;
        uint8_t  storage_class;
        uint8_t  number_of_aux_symbols;
    } symbol;
    struct {
        uint32_t tag_index;
        uint32_t total_size;
        uint32_t pointer_to_line_number;
        uint32_t pointer_to_next_function;
        uint16_t unused1;
    } function_definition;
    struct {
        uint32_t unused2;
        uint16_t line_number;
        uint8_t	 unused3[6];
        uint32_t pointer_to_next_function;
        uint16_t unused4;
    } bf_ef_symbol;
    struct {
        uint32_t tag_index;
        uint32_t characteristics;
        uint8_t  unused5[10];
    } weak_external;
    struct {
        char file_name[18];
    } file;
    struct {
        uint32_t length;
        uint16_t number_of_relocations;
        uint16_t number_of_line_numbers;
        uint32_t checksum;
        uint16_t number;
        uint8_t  selection;
        uint8_t  unused6[3];
    } section_definition;
};

// state tracking structures

struct COFFRelocState {
    uint32_t symbol_index;
    struct COFFRelocation reloc;
};

struct COFFSectionState {
    uint32_t contrib_index;
    struct COFFSectionHeader header;
    void* data;
    struct COFFRelocState relocs[2048];
    uint32_t reloc_count;
};

struct COFFBreadcrumbState {
    uint32_t global_symbol_index;
    uint32_t symbol_index;
};

struct COFFState {
    struct COFFSectionState* sections;
    uint32_t section_count;
    uint32_t section_capacity;

    union COFFSymbol symbols[8192];
    uint32_t symbol_count;

    struct COFFBreadcrumbState breadcrumbs[8192];
    uint32_t breadcrumb_count;

    char string_table[1048576];
    uint32_t string_table_length;
};

struct projectState {
    struct contrib* contribs;
    uint32_t contrib_count;

    struct module* modules;
    uint32_t module_count;

    struct reloc* relocs;
    uint32_t reloc_count;

    struct split* splits;
    uint32_t split_count;

    struct symbol* symbols;
    uint32_t symbol_count;
};

struct mainState {
    const struct projectState* project;
    const uint8_t* input_file_data;
    const char* output_dir_path;
    bool verbose;
};

NORETURN
void die(
    int code,
    const char *format,
    ...) {
    char buffer[4096] = { 0 };
    va_list args = NULL;
    va_start(args, format);
    vsnprintf(buffer, COUNTOF(buffer), format, args);
    va_end(args);

    fputs(buffer, stderr);

    exit(code);
}

#define CHECK(_x, _code, _format, ...) do { if (!(_x)) { die(_code, _format, __VA_ARGS__); } } while(false)

struct COFFState* coff_new(
    void) {
    struct COFFState* state = malloc(sizeof(*state));
    CHECK(state != NULL, EXIT_MALLOC_FAILED, "out of memory");
    state->sections = NULL;
    state->section_count = 0;
    state->section_capacity = 0;
    state->symbol_count = 0;
    state->breadcrumb_count = 0;
    state->string_table_length = 0;
    return state;
}

void coff_cleanup(
    struct COFFState* state) {
    for (uint32_t i = 0; i < state->section_count; i++) {
        struct COFFSectionState* section = &state->sections[i];
        if (section->data != NULL) {
            free(section->data);
        }
    }
    free(state->sections);
    free(state);
}

uint32_t coff_add_reloc(
    struct COFFSectionState* state) {
    CHECK(state->reloc_count < COUNTOF(state->relocs), EXIT_OOB, "out of relocs");
    return state->reloc_count++;
}

uint32_t coff_add_section(
    struct COFFState* state) {
    if (state->section_count == state->section_capacity) {
        state->section_capacity = __max(64, state->section_capacity * 2);
        state->sections = realloc(state->sections, state->section_capacity * sizeof(state->sections[0]));
        CHECK(state->sections != NULL, EXIT_MALLOC_FAILED, "out of memory");
    }
    return state->section_count++;
}

uint32_t coff_add_symbol(
    struct COFFState* state) {
    CHECK(state->symbol_count < COUNTOF(state->symbols), EXIT_OOB, "out of symbols");
    return state->symbol_count++;
}

uint32_t coff_add_breadcrumb(
    struct COFFState* state) {
    CHECK(state->breadcrumb_count < COUNTOF(state->breadcrumbs), EXIT_OOB, "out of breadcrumbs");
    return state->breadcrumb_count++;
}

uint32_t coff_add_string(
    struct COFFState* state,
    const char* string,
    size_t string_length) {
    size_t num_bytes = string_length + 1;
    uint32_t old_length = state->string_table_length;
    uint32_t new_length = old_length + (uint32_t)num_bytes;

    CHECK(new_length <= COUNTOF(state->string_table), EXIT_OOB, "out of string table space");
    state->string_table_length = new_length;
    memcpy(&state->string_table[old_length], string, num_bytes);

    // all string table positions count the size dword
    return old_length + 4;
}

void coff_set_symbol_name(
    struct COFFState* state,
    union COFFSymbolName* name,
    const char* string) {
    size_t string_length = strlen(string);

    if (string_length <= 8) {
        memset(name->name, 0, sizeof(name->name));
        memcpy(name->name, string, string_length);
    } else {
        name->extension.zeroes = 0;
        name->extension.offset = coff_add_string(state, string, string_length);
    }
}

void coff_write(
    struct COFFState* state,
    const char* file_path) {
    FILE* fp = fopen(file_path, "wb");
    CHECK(fp != NULL, EXIT_FILE_IO, "couldn't open %s", file_path);

    struct COFFFileHeader file_header;
    file_header.machine                 = 0x14c;
    file_header.number_of_sections      = state->section_count;
    file_header.time_date_stamp         = (uint32_t)-1;
    file_header.number_of_symbols       = state->symbol_count;
    file_header.size_of_optional_header = 0;
    file_header.characteristics         = 0;

    size_t next_free_byte = sizeof(file_header) + sizeof(struct COFFSectionHeader) * state->section_count;

    // tally section sizes

    for (uint32_t i = 0; i < state->section_count; i++) {
        struct COFFSectionState* section = &state->sections[i];

        section->header.pointer_to_raw_data = (uint32_t)next_free_byte;
        next_free_byte += section->header.size_of_raw_data;

        section->header.pointer_to_relocations = (uint32_t)next_free_byte;
        next_free_byte += section->header.number_of_relocations * sizeof(struct COFFRelocation);
    }

    // write header

    file_header.pointer_to_symbol_table = (uint32_t)next_free_byte;

    fwrite(&file_header, sizeof(file_header), 1, fp);

    // write section headers

    for (uint32_t i = 0; i < state->section_count; i++) {
        struct COFFSectionState* section = &state->sections[i];

        fwrite(&section->header, sizeof(section->header), 1 , fp);
    }

    // write section data

    for (uint32_t i = 0; i < state->section_count; i++) {
        struct COFFSectionState* section = &state->sections[i];

        fwrite(section->data, 1, section->header.size_of_raw_data, fp);

        for (uint32_t j = 0; j < section->reloc_count; j++) {
            struct COFFRelocState* reloc = &section->relocs[j];

            fwrite(&reloc->reloc, sizeof(reloc->reloc), 1, fp);
        }
    }

    // write everything else

    fwrite(state->symbols, sizeof(state->symbols[0]), state->symbol_count, fp);
    uint32_t string_table_length = state->string_table_length + 4;
    fwrite(&string_table_length, sizeof(string_table_length), 1, fp);
    fwrite(state->string_table, 1, state->string_table_length, fp);

    fclose(fp);
}

void do_file_symbols(
    struct COFFState* state,
    const char* string) {
    size_t string_length = strlen(string) + 1;
    uint8_t number_of_aux_symbols =
        (uint8_t)__max((string_length + sizeof(union COFFSymbol) - 1) / sizeof(union COFFSymbol), 1);

    uint32_t symbol_index = coff_add_symbol(state);
    union COFFSymbol* symbol = &state->symbols[symbol_index];

    coff_set_symbol_name(state, &symbol->symbol.name, ".file");
    symbol->symbol.value = 0;
    symbol->symbol.section_number = (uint16_t)-2;
    symbol->symbol.type = 0;
    symbol->symbol.storage_class = 103;
    symbol->symbol.number_of_aux_symbols = number_of_aux_symbols;

    CHECK(state->symbol_count + number_of_aux_symbols < COUNTOF(state->symbols), EXIT_OOB, "out of symbols");
    state->symbol_count += number_of_aux_symbols;

    union COFFSymbol* aux_symbols = &state->symbols[symbol_index + 1];
    memset(aux_symbols, 0, sizeof(aux_symbols[0]) * number_of_aux_symbols);
    memcpy(aux_symbols, string, string_length);
}

void do_section_symbols(
    struct COFFState* state,
    struct COFFSectionState* section,
    uint32_t section_index,
    const char* section_name,
    uint32_t selection) {
    uint32_t section_symbol_index = coff_add_symbol(state);
    union COFFSymbol* section_symbol = &state->symbols[section_symbol_index];

    coff_set_symbol_name(state, &section_symbol->symbol.name, section_name);
    section_symbol->symbol.value = 0;
    section_symbol->symbol.section_number = section_index + 1;
    section_symbol->symbol.type = 0;
    section_symbol->symbol.storage_class = 3;
    section_symbol->symbol.number_of_aux_symbols = 1;

    uint32_t section_aux_symbol_index = coff_add_symbol(state);
    union COFFSymbol* section_aux_symbol = &state->symbols[section_aux_symbol_index];

    section_aux_symbol->section_definition.length = section->header.size_of_raw_data;
    section_aux_symbol->section_definition.number_of_relocations = section->header.number_of_relocations;
    section_aux_symbol->section_definition.number_of_line_numbers = 0;
    section_aux_symbol->section_definition.checksum = 0;
    section_aux_symbol->section_definition.number = section_index + 1;
    section_aux_symbol->section_definition.selection = selection;
    memset(section_aux_symbol->section_definition.unused6,
        0,
        sizeof(section_aux_symbol->section_definition.unused6));
}

void do_module(
    const struct mainState* state,
    const struct module* module) {
    if (state->verbose) {
        printf("%04" PRIx32 " %s\n", module->index, module->name);
    }

    const struct projectState* project = state->project;

    uint32_t* contrib_indices = malloc(sizeof(contrib_indices[0]) * project->contrib_count);
    CHECK(contrib_indices != NULL, EXIT_MALLOC_FAILED, "out of memory");
    uint32_t contrib_count = 0;
    for (uint32_t i = 0; i < project->contrib_count; i++) {
        const struct contrib* contrib = &project->contribs[i];
        if (contrib->module_index == module->index) {
            contrib_indices[contrib_count++] = i;
        }
    }

    struct COFFState* coff = coff_new();

    // create file symbols

    do_file_symbols(coff, module->name);

    // create sections and symbols

    for (uint32_t i = 0; i < contrib_count; i++) {
        uint32_t contrib_index = contrib_indices[i];
        const struct contrib* contrib = &project->contribs[contrib_index];

        const char* section_name = NULL;
        for (uint32_t j = project->split_count; j > 0; j--) {
            const struct split* split = &project->splits[j - 1];
            if (contrib->file_offset >= split->file_offset) {
                section_name = split->name;
                break;
            }
        }

        // read in data

        uint8_t* raw_data = malloc(contrib->size);
        memcpy(raw_data, &state->input_file_data[contrib->file_offset], contrib->size);

        // create section

        uint32_t section_index = coff_add_section(coff);
        struct COFFSectionState* section = &coff->sections[section_index];

        section->contrib_index = contrib_index;
        section->data = raw_data;
        section->reloc_count = 0;

        // find relocations

        uint32_t reloc_count = 0;
        for (uint32_t j = 0; j < project->reloc_count; j++) {
            const struct reloc* reloc = &project->relocs[j];
            if (reloc->source_file_offset >= contrib->file_offset &&
                reloc->source_file_offset < contrib->file_offset + contrib->size) {
                // find the target symbol

                uint32_t target_symbol_index = 0;
                uint32_t target_symbol_offset = 0;
                for (uint32_t k = project->symbol_count; k > 0; k--) {
                    uint32_t symbol_index = k - 1;
                    const struct symbol* symbol = &project->symbols[symbol_index];
                    if (reloc->target_file_offset >= symbol->file_offset) {
                        target_symbol_index = symbol_index;
                        target_symbol_offset = reloc->target_file_offset - symbol->file_offset;
                        break;
                    }
                }

                // register reloc in list

                uint32_t section_reloc_index = coff_add_reloc(section);
                struct COFFRelocState* section_reloc = &section->relocs[section_reloc_index];
                section_reloc->symbol_index = target_symbol_index;

                uint32_t reloc_offset = reloc->source_file_offset - contrib->file_offset;
                section_reloc->reloc.virtual_address = reloc_offset;

                // set pointer in section contents

                uint32_t* pointer = (uint32_t*)(raw_data + reloc_offset);
                if (reloc->is_relative) {
                    section_reloc->reloc.type = 20;
                    *pointer = target_symbol_offset;
                } else {
                    section_reloc->reloc.type = 6;
                    *pointer = target_symbol_offset + reloc->target_addend;
                }

                reloc_count++;
            }
        }

        // populate section header

        size_t section_name_length = strlen(section_name);
        if (section_name_length <= 8) {
            memset(section->header.name, 0, sizeof(section->header.name));
            memcpy(section->header.name, section_name, section_name_length);
        } else {
            uint32_t string_table_offset = coff_add_string(coff, section_name, section_name_length);
            snprintf(section->header.name, COUNTOF(section->header.name), "/%" PRIu16, string_table_offset);
        }

        section->header.virtual_size = 0;
        section->header.virtual_address = 0;
        section->header.size_of_raw_data = contrib->size;
        section->header.pointer_to_line_numbers = 0;
        section->header.number_of_relocations = (uint16_t)reloc_count;
        section->header.number_of_line_numbers = 0;
        section->header.characteristics = contrib->flags;

        // create section symbols

        do_section_symbols(coff, section, section_index, section_name, contrib->selection);

        // create contrib symbols

        for (uint32_t j = 0; j < project->symbol_count; j++) {
            const struct symbol* symbol = &project->symbols[j];
            if (symbol->file_offset >= contrib->file_offset &&
                symbol->file_offset < contrib->file_offset + contrib->size) {
                uint32_t symbol_offset = symbol->file_offset - contrib->file_offset;

                uint32_t coff_symbol_index = coff_add_symbol(coff);
                union COFFSymbol* coff_symbol = &coff->symbols[coff_symbol_index];

                coff_set_symbol_name(coff, &coff_symbol->symbol.name, symbol->name);
                coff_symbol->symbol.value = symbol_offset;
                coff_symbol->symbol.section_number = section_index + 1;
                coff_symbol->symbol.type = contrib->flags & 0x20;
                coff_symbol->symbol.storage_class = 2;
                coff_symbol->symbol.number_of_aux_symbols = 0;
                
                // create breadcrumb
                
                uint32_t breadcrumb_index = coff_add_breadcrumb(coff);
                struct COFFBreadcrumbState* breadcrumb = &coff->breadcrumbs[breadcrumb_index];

                breadcrumb->global_symbol_index = j;
                breadcrumb->symbol_index = coff_symbol_index;
            }
        }
    }

    // resolve all relocations

    for (uint32_t i = 0; i < coff->section_count; i++) {
        struct COFFSectionState* section = &coff->sections[i];
        for (uint32_t j = 0; j < section->reloc_count; j++) {
            struct COFFRelocState* reloc = &section->relocs[j];

            // try find pre-existing symbol first

            struct COFFBreadcrumbState* found_breadcrumb = NULL;

            for (uint32_t k = 0; k < coff->breadcrumb_count; k++) {
                struct COFFBreadcrumbState* breadcrumb = &coff->breadcrumbs[k];
                if (breadcrumb->global_symbol_index == reloc->symbol_index) {
                    found_breadcrumb = breadcrumb;
                    break;
                }
            }

            if (found_breadcrumb == NULL) {
                const struct symbol* symbol = &project->symbols[reloc->symbol_index];

                // create extern symbol

                uint32_t extern_symbol_index = coff_add_symbol(coff);
                union COFFSymbol* extern_symbol = &coff->symbols[extern_symbol_index];

                coff_set_symbol_name(coff, &extern_symbol->symbol.name, symbol->name);
                extern_symbol->symbol.value = 0;
                extern_symbol->symbol.section_number = 0;
                extern_symbol->symbol.type = symbol->flags & 0x20;
                extern_symbol->symbol.storage_class = 2;
                extern_symbol->symbol.number_of_aux_symbols = 0;

                // create breadcrumb

                uint32_t breadcrumb_index = coff_add_breadcrumb(coff);
                found_breadcrumb = &coff->breadcrumbs[breadcrumb_index];

                found_breadcrumb->global_symbol_index = reloc->symbol_index;
                found_breadcrumb->symbol_index = extern_symbol_index;
            }

            reloc->reloc.symbol_table_index = found_breadcrumb->symbol_index;
        }
    }

    char output_file_path[_MAX_PATH] = { 0 };
    snprintf(output_file_path, COUNTOF(output_file_path), "%s/%s",
        state->output_dir_path,
        module->name);
    coff_write(coff, output_file_path);

    coff_cleanup(coff);

    free(contrib_indices);
}

uint8_t* read_file(
    const char *file_path,
    uint32_t* file_size_out) {
    FILE* fp = fopen(file_path, "rb");
    CHECK(fp != NULL, EXIT_FILE_IO, "couldn't open %s", file_path);

    CHECK(fseek(fp, 0, SEEK_END) == 0, EXIT_FILE_IO, "couldn't stat %s", file_path);

    int32_t file_size = ftell(fp);
    CHECK(file_size > 0, EXIT_FILE_IO, "couldn't stat %s", file_path);
    if (file_size_out != NULL) {
        *file_size_out = file_size;
    }

    CHECK(fseek(fp, 0, SEEK_SET) == 0, EXIT_FILE_IO, "couldn't stat %s", file_path);

    uint8_t* file = malloc(file_size);
    CHECK(file != NULL, EXIT_MALLOC_FAILED, "out of memory");

    int32_t bytes_read = fread(file, 1, file_size, fp);
    CHECK(bytes_read == file_size, EXIT_FILE_IO, "couldn't read %s", file_path);

    fclose(fp);

    return file;
}

void project_parse_splits(
    struct projectState* state,
    const cJSON* json) {
    int32_t split_count = (uint32_t)cJSON_GetArraySize(json);
    CHECK(split_count > 0, EXIT_INVALID_JSON, "no splits or invalid object type");

    struct split* splits = malloc(sizeof(splits[0]) * split_count);
    CHECK(splits != NULL, EXIT_MALLOC_FAILED, "out of memory");

    state->splits = splits;
    state->split_count = split_count;

    uint32_t split_index = 0;
    const cJSON* split_json = NULL;
    cJSON_ArrayForEach(split_json, json) {
        CHECK(split_index < split_count, EXIT_INVALID_JSON, "splits exceeded allocated count");
        struct split* split = &splits[split_index++];

        cJSON* json_file_offset = cJSON_GetObjectItemCaseSensitive(split_json, "file_offset");
        CHECK(cJSON_IsNumber(json_file_offset), EXIT_FAILURE, "split #%" PRIu32 ": invalid file_offset", split_index);

        cJSON* json_name = cJSON_GetObjectItemCaseSensitive(split_json, "name");
        CHECK(cJSON_IsString(json_name), EXIT_FAILURE, "split #%" PRIu32 ": invalid name", split_index);

        split->file_offset = (uint32_t)json_file_offset->valueint;
        strncpy(split->name, json_name->valuestring, COUNTOF(split->name) - 1);
        split->name[COUNTOF(split->name) - 1] = '\0';
    }
}

void project_parse_modules(
    struct projectState* state,
    const cJSON* json) {
    int32_t module_count = (uint32_t)cJSON_GetArraySize(json);
    CHECK(module_count > 0, EXIT_INVALID_JSON, "no modules or invalid object type");

    struct module* modules = malloc(sizeof(modules[0]) * module_count);
    CHECK(modules != NULL, EXIT_MALLOC_FAILED, "out of memory");

    state->modules = modules;
    state->module_count = module_count;

    uint32_t module_index = 0;
    const cJSON* module_json = NULL;
    cJSON_ArrayForEach(module_json, json) {
        CHECK(module_index < module_count, EXIT_INVALID_JSON, "modules exceeded allocated count");
        struct module* module = &modules[module_index++];

        cJSON* json_index = cJSON_GetObjectItemCaseSensitive(module_json, "index");
        CHECK(cJSON_IsNumber(json_index), EXIT_FAILURE, "module #%" PRIu32 ": invalid index", module_index);

        cJSON* json_name = cJSON_GetObjectItemCaseSensitive(module_json, "name");
        CHECK(cJSON_IsString(json_name), EXIT_FAILURE, "module #%" PRIu32 ": invalid name", module_index);

        module->index = (uint32_t)json_index->valueint;
        strncpy(module->name, json_name->valuestring, COUNTOF(module->name) - 1);
        module->name[COUNTOF(module->name) - 1] = '\0';
    }
}

void project_parse_symbols(
    struct projectState* state,
    const cJSON* json) {
    int32_t symbol_count = (uint32_t)cJSON_GetArraySize(json);
    CHECK(symbol_count > 0, EXIT_INVALID_JSON, "no symbols or invalid object type");

    struct symbol* symbols = malloc(sizeof(symbols[0]) * symbol_count);
    CHECK(symbols != NULL, EXIT_MALLOC_FAILED, "out of memory");

    state->symbols = symbols;
    state->symbol_count = symbol_count;

    uint32_t symbol_index = 0;
    const cJSON* symbol_json = NULL;
    cJSON_ArrayForEach(symbol_json, json) {
        CHECK(symbol_index < symbol_count, EXIT_INVALID_JSON, "symbols exceeded allocated count");
        struct symbol* symbol = &symbols[symbol_index++];

        cJSON* json_file_offset = cJSON_GetObjectItemCaseSensitive(symbol_json, "file_offset");
        CHECK(cJSON_IsNumber(json_file_offset), EXIT_FAILURE, "symbol #%" PRIu32 ": invalid file_offset", symbol_index);

        cJSON* json_flags = cJSON_GetObjectItemCaseSensitive(symbol_json, "flags");
        CHECK(cJSON_IsNumber(json_flags), EXIT_FAILURE, "symbol #%" PRIu32 ": invalid flags", symbol_index);

        cJSON* json_name = cJSON_GetObjectItemCaseSensitive(symbol_json, "name");
        CHECK(cJSON_IsString(json_name), EXIT_FAILURE, "symbol #%" PRIu32 ": invalid name", symbol_index);

        symbol->file_offset = (uint32_t)json_file_offset->valueint;
        symbol->flags = (uint32_t)json_flags->valueint;
        strncpy(symbol->name, json_name->valuestring, COUNTOF(symbol->name) - 1);
        symbol->name[COUNTOF(symbol->name) - 1] = '\0';
    }
}

void project_parse_contribs(
    struct projectState* state,
    const cJSON* json) {
    int32_t contrib_count = (uint32_t)cJSON_GetArraySize(json);
    CHECK(contrib_count > 0, EXIT_INVALID_JSON, "no contribs or invalid object type");

    struct contrib* contribs = malloc(sizeof(contribs[0]) * contrib_count);
    CHECK(contribs != NULL, EXIT_MALLOC_FAILED, "out of memory");

    state->contribs = contribs;
    state->contrib_count = contrib_count;

    uint32_t contrib_index = 0;
    const cJSON* contrib_json = NULL;
    cJSON_ArrayForEach(contrib_json, json) {
        CHECK(contrib_index < contrib_count, EXIT_INVALID_JSON, "contribs exceeded allocated count");
        struct contrib* contrib = &contribs[contrib_index++];

        cJSON* json_file_offset = cJSON_GetObjectItemCaseSensitive(contrib_json, "file_offset");
        CHECK(cJSON_IsNumber(json_file_offset), EXIT_FAILURE, "contrib #%" PRIu32 ": invalid file_offset", contrib_index);

        cJSON* json_size = cJSON_GetObjectItemCaseSensitive(contrib_json, "size");
        CHECK(cJSON_IsNumber(json_size), EXIT_FAILURE, "contrib #%" PRIu32 ": invalid size", contrib_index);

        cJSON* json_flags = cJSON_GetObjectItemCaseSensitive(contrib_json, "flags");
        CHECK(cJSON_IsNumber(json_flags), EXIT_FAILURE, "contrib #%" PRIu32 ": invalid flags", contrib_index);

        cJSON* json_module_index = cJSON_GetObjectItemCaseSensitive(contrib_json, "module_index");
        CHECK(cJSON_IsNumber(json_module_index), EXIT_FAILURE, "module #%" PRIu32 ": invalid module_index", contrib_index);

        cJSON* json_selection = cJSON_GetObjectItemCaseSensitive(contrib_json, "selection");
        CHECK(cJSON_IsNumber(json_selection), EXIT_FAILURE, "module #%" PRIu32 ": invalid selection", contrib_index);

        contrib->file_offset = (uint32_t)json_file_offset->valueint;
        contrib->size = (uint32_t)json_size->valueint;
        contrib->flags = (uint32_t)json_flags->valueint;
        contrib->module_index = (uint32_t)json_module_index->valueint;
        contrib->selection = (uint32_t)json_selection->valueint;
    }
}

void project_parse_relocs(
    struct projectState* state,
    const cJSON* json) {
    int32_t reloc_count = (uint32_t)cJSON_GetArraySize(json);
    CHECK(reloc_count > 0, EXIT_INVALID_JSON, "no relocs or invalid object type");

    struct reloc* relocs = malloc(sizeof(relocs[0]) * reloc_count);
    CHECK(relocs != NULL, EXIT_MALLOC_FAILED, "out of memory");

    state->relocs = relocs;
    state->reloc_count = reloc_count;

    uint32_t reloc_index = 0;
    const cJSON* reloc_json = NULL;
    cJSON_ArrayForEach(reloc_json, json) {
        CHECK(reloc_index < reloc_count, EXIT_INVALID_JSON, "relocs exceeded allocated count");
        struct reloc* reloc = &relocs[reloc_index++];

        cJSON* json_source_file_offset = cJSON_GetObjectItemCaseSensitive(reloc_json, "source_file_offset");
        CHECK(cJSON_IsNumber(json_source_file_offset), EXIT_FAILURE, "reloc #%" PRIu32 ": invalid source_file_offset", reloc_index);

        cJSON* json_target_file_offset = cJSON_GetObjectItemCaseSensitive(reloc_json, "target_file_offset");
        CHECK(cJSON_IsNumber(json_target_file_offset), EXIT_FAILURE, "reloc #%" PRIu32 ": invalid target_file_offset", reloc_index);

        cJSON* json_target_addend = cJSON_GetObjectItemCaseSensitive(reloc_json, "target_addend");
        CHECK(cJSON_IsNumber(json_target_addend), EXIT_FAILURE, "reloc #%" PRIu32 ": invalid target_addend", reloc_index);

        cJSON* json_is_relative = cJSON_GetObjectItemCaseSensitive(reloc_json, "is_relative");
        CHECK(cJSON_IsBool(json_is_relative), EXIT_FAILURE, "reloc #%" PRIu32 ": invalid is_relative", reloc_index);

        reloc->source_file_offset = (uint32_t)json_source_file_offset->valueint;
        reloc->target_file_offset = (uint32_t)json_target_file_offset->valueint;
        reloc->target_addend = (int32_t)json_target_addend->valueint;
        reloc->is_relative = (bool)json_is_relative->valueint;
    }
}

struct projectState* project_new_from_dir(
    const char* project_dir_path) {
    struct projectState* state = malloc(sizeof(*state));
    CHECK(state != NULL, EXIT_MALLOC_FAILED, "out of memory");

    const struct projectJsonHandler {
        const char* document_name;
        void (*parse_function)(struct projectState*, const cJSON*);
    } project_json_documents[] = {
        { "splits", project_parse_splits },
        { "modules", project_parse_modules },
        { "symbols", project_parse_symbols },
        { "contribs", project_parse_contribs },
        { "relocs", project_parse_relocs },
    };

    for (uint32_t i = 0; i < COUNTOF(project_json_documents); i++) {
        const struct projectJsonHandler* handler = &project_json_documents[i];

        char json_file_path[_MAX_PATH] = { 0 };
        snprintf(json_file_path, COUNTOF(json_file_path), "%s/%s.json",
            project_dir_path,
            handler->document_name);

        uint32_t file_size = 0;
        uint8_t* json_data = read_file(json_file_path, &file_size);

        cJSON* json = cJSON_ParseWithLength((const char*)json_data, file_size);
        CHECK(json != NULL, EXIT_INVALID_JSON, "couldn't parse json %s: %s", json_file_path, cJSON_GetErrorPtr());

        handler->parse_function(state, json);

        cJSON_Delete(json);
    }

    return state;
}

void project_cleanup(
    struct projectState* state) {
    free(state->contribs);
    free(state->modules);
    free(state->relocs);
    free(state->splits);
    free(state->symbols);
    free(state);
}

int main(
    int argc,
    char* argv[]) {
    const char* project_dir_path = NULL;
    const char* input_file_path = NULL;
    const char* output_dir_path = NULL;

    bool verbose = false;

    // parse arguments

    int i;
    for (i = 1; i < argc; i++) {
        const char* arg = argv[i];

        if (!strcmp(arg, "-i")) {
            input_file_path = (++i < argc) ? argv[i] : NULL;
        } else if (!strcmp(arg, "-p")) {
            project_dir_path = (++i < argc) ? argv[i] : NULL;
        } else if (!strcmp(arg, "-o")) {
            output_dir_path = (++i < argc) ? argv[i] : NULL;
        } else if (!strcmp(arg, "-v")) {
            verbose = true;
        } else {
            break;
        }
    }

    // display usage

    CHECK(project_dir_path && input_file_path && output_dir_path,
        EXIT_USAGE,
        "usage: %s -i <input file> -p <project dir> -o <output dir> <objects to dump>\n",
        argv[0]);

    // load project

    struct projectState* project = project_new_from_dir(project_dir_path);

    // parse module arguments

    uint32_t* module_indices = malloc(sizeof(module_indices[0]) * project->module_count);
    CHECK(module_indices != NULL, EXIT_MALLOC_FAILED, "out of memory");
    uint32_t module_count = 0;

    for (i; i < argc; i++) {
        const char* arg = argv[i];

        bool found_module = false;
        for (uint32_t i = 0; i < project->module_count; i++) {
            const struct module* module = &project->modules[i];
        
            if (!strcmp(arg, module->name)) {
                module_indices[module_count++] = i;
                found_module = true;
                break;
            }
        }
        
        CHECK(found_module, EXIT_INVALID_MODULE, "no module exists matching %s", arg);
    }

    // load input file

    uint8_t* input_file_data = read_file(input_file_path, NULL);

    // dump requested objects

    struct mainState state = { 0 };
    state.project = project;
    state.input_file_data = input_file_data;
    state.output_dir_path = output_dir_path;
    state.verbose = verbose;

    if (module_count > 0) {
        for (uint32_t i = 0; i < module_count; i++) {
            uint32_t module_index = module_indices[i];
            do_module(&state, &project->modules[module_index]);
        }
    } else {
        for (uint32_t i = 0; i < project->module_count; i++) {
            do_module(&state, &project->modules[i]);
        }
    }

    free(module_indices);

    // unload project

    project_cleanup(project);

    return EXIT_SUCCESS;
}
