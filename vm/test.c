// Copyright (c) 2015 Big Switch Networks, Inc
// SPDX-License-Identifier: Apache-2.0

/*
 * Copyright 2015 Big Switch Networks, Inc
 * Copyright 2017 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <ubpf_config.h>

#define _GNU_SOURCE
#include <inttypes.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/mman.h>
#include "ubpf.h"
#include "lookup3.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <time.h>

#include "../bpf/bpf.h"
#include "test.h"

#if defined(UBPF_HAS_ELF_H)
#if defined(UBPF_HAS_ELF_H_COMPAT)
#include <libelf.h>
#else
#include <elf.h>
#endif
#endif

// #define ENCRYPT

#ifdef ENCRYPT
#include <stdint.h>
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/chacha20_poly1305.h>
#include <wolfssl/wolfcrypt/random.h>
#endif

#include <syslog.h>
// #include <sys/time.h>

#define WAIT_TIME 5

/* for shm */
#define SHM_NAME "/dev/uio0"
#define SHM_SIZE (8 * 1024 * 1024) // 8MB

#define VM_AREA 0                                  // 
#define META_AREA (VM_AREA + 2 * 1024 * 1024)      // Start at 2MB
#define PACKETS_AREA (META_AREA + 2 * 1024 * 1024) // Start at 4MB

int fd;
void *shm_ptr;
/* end */

/* META_AREA */
typedef struct
{
    long long ovs_thread_id;
    int p4runtime_id;
} Connection;

#define MAX_CONNECTIONS 32
// #define MAX_CONNECTIONS 8
#define SHM_SESSION_TABLE META_AREA
#define SHM_TABLE_IS_LOCKED (SHM_SESSION_TABLE + sizeof(Connection) * MAX_CONNECTIONS)

Connection *session;
/* end */

/* PACKETS_AREA */
#define SHM_SIZE_DP_PACKET_2 64
#define SHM_SIZE_PACKET 64
#define SHM_SIZE_RESULT 32
#define SHM_SIZE_FLAGS 32
#define SHM_SIZE_PER_PACKET (SHM_SIZE_DP_PACKET_2 + SHM_SIZE_PACKET + SHM_SIZE_RESULT + SHM_SIZE_FLAGS)

#define SHM_FLAG_PACKETS (PACKETS_AREA + SHM_SIZE_PER_PACKET - SHM_SIZE_FLAGS)
#define SHM_FLAG_RESULTS (SHM_FLAG_PACKETS + 1)
#define SHM_FLAG_HOW_MANY_PACKETS (SHM_FLAG_PACKETS + 2) // use only first packet in batch
/* end */

#ifdef ENCRYPT
WC_RNG rng;
unsigned char key[CHACHA20_POLY1305_AEAD_KEYSIZE] = {
    0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
    0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
    0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
    0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f
};
// unsigned char iv[CHACHA20_POLY1305_AEAD_IV_SIZE];
// unsigned char authTag[CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE];
unsigned char ciphertext[256];

int decrypt_message(unsigned char* plaintext) {
    // syslog(LOG_INFO, "decrypt_message() called.");
    int ret = 0;
    unsigned int len;
    unsigned char iv[CHACHA20_POLY1305_AEAD_IV_SIZE];
    unsigned char authTag[CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE];
    
    unsigned char* ptr = (unsigned char*)shm_ptr;

    memcpy(&len, ptr, sizeof(len));
    ptr += sizeof(len);

    memcpy(iv, ptr, sizeof(iv));
    ptr += sizeof(iv);

    memcpy(ciphertext, ptr, len);
    ptr += len;

    memcpy(authTag, ptr, sizeof(authTag));

    ret = wc_ChaCha20Poly1305_Decrypt(
        key,
        iv,
        NULL,
        0,
        ciphertext,
        len,
        plaintext,
        authTag
    );

    return ret;
}

#endif

void
ubpf_set_register_offset(int x);
static void*
readfile(const char* path, size_t maxlen, size_t* len);
static void
register_functions(struct ubpf_vm* vm);

uint64_t get_vm_info();

enum ubpf_action{
ABORT,
DROP,
PASS,
REDIRECT,
};

struct standard_metadata {
    uint32_t input_port; /* bit<32> */
    uint32_t packet_length; /* bit<32> */
    enum ubpf_action output_action; /* ubpf_action */
    uint32_t output_port; /* bit<32> */
    uint8_t clone; /* bool */
    uint32_t clone_port; /* bit<32> */
};

static void
usage(const char* name)
{
    fprintf(stderr, "usage: %s [-h] [-j|--jit] [-m|--mem PATH] BINARY\n", name);
    fprintf(stderr, "\nExecutes the eBPF code in BINARY and prints the result to stdout.\n");
    fprintf(
        stderr, "If --mem is given then the specified file will be read and a pointer\nto its data passed in r1.\n");
    fprintf(stderr, "If --jit is given then the JIT compiler will be used.\n");
    fprintf(stderr, "\nOther options:\n");
    fprintf(stderr, "  -r, --register-offset NUM: Change the mapping from eBPF to x86 registers\n");
    fprintf(
        stderr,
        "  -d, --data: Change from treating R_BPF_64_64 relocations as relocations to maps to relocations to data.\n");
    fprintf(stderr, "  -U, --unload: unload the code and reload it (for testing only)\n");
    fprintf(
        stderr, "  -R, --reload: reload the code, without unloading it first (for testing only, this should fail)\n");
    fprintf(stderr, "  -s, --main-function NAME: Consider the symbol NAME to be the eBPF program's entry point");
}

typedef struct _map_entry
{
    struct bpf_map_def map_definition;
    const char* map_name;
    union
    {
        uint8_t* array;
    };
} map_entry_t;

static map_entry_t* _map_entries = NULL;
static int _map_entries_count = 0;
static int _map_entries_capacity = 0;
static uint8_t* _global_data = NULL;
static uint64_t _global_data_size = 0;

uint64_t
do_data_relocation(
    void* user_context,
    const uint8_t* map_data,
    uint64_t map_data_size,
    const char* symbol_name,
    uint64_t symbol_offset,
    uint64_t symbol_size)
{
    (void)user_context; // unused
    (void)symbol_name;  // unused
    (void)symbol_size;  // unused
    if (_global_data == NULL) {
        _global_data = calloc(map_data_size, sizeof(uint8_t));
        _global_data_size = map_data_size;
        memcpy(_global_data, map_data, map_data_size);
    }

    const uint64_t* target_address = (const uint64_t*)((uint64_t)_global_data + symbol_offset);
    return (uint64_t)target_address;
}

bool
data_relocation_bounds_check_function(void* user_context, uint64_t addr, uint64_t size)
{
    (void)user_context; // unused
    if ((uint64_t)_global_data <= addr && (addr + size) <= ((uint64_t)_global_data + _global_data_size)) {
        return true;
    }
    return false;
}

uint64_t
do_map_relocation(
    void* user_context,
    const uint8_t* map_data,
    uint64_t map_data_size,
    const char* symbol_name,
    uint64_t symbol_offset,
    uint64_t symbol_size)
{
    struct bpf_map_def map_definition = *(struct bpf_map_def*)(map_data + symbol_offset);
    (void)user_context;  // unused
    (void)symbol_offset; // unused
    (void)map_data_size; // unused

    if (symbol_size < sizeof(struct bpf_map_def)) {
        fprintf(stderr, "Invalid map size: %d\n", (int)symbol_size);
        return 0;
    }

    if (map_definition.type != BPF_MAP_TYPE_ARRAY) {
        fprintf(stderr, "Unsupported map type %d\n", map_definition.type);
        return 0;
    }

    if (map_definition.key_size != sizeof(uint32_t)) {
        fprintf(stderr, "Unsupported key size %d\n", map_definition.key_size);
        return 0;
    }

    for (int index = 0; index < _map_entries_count; index++) {
        if (strcmp(_map_entries[index].map_name, symbol_name) == 0) {
            return (uint64_t)&_map_entries[index];
        }
    }

    if (_map_entries_count == _map_entries_capacity) {
        _map_entries_capacity = _map_entries_capacity ? _map_entries_capacity * 2 : 4;
        _map_entries = realloc(_map_entries, _map_entries_capacity * sizeof(map_entry_t));
    }

    _map_entries[_map_entries_count].map_definition = map_definition;
    _map_entries[_map_entries_count].map_name = strdup(symbol_name);
    _map_entries[_map_entries_count].array = calloc(map_definition.max_entries, map_definition.value_size);

    return (uint64_t)&_map_entries[_map_entries_count++];
}

bool
map_relocation_bounds_check_function(void* user_context, uint64_t addr, uint64_t size)
{
    (void)user_context;
    for (int index = 0; index < _map_entries_count; index++) {
        if (addr >= (uint64_t)_map_entries[index].array &&
            addr + size <= (uint64_t)_map_entries[index].array + _map_entries[index].map_definition.max_entries *
                                                                     _map_entries[index].map_definition.value_size) {
            return true;
        }
    }
    return false;
}

void
shm_start(void)
{
    fd = open(SHM_NAME, O_RDWR);

    if (fd < 0) {
        perror("shm_open");
        exit(EXIT_FAILURE);
    }

    syslog(LOG_WARNING, "fd: %d, SHM_SIZE: %d", fd, SHM_SIZE);

    shm_ptr = mmap(NULL, SHM_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 4096);
    if (shm_ptr == MAP_FAILED) {
        perror("mmap");
        exit(EXIT_FAILURE);
    }

    syslog(LOG_WARNING, "SHM opened. mapped to %p", shm_ptr);
}

void
shm_init(void)
{
    /* VM_AREA */
    unsigned long threshold = 10000;
    unsigned long used_bytes = 0;
    memcpy(&threshold, (uint8_t*)shm_ptr + VM_AREA, sizeof(threshold));
    memcpy(&used_bytes, (uint8_t*)shm_ptr + VM_AREA + sizeof(threshold), sizeof(used_bytes));

    /* META_AREA */
    session = (Connection *)(shm_ptr + SHM_SESSION_TABLE);
}

void
shm_end(void)
{
    munmap(shm_ptr, SHM_SIZE);
    close(fd);
}

int
need_re_link(int session_id, long long ovs_tid)
{
    if (session_id == -1) // first time
        return 1;
    if (session[session_id].ovs_thread_id != ovs_tid) // changed tid
        return 1;
    return 0;
}

int
get_session_id(int runtime_pid)
{
    while(true)
    {
        for (int i = 0; i < MAX_CONNECTIONS; i++)
        {
            if (session[i].p4runtime_id == runtime_pid)
            {
                syslog(LOG_WARNING, "Session ID is %d", i);
                return i;
            }
        }
        // syslog(LOG_WARNING, "session not found for PID %d.", runtime_pid);
        usleep(1);
    }
    return -1;
}

long long
get_ovs_tid(int session_id)
{
    long long ret = session[session_id].ovs_thread_id;
    syslog(LOG_WARNING, "pair OVS TID is %lld", ret);
    return ret;
}

intptr_t
calc_offset(int session_id)
{
    intptr_t ret = SHM_SIZE_PER_PACKET * session_id;
    syslog(LOG_WARNING, "Calculated offset is %d", (int)ret);
    return ret;
}

int
receive_packets(ubpf_jit_fn fn)
{
    int                ret = 0;
    int                runtime_pid = -1;
    int                session_id = -1;
    long long          ovs_tid = -1;

    struct dp_packet_p4 *dp_packet2 = NULL;
    uint64_t           dp_packet2_size = sizeof(struct dp_packet_p4);
    char               *packet = NULL;
    struct standard_metadata std_meta;

    intptr_t offset = -1;
    uint64_t           fn_ret;
    size_t             how_many_packets = 0;

    // struct timespec start, end;

    openlog("uBPF VM", LOG_CONS | LOG_PID, LOG_USER);

    shm_start();
    shm_init();

    runtime_pid = (int)getpid();

    while(1){

        // clock_gettime(CLOCK_MONOTONIC, &start);


        if (need_re_link(session_id, ovs_tid) == 1)
        {
            session_id = get_session_id(runtime_pid);
            ovs_tid = get_ovs_tid(session_id);
            if(ovs_tid == -1)
            {
                // not linked with ovs thread
                usleep(1000); // 1ms
                continue;
            }
            offset = calc_offset(session_id);
        }

        // TODO: Implement shutdown logic

        while (*((char *)shm_ptr+offset+SHM_FLAG_PACKETS) != 1) {
            usleep(WAIT_TIME);
        }

        // __sync_synchronize(); // wait for reading

        memcpy(&how_many_packets, shm_ptr+offset+SHM_FLAG_HOW_MANY_PACKETS, 
            sizeof(how_many_packets));

        for (int packets = 0; packets < how_many_packets; packets++) {

            // dp_packet2
            dp_packet2 = (struct dp_packet_p4*)malloc(dp_packet2_size);
            if(dp_packet2 == NULL){
                syslog(LOG_WARNING, "ERROR: failed to malloc() 1");
                exit(EXIT_FAILURE);
            }
            memset(dp_packet2, 0, dp_packet2_size);
            memcpy(dp_packet2, shm_ptr+offset+PACKETS_AREA+
                (packets*SHM_SIZE_PER_PACKET), dp_packet2_size);

            // packet
            packet = NULL;
            if(dp_packet2->allocated_ == 0){
                printf("allocated_ is 0\n\n");
                fn_ret = 1; // (pass)
            }else{
                if (dp_packet2->allocated_ > SHM_SIZE_PACKET) {
                    syslog(LOG_WARNING, "ERROR: allocated_ exceeds limit");
                    free(dp_packet2);
                    exit(EXIT_FAILURE);
                }                
                packet = malloc(dp_packet2->allocated_);
                if(packet == NULL){
                    syslog(LOG_WARNING, "ERROR: failed to malloc() 2");
                    free(dp_packet2);
                    exit(EXIT_FAILURE);
                }

                dp_packet2->base_ = packet;

                memset(dp_packet2->base_, 0, dp_packet2->allocated_);
                memcpy(dp_packet2->base_, shm_ptr+offset+PACKETS_AREA+
                    (packets*SHM_SIZE_PER_PACKET)+SHM_SIZE_DP_PACKET_2, 
                    dp_packet2->allocated_);

                std_meta.packet_length = dp_packet2->allocated_;

#define BYPASS_P4

#ifdef BYPASS_P4
                fn_ret = 1; // always pass
#else
                // clock_gettime(CLOCK_MONOTONIC, &start);
                fn_ret = fn(dp_packet2, &std_meta);
                // clock_gettime(CLOCK_MONOTONIC, &end);
                // long seconds = end.tv_sec - start.tv_sec;
                // long nanoseconds = end.tv_nsec - start.tv_nsec;
                // long total_nanoseconds = seconds * 1000000000L + nanoseconds;

                // syslog(LOG_WARNING, "P4プログラム実行時間: %ld[ns] (%ld)", nanoseconds, start.tv_nsec);
#endif
            }
            // result
            while (*((char *)shm_ptr + offset + PACKETS_AREA + SHM_FLAG_RESULTS) != 0) {
                usleep(WAIT_TIME);
            }
            
            #ifdef DEBUG_RESULT_RANDOMLY
            srand((unsigned int)time(NULL));
            fn_ret = rand()%2;
            #endif
            
            *((volatile char *)shm_ptr+offset+
                PACKETS_AREA+(packets*SHM_SIZE_PER_PACKET)+
                SHM_SIZE_DP_PACKET_2+SHM_SIZE_PACKET) = (char)fn_ret;
            
            if(packet != NULL) {
                free(packet);
            }
            if(dp_packet2 != NULL){
                free(dp_packet2);
            }
        }
        // __sync_synchronize(); // prepare for reading
        *((volatile char *)shm_ptr + offset + SHM_FLAG_RESULTS) = 1;
        *((volatile char *)shm_ptr + offset + SHM_FLAG_PACKETS) = 0;

        // clock_gettime(CLOCK_MONOTONIC, &end);
        // long seconds = end.tv_sec - start.tv_sec;
        // long nanoseconds = end.tv_nsec - start.tv_nsec;
        // long total_microseconds = seconds * 1000000 + nanoseconds / 1000;

        // syslog(LOG_WARNING, "us/batch: %ld", total_microseconds);
    }

    shm_end();

    return ret;
}

int
main(int argc, char** argv)
{
    struct option longopts[] = {
        {
            .name = "help",
            .val = 'h',
        },
        {.name = "mem", .val = 'm', .has_arg = 1},
        {.name = "jit", .val = 'j'},
        {.name = "data", .val = 'd'},
        {.name = "register-offset", .val = 'r', .has_arg = 1},
        {.name = "unload", .val = 'U'}, /* for unit test only */
        {.name = "reload", .val = 'R'}, /* for unit test only */
        {.name = "main-function", .val = 's', .has_arg = 1},
        {0}};

    const char* mem_filename = NULL;
    const char* main_function_name = NULL;
    bool jit = true; // changed here.
    bool unload = false;
    bool reload = false;
    bool data_relocation = false; // treat R_BPF_64_64 as relocations to maps by default.

    uint64_t secret = (uint64_t)rand() << 32 | (uint64_t)rand();

    int opt;
    while ((opt = getopt_long(argc, argv, "hm:jdr:URs:", longopts, NULL)) != -1) {
        switch (opt) {
        case 'm':
            mem_filename = optarg;
            break;
        case 's':
            main_function_name = optarg;
            break;
        case 'j':
            jit = true;
            break;
        case 'd':
            data_relocation = true;
            break;
        case 'r':
            ubpf_set_register_offset(atoi(optarg));
            break;
        case 'h':
            usage(argv[0]);
            return 0;
        case 'U':
            unload = true;
            break;
        case 'R':
            reload = true;
            break;
        default:
            usage(argv[0]);
            return 1;
        }
    }

    if (unload && reload) {
        fprintf(stderr, "-U and -R can not be used together\n");
        return 1;
    }

    if (argc != optind + 1) {
        usage(argv[0]);
        return 1;
    }

    const char* code_filename = argv[optind];
    size_t code_len;
    void* code = readfile(code_filename, 1024 * 1024, &code_len);
    if (code == NULL) {
        return 1;
    }

    size_t mem_len = 0;
    void* mem = NULL;
    if (mem_filename != NULL) {
        mem = readfile(mem_filename, 1024 * 1024, &mem_len);
        if (mem == NULL) {
            return 1;
        }
    }

    struct ubpf_vm* vm = ubpf_create();
    if (!vm) {
        fprintf(stderr, "Failed to create VM\n");
        return 1;
    }

    if (data_relocation) {
        ubpf_register_data_relocation(vm, NULL, do_data_relocation);
        ubpf_register_data_bounds_check(vm, NULL, data_relocation_bounds_check_function);
    } else {
        ubpf_register_data_relocation(vm, NULL, do_map_relocation);
        ubpf_register_data_bounds_check(vm, NULL, map_relocation_bounds_check_function);
    }

    if (ubpf_set_pointer_secret(vm, secret) != 0) {
        fprintf(stderr, "Failed to set pointer secret\n");
        return 1;
    }

    register_functions(vm);

    /*
     * The ELF magic corresponds to an RSH instruction with an offset,
     * which is invalid.
     */
#if defined(UBPF_HAS_ELF_H)
    bool elf = code_len >= SELFMAG && !memcmp(code, ELFMAG, SELFMAG);
#endif

    char* errmsg;
    int rv;
load:
#if defined(UBPF_HAS_ELF_H)
    if (elf) {
        rv = ubpf_load_elf_ex(vm, code, code_len, main_function_name, &errmsg);
    } else {
#endif
        rv = ubpf_load(vm, code, code_len, &errmsg);
#if defined(UBPF_HAS_ELF_H)
    }
#endif
    if (unload) {
        ubpf_unload_code(vm);
        unload = false;
        goto load;
    }
    if (reload) {
        reload = false;
        goto load;
    }

    free(code);

    if (rv < 0) {
        fprintf(stderr, "Failed to load code: %s\n", errmsg);
        free(errmsg);
        ubpf_destroy(vm);
        return 1;
    }

    uint64_t ret;

    if (jit) {
        ubpf_jit_fn fn = ubpf_compile(vm, &errmsg);
        if (fn == NULL) {
            fprintf(stderr, "Failed to compile: %s\n", errmsg);
            free(errmsg);
            free(mem);
            return 1;
        }
        receive_packets(fn);
    } else {
        if (ubpf_exec(vm, mem, mem_len, &ret) < 0)
            ret = UINT64_MAX;
    }

    ubpf_destroy(vm);
    free(mem);

    return 0;
}

static void*
readfile(const char* path, size_t maxlen, size_t* len)
{
    FILE* file;
    if (!strcmp(path, "-")) {
        file = fdopen(STDIN_FILENO, "r");
    } else {
        file = fopen(path, "r");
    }

    if (file == NULL) {
        fprintf(stderr, "Failed to open %s: %s\n", path, strerror(errno));
        return NULL;
    }

    char* data = calloc(maxlen, 1);
    size_t offset = 0;
    size_t rv;
    while ((rv = fread(data + offset, 1, maxlen - offset, file)) > 0) {
        offset += rv;
    }

    if (ferror(file)) {
        fprintf(stderr, "Failed to read %s: %s\n", path, strerror(errno));
        fclose(file);
        free(data);
        return NULL;
    }

    if (!feof(file)) {
        fprintf(stderr, "Failed to read %s because it is too large (max %u bytes)\n", path, (unsigned)maxlen);
        fclose(file);
        free(data);
        return NULL;
    }

    fclose(file);
    if (len) {
        *len = offset;
    }
    return (void*)data;
}

#ifndef __GLIBC__
void*
memfrob(void* s, size_t n)
{
    for (int i = 0; i < n; i++) {
        ((char*)s)[i] ^= 42;
    }
    return s;
}
#endif

static void*
bpf_map_lookup_elem_impl(struct bpf_map* map, const void* key)
{
    map_entry_t* map_entry = (map_entry_t*)map;
    if (map_entry->map_definition.type == BPF_MAP_TYPE_ARRAY) {
        uint32_t index = *(uint32_t*)key;
        if (index >= map_entry->map_definition.max_entries) {
            return NULL;
        }
        return map_entry->array + index * map_entry->map_definition.value_size;
    } else {
        fprintf(stderr, "bpf_map_lookup_elem not implemented for this map type.\n");
        exit(1);
    }
    return NULL;
}

static int
bpf_map_update_elem_impl(struct bpf_map* map, const void* key, const void* value, uint64_t flags)
{
    map_entry_t* map_entry = (map_entry_t*)map;
    (void)flags; // unused
    if (map_entry->map_definition.type == BPF_MAP_TYPE_ARRAY) {
        uint32_t index = *(uint32_t*)key;
        if (index >= map_entry->map_definition.max_entries) {
            return -1;
        }
        memcpy(
            map_entry->array + index * map_entry->map_definition.value_size,
            value,
            map_entry->map_definition.value_size);
        return 0;
    } else {
        fprintf(stderr, "bpf_map_update_elem not implemented for this map type.\n");
        exit(1);
    }
    return 0;
}

static int
// bpf_map_delete_elem_impl(struct bpf_map* map, const void* key)
bpf_map_delete_elem_impl()
{
    // map_entry_t* map_entry = (map_entry_t*)map;
    // if (map_entry->map_definition.type == BPF_MAP_TYPE_ARRAY) {
    //     uint32_t index = *(uint32_t*)key;
    //     if (index >= map_entry->map_definition.max_entries) {
    //         return -1;
    //     }
    //     memset(
    //         map_entry->array + index * map_entry->map_definition.value_size, 0, map_entry->map_definition.value_size);
    //     return 0;
    // } else {
    //     fprintf(stderr, "bpf_map_delete_elem not implemented for this map type.\n");
    //     exit(1);
    // }
    return 0;
}

void *
ubpf_map_lookup(const struct ubpf_map *map, void *key)
{
    if (OVS_UNLIKELY(!map)) {
//        return NULL;
    }
    if (OVS_UNLIKELY(!map->ops.map_lookup)) {
//        return NULL;
    }
    if (OVS_UNLIKELY(!key)) {
//        return NULL;
    }
//    return map->ops.map_lookup(map, key);
    return "ok";
}

int
ubpf_map_update(struct ubpf_map *map, const void *key, void *item)
{
    if (OVS_UNLIKELY(!map)) {
        return -1;
    }
    if (OVS_UNLIKELY(!map->ops.map_update)) {
        return -2;
    }
    if (OVS_UNLIKELY(!key)) {
        return -3;
    }
    if (OVS_UNLIKELY(!item)) {
        return -4;
    }
    return map->ops.map_update(map, key, item);
}

static int
ubpf_map_add(struct ubpf_map *map, void *item)
{
    if (OVS_UNLIKELY(!map)) {
        return -1;
    }
    if (OVS_UNLIKELY(!map->ops.map_add)) {
        return -2;
    }
    if (OVS_UNLIKELY(!item)) {
        return -3;
    }
    return map->ops.map_add(map, item);
}

static int
ubpf_map_delete(struct ubpf_map *map, const void *key)
{
    if (OVS_UNLIKELY(!map)) {
        return -1;
    }
    if (OVS_UNLIKELY(!map->ops.map_delete)) {
        return -2;
    }
    if (OVS_UNLIKELY(!key)) {
        return -3;
    }
    return map->ops.map_delete(map, key);
}

static void
ubpf_printf(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    va_end(args);
}

static uint64_t
ubpf_time_get_ns(void)
{
    struct timespec curr_time = {0, 0};
    uint64_t curr_time_ns = 0;
    clock_gettime(CLOCK_REALTIME, &curr_time);
    curr_time_ns = curr_time.tv_nsec + curr_time.tv_sec * 1.0e9;
    return curr_time_ns;
}

static uint32_t
ubpf_hash(void *item, uint64_t size)
{
    return hashlittle(item, (uint32_t)size, 0);
}

void *
ubpf_adjust_head(void* ctx, int offset) {
    printf("ubpf_adjust_head is called.");
    struct dp_packet *packet = (struct dp_packet *) ctx;

    void *pkt = NULL;
    if (offset >= 0)  // encapsulation
        pkt = dp_packet_push_zeros(packet, offset);
    else {  // decapsulation
        dp_packet_reset_packet(packet, abs(offset));
        pkt = dp_packet_data(packet);
    }

    return pkt;
}

/*
void *
ubpf_adjust_head(void* ctx)
{
    struct dp_packet *packet = (struct dp_packet *) ctx;
    return packet;
}
*/

void *
ubpf_packet_data(void *ctx)
{
    struct dp_packet *packet = (struct dp_packet *) ctx;
    return dp_packet_data(packet);
}

static uint32_t
ubpf_get_rss_hash(void *ctx)
{
    struct dp_packet *packet = (struct dp_packet *) ctx;
    return dp_packet_get_rss_hash(packet);
}

static uint32_t
ubpf_truncate_packet()
{
    return 0;
}

uint64_t
read_vm_info()
{
    uint64_t data = 0;
#ifdef ENCRYPT
    unsigned char plaintext[256];
    int ret = decrypt_message(plaintext);
    if (ret != 0) {
        printf("decrypt failed. err: %d\n", ret);
        // exit(1);
        data = 0;
    }else{
        for (int i = 0; i < 8; i++) {
            data = (data << 8) | plaintext[i];
        }
    }
#else
    memcpy(&data, (uint8_t*)shm_ptr + VM_AREA, sizeof(data));
#endif
    return data;
}

void
myPrintf(int i)
{
    printf("%d\n", i);
}

static void
register_functions(struct ubpf_vm* vm)
{
    ubpf_register(vm, 1, "ubpf_map_lookup", ubpf_map_lookup);
    ubpf_register(vm, 2, "ubpf_map_update", ubpf_map_update);
    ubpf_register(vm, 3, "ubpf_map_delete", ubpf_map_delete);
    ubpf_register(vm, 4, "ubpf_map_add", ubpf_map_add);
    ubpf_register(vm, 5, "ubpf_time_get_ns", ubpf_time_get_ns);
    ubpf_register(vm, 6, "ubpf_hash", ubpf_hash);
    ubpf_register(vm, 7, "ubpf_printf", ubpf_printf);
    ubpf_register(vm, 8, "ubpf_adjust_head", ubpf_adjust_head);
    ubpf_register(vm, 9, "ubpf_packet_data", ubpf_packet_data);
    ubpf_register(vm, 10, "ubpf_get_rss_hash", ubpf_get_rss_hash);
    ubpf_register(vm, 11, "ubpf_truncate_packet", ubpf_truncate_packet);
    ubpf_register(vm, 20, "read_vm_info", read_vm_info);
    ubpf_register(vm, 21, "myPrintf", myPrintf);

    ubpf_set_unwind_function_index(vm, 5);
    ubpf_register(vm, (unsigned int)(uintptr_t)bpf_map_lookup_elem, "bpf_map_lookup_elem", bpf_map_lookup_elem_impl);
    ubpf_register(vm, (unsigned int)(uintptr_t)bpf_map_update_elem, "bpf_map_update_elem", bpf_map_update_elem_impl);
    ubpf_register(vm, (unsigned int)(uintptr_t)bpf_map_delete_elem, "bpf_map_delete_elem", bpf_map_delete_elem_impl);
}