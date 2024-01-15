/*
 * Copyright 2015 Big Switch Networks, Inc
 * Copyright (c) 2008, 2009, 2010, 2012, 2013, 2015, 2016 Nicira, Inc.
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

#ifndef UBPF_INT_H
#define UBPF_INT_H

#include "ubpf.h"
#include "ebpf.h"

#include <stdarg.h>
#include "time.h"
#include "dp-packet.h"

#define UBPF_ADJUST_HEAD_ID 8

// from "p4rt-ovs/include/openvswitch/hmap.h"
struct hmap_node {
    size_t hash;                /* Hash value. */
    struct hmap_node *next;     /* Next in linked list. */
};
// end

enum ubpf_map_type {
    UBPF_MAP_TYPE_ARRAY = 1,
    UBPF_MAP_TYPE_BLOOMFILTER = 2,
    UBPF_MAP_TYPE_COUNTMIN = 3,
    UBPF_MAP_TYPE_HASHMAP = 4,
};

struct ubpf_map;

struct ubpf_map_ops {
    unsigned int (*map_size)(const struct ubpf_map *map);
    unsigned int (*map_dump)(const struct ubpf_map *map, void *data);
    void *(*map_lookup)(const struct ubpf_map *map, const void *key);
    int (*map_update)(struct ubpf_map *map, const void *key, void *value);
    int (*map_delete)(struct ubpf_map *map, const void *key);
    int (*map_add)(struct ubpf_map *map, void *value);
};

struct ubpf_map {
    enum ubpf_map_type type;
    struct ubpf_map_ops ops;
    unsigned int key_size;
    unsigned int value_size;
    unsigned int max_entries;
    void *data;
};

struct ubpf_vm {
    ovs_be16 prog_id;
    struct hmap_node hmap_node;
    struct ebpf_inst *insts;
    uint16_t num_insts;
    ubpf_jit_fn jitted;
    size_t jitted_size;
    struct ubpf_func_proto *ext_funcs;
    const char **ext_func_names;
    struct ubpf_map **ext_maps;
    const char **ext_map_names;
    uint16_t nb_maps;
    unsigned long long int loaded_at;
};

#endif
