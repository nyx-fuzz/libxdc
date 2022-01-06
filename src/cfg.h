/*
Copyright (c) 2020 Sergej Schumilo, Cornelius Aschermann

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

#pragma once
#define _GNU_SOURCE
#include <stdint.h>
#include <stdbool.h>
#include "khash.h"
#include <stdlib.h>

KHASH_MAP_INIT_INT(ADDR0, uint64_t)

typedef enum cofi_types{
	COFI_TYPE_CONDITIONAL_BRANCH, 
	COFI_TYPE_UNCONDITIONAL_DIRECT_BRANCH, 
	COFI_TYPE_INDIRECT_BRANCH, 
	COFI_TYPE_NEAR_RET, 
	COFI_TYPE_FAR_TRANSFERS,
	NO_COFI_TYPE, //COFI_FALLTHROUGH_BASIC_BLOCK
	OUT_OF_BOUNDS,
	INFINITE_LOOP,
	PAGE_CACHE_FAILED,
} cofi_type;

typedef uint32_t  node_id_t; 

typedef struct cfg_branch_s {
    node_id_t node_id;
    uint32_t bitmap_id;
} cfg_branch_t;

#define NODE_PAGE_FAULT 0x0 //NODE_PAGE_FAULT is used to indicate that disassembly failed due to missing memory
#define NODE_OOB 0x1 //NODE_OOB is used to indicate that disassembly failed to to trace area OOB
#define NODE_NOT_DEFINED 0xffffffff

typedef struct disassembler_cfg_s{

	cfg_branch_t* br1;
	cfg_branch_t* br2;
	uint64_t* base_addr;
    uint64_t* cofi_addr;
    uint64_t* br1_addr;
    uint64_t* br2_addr;
    cofi_type* type;

    uint32_t max_size;
    uint32_t next_node_id;
    uint32_t next_bitmap_id;
    khash_t(ADDR0) *ip_to_node_id;
} disassembler_cfg_t;

bool                disassembler_cfg_init(disassembler_cfg_t* res, uint32_t size);
void                disassembler_cfg_destroy(disassembler_cfg_t* self);
void                disassembler_cfg_inspect(disassembler_cfg_t* self, node_id_t nid);
void                disassembler_cfg_resize(disassembler_cfg_t* self);
uint32_t            disassembler_cfg_get_node_id(disassembler_cfg_t* self, uint64_t ip);
node_id_t           disassembler_cfg_add_node(disassembler_cfg_t* self, uint64_t base_ip, uint64_t cofi_ip, cofi_type type);
void                disassembler_cfg_add_br1_addr(disassembler_cfg_t* self, node_id_t node, uint64_t target);
void                disassembler_cfg_add_br1_nid(disassembler_cfg_t* self, node_id_t node, node_id_t target_nid);
void                disassembler_cfg_add_br2_addr(disassembler_cfg_t* self, node_id_t node, uint64_t target);
void                disassembler_cfg_add_br2_nid(disassembler_cfg_t* self, node_id_t node, node_id_t target_nid);
node_id_t           disassembler_cfg_prefix_node(disassembler_cfg_t* self, uint64_t base_address, node_id_t old_node);
