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

#include <stdint.h>
#include <inttypes.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "khash.h"
#include <unistd.h>
#include <sys/time.h>
#include <capstone/capstone.h>
#include <capstone/x86.h>
#include "tnt_cache.h"
#include "cfg.h"

#define INIT_TRACE_IP 0xFFFFFFFFFFFFFFFFULL

#define likely(x)       __builtin_expect((x),1)
#define unlikely(x)     __builtin_expect((x),0)

typedef struct tracelet_cache_s{
	uint64_t next_entry_address;
	uint8_t tnt_bits;

	uint8_t result_bits; 
	uint8_t result_bits_max;
	uint32_t* bitmap_results;
	bool cont_exec;
} tracelet_cache_t;


typedef struct tracelet_cache_tmp_s{
	tracelet_cache_t cache;
	uint8_t* lookup_bitmap;
} tracelet_cache_tmp_t;

typedef struct trace_cache_key_s{
	uint64_t tnt_hash;
	uint64_t entry;
	uint64_t limit;
} trace_cache_key_t;


#define kh_trace_cache_key_t_hash_func(key)  (khint32_t)(((key.entry)>>33^(key.entry)^(key.entry)<<11) ^ ((key.limit)>>33^(key.limit)^(key.limit)<<11) ^ ((key.tnt_hash)>>33^(key.tnt_hash)^(key.tnt_hash)<<11))

//static inline int kh_trace_cache_key_t_equal(trace_cache_key_t k1, trace_cache_key_t k2) { return !memcmp(&k1, &k2, sizeof(k1)); }
static inline int kh_trace_cache_key_t_equal(trace_cache_key_t k1, trace_cache_key_t k2) { return k1.tnt_hash == k2.tnt_hash && k1.entry == k2.entry && k1.limit == k2.limit ; }

KHASH_INIT(TRACE_CACHE, trace_cache_key_t, tracelet_cache_t*, 1, kh_trace_cache_key_t_hash_func, kh_trace_cache_key_t_equal)

typedef struct trace_cache_s{
	khash_t(TRACE_CACHE) *lookup;
	tracelet_cache_tmp_t* trace_cache;
} trace_cache_t;

typedef struct fuzz_bitmap_s {
	uint8_t* bitmap;
	uint32_t bitmap_size;
} fuzz_bitmap_t;

typedef struct{
	uint16_t opcode;
	uint8_t modrm;
	uint8_t opcode_prefix;
} cofi_ins;


typedef enum disas_result_s { 
	disas_success, 
	disas_tnt_empty, 
	disas_tip_pending,
	disas_out_of_bounds,
	disas_infinite_loop,
	disas_page_fault,
} disas_result_t;


typedef enum disassembler_mode_s { 
	mode_16, 
	mode_32, 
	mode_64,
} disassembler_mode_t;

typedef struct disassembler_s{
	bool infinite_loop_found;

	uint8_t* code;
	uint64_t min_addr_0;
	uint64_t max_addr_0;
	uint64_t min_addr_1;
	uint64_t max_addr_1;
	uint64_t min_addr_2;
	uint64_t max_addr_2;
	uint64_t min_addr_3;
	uint64_t max_addr_3;

	bool debug;
	bool has_pending_indirect_branch;
	uint64_t pending_indirect_branch_src;
	fuzz_bitmap_t* fuzz_bitmap;
	trace_cache_t* trace_cache;

	uint8_t disassemble_cache[32];

	csh handle_16;
	csh handle_32;
	csh handle_64;

	bool trace_mode;

	void* (*page_cache_fetch_fptr)(void*, uint64_t, bool*);
	void* page_cache_fetch_opaque;

	void (*trace_edge_callback)(void*, disassembler_mode_t, uint64_t, uint64_t);
	void* trace_edge_callback_opaque;

	void (*basic_block_callback)(void*, disassembler_mode_t, uint64_t, uint64_t);
	void* basic_block_callback_opaque;

	disassembler_cfg_t cfg;

} disassembler_t;



typedef enum decoder_state { 
	TraceDisabled=1, 
	TraceEnabledWithLastIP, 
	TraceEnabledWOLastIP} 
decoder_state_e;

typedef struct DecoderStateMachine{
  decoder_state_e state;
  uint64_t last_ip;
} decoder_state_machine_t;

/*
Used as return type for statemachine updates, start and end are undefined unless valid is true
*/
typedef struct ShouldDisasm{
  uint64_t start;
  uint64_t end;
  bool valid;
} should_disasm_t;


typedef struct decoder_s{
	bool page_fault_found;
	uint64_t page_fault_addr;
	bool ovp_state; 
	uint64_t last_tip;
	uint64_t last_tip_tmp;
	uint64_t last_fup_src;
	bool fup_bind_pending;
	disassembler_t* disassembler_state;
	tnt_cache_t* tnt_cache_state;
	decoder_state_machine_t* decoder_state;
	should_disasm_t* decoder_state_result;
	disassembler_mode_t mode;
	int error_counter;

	void (*ip_callback)(void*, disassembler_mode_t, uint64_t);
	void* ip_callback_opaque;

#ifdef DECODER_LOG
	struct decoder_log_s{
		uint64_t tnt64;
		uint64_t tnt8;
		uint64_t pip;
		uint64_t cbr;
		uint64_t ts;
		uint64_t ovf;
		uint64_t psbc;
		uint64_t psbend;
		uint64_t mnt;
		uint64_t tma;
		uint64_t vmcs;
		uint64_t pad;
		uint64_t tip;
		uint64_t tip_pge;
		uint64_t tip_pgd;
		uint64_t tip_fup;
		uint64_t mode;
	} log;
#endif
} decoder_t;

typedef enum decoder_result_s { 
	decoder_success, 
	decoder_success_pt_overflow,
	decoder_page_fault, 
	decoder_error,
	decoder_unkown_packet,
} decoder_result_t;


typedef struct libxdc_s {
	fuzz_bitmap_t* fuzz_bitmap;
  decoder_t* decoder;
  disassembler_t* disassembler;

  uint64_t trace_regions[4][2];
} libxdc_t;

#ifdef DEBUG_TRACES
#define LOGGER(format, ...) (printf(format, ##__VA_ARGS__))
#else
#define LOGGER(format, ...)  (void)0 
#endif