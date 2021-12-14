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
#include <stdlib.h>
#include "khash.h"
#include "tnt_cache.h"
#include "core.h"

/* 
	6 bit of an uint64_t are used to encode the number of tnt bits-
	The remaining 58 bits are used to store the actual tnt bits. 
*/
#define MAX_RESULTS_PER_CACHE 58

tracelet_cache_tmp_t* new_tracelet_cache(size_t bitmap_size);
void tracelet_cache_tmp_destroy(tracelet_cache_tmp_t* self);
void reset_tracelet_tmp_cache(tracelet_cache_tmp_t* self);
void add_result_tracelet_cache(tracelet_cache_tmp_t* self, uint64_t from, uint64_t to, fuzz_bitmap_t* fuzz_bitmap);
void set_next_entry_addres_tracelet_cache(tracelet_cache_t* self, uint64_t next_entry_address);


tracelet_cache_t* new_from_tracelet_cache_tmp(tracelet_cache_tmp_t* tmp_cache, bool cont_exec);
void tracelet_cache_destroy(tracelet_cache_t* self);
uint64_t apply_trace_cache_to_bitmap(tracelet_cache_t* self, tnt_cache_t* tnt_cache_state, bool adjust, fuzz_bitmap_t* fuzz_bitmap);

fuzz_bitmap_t* net_fuzz_bitmap(uint8_t* bitmap, uint32_t bitmap_size);



/* singleton implementation */
uint32_t fuzz_bitmap_get_size(fuzz_bitmap_t* self);
//void fuzz_bitmap_set_size(fuzz_bitmap_t self, uint32_t size);
//void fuzz_bitmap_set_ptr(fuzz_bitmap_t self, void* ptr);
void fuzz_bitmap_reset(fuzz_bitmap_t* self);
uint64_t fuzz_bitmap_get_hash(fuzz_bitmap_t* self);
void fuzz_bitmap_set(fuzz_bitmap_t* self, uint64_t from, uint64_t to);
uint8_t* fuzz_bitmap_get_ptr(fuzz_bitmap_t* self);



trace_cache_t* trace_cache_new(size_t bitmap_size);
void trace_cache_destroy(trace_cache_t* self);
void trace_cache_add(trace_cache_t* self, trace_cache_key_t key, tracelet_cache_t* tracelet);
tracelet_cache_t* trace_cache_fetch(trace_cache_t* self, trace_cache_key_t key);

