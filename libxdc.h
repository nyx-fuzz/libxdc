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

/* user header */

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>

#define LIBXDC_RELEASE_VERSION 2

#define PT_TRACE_END			__extension__ 0b01010101

typedef void libxdc_t;

typedef enum decoder_result_s { 
	decoder_success, 
	decoder_success_pt_overflow,
	decoder_page_fault, 
	decoder_error,
	decoder_unkown_packet,
} decoder_result_t;

typedef enum disassembler_mode_s { 
	mode_16, 
	mode_32, 
	mode_64,
} disassembler_mode_t;

uint16_t libxdc_get_release_version(void);

void libxdc_reset_trace_cache(libxdc_t* self);

libxdc_t* libxdc_init(uint64_t filter[4][2], void* (*page_cache_fetch_fptr)(void*, uint64_t, bool*), void* page_cache_fetch_opaque, void* bitmap_ptr, size_t bitmap_size);
decoder_result_t libxdc_decode(libxdc_t* self, uint8_t* data, size_t len);

uint64_t libxdc_bitmap_get_hash(libxdc_t* self);
uint64_t libxdc_get_page_fault_addr(libxdc_t* self);

void libxdc_free(libxdc_t* self);
void libxdc_bitmap_reset(libxdc_t* self);

void libxdc_register_bb_callback(libxdc_t* self,  void (*basic_block_callback)(void*, disassembler_mode_t, uint64_t, uint64_t), void* basic_block_callback_opaque);
void libxdc_register_edge_callback(libxdc_t* self,  void (*edge_callback)(void*, disassembler_mode_t, uint64_t, uint64_t), void* edge_callback_opaque);
void libxdc_register_ip_callback(libxdc_t* self,  void (*ip_callback)(void*, disassembler_mode_t, uint64_t), void* ip_callback_opaque);

void libxdc_enable_tracing(libxdc_t* self);
void libxdc_disable_tracing(libxdc_t* self);
