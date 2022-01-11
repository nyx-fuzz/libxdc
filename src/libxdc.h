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
#include <stdbool.h>


#include "core.h"

__attribute__ ((visibility ("default"))) libxdc_t* libxdc_init(uint64_t filter[4][2], void* (*page_cache_fetch_fptr)(void*, uint64_t, bool*), void* page_cache_fetch_opaque, void* bitmap_ptr, size_t bitmap_size);
__attribute__ ((visibility ("default"))) decoder_result_t libxdc_decode(libxdc_t* self, uint8_t* data, size_t len);

__attribute__ ((visibility ("default"))) uint64_t libxdc_bitmap_get_hash(libxdc_t* self);
__attribute__ ((visibility ("default"))) uint64_t libxdc_get_page_fault_addr(libxdc_t* self);

__attribute__ ((visibility ("default"))) void libxdc_enable_tracing(libxdc_t* self);
__attribute__ ((visibility ("default"))) void libxdc_disable_tracing(libxdc_t* self);

__attribute__ ((visibility ("default"))) void libxdc_free(libxdc_t* self);
__attribute__ ((visibility ("default"))) void libxdc_bitmap_reset(libxdc_t* self);

__attribute__ ((visibility ("default")))  void libxdc_register_bb_callback(libxdc_t* self,  void (*basic_block_callback)(void*, disassembler_mode_t, uint64_t, uint64_t), void* basic_block_callback_opaque);
__attribute__ ((visibility ("default")))  void libxdc_register_edge_callback(libxdc_t* self,  void (*edge_callback)(void*, disassembler_mode_t, uint64_t, uint64_t), void* edge_callback_opaque);
__attribute__ ((visibility ("default")))  void libxdc_register_ip_callback(libxdc_t* self,  void (*ip_callback)(void*, disassembler_mode_t, uint64_t), void* ip_callback_opaque);
