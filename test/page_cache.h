
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
#include "khash.h"

KHASH_MAP_INIT_INT64(PC_CACHE, uint64_t)

typedef struct page_cache_s{

	khash_t(PC_CACHE) *lookup;
	int fd_page_file;
	int fd_address_file; 
	int fd_lock;
	uint8_t disassemble_cache[32];
	void* page_data;
	uint32_t num_pages;

	uint64_t last_page;
	uint64_t last_addr;  
} page_cache_t;

page_cache_t* page_cache_new(const char* cache_file);
void page_cache_destroy(page_cache_t* self);
bool append_page(page_cache_t* self, uint64_t page, uint8_t* ptr);

void* page_cache_fetch(void* self_ptr, uint64_t page, bool* success);
