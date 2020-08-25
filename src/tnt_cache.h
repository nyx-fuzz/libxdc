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

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>

//#define NON_BRANCH_LESS_CODE
#define BRANCH_LESS_CODE

#define NOT_TAKEN			0
#define TAKEN				1
#define TNT_EMPTY			2

#define SHORT_TNT_OFFSET	1
#define SHORT_TNT_MAX_BITS	8-1-SHORT_TNT_OFFSET

#define LONG_TNT_OFFSET		16
#define LONG_TNT_MAX_BITS	64-1-LONG_TNT_OFFSET

#define BUF_SIZE 0x100000000	/* 4G slots */
#define BL_BUF_ENTRIES ((BUF_SIZE/8)/32)

typedef struct tnt_cache_s{
#ifdef NON_BRANCH_LESS_CODE
	uint8_t* tnt_memory;
	uint64_t pos;
	uint64_t max;
	uint64_t tnt;
#endif

#ifdef BRANCH_LESS_CODE
	uint32_t* bl_tnt_memory;
	uint64_t bl_pos;
	uint64_t bl_max;
	uint64_t bl_tnt;
#endif
} tnt_cache_t;

uint64_t get_tnt_hash(tnt_cache_t* self);

tnt_cache_t* tnt_cache_init(void);
void tnt_cache_destroy(tnt_cache_t* self);
void tnt_cache_flush(tnt_cache_t* self);


bool is_empty_tnt_cache(tnt_cache_t* self);
int count_tnt(tnt_cache_t* self);
uint8_t process_tnt_cache(tnt_cache_t* self);

void append_tnt_cache(tnt_cache_t* self, uint8_t data);
void append_tnt_cache_ltnt(tnt_cache_t* self, uint64_t data);

void adjust_tnt_cache(tnt_cache_t* self, uint8_t num);
