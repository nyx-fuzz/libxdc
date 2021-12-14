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

#include "tnt_cache.h"
#include <assert.h>
#include <sys/mman.h>
#include <string.h>

//#define DEBUG

#define BIT(x)				(1ULL << (x))

#if defined(__x86_64__)

static inline uint8_t bsr(uint64_t x){
        asm ("bsrq %0, %0" : "=r" (x) : "0" (x));
        return x;
}

#elif defined(__aarch64__)

static inline uint32_t clz(uint32_t x){
        __asm__( "clz %w0, %w1" : "=r" ( x ) : "r" ( x ) );
        return x;
}

static inline uint8_t bsr(uint64_t x){
        uint32_t l = 31-clz(x);
        uint32_t h = 1-clz(x>>32);
        return (x & 0xFFFFFFFF00000000ULL) ? h : l;
}

#else
#error "Unsupported architecture!"
#endif

#define TNT_HASH_SPLIT_VALUE_BITS 58
#define TNT_HASH_SPLIT_COUNT_BITS 6

uint64_t get_tnt_hash(tnt_cache_t* self){
	uint64_t count = 0;
	uint64_t value = 0;


	if(self->bl_tnt == 0){
		self->bl_max = 0;
		self->bl_pos = 0;
		// fast path 
		return 0;
	}
	
	count = (self->bl_tnt/TNT_HASH_SPLIT_VALUE_BITS) != 0 ? TNT_HASH_SPLIT_VALUE_BITS : self->bl_tnt;
	//count = (TNT_HASH_SPLIT_VALUE_BITS*!!(self->bl_tnt/TNT_HASH_SPLIT_VALUE_BITS)) | (self->bl_tnt*!!!(self->bl_tnt/TNT_HASH_SPLIT_VALUE_BITS));

	/*
	for(int i = 0; i < count; i++){
		uint8_t res =  !!((BIT(31) >> ((self->bl_pos+i)%32)) & self->bl_tnt_memory[((self->bl_pos+i)/32)%BL_BUF_ENTRIES]);
		value2 |= res;
		value2 <<= 1;
	}
	value2 >>= 1;
	return (count << TNT_HASH_SPLIT_VALUE_BITS) | value2;
	*/

	//value >>= 58-count;
	//fprintf(stderr, "=> %lx\n", value);
	

	//fprintf(stderr, "count: %d\n", count);
	uint8_t bits_1 = 32 - (self->bl_pos%32); 	

	uint8_t tmp1 = (TNT_HASH_SPLIT_VALUE_BITS-bits_1)%32;
	uint8_t tmp2 = !!((TNT_HASH_SPLIT_VALUE_BITS-bits_1)/32);
	uint8_t bits_2 = (32*tmp2) | (tmp1*(!tmp2));

	uint8_t bits_3 = TNT_HASH_SPLIT_VALUE_BITS-(bits_1+bits_2);

	uint32_t value_1 = self->bl_tnt_memory[((self->bl_pos/32)+0)%BL_BUF_ENTRIES];
	uint32_t value_2 = self->bl_tnt_memory[((self->bl_pos/32)+1)%BL_BUF_ENTRIES];
	uint32_t value_3 = self->bl_tnt_memory[((self->bl_pos/32)+2)%BL_BUF_ENTRIES];

	/* mask + shift */
	value = (((uint64_t)value_1) & (0xFFFFFFFF >> (32-bits_1))) << (TNT_HASH_SPLIT_VALUE_BITS-bits_1); /* done und passt! */
	//fprintf(stderr, "(1) bits: %d\t% x (%lx)\n", bits_1, value_1, value);
	value |= ((((uint64_t)value_2) & (0xFFFFFFFF << (32-bits_2))) << (TNT_HASH_SPLIT_VALUE_BITS-bits_2-bits_1)) >> (32-bits_2);  /* done! */
	//fprintf(stderr, "(2) bits: %d\t% x (%lx)\n", bits_2, value_2, ((uint64_t)value_2) & (0xFFFFFFFF << (32-bits_2))) ;
	value |= ((((uint64_t)value_3) & (0xFFFFFFFF << ((32-bits_3)&0x1F))) >> (32-bits_3)); /* don't shift */
	//fprintf(stderr, "(3) bits: %d\t% x (%lx)\n", bits_3, value_3, ((uint64_t)value_3) & (0xFFFFFFFF << (32-bits_3)));

	value >>= (TNT_HASH_SPLIT_VALUE_BITS-count);

	/*
	if(value != value2){
		printf("VALUE MISMATCH %lx vs %lx\n", value, value2);
		abort();
	}
	*/

	//fprintf(stderr, "=> %lx\n", value);
	//assert(value < 0x400000000000000ULL);
	return (count << TNT_HASH_SPLIT_VALUE_BITS) | value;
}	


#ifdef NON_BRANCH_LESS_CODE
static inline uint8_t process_tnt_cache_nbl(tnt_cache_t* self){
	uint8_t result;
	if (self->tnt){
		result = self->tnt_memory[self->pos];
		self->tnt--;
		self->pos = (self->pos + 1) % BUF_SIZE;
#ifdef DEBUG
		printf("-> %d\n", result);
#endif
		return result;
	}
	return TNT_EMPTY;
}

static inline void append_tnt_cache_nbl(tnt_cache_t* self, uint8_t data){
	uint8_t bits = bsr(data)-SHORT_TNT_OFFSET;
	for(uint8_t i = SHORT_TNT_OFFSET; i < bits+SHORT_TNT_OFFSET; i++){
#ifdef DEBUG
		printf("%x\n", ((data) & BIT(i)) >> i);
#endif
		self->tnt_memory[((self->max+bits-i)%BUF_SIZE)] = ((data) & BIT(i)) >> i;
	}

	self->tnt += bits;
	assert(self->tnt < BUF_SIZE);
	self->max = (self->max + bits) % BUF_SIZE;
}
#endif

#ifdef BRANCH_LESS_CODE
static inline uint8_t process_tnt_cache_bl(tnt_cache_t* self){
	if(self->bl_tnt){
	  uint8_t res =  !!((BIT(31) >> (self->bl_pos%32)) & self->bl_tnt_memory[(self->bl_pos/32)%BL_BUF_ENTRIES]);
		self->bl_tnt--;
		self->bl_pos = (self->bl_pos + 1) % (BUF_SIZE);
		return res;
	}
	self->bl_max = 0;
	self->bl_pos = 0;
	return TNT_EMPTY;
}

static inline void append_tnt_cache_bl(tnt_cache_t* self, uint8_t data){
	uint8_t bits = bsr(data)-SHORT_TNT_OFFSET;
	uint64_t offset = (self->bl_tnt+self->bl_pos);
	
	uint64_t tmp_data = (((uint64_t)data) << (64-bits-SHORT_TNT_OFFSET)) >> (offset%32);
	uint64_t tmp_value = (((uint64_t)self->bl_tnt_memory[(offset/32)%BL_BUF_ENTRIES]) << 32) | (uint64_t)self->bl_tnt_memory[((offset/32)+1)%BL_BUF_ENTRIES];
	uint64_t result = (tmp_value & ~(0xFFFFFFFFFFFFFFFFULL >> (offset%32))) | tmp_data;

	self->bl_tnt_memory[(offset/32)%BL_BUF_ENTRIES] = result >> 32;
	self->bl_tnt_memory[((offset/32)+1)%BL_BUF_ENTRIES] = result & 0xFFFFFFFFULL;
	self->bl_tnt += bits;
}
#endif


uint8_t process_tnt_cache(tnt_cache_t* self){
#if defined(NON_BRANCH_LESS_CODE) && defined(BRANCH_LESS_CODE)
	assert(self->tnt == self->bl_tnt);
	uint8_t result_a = process_tnt_cache_nbl(self);
	uint8_t result_b = process_tnt_cache_bl(self);
	assert(result_a == result_b);
	return result_b;
#endif

#ifdef NON_BRANCH_LESS_CODE
	return process_tnt_cache_nbl(self);
#endif
#ifdef BRANCH_LESS_CODE
	return process_tnt_cache_bl(self);
#endif
}

void append_tnt_cache(tnt_cache_t* self, uint8_t data){
#ifdef NON_BRANCH_LESS_CODE
	append_tnt_cache_nbl(self, data);
#endif
#ifdef BRANCH_LESS_CODE
	append_tnt_cache_bl(self, data);
#endif
}

void append_tnt_cache_ltnt(tnt_cache_t* self, uint64_t data){
#ifdef NON_BRANCH_LESS_CODE
	uint8_t bits = bsr(data)-LONG_TNT_MAX_BITS;
	for(uint8_t i = LONG_TNT_MAX_BITS; i < bits+LONG_TNT_MAX_BITS; i++){
		self->tnt_memory[((self->max+bits-i)%BUF_SIZE)] = ((data) & BIT(i)) >> i;
	}

	self->tnt += bits;
	assert(self->tnt < BUF_SIZE);
	self->max = (self->max + bits) % BUF_SIZE;
#endif

#ifdef BRANCH_LESS_CODE
	assert(0);
#endif
}	

bool is_empty_tnt_cache(tnt_cache_t* self){
#ifdef NON_BRANCH_LESS_CODE
	return self->tnt == 0;
#endif
#ifdef BRANCH_LESS_CODE
	return self->bl_tnt == 0;
#endif
}

int count_tnt(tnt_cache_t* self){
#ifdef NON_BRANCH_LESS_CODE
	return self->tnt;
#endif
#ifdef BRANCH_LESS_CODE
	return self->bl_tnt;
#endif
}

tnt_cache_t* tnt_cache_init(void){
	tnt_cache_t* self = malloc(sizeof(tnt_cache_t));
#ifdef NON_BRANCH_LESS_CODE
	self->tnt_memory = (uint8_t*)mmap(NULL, BUF_SIZE, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, 0, 0);
	self->max = 0;
	self->pos = 0;
	self->tnt = 0;
#endif

#ifdef BRANCH_LESS_CODE
	self->bl_tnt_memory = (uint32_t*)mmap(NULL, BUF_SIZE/8, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, 0, 0);
	self->bl_max = 0;
	self->bl_pos = 0;
	self->bl_tnt = 0;
#endif

	return self;
}

void tnt_cache_flush(tnt_cache_t* self){
#ifdef NON_BRANCH_LESS_CODE
	self->max = 0;
	self->pos = 0;
	self->tnt = 0;
#endif

#ifdef BRANCH_LESS_CODE
	self->bl_max = 0;
	self->bl_pos = 0;
	self->bl_tnt = 0;
#endif
}

void tnt_cache_destroy(tnt_cache_t* self){
#ifdef NON_BRANCH_LESS_CODE
	munmap(self->tnt_memory, BUF_SIZE);
	self->max = 0;
	self->pos = 0;
	self->tnt = 0;
#endif

#ifdef BRANCH_LESS_CODE
	munmap(self->bl_tnt_memory, BUF_SIZE/8);
	self->bl_max = 0;
	self->bl_pos = 0;
	self->bl_tnt = 0;
#endif

	free(self);
}

void adjust_tnt_cache(tnt_cache_t* self, uint8_t num){
	if (num > self->bl_tnt){
		num = self->bl_tnt;
	}

	self->bl_tnt -= num;
	self->bl_pos = (self->bl_pos + num) % (BUF_SIZE);
}

