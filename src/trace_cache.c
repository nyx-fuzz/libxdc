
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

#include <assert.h>
#include <string.h>
#include "trace_cache.h"
#include "mmh3.h"

tracelet_cache_tmp_t* new_tracelet_cache(size_t bitmap_size){

	tracelet_cache_tmp_t* self = malloc(sizeof(tracelet_cache_tmp_t));
	self->cache.next_entry_address = 0;
	self->cache.tnt_bits = 0;
	self->cache.result_bits = 0;
	self->cache.result_bits_max = MAX_RESULTS_PER_CACHE;
	self->cache.bitmap_results = malloc(sizeof(uint32_t)*MAX_RESULTS_PER_CACHE);

	self->lookup_bitmap = malloc(sizeof(uint8_t)*bitmap_size);
	memset(self->lookup_bitmap, 0x0, bitmap_size);

	return self;
}

void tracelet_cache_tmp_destroy(tracelet_cache_tmp_t* self){
	free(self->cache.bitmap_results);
	free(self->lookup_bitmap);
	free(self);
}

void set_next_entry_addres_tracelet_cache(tracelet_cache_t* self, uint64_t next_entry_address){
	self->next_entry_address = next_entry_address;
}


void reset_tracelet_tmp_cache(tracelet_cache_tmp_t* self){
	self->cache.next_entry_address = 0xFFFFFFFFFFFFFFFFULL;

	for(uint8_t i = 0; i < self->cache.result_bits; i++){
		self->lookup_bitmap[self->cache.bitmap_results[i]] = 0;
	}

	self->cache.tnt_bits = 0;
	self->cache.result_bits = 0;
}


static inline uint64_t mix_bits(uint64_t v) {
  v ^= (v >> 31);
  v *= 0x7fb5d329728ea185;
  /*
  v ^= (v >> 27);
  v *= 0x81dadef4bc2dd44d;
  v ^= (v >> 33);
  */
  return v;
}

static uint32_t generate_result_offset(uint64_t from, uint64_t to){
	uint32_t transition_value = mix_bits(to)^(mix_bits(from)>>1);
	return transition_value;
}

fuzz_bitmap_t* net_fuzz_bitmap(uint8_t* bitmap, uint32_t bitmap_size){
	fuzz_bitmap_t* self = malloc(sizeof(fuzz_bitmap_t));
	self->bitmap = bitmap;
	self->bitmap_size = bitmap_size;
	return self;
}

void add_result_tracelet_cache(tracelet_cache_tmp_t* self, uint64_t from, uint64_t to, fuzz_bitmap_t* fuzz_bitmap){
	assert(self->cache.result_bits < self->cache.result_bits_max);

	uint32_t offset = generate_result_offset(from, to) & (fuzz_bitmap->bitmap_size-1);

	if(!self->lookup_bitmap[offset]){
		self->cache.bitmap_results[self->cache.result_bits++] = offset;
	}

	//fprintf(stderr, "-> %lx %d\n", offset, self->cache.result_bits);

	self->lookup_bitmap[offset]++;
	self->cache.tnt_bits++;
}

tracelet_cache_t* new_from_tracelet_cache_tmp(tracelet_cache_tmp_t* tmp_cache, bool cont_exec){
	tracelet_cache_t* new = malloc(sizeof(tracelet_cache_t));

	new->next_entry_address = tmp_cache->cache.next_entry_address;
	new->tnt_bits = tmp_cache->cache.tnt_bits;
	//fprintf(stderr, "%s %d!\n", __func__, tmp_cache->cache.tnt_bits);
	new->result_bits = tmp_cache->cache.result_bits;
	new->result_bits_max = new->result_bits;
	/* replace this one later */
	new->bitmap_results = malloc(sizeof(uint32_t)*tmp_cache->cache.result_bits);
	new->cont_exec = cont_exec;
	//fprintf(stderr, "result_bits: %d\n", tmp_cache->cache.result_bits);
	//memcpy(new->bitmap_results, tmp_cache->cache.bitmap_results, sizeof(uint32_t)*new->result_bits);


	for(uint8_t i = 0; i < tmp_cache->cache.result_bits; i++){
		uint32_t offset = tmp_cache->cache.bitmap_results[i];
		uint32_t result = tmp_cache->lookup_bitmap[offset] << 24;
		new->bitmap_results[i] = result | offset;
	}


	return new;
}

void tracelet_cache_destroy(tracelet_cache_t* self){
	free(self->bitmap_results);
	free(self);
}

uint64_t apply_trace_cache_to_bitmap(tracelet_cache_t* self, tnt_cache_t* tnt_cache_state, bool adjust, fuzz_bitmap_t* fuzz_bitmap){
	
	for(uint8_t i = 0; i < self->result_bits; i++){
		
		uint8_t result = self->bitmap_results[i] >> 24;
		uint32_t offset = self->bitmap_results[i] & 0xFFFFFF;
		fuzz_bitmap->bitmap[offset] += result;
		
	}
	
	if(adjust){
		adjust_tnt_cache(tnt_cache_state, self->tnt_bits);
	}

	return self->next_entry_address;
}

uint32_t fuzz_bitmap_get_size(fuzz_bitmap_t* self){
	return self->bitmap_size;
}

void fuzz_bitmap_reset(fuzz_bitmap_t* self){
	if(self){
    //fprintf(stderr, "%s: %lx %lx\n", __func__, fuzz_bitmap, fuzz_bitmap_size);
		memset(self->bitmap, 0x00, self->bitmap_size);
	}
}

uint64_t fuzz_bitmap_get_hash(fuzz_bitmap_t* self){
	if(self){
		uint64_t hash[2];
		mmh3_x64_128(self->bitmap, self->bitmap_size, 0xaaaaaaaa, &hash);

		return hash[0];
	}
	return 0;
}

void fuzz_bitmap_set(fuzz_bitmap_t* self, uint64_t from, uint64_t to){
	uint32_t transition_value = 0;
	if(self){		
		transition_value = mix_bits(to)^(mix_bits(from)>>1);	

		self->bitmap[transition_value & (self->bitmap_size-1)]++;
	}
}

uint8_t* fuzz_bitmap_get_ptr(fuzz_bitmap_t* self){
	return self->bitmap;
}


trace_cache_t* trace_cache_new(size_t bitmap_size){
	trace_cache_t* self = malloc(sizeof(trace_cache_t));
	self->lookup = kh_init(TRACE_CACHE);
	self->trace_cache = new_tracelet_cache(bitmap_size);
	return self;
}

void trace_cache_destroy(trace_cache_t* self){
	khiter_t k;
	for (k = kh_begin(self->lookup); k != kh_end(self->lookup); ++k){
		if (kh_exist(self->lookup, k)){
			tracelet_cache_destroy(kh_value(self->lookup, k));
		}
	}

	kh_destroy(TRACE_CACHE, self->lookup);
	tracelet_cache_tmp_destroy(self->trace_cache);
	free(self);
}

void trace_cache_add(trace_cache_t* self, trace_cache_key_t key, tracelet_cache_t* tracelet){
	khiter_t k;
	int ret;
	k = kh_get(TRACE_CACHE, self->lookup, key); 
	if(k == kh_end(self->lookup)){
		k = kh_put(TRACE_CACHE, self->lookup, key, &ret); 
		kh_value(self->lookup, k) = tracelet;
	}
	else{
		fprintf(stderr, "KEY EXITS\n");
	}
	return;
}

tracelet_cache_t* trace_cache_fetch(trace_cache_t* self, trace_cache_key_t key){
	khiter_t k;
	//int ret;
	k = kh_get(TRACE_CACHE, self->lookup, key); 
	if(k != kh_end(self->lookup)){
		return kh_value(self->lookup, k);
	}
	//fprintf(stderr, "%s not found\n", __func__);
	return NULL;
}


