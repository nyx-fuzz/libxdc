
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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE  
#endif


#include <errno.h>
#include <capstone/capstone.h>
#include <capstone/x86.h>
#include <sys/file.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/mman.h>
#include <assert.h>
#include "page_cache.h"



#define PAGE_SIZE 0x1000UL
#define PAGE_CACHE_ADDR_LINE_SIZE sizeof(uint64_t)

#define UNMAPPED_PAGE 0xFFFFFFFFFFFFFFFFULL


bool reload_addresses(page_cache_t* self){
	khiter_t k;
	int ret;
	uint64_t addr, offset;
	uint64_t value = 0;

	size_t self_offset = lseek(self->fd_address_file, 0, SEEK_END);

	if(self_offset != self->num_pages*PAGE_CACHE_ADDR_LINE_SIZE){
		//fprintf(stderr, "Reloading files ...\n");

		lseek(self->fd_address_file, self->num_pages*PAGE_CACHE_ADDR_LINE_SIZE, SEEK_SET);
		offset = self->num_pages;
		while(read(self->fd_address_file, &value, PAGE_CACHE_ADDR_LINE_SIZE)){
			addr = value & 0xFFFFFFFFFFFFF000ULL; 
			offset++;

			/* put new addresses and offsets into the hash map */
			k = kh_get(PC_CACHE, self->lookup, addr); 
			if(k == kh_end(self->lookup)){

				if(value & 0xFFF){
					fprintf(stderr, "Load page: %lx (UNMAPPED)\n", addr);
					//k = kh_put(PC_CACHE, self->lookup, addr, &ret); 
					//kh_value(self->lookup, k) = UNMAPPED_PAGE;
				}
				else{
					//fprintf(stderr, "Load page: %lx\n", addr);
					k = kh_put(PC_CACHE, self->lookup, addr, &ret); 
					kh_value(self->lookup, k) = (offset-1)*PAGE_SIZE;
				}

			}
			else{
				fprintf(stderr, "----------> Page duplicate found ...skipping! %lx\n", addr);
				//abort();
			}
		}


		/* reload page dump file */
		munmap(self->page_data, self->num_pages*PAGE_SIZE);
		self->num_pages = self_offset/PAGE_CACHE_ADDR_LINE_SIZE;
		self->page_data = mmap(NULL, (self->num_pages)*PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, self->fd_page_file, 0);

		return true;
	}

	return false;
}


bool append_page(page_cache_t* self, uint64_t page, uint8_t* ptr){
	self->last_page = 0xFFFFFFFFFFFFFFFF;
	self->last_addr = 0xFFFFFFFFFFFFFFFF;
	page &= 0xFFFFFFFFFFFFF000ULL;
	bool success = true;
	if(!self->num_pages){
		assert(!ftruncate(self->fd_page_file, (self->num_pages+1)*PAGE_SIZE));
		self->page_data = mmap(NULL, (self->num_pages+1)*PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, self->fd_page_file, 0);
	}
	else{
		munmap(self->page_data, self->num_pages*PAGE_SIZE);
		assert(!ftruncate(self->fd_page_file, (self->num_pages+1)*PAGE_SIZE));
		self->page_data = mmap(NULL, (self->num_pages+1)*PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, self->fd_page_file, 0);
	}

	memcpy(self->page_data+(PAGE_SIZE*self->num_pages), ptr, PAGE_SIZE);

	fsync(self->fd_page_file);

	int ret;
	khiter_t k;
	k = kh_put(PC_CACHE, self->lookup, page, &ret); 
	kh_value(self->lookup, k) = self->num_pages*PAGE_SIZE;
	assert(write(self->fd_address_file, &page, PAGE_CACHE_ADDR_LINE_SIZE) == PAGE_CACHE_ADDR_LINE_SIZE);

	self->num_pages++;

	return success;
}

static void page_cache_lock(page_cache_t* self){

}

static void page_cache_unlock(page_cache_t* self){

}

static bool update_page_cache(page_cache_t* self, uint64_t page, khiter_t* k){

	//#define DEBUG_PAGE_CACHE_LOCK

	page_cache_lock(self);
#ifdef DEBUG_PAGE_CACHE_LOCK
	fprintf(stderr, "%d: LOCKING PAGE CACHE\n", getpid());
#endif

	if(reload_addresses(self)){
		*k = kh_get(PC_CACHE, self->lookup, page); 
	}

	if(*k == kh_end(self->lookup)){
		//printf("PAGE NOT FOUND: %lx! ABORTING\n", page);
		page_cache_unlock(self);
		return false;
		abort();
	}
	
#ifdef DEBUG_PAGE_CACHE_LOCK
	fprintf(stderr, "%d: UNLOCKING PAGE CACHE\n", getpid());
#endif

	page_cache_unlock(self);
	return true;
}

void* page_cache_fetch(void* self_ptr, uint64_t page, bool* success){	
	page_cache_t* self = self_ptr; 
	page &= 0xFFFFFFFFFFFFF000ULL;
	bool test_mode = false;

	if (self->last_page == page){
		*success = true;
		return (void*)self->last_addr;
	}

	//QEMU_PT_PRINTF(PAGE_CACHE_PREFIX, "page_cache_fetch %lx", page);
	
	khiter_t k;
	k = kh_get(PC_CACHE, self->lookup, page); 
	if(k == kh_end(self->lookup)){
		if(test_mode || update_page_cache(self, page, &k) == false){
			*success = false;
			return 0;
		}
	}

	self->last_page = page;

	if(kh_value(self->lookup, k) == UNMAPPED_PAGE){
		self->last_addr = UNMAPPED_PAGE;
	}
	else{
		self->last_addr = (uint64_t)self->page_data+kh_value(self->lookup, k);
	}

	*success = true;
	return (void*)self->last_addr;
}


page_cache_t* page_cache_new(const char* cache_file){
	page_cache_t* self = malloc(sizeof(page_cache_t));

	char* tmp1;
	char* tmp2;
	char* tmp3;
	assert(asprintf(&tmp1, "%s.dump", cache_file) != -1);
	assert(asprintf(&tmp2, "%s.addr", cache_file) != -1);
	assert(asprintf(&tmp3, "%s.lock", cache_file) != -1);


	self->lookup = kh_init(PC_CACHE);
	self->fd_page_file = open(tmp1, O_CLOEXEC | O_RDWR, S_IRWXU);
	self->fd_address_file = open(tmp2, O_CLOEXEC | O_RDWR, S_IRWXU);

	if(self->fd_page_file == -1 || self->fd_address_file == -1){
		printf("[ ] Page cache files not found...\n");
		exit(1);
	}

	memset(self->disassemble_cache, 0x0, 16);

	self->page_data = NULL;
	self->num_pages = 0;

	self->last_page = 0xFFFFFFFFFFFFFFFF;
	self->last_addr = 0xFFFFFFFFFFFFFFFF;

	free(tmp3);
	free(tmp2);
	free(tmp1);

	return self;
}

void page_cache_destroy(page_cache_t* self){
	munmap(self->page_data, self->num_pages * 0x1000);
	kh_destroy(PC_CACHE, self->lookup);

	free(self);
}
