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
#include "tnt_cache.h"
#include "trace_cache.h"
#include "decoder.h"
#include "disassembler.h"
#include "libxdc.h"
#include "core.h"


#define LIBXDC_RELEASE_VERSION 2

__attribute__ ((visibility ("default")))  uint16_t libxdc_get_release_version(void){
  return LIBXDC_RELEASE_VERSION;
}

__attribute__ ((visibility ("default")))  void libxdc_reset_trace_cache(libxdc_t* self){
  reset_trace_cache(self->disassembler);
}

/*
Initlizes basic data structeres and expects function pointers to specific functions. 
*/
__attribute__ ((visibility ("default")))  libxdc_t* libxdc_init(uint64_t filter[4][2], void* (*page_cache_fetch_fptr)(void*, uint64_t, bool*), void* page_cache_fetch_opaque, void* bitmap_ptr, size_t bitmap_size){
  
  if (filter[0][0] == 0 && filter[0][1] == 0 && 
    filter[1][0] == 0 && filter[1][1] == 0 && 
    filter[2][0] == 0 && filter[2][1] == 0 && 
    filter[3][0] == 0 && filter[3][1] == 0){
      fprintf(stderr, "libxdc error: empty filter configuration passed!\n");
      return (void*)-1;
  }
  
  libxdc_t* self = malloc(sizeof(libxdc_t));
  memset(self, 0, sizeof(libxdc_t));

  self->fuzz_bitmap = net_fuzz_bitmap(bitmap_ptr, bitmap_size);
  self->decoder = pt_decoder_init();
  self->disassembler = init_disassembler(filter, page_cache_fetch_fptr, page_cache_fetch_opaque, self->fuzz_bitmap);

  if ( !self->disassembler )
  {
    libxdc_free(self);
    return NULL;
  }

  self->decoder->disassembler_state = self->disassembler;

  fuzz_bitmap_reset(self->fuzz_bitmap);

  return self;
}

/* register rq handler */
__attribute__ ((visibility ("default")))  void libxdc_register_bb_callback(libxdc_t* self,  void (*basic_block_callback)(void*, disassembler_mode_t, uint64_t, uint64_t), void* basic_block_callback_opaque){
  assert(self);
  self->disassembler->basic_block_callback = basic_block_callback;
  self->disassembler->basic_block_callback_opaque = basic_block_callback_opaque;
}

/* register rq handler */
__attribute__ ((visibility ("default")))  void libxdc_register_edge_callback(libxdc_t* self,  void (*edge_callback)(void*, disassembler_mode_t, uint64_t, uint64_t), void* edge_callback_opaque){
  assert(self);
  self->disassembler->trace_edge_callback = edge_callback;
  self->disassembler->trace_edge_callback_opaque = edge_callback_opaque;
}

/* register rq handler */
__attribute__ ((visibility ("default")))  void libxdc_register_ip_callback(libxdc_t* self,  void (*ip_callback)(void*, disassembler_mode_t, uint64_t), void* ip_callback_opaque){
  assert(self);
  self->decoder->ip_callback = ip_callback;
  self->decoder->ip_callback_opaque = ip_callback_opaque;
} 

/* enable rq tracing */
__attribute__ ((visibility ("default")))  void libxdc_enable_tracing(libxdc_t* self){
  self->disassembler->trace_mode = true;
}

/* disable rq tracing */
__attribute__ ((visibility ("default")))  void libxdc_disable_tracing(libxdc_t* self){
  self->disassembler->trace_mode = false;
}

/* get bitmap hash */
__attribute__ ((visibility ("default")))  uint64_t libxdc_bitmap_get_hash(libxdc_t* self){
  return fuzz_bitmap_get_hash(self->fuzz_bitmap);
}

__attribute__ ((visibility ("default"))) void libxdc_bitmap_reset(libxdc_t* self){
  fuzz_bitmap_reset(self->fuzz_bitmap);
}

/* decode trace */
__attribute__ ((visibility ("default"))) decoder_result_t libxdc_decode(libxdc_t* self, uint8_t* data, size_t len){
  assert(data[len] == 0x55);
  return decode_buffer(self->decoder, data, len);
}

/* get page fault addr */
__attribute__ ((visibility ("default")))  uint64_t libxdc_get_page_fault_addr(libxdc_t* self){
  return pt_decoder_get_page_fault_addr(self->decoder);
}

__attribute__ ((visibility ("default")))  void libxdc_free(libxdc_t* self){
  destroy_disassembler(self->disassembler);
  pt_decoder_destroy(self->decoder);
  free(self->fuzz_bitmap);
  free(self);
}
