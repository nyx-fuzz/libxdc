#ifndef _MMH3_H
#define _MMH3_H

#include <stdint.h>

__extension__ typedef unsigned __int128 uint128_t;

void mmh3_x86_32(const void *key, uint64_t len, uint32_t seed, void *out);
void mmh3_x86_128(const void *key, uint64_t len, uint32_t seed, void *out);
void mmh3_x64_128(const void *key, uint64_t len, uint32_t seed, void *out);

#endif
