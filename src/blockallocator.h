/*
Copyright 2016 BitTorrent Inc

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// This is only used by the DHT, and is kind of silly.
#ifndef __BLOCKALLOCATOR_H__
#define __BLOCKALLOCATOR_H__

#include "utypes.h"
#include <stddef.h> // for NULL

struct BlockAllocator {
	BlockAllocator():_size(0),_grow(0), _free(NULL){}
	uint16 _size, _grow;
	void *_free;
	void Grow();
	void *GetBlock();
	void FreeBlock(void *a);
};

template<typename T> struct BlockAllocatorX : public BlockAllocator {

	T *Alloc() { return (T*)((BlockAllocator*)this)->GetBlock(); }
	void Free(T *a) { ((BlockAllocator*)this)->FreeBlock(a); }
};

#define MAKE_BLOCK_ALLOCATOR(name,T,grow) BlockAllocatorX<T> name = { sizeof(T), grow, NULL }

#endif	// __BLOCKALLOCATOR_H__
