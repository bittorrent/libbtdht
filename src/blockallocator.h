// This is only used by the DHT, and is kind of silly.
#ifndef __BLOCKALLOCATOR_H__
#define __BLOCKALLOCATOR_H__

#include "utypes.h"

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
