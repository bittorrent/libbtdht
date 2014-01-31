// Only used by the DHT.  Maybe could be replaced someday
// with something reasonable.
#include "blockallocator.h"
#include <stdlib.h> // for NULL and malloc()

template<typename T> T static inline exch(T &a, const T b) {
   const T t = a;
   a = b;
   return t;
}

void BlockAllocator::Grow()
{
	byte *block = new byte[int64(_size) * _grow];
	for(int i=_grow; --i>=0; ) {
		void *a = block + i * _size;
		*(void**)a = exch(_free, a);
	}
}

void *BlockAllocator::GetBlock()
{
	//	return malloc(_size);
	if (_free == NULL) Grow();
	return exch(_free, *(void**)_free);
}

void BlockAllocator::FreeBlock(void *a)
{
	*(void**)a = exch(_free, a);
	if(a != NULL && a != _free){
		free(a);
	}
}
