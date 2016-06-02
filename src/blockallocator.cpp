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
