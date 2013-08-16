#ifndef __BUFFER__
#define __BUFFER__

#include "utypes.h"

struct Buffer
{
	byte *b;
	size_t len;

	Buffer() : b(NULL), len(0) {}
	Buffer(byte* buf, int l) : b(buf), len(l) {}
	byte operator [] (size_t i) const { return b[i]; }
};

#endif // __BUFFER__
