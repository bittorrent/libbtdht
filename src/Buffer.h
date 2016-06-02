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
