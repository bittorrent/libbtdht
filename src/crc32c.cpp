/* crc32c.c -- compute CRC-32C using the Intel crc32 instruction
 * Copyright (C) 2013 Mark Adler
 * Version 1.1  1 Aug 2013  Mark Adler
 */

/*
  This software is provided 'as-is', without any express or implied
  warranty.  In no event will the author be held liable for any damages
  arising from the use of this software.

  Permission is granted to anyone to use this software for any purpose,
  including commercial applications, and to alter it and redistribute it
  freely, subject to the following restrictions:

  1. The origin of this software must not be misrepresented; you must not
     claim that you wrote the original software. If you use this software
     in a product, an acknowledgment in the product documentation would be
     appreciated but is not required.
  2. Altered source versions must be plainly marked as such, and must not be
     misrepresented as being the original software.
  3. This notice may not be removed or altered from any source distribution.

  Mark Adler
  madler@alumni.caltech.edu
 */

/* Use hardware CRC instruction on Intel SSE 4.2 processors.  This computes a
   CRC-32C, *not* the CRC-32 used by Ethernet and zip, gzip, etc.  A software
   version is provided as a fall-back, as well as for speed comparisons. */

/* Version history:
   1.0  10 Feb 2013  First version
   1.1   1 Aug 2013  Correct comments on why three crc instructions in parallel
 */

//#include<iostream>
/* CRC-32C (iSCSI) polynomial in reversed bit order. */
#include "utypes.h"
#include <stdint.h>
#define POLY 0x82f63b78

/* Table for a quadword-at-a-time software crc. */
//static pthread_once_t crc32c_once_sw = PTHREAD_ONCE_INIT;
static uint32 crc32c_table[256];

/* Construct table for software CRC-32C calculation. */
static void crc32c_init(void)
{
    uint32 n, crc;

    for (n = 0; n < 256; n++) {
        crc = n;
        crc = crc & 1 ? (crc >> 1) ^ POLY : crc >> 1;
        crc = crc & 1 ? (crc >> 1) ^ POLY : crc >> 1;
        crc = crc & 1 ? (crc >> 1) ^ POLY : crc >> 1;
        crc = crc & 1 ? (crc >> 1) ^ POLY : crc >> 1;
        crc = crc & 1 ? (crc >> 1) ^ POLY : crc >> 1;
        crc = crc & 1 ? (crc >> 1) ^ POLY : crc >> 1;
        crc = crc & 1 ? (crc >> 1) ^ POLY : crc >> 1;
        crc = crc & 1 ? (crc >> 1) ^ POLY : crc >> 1;
        crc32c_table[n] = crc;
    }
}

static struct init_crc32c 
{
	init_crc32c()
	{
		crc32c_init();
	}
} initialize_crc32c_table;

/* Table-driven software version as a fall-back.  This is about 15 times slower
   than using the hardware instructions.  This assumes little-endian integers,
   as is the case on Intel processors that the assembler code here is for. */

uint32 crc32c(const unsigned char *buf, uint32 len=4)
{
    const unsigned char *next = buf;
    uint64 crc;
	crc = 0xffffffff;
    while (len && ((uintptr_t)next & 7) != 0) {
        crc = crc32c_table[(crc ^ *next++) & 0xff] ^ (crc >> 8);
        len--;
    }
	while (len) {
        crc = crc32c_table[(crc ^ *next++) & 0xff] ^ (crc >> 8);
        len--;
    }
    return (uint32)crc ^ 0xffffffff;
}
