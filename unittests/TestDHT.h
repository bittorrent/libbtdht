#pragma once
#undef _M_CEE_PURE
#undef new

// TODO: SCOPED_TRACE, ASSERT_NO_FATAL_FAILURE
#if __cplusplus < 201103L
#define override
#endif

#include <fstream>
#include <arpa/inet.h>

#include <boost/uuid/sha1.hpp>
using namespace boost::uuids::detail;

#include "gtest/gtest.h"
#include "gmock/gmock.h"
using namespace ::testing;

#include "utypes.h"
#include "endian_utils.h"
#include "dht.h"
#include "DhtImpl.h"
#include "bencoding.h"
#include "sha1_hash.h"
#include "UnitTestUDPSocket.h"

// constant values to use in the dht under test
const std::string DHTID_BYTES("AAAABBBBCCCCDDDDEEEE"); // the dht ID should be 20 bytes (characters) long.

// defined in DhtImpl.cpp
extern bool DhtVerifyHardenedID(const SockAddr& addr, byte const* node_id, DhtSHACallback* sha);
extern void DhtCalculateHardenedID(const SockAddr& addr, byte *node_id, DhtSHACallback* sha);

// defined in dht.cpp
extern sha1_hash generate_node_id_prefix(const SockAddr& addr, int random, DhtSHACallback* sha);

// utility objects
inline sha1_hash sha1_callback(const byte* buf, int len)
{
	sha1 hash;
	unsigned int digest[5];
	hash.process_bytes(buf, len);
	hash.get_digest(digest);
	for(unsigned short i = 0; i < 5; i++) {
		digest[i] = htonl(digest[i]);
	}
	sha1_hash ret(reinterpret_cast<byte*>(digest));
	return ret;
}

class dht_test : public Test {
	protected:
		virtual void SetUp() {}
		virtual void TearDown() {}
};
