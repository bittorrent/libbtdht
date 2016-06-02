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

#pragma once
#undef _M_CEE_PURE
#undef new

// TODO: SCOPED_TRACE in all fixtured tests, for convenience
#if __cplusplus < 201103L && !defined _MSC_VER
#define override
#endif

#include <fstream>

#ifdef _WIN32
#include <winsock2.h>
#else
#include <arpa/inet.h>
#endif

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
// the dht ID should be 20 bytes (characters) long.
const std::string DHTID_BYTES("AAAABBBBCCCCDDDDEEEE");

// defined in DhtImpl.cpp
extern bool DhtVerifyHardenedID(const SockAddr& addr, byte const* node_id);
extern void DhtCalculateHardenedID(const SockAddr& addr, byte *node_id);

// defined in dht.cpp
extern uint32 generate_node_id_prefix(const SockAddr& addr, int random);

// utility objects
inline sha1_hash sha1_callback(const byte* buf, int len) {
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
