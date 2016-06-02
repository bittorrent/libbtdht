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

#include "TestDHT.h"

TEST(secure_dht_id_test, secure_dht_id_test) {

	byte Id_1[20], Id_2[20];
	SockAddr addr_1 = SockAddr::parse_addr("4.3.2.1");
	SockAddr addr_2 = SockAddr::parse_addr("[2001:420:80:1::5]");

	for( int i = 0;  i <5;  i++) {
		DhtCalculateHardenedID(addr_1, Id_1);
		DhtCalculateHardenedID(addr_2, Id_2);
		EXPECT_TRUE(DhtVerifyHardenedID(addr_1, Id_1));
		EXPECT_TRUE(DhtVerifyHardenedID(addr_2, Id_2));
		EXPECT_TRUE(!DhtVerifyHardenedID(addr_2, Id_1));
		EXPECT_TRUE(!DhtVerifyHardenedID(addr_1, Id_2));
		addr_1._sin4++;
		addr_2._sin4++;
	}

	char const* ips[] = {
		"124.31.75.21",
		"21.75.31.124",
		"65.23.51.170",
		"84.124.73.14",
		"43.213.53.83"
	};

	uint8 seeds[] = { 1, 86, 22, 65, 90 };

	uint8 prefixes[][4] = {
		{ 0x5f, 0xbf, 0xbf },
		{ 0x5a, 0x3c, 0xe9 },
		{ 0xa5, 0xd4, 0x32 },
		{ 0x1b, 0x03, 0x21 },
		{ 0xe5, 0x6f, 0x6c },
	};

	uint8 mask[3] = { 0xff, 0xff, 0xf8 };


	for (int i = 0; i < 5; ++i) {
		SockAddr addr = SockAddr::parse_addr(ips[i]);
		uint32 id = generate_node_id_prefix(addr, seeds[i]);
		int bits_to_shift = 24;
		for (int j = 0; j < 3; ++j) { 
			EXPECT_EQ(prefixes[i][j] & mask[j] , (byte)((id>>bits_to_shift) & 0xff) & mask[j]);
			bits_to_shift -= 8;
		}
	}
}
