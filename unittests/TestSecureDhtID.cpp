#include "TestDHT.h"

TEST(secure_dht_id_test, secure_dht_id_test) {
#ifdef WIN32
	// XXX: ouch. akelly in r20567 made me do this.
	extern DWORD _tls_index;
	extern bool _tls_set;
	_tls_index = TlsAlloc();
	EXPECT_TRUE(_tls_index != TLS_OUT_OF_INDEXES);
	_tls_set = true;
#endif

	byte Id_1[20], Id_2[20];
	SockAddr addr_1 = SockAddr::parse_addr("4.3.2.1");
	SockAddr addr_2 = SockAddr::parse_addr("[2001:420:80:1::5]");

	for( int i = 0;  i <5;  i++) {
		DhtCalculateHardenedID(addr_1, Id_1, sha1_callback);
		DhtCalculateHardenedID(addr_2, Id_2, sha1_callback);
		EXPECT_TRUE(DhtVerifyHardenedID(addr_1, Id_1, sha1_callback));
		EXPECT_TRUE(DhtVerifyHardenedID(addr_2, Id_2, sha1_callback));
		EXPECT_TRUE(!DhtVerifyHardenedID(addr_2, Id_1, sha1_callback));
		EXPECT_TRUE(!DhtVerifyHardenedID(addr_1, Id_2, sha1_callback));
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
		{ 0xf7, 0x66, 0xf9, 0xf5 },
		{ 0x7e, 0xe0, 0x47, 0x79 },
		{ 0x76, 0xa6, 0x26, 0xff },
		{ 0xbe, 0xb4, 0xe6, 0x19 },
		{ 0xac, 0xe5, 0x61, 0x3a },
	};

	for (int i = 0; i < 5; ++i) {
		SockAddr addr = SockAddr::parse_addr(ips[i]);
		sha1_hash id = generate_node_id_prefix(addr, seeds[i], sha1_callback);
		for (int j = 0; j < 4; ++j) {
			EXPECT_EQ(prefixes[i][j], id[j]);
		}
	}
}
