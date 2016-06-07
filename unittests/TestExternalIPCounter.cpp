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

#include "gtest/gtest.h"
#include <algorithm>
#include "ExternalIPCounter.h"
#include "sockaddr.h"
#include <sha1_hash.h>

#include <boost/uuid/sha1.hpp>
using namespace boost::uuids::detail;

struct ip_change_observer_test : ip_change_observer{
	bool flag;
	void on_ip_change(SockAddr const & new_ip)
	{
		flag = true;
		return;
	}
};

static const std::vector<const char*> src_addrs
{
    "10.10.10.10:10000",
    "20.10.10.10:20000",
    "30.10.10.10:10000",
    "40.10.10.10:20000",
};

static const std::vector<const char*> test_addrs
{
    "10.30.30.10:30000",
    "20.20.20.20:40000",
    "30.30.30.10:30000",
    "40.20.20.20:40000",
};

sha1_hash sha1_fun(const byte* buf, int len)
{
	sha1 hash;
	unsigned int digest[5];
	hash.process_bytes(buf, len);
	hash.get_digest(digest);
	for(short i = 0; i < 5; i++) {
		digest[i] = htonl(digest[i]);
	}
	sha1_hash ret(reinterpret_cast<byte*>(digest));
	return ret;
}

TEST(externalipcounter, trigger)
{
	ExternalIPCounter external_ip(&sha1_fun);
	ip_change_observer_test icot;
	external_ip.set_ip_change_observer(&icot);


	bool ok = false;
	
	// Create voter addresses
	SockAddr src_addr1 = SockAddr::parse_addr(src_addrs[0], &ok);
	ASSERT_TRUE(ok) << "Failed to parse: " << src_addrs[0];

	SockAddr src_addr2 = SockAddr::parse_addr(src_addrs[1], &ok);
	ASSERT_TRUE(ok) << "Failed to parse: " << src_addrs[1];
	
	SockAddr src_addr3 = SockAddr::parse_addr(src_addrs[2], &ok);
	ASSERT_TRUE(ok) << "Failed to parse: " << src_addrs[2];
	
	SockAddr src_addr4 = SockAddr::parse_addr(src_addrs[3], &ok);
	ASSERT_TRUE(ok) << "Failed to parse: " << src_addrs[3];

	// Create test addresses
	SockAddr addr1 = SockAddr::parse_addr(test_addrs[0], &ok);
	ASSERT_TRUE(ok) << "Failed to parse: " << test_addrs[0];

	SockAddr addr2 = SockAddr::parse_addr(test_addrs[1], &ok);
	ASSERT_TRUE(ok) << "Failed to parse: " << test_addrs[1];
	
	SockAddr addr3 = SockAddr::parse_addr(test_addrs[2], &ok);
	ASSERT_TRUE(ok) << "Failed to parse: " << test_addrs[2];
	
	SockAddr addr4 = SockAddr::parse_addr(test_addrs[3], &ok);
	ASSERT_TRUE(ok) << "Failed to parse: " << test_addrs[3];

	icot.flag = false;
	external_ip.CountIP(addr1, src_addr1, 10);
	external_ip.CountIP(addr2, src_addr2, 20);

	SockAddr sockAddr;
	external_ip.GetIP(sockAddr);

	ASSERT_EQ(sockAddr, addr2);
	ASSERT_FALSE(icot.flag);

	external_ip.CountIP(addr2, src_addr3, 60);
	ASSERT_FALSE(icot.flag);

	external_ip.CountIP(addr3, src_addr3, 60);
	external_ip.CountIP(addr4, src_addr4, 61);
	external_ip.GetIP(sockAddr);
	ASSERT_EQ(sockAddr, addr4);
	ASSERT_TRUE(icot.flag);

}
