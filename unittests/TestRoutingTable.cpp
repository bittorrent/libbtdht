#include "TestDhtImpl.h"

DhtID random_id() {
	byte bytes[20];
	for (int i = 0; i < 20; ++i) {
		bytes[i] = rand() & 0xff;
	}
	DhtID id;
	CopyBytesToDhtID(id, bytes);
	return id;
}

SockAddr random_address() {
	SockAddr ret;
	memset(ret._in._in6, 0, 16);
	for (int i  = 12; i < 16; ++i) {
		ret._in._in6[i] = rand() & 0xff;
	}
	ret.set_port((rand() % 1000) + 1024);
	return ret;
}

class dht_routing_test : public dht_impl_test {
	protected:
		DhtID my_id;

		virtual void SetUp() override {
			dht_impl_test::SetUp();
			my_id = random_id();
			impl->SetId(my_id);
			impl->Enable(true, 0);
		}
};

TEST_F(dht_routing_test, TestRoutingTable) {
	// insert 128 random IDs uniformly distributed
	// all RTTs are 500, later we'll test to make sure we can replace
	// them with lower RTT nodes

	for (int i = 0; i < 256; ++i) {
		DhtID id = random_id();
		id.id[0] = (uint(i) << 24) | 0xffffff;

		DhtPeerID p;
		p.id = id;
		p.addr = random_address();
		DhtPeer* k = impl->Update(p, IDht::DHT_ORIGIN_INCOMING, true, 500);
		EXPECT_TRUE(k) << "a DHT node failed to be inserted";
	}

	EXPECT_EQ(256, impl->GetNumPeers()) <<
			"the number of nodes is not the number we inserted";
	EXPECT_EQ(32, impl->NumBuckets()) <<
			"the number buckets is supposed to be 32 still";

	// now, split the bucket
	DhtID id = random_id();
	// copy just the 8 most significant bits from our ID
	uint mask = 0xffffffff >> 8;
	id.id[0] &= mask;
	id.id[0] |= my_id.id[0] & ~mask;
	DhtPeerID p;
	p.id = id;
	p.addr = random_address();
	impl->Update(p, IDht::DHT_ORIGIN_INCOMING, true, 500);

	EXPECT_EQ(33, impl->NumBuckets()) <<
			"the number buckets is supposed to be 33";

	// TODO: somehow assert that there are 14 nodes in bucket 1 and 128 nodes
	// in bucket 0
}

TEST_F(dht_routing_test, TestDhtRestart) {
	// insert some nodes
	for (int i = 0; i < 10; ++i) {
		DhtPeerID p;
		p.id = random_id();
		p.addr = random_address();
		DhtPeer* k = impl->Update(p, IDht::DHT_ORIGIN_INCOMING, true, 500);
		EXPECT_TRUE(k) << "a DHT node failed to be inserted";
	}
	impl->Restart();
}
