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

/**
Test the routing table functionality of the DHT
*/


// if defined, the testcase requiring user input will be enabled
//#define INCLUDE_MANUAL_DEMO

#undef _M_CEE_PURE
#undef new

#include <fstream>

#include "gtest/gtest.h"
#include "gmock/gmock.h"

#include "dht.h"
#include "DhtImpl.h"
#include "bencoding.h"
#include "UnitTestUDPSocket.h"
#include <vector>

using namespace std;


//extern CRITICAL_SECTION g_csTickWrapping;

// constant values to use in the dht under test
const std::string DHTID_BYTES("AAAABBBBCCCCDDDDEEEE"); // the dht ID should be 20 bytes (characters) long.

//void Log_Init(void);

//extern void InitDHTTestEnvironment();

TEST(TestDhtStructs, TestDhtIDGetBit)
{
	DhtID testID;

	// test for a single bit
	for(int x=0; x<5; ++x) testID.id[x] = 0; // clear all bits to 0
	testID.id[4] = 0x08000000;  // set bit 27 to 1
	// see that only the one bit is set
	for(int x=0; x<160; ++x){
		if(x == 27)
			EXPECT_TRUE(testID.GetBit(x)); // see that we get true for the one bit we set
		else
			EXPECT_FALSE(testID.GetBit(x));
	}

	// test a block of bits crossing a word boundary
	for(int x=0; x<5; ++x) testID.id[x] = 0; // clear all bits to 0
	testID.id[1] = 0xf0000000;
	testID.id[0] = 0x0000000f;
	for(int x=0; x<160; ++x){
		if(x >= 124 && x <= 131) // if x is in the block of true bits that we set
			EXPECT_TRUE(testID.GetBit(x)) << "value of x:  " << x;
		else
			EXPECT_FALSE(testID.GetBit(x)) << "value of x:  " << x;
	}

}


TEST(TestDhtStructs, TestDhtPeerSubPrefixComputation)
{
	DhtPeer testPeer;
	for(int x=0; x<5; ++x) testPeer.id.id.id[x] = 0; // clear all bits to 0
	testPeer.id.id.id[0] = 0xaa00000f; // set some specific bits in the lower 32 bit word of the id

	// basic tests on the bit pattern 10101010  (0xaa)
	testPeer.ComputeSubPrefix(159, 3);
	ASSERT_EQ(2, testPeer.GetSubprefixInt());

	testPeer.ComputeSubPrefix(158, 3);
	ASSERT_EQ(5, testPeer.GetSubprefixInt());

	// test that it works if the combination of span and subPrefix size crosses a word boundary
	// tested on the 0x0000000f of id[4] and 0x00000000 if id[3]
	testPeer.ComputeSubPrefix(129, 3);
	ASSERT_EQ(4, testPeer.GetSubprefixInt());

	testPeer.ComputeSubPrefix(130, 3);
	ASSERT_EQ(6, testPeer.GetSubprefixInt());

	testPeer.ComputeSubPrefix(131, 3);
	ASSERT_EQ(7, testPeer.GetSubprefixInt());

	// test the case of the span being less than or equal to the number of bits in the sub prefix
	testPeer.id.id.id[4] = 0x0000000e;

	testPeer.ComputeSubPrefix(3, 3);
	ASSERT_EQ(6, testPeer.GetSubprefixInt());

	testPeer.ComputeSubPrefix(2, 3);
	ASSERT_EQ(2, testPeer.GetSubprefixInt());

	testPeer.ComputeSubPrefix(1, 3);
	ASSERT_EQ(0, testPeer.GetSubprefixInt());
}

void CountNodesInBuckets(vector<DhtBucket*> &buckets, vector<int> &peerCountOut, vector<int> &replacementCountOut)
{
	peerCountOut.clear();
	replacementCountOut.clear();
	for(int i = 0; i < buckets.size(); i++) {
		DhtPeer* p = buckets[i]->peers.first();
		int ctr = 0;
		while(p){
			ctr++;
			p = p->next;
		}
		peerCountOut.push_back(ctr);

		p = buckets[i]->replacement_peers.first();
		ctr = 0;
		while(p){
			ctr++;
			p = p->next;
		}
		replacementCountOut.push_back(ctr);
	}
}

void OutputBuckets(vector<DhtBucket*> &buckets)
{
	vector<int> nodeCounts;
	vector<int> replacementCounts;
	CountNodesInBuckets(buckets, nodeCounts, replacementCounts);

	int nctr=0; int rctr=0;
	printf("\nBucket\t#nodes\t#replace\tspan\n");
	for(int x=0; x<buckets.size(); x++){
		nctr+= nodeCounts[x]; rctr += replacementCounts[x];
		printf("%d\t%d\t%d\t\t%d\t", x, nodeCounts[x], replacementCounts[x], buckets[x]->span);

		for (DhtPeer* i = buckets[x]->peers.first(); i; i = i->next) {
			printf("(%d) ", i->rtt);
		}
		printf("\n");
	}
	printf("Total nodes=%d \tTotal replacements=%d\n",nctr,rctr);
}

/**
	This will collect all of the pointers to DhtPeer objects in a single list
	from both the peer nodes list and the replacement nodes list in all of 
	the buckets.
*/
void PutDhtPtrsAndIdsInLists(vector<DhtBucket*> &buckets, vector<DhtPeer*> &nodePtrs, vector<DhtID> &dhtIds)
{
	nodePtrs.clear();
	dhtIds.clear();
	for(int bucketNum = 0; bucketNum<buckets.size(); ++bucketNum)
	{
		DhtPeer* p = buckets[bucketNum]->peers.first();
		int ctr=0;
		// first add the main peer node poiinters
		while(p)
		{
			ctr++;
			nodePtrs.push_back(p);
			dhtIds.push_back(p->id.id);
			p = p->next;
			EXPECT_TRUE(ctr <= KADEMLIA_BUCKET_SIZE) << "Too many nodes in linked list for peers node list in bucket " << bucketNum;
		}
		// now add the replacement node pointers
		p = buckets[bucketNum]->replacement_peers.first();
		ctr=0;
		while(p)
		{
			ctr++;
			nodePtrs.push_back(p);
			dhtIds.push_back(p->id.id);
			p = p->next;
			EXPECT_TRUE(ctr <= KADEMLIA_BUCKET_SIZE) << "Too many nodes in linked list for replacement_peers node list in bucket " << bucketNum;
		}
	}
}

template<class T>
bool ListHasUniqueElements(const vector<T> &list)
{
	for(int x=0; x<list.size()-1; ++x)
	{
		for(int y=x+1; y<list.size(); ++y)
		{
			if(list[x] == list[y])
				return false;
		}
	}
	return true;
}

bool VerifyBuckets(vector<DhtBucket*> &buckets)
{
	for(int bucketNum = 0; bucketNum<buckets.size(); ++bucketNum)
	{
		// first check the active peers node list
		DhtPeer* p = buckets[bucketNum]->peers.first();
		int ctr=0;
		// first add the main peer node poiinters
		while(p)
		{
			// check the number of nodes in the bucket
			ctr++;
			if(ctr>KADEMLIA_BUCKET_SIZE){
				EXPECT_LE(ctr, KADEMLIA_BUCKET_SIZE) << "Too many nodes in linked list of bucket.peers list for bucket: " << bucketNum;
				return false;
			}

			// check the sub-prefix value (it should be calculated for any node that is in the bucket)
			if(p->GetSubprefixInt() < 0 || p->GetSubprefixInt() >= KADEMLIA_BUCKET_SIZE){
				EXPECT_TRUE(p->GetSubprefixInt() < 0 || p->GetSubprefixInt() >= KADEMLIA_BUCKET_SIZE) << "SubPrefix out of range (not set or computed) in bucket " << bucketNum << ".  Actual value:  " << p->GetSubprefixInt();
				return false;
			}

			p = p->next;
		}


		// now check the replacement node list
		p = buckets[bucketNum]->replacement_peers.first();
		ctr=0;
		while(p)
		{
			// check the number of nodes in the bucket
			ctr++;
			if(ctr>KADEMLIA_BUCKET_SIZE){
				EXPECT_LE(ctr, KADEMLIA_BUCKET_SIZE) << "Too many nodes in linked list of bucket.replacement_peers list for bucket: " << bucketNum;
				return false;
			}

			// check the sub-prefix value (it should be calculated for any node that is in the bucket)
			if(p->GetSubprefixInt() < 0 || p->GetSubprefixInt() >= KADEMLIA_BUCKET_SIZE){
				EXPECT_TRUE(p->GetSubprefixInt() < 0 || p->GetSubprefixInt() >= KADEMLIA_BUCKET_SIZE) << "SubPrefix out of range (not set or computed) in bucket " << bucketNum << ".  Actual value:  " << p->GetSubprefixInt();
				return false;
			}

			p = p->next;
		}
	}

	// all pointers to nodes in the buckets should be unique
	vector<DhtPeer*> nodePtrs;
	vector<DhtID> dhtIds;
	PutDhtPtrsAndIdsInLists(buckets, nodePtrs, dhtIds);
	if(!ListHasUniqueElements(nodePtrs)){
		EXPECT_TRUE(ListHasUniqueElements(nodePtrs)) << "There are duplicate DhtPeer*'s in the buckets";
		return false;
	}
	if(!ListHasUniqueElements(dhtIds)){
		EXPECT_TRUE(ListHasUniqueElements(dhtIds)) << "There are duplicate DhtID's in the buckets";
		return false;
	}

	return true;
}

void outputListValues(DhtBucketList &list)
{
	int rtt[8];
	int subPrefix[8];
	for(int x=0; x<8; ++x){
		rtt[x] = subPrefix[x] = -1;
	}

	int x=0;
	for (DhtPeer **peer = &list.first(); *peer; peer=&(*peer)->next, ++x) {
		DhtPeer *p = *peer;
		rtt[x] = p->rtt;
		subPrefix[x] = p->GetSubprefixInt();
	}
	EXPECT_TRUE(false) <<rtt[0]<<"  "<<rtt[1]<<"  "<<rtt[2]<<"  "<<rtt[3]<<"  "<<rtt[4]<<"  "<<rtt[5]<<"  "<<rtt[6]<<"  "<<rtt[7];
	EXPECT_TRUE(false) <<subPrefix[0]<<"  "<<subPrefix[1]<<"  "<<subPrefix[2]<<"  "<<subPrefix[3]<<"  "<<subPrefix[4]<<"  "<<subPrefix[5]<<"  "<<subPrefix[6]<<"  "<<subPrefix[7];
}

inline int GetBit(DhtID &id, int bitIndex)
{
	if (bitIndex >= 160 || bitIndex < 0)
		return 0;
	unsigned int wordIndex = 4-(bitIndex / 32);
	return (id.id[wordIndex] >> (bitIndex - (wordIndex * 32))) & 0x00000001;
}

inline void SetBit(DhtID &id, int bitIndex)
{
	if (bitIndex >= 160 || bitIndex < 0)
		return;
	unsigned int wordIndex = 4-(bitIndex / 32);
	id.id[wordIndex] |= 0x00000001 << (bitIndex - (wordIndex * 32));
}

inline void ClearBit(DhtID &id, int bitIndex)
{
	if (bitIndex >= 160 || bitIndex < 0)
		return;
	unsigned int wordIndex = 4-(bitIndex / 32);
	id.id[wordIndex] &= ~(0x00000001 << (bitIndex - (wordIndex * 32)));
}

inline void ProgramBit(DhtID &id, int bitIndex, bool value)
{
	if(value)
		SetBit(id, bitIndex);
	else
		ClearBit(id, bitIndex);
}

enum SubPrefixType
{
	evenBitDistribution,
	randomBitDistribution
};

/**
	Uses the dht's ID (myId) as the base for nodes to be added.  New nodes are always added
	to the bucket that contains myId thus forcing the split.  The dht buckets quit splitting
	once the span of the bucket containing myId reaches 3 (decending from 160).  At this
	there are only 8 possible ID's that can fill the 8 slots in the bucket.

	Note that the number of additions returned includes both new nodes added and existing
	nodes already in the list that are updated.
*/
int FillBucketList(smart_ptr<DhtImpl> &dhtObj, time_t rtt, SubPrefixType subPrefixType, int numPrefixBits = 0, int diff = 1)
{
	static uint32 ipCounter = 1;
	int added = 0;
	if(numPrefixBits >=160 || numPrefixBits < 0)
		return added;

	DhtID subPrefixBits;
	DhtPeerID peerId;
	peerId.addr.set_port(128);

	for(int ctr=0; ctr<16; ++ctr)
	{
		// copy myID
		for(int y=0; y<5; ++y)
			peerId.id.id[y] = dhtObj->_my_id.id[y];

		subPrefixBits.id[4] = subPrefixType==evenBitDistribution ? ctr : rand()*rand();
		if(subPrefixType==evenBitDistribution)
		{
			// move the counter bits (4 bits) into the bits immediatly following the prefix bits
			// the bit range is 0 -> 159
			for(int x=0; x<4; ++x)
			{
				ProgramBit(peerId.id, 159-numPrefixBits-x, GetBit(subPrefixBits, 3-x));
			}
		}
		else
		{
			for(int x=0; x<32; ++x)
			{
				ProgramBit(peerId.id, 159-numPrefixBits-x, GetBit(subPrefixBits, x));
			}
		}


		//dctr.id[4] = subPrefixType==evenBitDistribution ? ctr : rand()*rand();
		//// move the counter bits (4 bits) into the bits immediatly following the prefix bits
		//// the bit range is 0 -> 159
		//for(int x=0; x<32; ++x)
		//{
		//	ProgramBit(peerId.id, 159-numPrefixBits-x, GetBit(dctr, x));
		//}

		peerId.addr.set_addr4(ipCounter++);
		(dhtObj->Update(peerId, 0, true, rtt))? ++added:0;
	}
	added += FillBucketList(dhtObj, rtt, subPrefixType, numPrefixBits+diff, diff);

	return added;
}


int OverFillBuckets(smart_ptr<DhtImpl> &dhtObj, time_t rtt)
{
	int added = 0;
	DhtID dctr;
	DhtPeerID peerId;
	peerId.addr.set_port(128);
	int numPrefixBits;

	for(int bucketNum=0; bucketNum < dhtObj->_buckets.size(); ++bucketNum)
	{
		numPrefixBits = 160 - dhtObj->_buckets[bucketNum]->span;
		for(int ctr=0; ctr<16; ++ctr)
		{
			// copy "first"
			for(int y=0; y<5; ++y)
				peerId.id.id[y] = dhtObj->_buckets[bucketNum]->first.id[y];

			dctr.id[4] = ctr;
			// move the counter bits (4 bits) into the bits immediatly following the prefix bits
			// the bit range is 0 -> 159
			for(int x=0; x<4; ++x)
			{
				ProgramBit(peerId.id, 159-numPrefixBits-x, GetBit(dctr, 3-x));
			}
			peerId.addr.set_addr4((bucketNum << 24) | (ctr << 16) | (bucketNum << 8) | rand() % 256);
			(dhtObj->Update(peerId, 0, true, rtt))? ++added:0;
		}
	}
	return added;
}

int FillPreallocatedBuckets(smart_ptr<DhtImpl> &dhtObj, time_t rtt)
{
	int added = 0;

	DhtID dctr;
	DhtPeerID peerId;
	peerId.addr.set_port(128);

	for(int ctr=0; ctr<32; ++ctr)
	{
		dctr.id[4] = ctr;

		// put 8 nodes in the bucket
		for(int nodenum=0; nodenum<8; nodenum++)
		{
			// make a random myID
			for(int y=0; y<5; ++y)
				peerId.id.id[y] = rand();

			// copy the counter bits (5 bits) into the upper 5 bits of the id to be added
			// (to address the particular preallocated bucket)
			for(int x=0; x<5; ++x)
			{
				ProgramBit(peerId.id, 159-x, GetBit(dctr, 4-x));
			}

			peerId.addr.set_addr4((nodenum << 24) | (ctr << 16) | (nodenum << 8) | rand() % 256);

			// add the node
			(dhtObj->Update(peerId, 0, true, rtt))? ++added:0;
		}
	}
	return added;
}


TEST(TestDhtRoutingTables, SimpleInsertNodes)
{
	//InitDHTTestEnvironment();

	UnitTestUDPSocket socket4;
	UnitTestUDPSocket socket6;
	BencodedDict bDictGetPeer;
	SockAddr sAddr(0x7a7a7a7a,0x7878); // ip = zzzz and socket = xx
	socket4.SetBindAddr(sAddr);
	smart_ptr<DhtImpl> dhtTestObj(new DhtImpl(&socket4, &socket6));
	dhtTestObj->_dht_utversion[2] = 'x';
	dhtTestObj->_dht_utversion[3] = 'x';

	DhtID myId;
	myId.id[0] = 0x07000000;
	myId.id[1] = myId.id[2] = myId.id[3] = myId.id[4] = 0;

	// prepare the object for use
	dhtTestObj->Enable(true,0);
	dhtTestObj->SetId((byte*)DHTID_BYTES.c_str());

	// 
	const int numIds = 16;
	DhtPeerID peerIds[numIds];
	for(int x=0; x<numIds; ++x){
		for(int y=0; y<5; ++y){
			peerIds[x].id.id[y] = x<<24;
			peerIds[x].addr.set_port(128);
			peerIds[x].addr.set_addr4((x << 24) | (y << 16) | (x << 8) | y);
		}
		peerIds[x].id.id[0] = (x % 8)<<24;
		dhtTestObj->Update(peerIds[x], 0, true, 100);
	}

	// everything should be in bucket 0; evenly distributed across the sub-prefixes
	// in both the peer and replacement lists.
	DhtBucket &bucket = *dhtTestObj->_buckets[0];
	bucket.peers.ComputeSubPrefixInfo();
	bucket.replacement_peers.ComputeSubPrefixInfo();
	EXPECT_EQ(0xff, bucket.peers.subPrefixMask) << "the peer list sub-prefix mask is wrong";
	EXPECT_EQ(0xff, bucket.replacement_peers.subPrefixMask) << "the replacement list sub-prefix mask is wrong";
	for(int x=0; x<KADEMLIA_BUCKET_SIZE; ++x){
		EXPECT_EQ(1, bucket.peers.subPrefixCounts[x]) << "there should only be 1 entry for each sub-prefix in the peer list:  index " << x << " has a value of " << (int)bucket.peers.subPrefixCounts[x];
		EXPECT_EQ(1, bucket.replacement_peers.subPrefixCounts[x]) << "there should only be 1 entry for each sub-prefix in the replacement list  index " << x << " has a value of " << (int)bucket.replacement_peers.subPrefixCounts[x];
	}
	EXPECT_TRUE(VerifyBuckets(dhtTestObj->_buckets)) << "Buckets did not verify; see previous message";
}


TEST(TestDhtRoutingTables, InsertNodesWithSplit)
{
	//InitDHTTestEnvironment();

	UnitTestUDPSocket socket4;
	UnitTestUDPSocket socket6;
	BencodedDict bDictGetPeer;
	SockAddr sAddr(0x7a7a7a7a,0x7878); // ip = zzzz and socket = xx
	socket4.SetBindAddr(sAddr);
	smart_ptr<DhtImpl> dhtTestObj(new DhtImpl(&socket4, &socket6));
	dhtTestObj->_dht_utversion[2] = 'x';
	dhtTestObj->_dht_utversion[3] = 'x';

	DhtID myId;
	// this is designed to place the id of this node (my id) in the same bucket as the
	// test nodes that are added below.  The bucket should be split as the nodes are added
	myId.id[0] = 0x07000000;  // binary prefix of 00000sss...; binary sub-prefix of 111
	myId.id[1] = myId.id[2] = myId.id[3] = myId.id[4] = 0;

	// prepare the object for use
	dhtTestObj->Enable(true,0);
	dhtTestObj->SetId(myId);

	EXPECT_EQ(32, dhtTestObj->_buckets.size()) << "Actual number of initial buckets:  " << dhtTestObj->_buckets.size();

	// add nodes that count through the sub-prefixs 000 to 111 binary
	const int numIds = 16;
	DhtPeerID peerIds[numIds];
	for(int x=0; x<numIds; ++x){
		for(int y=0; y<5; ++y){
			peerIds[x].id.id[y] = x<<24;
			peerIds[x].addr.set_port(128);
			peerIds[x].addr.set_addr4((x << 24) | (y << 16) | (x << 8) | y);
		}
		peerIds[x].id.id[0] = (x % 8)<<24; // make sure the only bits added to the most significant word are only the 3 sub-prefix bits; all other bits are 0
		dhtTestObj->Update(peerIds[x], 0, true, 100);
	}
	EXPECT_EQ(33, dhtTestObj->_buckets.size()) << "Actual number of final buckets:  " << dhtTestObj->_buckets.size();

	// the id of this node (my id) is:                           000001110000...
	// the initial sub-prefix bits of the nodes added above is:  pppppSSS0000...
	// the position of the split buckets sub-prefix is:          ppppppSSS000...

	// after the bucket split, only even sub prefixes will be represented in the 
	// buckets (000, 010, 100, and 110) since the nodes added above were designed to have
	// the bit following the original sub-prefix be 0

	// bucket[0] should contain nodes with binary prefix:  000001SSS... (where the 3rd S will be 0)
	// bucket[1] should contain nodes with binary prefix:  000000SSS... (where the 3rd S will be 0)

	// based on the nodes added and my id (the id of this node), only even positions in the 
	// sub-prefix should be represented with nodes (bit positions 0,2,4, and 8 in the sub-prefix mask
	// and indexes 0, 2, 4, and 6 of the sub-prefix counts should a value of 2 for a total of 8 nodes
	// no nodes should be in the replacement bucket
	DhtBucket &bucket0 = *dhtTestObj->_buckets[0];
	bucket0.peers.ComputeSubPrefixInfo();
	bucket0.replacement_peers.ComputeSubPrefixInfo();
	EXPECT_EQ(0x55, bucket0.peers.subPrefixMask) << "bucket0: the peer list sub-prefix mask is wrong; nodes are not evenly distributed";
	EXPECT_EQ(0x00, bucket0.replacement_peers.subPrefixMask) << "bucket0: the replacement list sub-prefix mask is wrong; no nodes should be in the replacement list";
	for(int x=0; x<KADEMLIA_BUCKET_SIZE; ++x){
		if(x & 0x01) // if odd
			EXPECT_EQ(0, bucket0.peers.subPrefixCounts[x]) << "bucket0: there should not entry for a sub-prefix in an odd position of the peer list:  index " << x << " has a value of " << (int)bucket0.peers.subPrefixCounts[x];
		else
			EXPECT_EQ(2, bucket0.peers.subPrefixCounts[x]) << "bucket0: there should be 2 entries for a sub-prefix in an even position of the peer list:  index " << x << " has a value of " << (int)bucket0.peers.subPrefixCounts[x];

		EXPECT_EQ(0, bucket0.replacement_peers.subPrefixCounts[x]) << "bucket0: there should NO entries in the replacement list  index " << x << " has a value of " << (int)bucket0.replacement_peers.subPrefixCounts[x];
	}
	
	DhtBucket &bucket1 = *dhtTestObj->_buckets[1];
	bucket1.peers.ComputeSubPrefixInfo();
	bucket1.replacement_peers.ComputeSubPrefixInfo();
	EXPECT_EQ(0x55, bucket1.peers.subPrefixMask) << "bucket1: the peer list sub-prefix mask is wrong; nodes are not evenly distributed";
	EXPECT_EQ(0x00, bucket1.replacement_peers.subPrefixMask) << "bucket1: the replacement list sub-prefix mask is wrong; no nodes should be in the replacement list";
	for(int x=0; x<KADEMLIA_BUCKET_SIZE; ++x){
		if(x & 0x01) // if odd
			EXPECT_EQ(0, bucket1.peers.subPrefixCounts[x]) << "bucket1: there should not entry for a sub-prefix in an odd position of the peer list:  index " << x << " has a value of " << (int)bucket0.peers.subPrefixCounts[x];
		else
			EXPECT_EQ(2, bucket1.peers.subPrefixCounts[x]) << "bucket1: there should be 2 entries for a sub-prefix in an even position of the peer list:  index " << x << " has a value of " << (int)bucket0.peers.subPrefixCounts[x];

		EXPECT_EQ(0, bucket1.replacement_peers.subPrefixCounts[x]) << "bucket1: there should NO entries in the replacement list  index " << x << " has a value of " << (int)bucket0.replacement_peers.subPrefixCounts[x];
	}

	// there should be 8 nodes in each peer list and no nodes in the replacement lists
	// for the first two buckets.
	vector<int> nodeCounts;
	vector<int> replacementCounts;
	CountNodesInBuckets(dhtTestObj->_buckets, nodeCounts, replacementCounts);
	EXPECT_EQ(8, nodeCounts[0]) << "there should be exactly 8 nodes in bucket 0";
	EXPECT_EQ(0, replacementCounts[0]) << "there are nodes in the replacement list when there should be none";
	EXPECT_EQ(8, nodeCounts[1]) << "there should be exactly 8 nodes in bucket 1";;
	EXPECT_EQ(0, replacementCounts[1]) << "there are nodes in the replacement list when there should be none";

	// there should not be any nodes in the remaining buckets
	for(int x=2; x<nodeCounts.size(); ++x){
		EXPECT_EQ(0, nodeCounts[x]) << "there should not be any nodes in peer bucket " << x;
		EXPECT_EQ(0, replacementCounts[x]) << "there should not be any nodes in replacement bucket " << x;
	}
	EXPECT_TRUE(VerifyBuckets(dhtTestObj->_buckets)) << "Buckets did not verify; see previous message";
}


TEST(TestDhtRoutingTables, PopBestNode)
{
	//InitDHTTestEnvironment();

	UnitTestUDPSocket socket4;
	UnitTestUDPSocket socket6;
	BencodedDict bDictGetPeer;
	SockAddr sAddr(0x7a7a7a7a,0x7878); // ip = zzzz and socket = xx
	socket4.SetBindAddr(sAddr);
	smart_ptr<DhtImpl> dhtTestObj(new DhtImpl(&socket4, &socket6));
	dhtTestObj->_dht_utversion[2] = 'x';
	dhtTestObj->_dht_utversion[3] = 'x';

	DhtID myId;
	myId.id[0] = 0x07000000;
	myId.id[1] = myId.id[2] = myId.id[3] = myId.id[4] = 0;

	// prepare the object for use
	dhtTestObj->Enable(true,0);
	dhtTestObj->SetId((byte*)DHTID_BYTES.c_str());

	vector<int> nodeCounts;
	vector<int> replacementCounts;

	// popping from and empty queue should give us NULL
	EXPECT_FALSE(dhtTestObj->_buckets[0]->peers.PopBestNode(-1)) << "did not receive NULL when popping from and empty queue";
	// now put in nodes for each sub-prefix
	const int numIds = 16;
	DhtPeerID peerIds[numIds];
	for(int x=0; x<numIds; ++x){
		for(int y=0; y<5; ++y){
			peerIds[x].id.id[y] = x<<24;
			peerIds[x].addr.set_port(128);
			peerIds[x].addr.set_addr4((x << 24) | (y << 16) | (x << 8) | y);
		}
		peerIds[x].id.id[0] = (x % 8)<<24;
		dhtTestObj->Update(peerIds[x], 0, true, 100 + 10 * (x % 8)); // make different rtt's (arbitrarily based on sub-prefix value)
	}

	CountNodesInBuckets(dhtTestObj->_buckets, nodeCounts, replacementCounts);
	for(int x = 0; x<nodeCounts.size(); ++x){
		if(x==0){
			EXPECT_EQ(8, nodeCounts[x]) << "there should be 8 nodes in the 0th bucket's peer list";
			EXPECT_EQ(8, replacementCounts[x]) << "there should be 8 nodes in the 0th bucket's replacement list";
		}
		else{
			EXPECT_EQ(0, nodeCounts[x]) << "there should be 0 nodes in the bucket "<< x <<"'s peer list";
			EXPECT_EQ(0, replacementCounts[x]) << "there should be 0 nodes in bucket "<< x <<"'s replacement list";
		}
	}

	// get a node with a sub-prefix value of 3
	DhtPeer* subPrefixNode = dhtTestObj->_buckets[0]->peers.PopBestNode(3);
	EXPECT_TRUE(subPrefixNode) << "a NULL was returned from a non-empty queue";
	EXPECT_EQ(3, subPrefixNode->GetSubprefixInt());
	CountNodesInBuckets(dhtTestObj->_buckets, nodeCounts, replacementCounts);
	EXPECT_EQ(7, nodeCounts[0]) << "there should be 7 nodes in the 0th bucket's peer list";

	// try getting sub-prefix 3 again (it should no longer be in the queue and we should
	// get a node with the shortest rtt
	subPrefixNode = dhtTestObj->_buckets[0]->peers.PopBestNode(3);
	EXPECT_TRUE(subPrefixNode) << "a NULL was returned from a non-empty queue";
	EXPECT_EQ(0, subPrefixNode->GetSubprefixInt());
	EXPECT_EQ(100, subPrefixNode->rtt);
	CountNodesInBuckets(dhtTestObj->_buckets, nodeCounts, replacementCounts);
	EXPECT_EQ(6, nodeCounts[0]) << "there should be 6 nodes in the 0th bucket's peer list";

	// do it again to get the next fastest node
	subPrefixNode = dhtTestObj->_buckets[0]->peers.PopBestNode(3);
	EXPECT_TRUE(subPrefixNode) << "a NULL was returned from a non-empty queue";
	EXPECT_EQ(1, subPrefixNode->GetSubprefixInt());
	EXPECT_EQ(110, subPrefixNode->rtt);
	CountNodesInBuckets(dhtTestObj->_buckets, nodeCounts, replacementCounts);
	EXPECT_EQ(5, nodeCounts[0]) << "there should be 5 nodes in the 0th bucket's peer list";

	// load an error into the node with sub-prefix of 2 (which should now be first in the list)
	dhtTestObj->_buckets[0]->peers.first()->num_fail = 1;
	// now when getting the next fastest node, this should be skipped in favor of the
	// node with sub-prefix of 4
	subPrefixNode = dhtTestObj->_buckets[0]->peers.PopBestNode(3);
	EXPECT_TRUE(subPrefixNode) << "a NULL was returned from a non-empty queue";
	EXPECT_EQ(4, subPrefixNode->GetSubprefixInt());
	EXPECT_EQ(140, subPrefixNode->rtt);
	CountNodesInBuckets(dhtTestObj->_buckets, nodeCounts, replacementCounts);
	EXPECT_EQ(4, nodeCounts[0]) << "there should be 4 nodes in the 0th bucket's peer list";

	EXPECT_TRUE(VerifyBuckets(dhtTestObj->_buckets)) << "Buckets did not verify; see previous message";
}


/**
	Force the dht buckets to be split down to the minimum span (3 bits) and filled with
	nodes.  Ultimatly every bucket and reserve bucket should have 8 nodes (no more, no
	fewer)
*/
TEST(TestDhtRoutingTables, FullTables)
{
	//InitDHTTestEnvironment();

	UnitTestUDPSocket socket4;
	UnitTestUDPSocket socket6;
	BencodedDict bDictGetPeer;
	SockAddr sAddr(0x7a7a7a7a,0x7878); // ip = zzzz and socket = xx
	socket4.SetBindAddr(sAddr);
	smart_ptr<DhtImpl> dhtTestObj(new DhtImpl(&socket4, &socket6));
	dhtTestObj->_dht_utversion[2] = 'x';
	dhtTestObj->_dht_utversion[3] = 'x';

	DhtID myId;
	myId.id[0] = 'AAAA';
	myId.id[1] = 'BBBB';
	myId.id[2] = 'CCCC';
	myId.id[3] = 'DDDD';
	myId.id[4] = 'FFFF';

	// prepare the object for use
	dhtTestObj->Enable(true,0);
	dhtTestObj->SetId(myId);

	time_t rtt = 1000;
	FillPreallocatedBuckets(dhtTestObj, rtt);
	FillPreallocatedBuckets(dhtTestObj, rtt);
	FillBucketList(dhtTestObj,rtt,evenBitDistribution);
	OverFillBuckets(dhtTestObj,rtt);

	vector<int> nodeCounts;
	vector<int> replacementCounts;
	CountNodesInBuckets(dhtTestObj->_buckets, nodeCounts, replacementCounts);

	EXPECT_EQ(184, nodeCounts.size());
	EXPECT_EQ(184, replacementCounts.size());

	for(int x=0; x<nodeCounts.size(); ++x)
	{
		EXPECT_FALSE(nodeCounts[x] == 0) << nodeCounts[x] << "bucket " << x << " has an empty list";
		EXPECT_TRUE(nodeCounts[x] <= KADEMLIA_BUCKET_SIZE) << "bucket " << x << " has more than " << KADEMLIA_BUCKET_SIZE << " nodes in it";
	}

	// the two buckets at the bottom of the split (with span of 3 bits) will not have any
	// nodes in the replacement list
	for(int x=0; x<replacementCounts.size(); ++x)
	{
		if(x==53 || x==54)
			EXPECT_TRUE(replacementCounts[x] == 0) << "replacement bucket " << x << " is NOT an empty list";
		else
			EXPECT_FALSE(replacementCounts[x] == 0) << "replacement bucket " << x << " has an empty list";
		EXPECT_TRUE(replacementCounts[x] <= KADEMLIA_BUCKET_SIZE) << "replacement bucket " << x << " has more than " << KADEMLIA_BUCKET_SIZE << " nodes in it";
	}

	EXPECT_TRUE(VerifyBuckets(dhtTestObj->_buckets)) << "Buckets did not verify; see previous message";

	// none of the nodes should be errored; check that num_fail is 0 for every node
	for(int x=0; x<dhtTestObj->_buckets.size(); ++x)
	{
		DhtPeer* p = dhtTestObj->_buckets[x]->peers.first();
		while(p){
			EXPECT_EQ(0, p->num_fail) << "An errored node was found in primary 'peers' list of bucket " << x;
			p = p->next;
		}

		p = dhtTestObj->_buckets[x]->replacement_peers.first();
		while(p){
			EXPECT_EQ(0, p->num_fail) << "An errored node was found in the replacement list of bucket " << x;
			p = p->next;
		}
	}
}

TEST(TestDhtRoutingTables, AllNodesInBucketsAreUnique)
{
	//InitDHTTestEnvironment();

	UnitTestUDPSocket socket4;
	UnitTestUDPSocket socket6;
	BencodedDict bDictGetPeer;
	SockAddr sAddr(0x7a7a7a7a,0x7878); // ip = zzzz and socket = xx
	socket4.SetBindAddr(sAddr);
	smart_ptr<DhtImpl> dhtTestObj(new DhtImpl(&socket4, &socket6));
	dhtTestObj->_dht_utversion[2] = 'x';
	dhtTestObj->_dht_utversion[3] = 'x';

	DhtID myId;
	myId.id[0] = 'AAAA';
	myId.id[1] = 'BBBB';
	myId.id[2] = 'CCCC';
	myId.id[3] = 'DDDD';
	myId.id[4] = 'FFFF';

	// prepare the object for use
	dhtTestObj->Enable(true,0);
	dhtTestObj->SetId(myId);

	time_t rtt = 1000;
	FillPreallocatedBuckets(dhtTestObj, rtt);
	FillPreallocatedBuckets(dhtTestObj, rtt);
	FillBucketList(dhtTestObj,rtt,evenBitDistribution);
	OverFillBuckets(dhtTestObj,rtt);

	vector<DhtPeer*> nodePtrs;
	vector<DhtID> dhtIds;
	// all pointers to nodes in the buckets should be unique
	PutDhtPtrsAndIdsInLists(dhtTestObj->_buckets, nodePtrs, dhtIds);
	EXPECT_TRUE(ListHasUniqueElements(nodePtrs)) << "There are duplicate DhtPeer*'s in the buckets";
	EXPECT_TRUE(ListHasUniqueElements(dhtIds)) << "There are duplicate DhtID's in the buckets";
}

bool SubPrefixesEvenlySpanNodeList(DhtBucketList &list)
{
	int rtt[8];
	int subPrefix[8];
	for(int x=0; x<8; ++x){
		rtt[x] = subPrefix[x] = -1;
	}

	int bits = 0;

	int x=0;
	for (DhtPeer **peer = &list.first(); *peer; peer=&(*peer)->next, ++x) {
		DhtPeer *p = *peer;
		bits |= 0x00000001 << p->GetSubprefixInt();
	}
	return (bits ^ 0x000000ff)?false:true;
}

enum NodeListType
{
	mainNodeList,
	replacementNodeList
};

bool SubPrefixesEvenlySpanBucketList(DhtBucket &bucket, NodeListType listType)
{
	if(listType == mainNodeList)
		return SubPrefixesEvenlySpanNodeList(bucket.peers);
	else
		return SubPrefixesEvenlySpanNodeList(bucket.replacement_peers);
}

TEST(TestDhtRoutingTables, SubPrefixDistributionIsUniform)
{
	//InitDHTTestEnvironment();

	UnitTestUDPSocket socket4;
	UnitTestUDPSocket socket6;
	BencodedDict bDictGetPeer;
	SockAddr sAddr(0x7a7a7a7a,0x7878); // ip = zzzz and socket = xx
	socket4.SetBindAddr(sAddr);
	smart_ptr<DhtImpl> dhtTestObj(new DhtImpl(&socket4, &socket6));
	dhtTestObj->_dht_utversion[2] = 'x';
	dhtTestObj->_dht_utversion[3] = 'x';

	DhtID myId;
	myId.id[0] = 'AAAA';
	myId.id[1] = 'BBBB';
	myId.id[2] = 'CCCC';
	myId.id[3] = 'DDDD';
	myId.id[4] = 'FFFF';

	// prepare the object for use
	dhtTestObj->Enable(true,0);
	dhtTestObj->SetId(myId);

	DhtPeerID peerId;
	peerId.addr.set_port(128);
	peerId.addr.set_addr4(0xf0f0f0f0);

	time_t rtt = 100;

	for(int x=0; x<8; ++x)
		FillBucketList(dhtTestObj, rtt, randomBitDistribution);

	vector<int> nodeCounts;
	vector<int> replacementCounts;
	CountNodesInBuckets(dhtTestObj->_buckets, nodeCounts, replacementCounts);

	// all pointers to nodes in the buckets should be unique
	vector<DhtPeer*> nodePtrs;
	vector<DhtID> dhtIds;
	PutDhtPtrsAndIdsInLists(dhtTestObj->_buckets, nodePtrs, dhtIds);
	EXPECT_TRUE(ListHasUniqueElements(nodePtrs)) << "There are duplicate DhtPeer*'s in the buckets";
	EXPECT_TRUE(ListHasUniqueElements(dhtIds)) << "There are duplicate DhtID's in the buckets";
	
	// go through the buckets and examine only the buckets that have 8 nodes
	int num8ctLists = 0;
	int num8ctListsWithUnevenSubprefixDistribution = 0;
	for(int x=0; x<nodeCounts.size(); x++)
	{
		if(nodeCounts[x] == 8)
		{
			num8ctLists++;
			num8ctListsWithUnevenSubprefixDistribution += (SubPrefixesEvenlySpanBucketList(*(dhtTestObj->_buckets[x]), mainNodeList))?0:1;
		}
	}
	ASSERT_TRUE(num8ctListsWithUnevenSubprefixDistribution < num8ctLists) << "The test is invalid if there are no un-evenly distributed subprefixes in the list of nodes (peer nodes list)";
	num8ctLists = 0;
	num8ctListsWithUnevenSubprefixDistribution = 0;
	for(int x=0; x<nodeCounts.size(); x++)
	{
		if(nodeCounts[x] == 8)
		{
			num8ctLists++;
			num8ctListsWithUnevenSubprefixDistribution += (SubPrefixesEvenlySpanBucketList(*(dhtTestObj->_buckets[x]), replacementNodeList))?0:1;
		}
	}
	ASSERT_TRUE(num8ctListsWithUnevenSubprefixDistribution < num8ctLists) << "The test is invalid if there are no un-evenly distributed subprefixes in the list of nodes (replacement nodes list)";

	//int nctr=0; int rctr=0;
	//for(int x=0; x<nodeCounts.size(); x++){
	//	nctr+= nodeCounts[x]; rctr+=replacementCounts[x];
	//	printf("Bucket %d \tpeer=%d \trep=%d\n", x, nodeCounts[x], replacementCounts[x]);
	//}
	//printf("#nodes=%d \t#replacements=%d\n",nctr,rctr);

	// fill the list with nodes that will satisfy the sub-prefix requirements
	// the nodes in the buckets should be moved or discarded to fulfill the
	// affinity to evenly distribute the sub-prefixes within the buckets
	FillBucketList(dhtTestObj, rtt, evenBitDistribution);
	FillPreallocatedBuckets(dhtTestObj, rtt);
	FillPreallocatedBuckets(dhtTestObj, rtt);
	OverFillBuckets(dhtTestObj,rtt);

	num8ctLists = 0;
	num8ctListsWithUnevenSubprefixDistribution = 0;
	for(int x=0; x<nodeCounts.size(); x++)
	{
		if(nodeCounts[x] == 8)
		{
			num8ctLists++;
			num8ctListsWithUnevenSubprefixDistribution += (SubPrefixesEvenlySpanBucketList(*(dhtTestObj->_buckets[x]), mainNodeList))?0:1;
		}
	}
	EXPECT_EQ(0,num8ctListsWithUnevenSubprefixDistribution) << "All 8 count lists should have an even distribution of sub-prefixes (peer nodes list)";

	EXPECT_TRUE(VerifyBuckets(dhtTestObj->_buckets)) << "Buckets did not verify; see previous message";
}


TEST(TestDhtRoutingTables, ReplaceSlowNodes)
{
	//InitDHTTestEnvironment();

	UnitTestUDPSocket socket4;
	UnitTestUDPSocket socket6;
	BencodedDict bDictGetPeer;
	SockAddr sAddr(0x7a7a7a7a,0x7878); // ip = zzzz and socket = xx
	socket4.SetBindAddr(sAddr);
	smart_ptr<DhtImpl> dhtTestObj(new DhtImpl(&socket4, &socket6));
	dhtTestObj->_dht_utversion[2] = 'x';
	dhtTestObj->_dht_utversion[3] = 'x';

	DhtID myId;
	myId.id[0] = 'AAAA';
	myId.id[1] = 'BBBB';
	myId.id[2] = 'CCCC';
	myId.id[3] = 'DDDD';
	myId.id[4] = 'FFFF';

	// prepare the object for use
	dhtTestObj->Enable(true,0);
	dhtTestObj->SetId(myId);

	DhtPeerID peerId;
	peerId.addr.set_port(128);
	peerId.addr.set_addr4(0xf0f0f0f0);
	for(int y=0; y<5; ++y)
		peerId.id.id[y] = rand();
	dhtTestObj->Update(peerId, 0, true, 10000);

	// now, make sure we replace 
	for (int i = 0; i < 32; ++i) {
		peerId.id.id[4] = rand();
		dhtTestObj->Update(peerId, 0, true, 50);
	}

	OutputBuckets(dhtTestObj->_buckets);

	EXPECT_TRUE(VerifyBuckets(dhtTestObj->_buckets)) << "Buckets did not verify; see previous message";

	// All of the nodes in the working peers list should have an rtt of 50
	// All of the nodes in the replacement list should have an rtt of 10000
	for(int i = 0; i < dhtTestObj->_buckets.size(); i++) {
		DhtPeer* p = dhtTestObj->_buckets[i]->peers.first();
		while(p){
			EXPECT_EQ(50, p->rtt) << "main nodes list in bucket " << i << " has a node with an rtt of: " << p->rtt;
			p = p->next;
		}
	}
}

/**
	SubPrefixToUse should be in the range 0 to 7 (000 to 111 binary)
*/
DhtPeerID MakeNodeForBucket(smart_ptr<DhtImpl> &dhtObj,int bucketNum, int SubPrefixToUse)
{
	assert(bucketNum>=0 && bucketNum < dhtObj->_buckets.size());

	DhtID subPrefixBits;
	subPrefixBits.id[4] = SubPrefixToUse;
	int span = dhtObj->_buckets[bucketNum]->span;
	int numPrefixBits = 160-span;
	DhtPeerID peerId;
	peerId.addr.set_port(128);
	peerId.addr.set_addr4(0xf0f0f0f0);

	// set the prefix bits
	peerId.id = dhtObj->_buckets[bucketNum]->first;

	// Make a random dht id
	DhtID randId;
	for(int x=0; x<5; ++x)
		randId.id[x] = rand()*rand();

	// put in the bits below the prefix
	for(int x=0; x<span; ++x)
	{
		ProgramBit(peerId.id, 159-numPrefixBits-x, (x<3)?GetBit(subPrefixBits, 2-x):GetBit(randId,x));
	}
	return peerId;
}

/**
	Returns the index of the bucket containing idToFind.  Both the peers and replacement lists are searched.
	Returns -1 if id not found.
*/
int FindBucketWithId(smart_ptr<DhtImpl> &dhtObj, const DhtID &idToFind)
{
	for(int x=0; x<dhtObj->_buckets.size(); ++x)
	{
		DhtPeer* p = dhtObj->_buckets[x]->peers.first();
		while(p){
			if(p->id.id == idToFind)
				return x;
			p = p->next;
		}

		p = dhtObj->_buckets[x]->replacement_peers.first();
		while(p){
			if(p->id.id == idToFind)
				return x;
			p = p->next;
		}
	}
	return -1;
}

bool IsIdInList(DhtBucketList &list, const DhtID &idToFind)
{
	DhtPeer* p = list.first();
	while(p){
		if(p->id.id == idToFind)
			return true;
		p = p->next;
	}
	return false;
}

int CountNodesInList(DhtBucketList &list)
{
	DhtPeer* p = list.first();
	int ctr = 0;
	while(p){
		ctr++;
		p = p->next;
	}
	return ctr;
}

int CountNodesInPrimaryList(smart_ptr<DhtImpl> &dhtObj,int bucketNum)
{
	assert(bucketNum>=0 && bucketNum < dhtObj->_buckets.size());
	return CountNodesInList(dhtObj->_buckets[bucketNum]->peers);
}

int CountNodesInReplacementList(smart_ptr<DhtImpl> &dhtObj,int bucketNum)
{
	assert(bucketNum>=0 && bucketNum < dhtObj->_buckets.size());
	return CountNodesInList(dhtObj->_buckets[bucketNum]->replacement_peers);
}

/**
	If the idToFind is not in the list, NULL is returned, othewise the pointer to the element in the list
	with the matching id is returned.
*/
DhtPeer* GetPtrForIdInList(DhtBucketList &list, const DhtID &idToFind)
{
	DhtPeer* p = list.first();
	while(p){
		if(p->id.id == idToFind)
			return p;
		p = p->next;
	}
	return NULL;
}

TEST(TestDhtRoutingTables, SimpleErroredNode)
{
	//InitDHTTestEnvironment();

	UnitTestUDPSocket socket4;
	UnitTestUDPSocket socket6;
	BencodedDict bDictGetPeer;
	SockAddr sAddr(0x7a7a7a7a,0x7878); // ip = zzzz and socket = xx
	socket4.SetBindAddr(sAddr);
	smart_ptr<DhtImpl> dhtTestObj(new DhtImpl(&socket4, &socket6));
	dhtTestObj->_dht_utversion[2] = 'x';
	dhtTestObj->_dht_utversion[3] = 'x';

	DhtID myId;	// this id falls into bucket #0 of the initial preallocated buckets (the \0 is the top 8 most significant bits of the dht id)
	myId.id[0] = '\0AAA';
	myId.id[1] = 'BBBB';
	myId.id[2] = 'CCCC';
	myId.id[3] = 'DDDD';
	myId.id[4] = 'FFFF';

	// prepare the object for use
	dhtTestObj->Enable(true,0);
	dhtTestObj->SetId(myId);

	// create 8 nodes to go into pre-allocated bucket #5
	int workingBucket = 5;
	int rtt = 500;
	DhtPeerID peerIds[8];
	for(int subPrefix=0; subPrefix<8; ++subPrefix){
		peerIds[subPrefix]= MakeNodeForBucket(dhtTestObj, workingBucket, subPrefix);
		peerIds[subPrefix].addr.set_port(128);
		peerIds[subPrefix].addr.set_addr4((subPrefix << 24) | (subPrefix << 16) | (subPrefix << 8) | subPrefix);
		dhtTestObj->Update(peerIds[subPrefix], 0, true, rtt);
	}

	// there should be 8 nodes in the primary list and 0 nodes in the reserve list.
	EXPECT_EQ(8, CountNodesInPrimaryList(dhtTestObj, workingBucket));
	EXPECT_EQ(0, CountNodesInReplacementList(dhtTestObj, workingBucket));

	// error the node at sub-prefix 4;
	dhtTestObj->UpdateError(peerIds[4]);
	DhtPeer* nodePtr = GetPtrForIdInList(dhtTestObj->_buckets[workingBucket]->peers, peerIds[4].id);
	EXPECT_TRUE(nodePtr) << "the node being errored is not in the bucket";

	// create a different node with the same sub-prefix for the bucket
	DhtPeerID newNode = peerIds[4];
	newNode.addr.set_addr4(~newNode.addr.get_addr4());
	newNode.id.id[4] = ~newNode.id.id[4]; // just invert the last word
	// add the new node
	dhtTestObj->Update(newNode, 0, true, rtt);
	// there should be 8 nodes in the primary list and 0 nodes in the reserve list.
	EXPECT_EQ(8, CountNodesInPrimaryList(dhtTestObj, workingBucket));
	EXPECT_EQ(0, CountNodesInReplacementList(dhtTestObj, workingBucket));

	// see that the errored node is gone from the buckets;
	EXPECT_EQ(-1, FindBucketWithId(dhtTestObj, peerIds[4].id)) << "the errored node is still in the bucket list - it should have been discarded";
	EXPECT_EQ(workingBucket, FindBucketWithId(dhtTestObj, newNode.id)) << "The new node is not in the buckets";

	EXPECT_TRUE(VerifyBuckets(dhtTestObj->_buckets)) << "Buckets did not verify; see previous message";
}


TEST(TestDhtRoutingTables, FasterNodeErroredNode)
{
	//InitDHTTestEnvironment();

	UnitTestUDPSocket socket4;
	UnitTestUDPSocket socket6;
	BencodedDict bDictGetPeer;
	SockAddr sAddr(0x7a7a7a7a,0x7878); // ip = zzzz and socket = xx
	socket4.SetBindAddr(sAddr);
	smart_ptr<DhtImpl> dhtTestObj(new DhtImpl(&socket4, &socket6));
	dhtTestObj->_dht_utversion[2] = 'x';
	dhtTestObj->_dht_utversion[3] = 'x';

	DhtID myId;	// this id falls into bucket #0 of the initial preallocated buckets (the \0 is the top 8 most significant bits of the dht id)
	myId.id[0] = '\0AAA';
	myId.id[1] = 'BBBB';
	myId.id[2] = 'CCCC';
	myId.id[3] = 'DDDD';
	myId.id[4] = 'FFFF';

	// prepare the object for use
	dhtTestObj->Enable(true,0);
	dhtTestObj->SetId(myId);

	// create 8 nodes to go into pre-allocated bucket #5
	int workingBucket = 5;
	int rtt = 10000;
	DhtPeerID peerIds[8];
	for(int subPrefix=0; subPrefix<8; ++subPrefix){
		peerIds[subPrefix]= MakeNodeForBucket(dhtTestObj, workingBucket, subPrefix);
		peerIds[subPrefix].addr.set_port(128);
		peerIds[subPrefix].addr.set_addr4((subPrefix << 24) | (subPrefix << 16) | (subPrefix << 8) | subPrefix);
		dhtTestObj->Update(peerIds[subPrefix], 0, true, rtt);
	}

	// there should be 8 nodes in the primary list and 0 nodes in the reserve list.
	EXPECT_EQ(8, CountNodesInPrimaryList(dhtTestObj, workingBucket));
	EXPECT_EQ(0, CountNodesInReplacementList(dhtTestObj, workingBucket));
	// nodes in the primary list should have unique sub-prefixes
	ASSERT_TRUE(SubPrefixesEvenlySpanNodeList(dhtTestObj->_buckets[workingBucket]->peers)) << "the node sub-prefixes are not evenly distributed and unique";

	// create a different node sub-prefix 4 for the bucket with a much FASTER rtt
	// this should move the original node at sub-prefix 4 to the replacement bucket
	DhtPeerID newNode = peerIds[4];
	newNode.addr.set_addr4(~newNode.addr.get_addr4());
	newNode.id.id[4] = ~newNode.id.id[4]; // just invert the last word
	// add the new node
	rtt = 4000;
	dhtTestObj->Update(newNode, 0, true, rtt);
	EXPECT_EQ(8, CountNodesInPrimaryList(dhtTestObj, workingBucket)) << "There should still be 8 nodes in the primary list after a slow node is replaced with a faster node";
	EXPECT_EQ(1, CountNodesInReplacementList(dhtTestObj, workingBucket)) << "The slow node should be the only node in the replacement list";
	EXPECT_TRUE(SubPrefixesEvenlySpanNodeList(dhtTestObj->_buckets[workingBucket]->peers)) << "the node sub-prefixes are not evenly distributed and unique";

	// error the node at sub-prefix 2;
	// the slow node pushed out earlier should be moved in from the replacement bucket
	dhtTestObj->UpdateError(peerIds[2]);
	DhtPeer* nodePtr = GetPtrForIdInList(dhtTestObj->_buckets[workingBucket]->peers, peerIds[2].id);
	EXPECT_FALSE(nodePtr) << "the node being errored is still in the bucket";
	EXPECT_FALSE(SubPrefixesEvenlySpanNodeList(dhtTestObj->_buckets[workingBucket]->peers)) << "the node sub-prefixes should not be evenly distributed any more";

	// there should be 8 nodes in the primary list and 0 nodes in the reserve list.
	// the node that was re-added should not be in the reserve list
	EXPECT_EQ(8, CountNodesInPrimaryList(dhtTestObj, workingBucket));
	EXPECT_EQ(0, CountNodesInReplacementList(dhtTestObj, workingBucket));

	// see that the errored node is gone from the buckets;
	EXPECT_EQ(-1, FindBucketWithId(dhtTestObj, peerIds[2].id)) << "the errored node is still in the bucket list - it should have been discarded";
	EXPECT_EQ(workingBucket, FindBucketWithId(dhtTestObj, newNode.id)) << "The new node is not in the buckets";

	EXPECT_TRUE(VerifyBuckets(dhtTestObj->_buckets)) << "Buckets did not verify; see previous message";
}


TEST(TestDhtRoutingTables, ReplacementListPullBackAndUpdate)
{
	//InitDHTTestEnvironment();

	UnitTestUDPSocket socket4;
	UnitTestUDPSocket socket6;
	BencodedDict bDictGetPeer;
	SockAddr sAddr(0x7a7a7a7a,0x7878); // ip = zzzz and socket = xx
	socket4.SetBindAddr(sAddr);
	smart_ptr<DhtImpl> dhtTestObj(new DhtImpl(&socket4, &socket6));
	dhtTestObj->_dht_utversion[2] = 'x';
	dhtTestObj->_dht_utversion[3] = 'x';

	DhtID myId;	// this id falls into bucket #0 of the initial preallocated buckets (the \0 is the top 8 most significant bits of the dht id)
	myId.id[0] = '\0AAA';
	myId.id[1] = 'BBBB';
	myId.id[2] = 'CCCC';
	myId.id[3] = 'DDDD';
	myId.id[4] = 'FFFF';

	// prepare the object for use
	dhtTestObj->Enable(true,0);
	dhtTestObj->SetId(myId);

	// create 8 nodes to go into pre-allocated bucket #5
	int workingBucket = 5;
	int rtt = 10000;
	DhtPeerID peerIds[8];
	for(int subPrefix=0; subPrefix<8; ++subPrefix){
		peerIds[subPrefix]= MakeNodeForBucket(dhtTestObj, workingBucket, subPrefix);
		peerIds[subPrefix].addr.set_port(128);
		peerIds[subPrefix].addr.set_addr4((subPrefix << 24) | (subPrefix << 16) | (subPrefix << 8) | subPrefix);
		dhtTestObj->Update(peerIds[subPrefix], 0, true, rtt);
	}

	rtt = 4000;
	DhtPeerID fasterPeerIds[8];
	for(int subPrefix=0; subPrefix<8; ++subPrefix){
		fasterPeerIds[subPrefix]= peerIds[subPrefix];
		fasterPeerIds[subPrefix].addr.set_addr4(~fasterPeerIds[subPrefix].addr.get_addr4());
		fasterPeerIds[subPrefix].id.id[4] = ~fasterPeerIds[subPrefix].id.id[4]; // make this id different in the least significant bits
		dhtTestObj->Update(fasterPeerIds[subPrefix], 0, true, rtt);
	}

	// there should be 8 nodes in the primary list and 8 nodes in the reserve list.
	EXPECT_EQ(8, CountNodesInPrimaryList(dhtTestObj, workingBucket));
	EXPECT_EQ(8, CountNodesInReplacementList(dhtTestObj, workingBucket));
	// nodes in the primary list should have unique sub-prefixes
	ASSERT_TRUE(SubPrefixesEvenlySpanNodeList(dhtTestObj->_buckets[workingBucket]->peers)) << "the node sub-prefixes are not evenly distributed and unique";
	ASSERT_TRUE(SubPrefixesEvenlySpanNodeList(dhtTestObj->_buckets[workingBucket]->replacement_peers)) << "the node sub-prefixes in the replacement list are NOT evenly distributed";

	// error the node at sub-prefix 2 in the replacement bucket;
	dhtTestObj->UpdateError(peerIds[2]);
	DhtPeer* nodePtr = GetPtrForIdInList(dhtTestObj->_buckets[workingBucket]->peers, peerIds[2].id);
	EXPECT_FALSE(nodePtr) << "the node being errored is still in the bucket";
	EXPECT_TRUE(SubPrefixesEvenlySpanNodeList(dhtTestObj->_buckets[workingBucket]->peers)) << "the node sub-prefixes should still be evenly distributed";
	EXPECT_TRUE(SubPrefixesEvenlySpanNodeList(dhtTestObj->_buckets[workingBucket]->replacement_peers)) << "the node sub-prefixes should still be evenly distributed";

	// there should be 8 nodes in the primary list and 8 nodes in the reserve list.
	// the node that was re-added should not be in the reserve list
	EXPECT_EQ(8, CountNodesInPrimaryList(dhtTestObj, workingBucket));
	EXPECT_EQ(8, CountNodesInReplacementList(dhtTestObj, workingBucket));

	// see that the errored node is still in the replacement bucket
	EXPECT_NE(-1, FindBucketWithId(dhtTestObj, peerIds[2].id)) << "the errored node is still in the bucket list - it should have been discarded";

	// now add a node with the errored node's sub-prefix; it should replace the errored node in the replacement list
	DhtPeerID newNode = peerIds[3];
	newNode.addr.set_addr4(~newNode.addr.get_addr4()+123456);
	newNode.id.id[3] = newNode.id.id[3]+1; // add something to make it different
	// add the new node
	dhtTestObj->Update(newNode, 0, true, rtt);
	// there should still be 8 nodes in each list
	EXPECT_EQ(8, CountNodesInPrimaryList(dhtTestObj, workingBucket));
	EXPECT_EQ(8, CountNodesInReplacementList(dhtTestObj, workingBucket));
	nodePtr = GetPtrForIdInList(dhtTestObj->_buckets[workingBucket]->peers, peerIds[2].id);
	EXPECT_FALSE(nodePtr) << "the node being errored is still in the bucket";
	EXPECT_TRUE(SubPrefixesEvenlySpanNodeList(dhtTestObj->_buckets[workingBucket]->peers)) << "the node sub-prefixes should still be evenly distributed";
	EXPECT_FALSE(SubPrefixesEvenlySpanNodeList(dhtTestObj->_buckets[workingBucket]->replacement_peers)) << "the node sub-prefixes are still unique but errored sub-prefix 2 should be replaced with working sub-prefix 3 in the replacement bucket";
	EXPECT_EQ(5, FindBucketWithId(dhtTestObj, newNode.id)) << "the new node is NOT in the bucket";


	EXPECT_TRUE(VerifyBuckets(dhtTestObj->_buckets)) << "Buckets did not verify; see previous message";
}


TEST(TestDhtRoutingTables, ThrashingNode)
{
	//InitDHTTestEnvironment();

	UnitTestUDPSocket socket4;
	UnitTestUDPSocket socket6;
	BencodedDict bDictGetPeer;
	SockAddr sAddr(0x7a7a7a7a,0x7878); // ip = zzzz and socket = xx
	socket4.SetBindAddr(sAddr);
	smart_ptr<DhtImpl> dhtTestObj(new DhtImpl(&socket4, &socket6));
	dhtTestObj->_dht_utversion[2] = 'x';
	dhtTestObj->_dht_utversion[3] = 'x';

	DhtID myId;	// this id falls into bucket #0 of the initial preallocated buckets (the \0 is the top 8 most significant bits of the dht id)
	myId.id[0] = '\0AAA';
	myId.id[1] = 'BBBB';
	myId.id[2] = 'CCCC';
	myId.id[3] = 'DDDD';
	myId.id[4] = 'FFFF';

	// prepare the object for use
	dhtTestObj->Enable(true,0);
	dhtTestObj->SetId(myId);

	// create 8 nodes to go into pre-allocated bucket #5
	int workingBucket = 5;
	int rtt = 10000;
	DhtPeerID peerIds[8];
	for(int subPrefix=0; subPrefix<8; ++subPrefix){
		peerIds[subPrefix]= MakeNodeForBucket(dhtTestObj, workingBucket, subPrefix);
		peerIds[subPrefix].addr.set_port(128);
		peerIds[subPrefix].addr.set_addr4((subPrefix << 24) | (subPrefix << 16) | (subPrefix << 8) | subPrefix);
		dhtTestObj->Update(peerIds[subPrefix], 0, true, rtt);
	}

	// there should be 8 nodes in the primary list and 0 nodes in the reserve list.
	EXPECT_EQ(8, CountNodesInPrimaryList(dhtTestObj, workingBucket));
	EXPECT_EQ(0, CountNodesInReplacementList(dhtTestObj, workingBucket));
	// nodes in the primary list should have unique sub-prefixes
	ASSERT_TRUE(SubPrefixesEvenlySpanNodeList(dhtTestObj->_buckets[workingBucket]->peers)) << "the node sub-prefixes are not evenly distributed and unique";

	// create a different node sub-prefix 4 for the bucket with a much FASTER rtt
	// this should move the original node at sub-prefix 4 to the replacement bucket
	DhtPeerID newNode = peerIds[4];
	newNode.addr.set_addr4(~newNode.addr.get_addr4());
	newNode.id.id[4] = ~newNode.id.id[4]; // just invert the last word
	// add the new node
	rtt = 2000;
	dhtTestObj->Update(newNode, 0, true, rtt);
	EXPECT_EQ(8, CountNodesInPrimaryList(dhtTestObj, workingBucket)) << "There should still be 8 nodes in the primary list after a slow node is replaced with a faster node";
	EXPECT_EQ(1, CountNodesInReplacementList(dhtTestObj, workingBucket)) << "The slow node should be the only node in the replacement list";
	EXPECT_TRUE(SubPrefixesEvenlySpanNodeList(dhtTestObj->_buckets[workingBucket]->peers)) << "the node sub-prefixes are not evenly distributed and unique";

	// now submit the original node with even faster rtt
	rtt = 100;
	dhtTestObj->Update(peerIds[4], 0, true, rtt);

	// there should be 8 nodes in the primary list and 1 nodes in the reserve list.
	// the node that was re-added should not be in the reserve list
	EXPECT_EQ(8, CountNodesInPrimaryList(dhtTestObj, workingBucket));
	EXPECT_EQ(1, CountNodesInReplacementList(dhtTestObj, workingBucket));

	EXPECT_TRUE(VerifyBuckets(dhtTestObj->_buckets)) << "Buckets did not verify; see previous message";
}


