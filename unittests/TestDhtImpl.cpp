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

#include <bitset>
#include "utypes.h"
#include "TestDhtImpl.h"

int put_callback(void* ctx, std::vector<char>& buffer, int64& seq, SockAddr src) {
	++seq;
	if (ctx != NULL) {
		*(reinterpret_cast<int64*>(ctx)) = seq;
	}
	char b[] = { '6', ':', 's', 'a', 'm', 'p', 'l', 'e' };
	buffer.assign(b, b + sizeof(b));
	return 0;
}

unsigned int count_set_bits(Buffer &data) {
	unsigned int count = 0;
	for(unsigned int x = 0; x < data.len; ++x) {
		count += std::bitset<8>(data.b[x]).count();
	}
	return count;
}

TEST_F(dht_impl_test, SimpleInitializationTest) {
	impl->Enable(true, 0);
	ASSERT_EQ(0, impl->GetNumPeersTracked());
}

TEST_F(dht_impl_test, PeersTest) {
	const char* DHTTestStoreFilename = "dhtstore.test";

	DhtID id;
	for (int i = 0; i < 5; ++i) {
		id.id[i] = rand();
	}

	impl->AddPeerToStore(id, DHTTestStoreFilename,
			SockAddr::parse_addr("10.0.1.0"), false);
	impl->AddPeerToStore(id, DHTTestStoreFilename,
			SockAddr::parse_addr("10.0.1.1"), false);
	impl->AddPeerToStore(id, DHTTestStoreFilename,
			SockAddr::parse_addr("10.0.1.2"), false);
	impl->AddPeerToStore(id, DHTTestStoreFilename,
			SockAddr::parse_addr("10.0.1.3"), true);
	impl->AddPeerToStore(id, DHTTestStoreFilename,
			SockAddr::parse_addr("10.0.1.4"), true);
	impl->AddPeerToStore(id, DHTTestStoreFilename,
			SockAddr::parse_addr("10.0.1.0"), true);

	str file_name = NULL;
	std::vector<StoredPeer> *peers = impl->GetPeersFromStore(id
		, &file_name, 200);
	EXPECT_TRUE(peers);
	if (peers) {
		ASSERT_EQ(5, peers->size());
	}
}

TEST_F(dht_impl_test, TestTheUnitTestUDPSocketClass) {
	UnitTestUDPSocket TestSocket;
	SockAddr DummySockAddr;
	std::string resultData;
	// be careful with test data containing '\0' in the middle of the string.
	std::string testData("abcdefghijklmnopqrstuvwxyz\t1234567890\xf1\x04");
	std::string additionalData("More Data");

	// "send" some data
	TestSocket.Send(DummySockAddr, "", (const unsigned char*)(testData.c_str()),
			testData.size());
	TestSocket.Send(DummySockAddr, "",
			(const unsigned char*)(additionalData.c_str()), additionalData.size());

	// see that the test socket faithfully represents the data.
	resultData = TestSocket.GetSentDataAsString(1);
	EXPECT_EQ(additionalData, resultData);
	TestSocket.popPacket();

	resultData = TestSocket.GetSentDataAsString(0);
	EXPECT_EQ(testData, resultData);
}

TEST_F(dht_impl_test, TestSendTo) {
	// the test data must be a valid bencoded string
	std::string
		testData("d1:ad2:id20:abcdefghij0123456789e1:q4:ping1:t2:aa1:y1:qe");

	impl->Enable(true, 0);

	impl->SendTo(peer_id.addr,
			(const unsigned char*)(testData.c_str()), testData.size());
	EXPECT_TRUE(socket4.GetSentDataAsString() == testData);
}

TEST_F(dht_impl_test, TestPingRPC_ipv4) {
	// prepare the object for use
	impl->Enable(true, 0);
	init_dht_id();

	// specify, parse, and send the message
	std::string testData("d1:ad2:id20:abcdefghij0123456789e1:q4:ping1:t2:aa1:y"
			"1:qe");
	ASSERT_NO_FATAL_FAILURE(fetch_response_to_message(&testData));
	expect_transaction_id("aa", 2);
	expect_reply_id();
}

TEST_F(dht_impl_test, TestPingRPC_ipv4_ParseKnownPackets) {
	// this test is aimed at the ParseKnownPackets member function that is optimized for a specific ping message format
	// as quoted from the code itself:
	//
	// currently we only know one packet type, the most common uT ping:
	// 'd1:ad2:id20:\t9\x93\xd4\xb7G\x10,Q\x9b\xf4\xc5\xfc\t\x87\x89\xeb\x93Q,e1:q4:ping1:t4:\x95\x00\x00\x001:v4:UT#\xa31:y1:qe'

	impl->Enable(true, 0);
	init_dht_id();

	std::string testData("d1:ad2:id20:abcdefghij0123456789e1:q4:ping1:t4:wxyz"
			"1:v4:UTUT1:y1:qe");
	ASSERT_NO_FATAL_FAILURE(fetch_response_to_message(&testData));
	expect_transaction_id("wxyz", 4);
	expect_reply_id();
}

TEST_F(dht_impl_test, TestGetPeersRPC_ipv4) {
	// prepare the object for use
	impl->Enable(true, 0);
	init_dht_id();

	add_node("abcdefghij0101010101");

	// specify, parse, and send the message
	std::string testData("d1:ad2:id20:abcdefghij01010101019:info_hash"
			"20:mnopqrstuvwxyz123456e1:q9:get_peers1:t2:aa1:y1:qe");
	ASSERT_NO_FATAL_FAILURE(fetch_response_to_message(&testData));
	expect_transaction_id("aa", 2);
	expect_reply_id();

	// in the test environment there is exactly one node.
	// expect back the id provided in the query, ip=zzzz port=xx (since the querying node and this node are the same in this test)
	Buffer nodes;
	nodes.b = (unsigned char*)reply->GetString("nodes", &nodes.len);
	ASSERT_EQ(26, nodes.len) << "ERROR:  The length of the 26 unsigned char"
		" node info extracted from the response arguments is the wrong size";
	EXPECT_FALSE(memcmp((const void*)nodes.b,
			(const void *)"abcdefghij0101010101", 20));

	// check that there is a token
	Buffer token;
	token.b = (unsigned char*)reply->GetString("token", &token.len);
	EXPECT_TRUE(token.len) << "There should have been a token of non-zero length";
}

TEST_F(dht_impl_test, TestFindNodeRPC_ipv4) {
	// prepare the object for use
	impl->Enable(true, 0);
	init_dht_id();

	add_node("abcdefghij0123456789");

	// specify, parse, and send the message
	std::string testData("d1:ad2:id20:abcdefghij01234567896:target"
			"20:mnopqrstuvwxyz123456e1:q9:find_node1:t2:aa1:y1:qe");
	ASSERT_NO_FATAL_FAILURE(fetch_response_to_message(&testData));
	expect_transaction_id("aa", 2);
	expect_reply_id();
	
	// There should be a single node, the one added above
	Buffer nodes;
	nodes.b = (unsigned char*)reply->GetString("nodes", &nodes.len);
	ASSERT_EQ(26, nodes.len) << "ERROR:  The length of the 26 unsigned char"
		" node info extracted from the response arguments is the wrong size";
	EXPECT_FALSE(memcmp((const void*)nodes.b,
			(const void *)"abcdefghij0123456789", 20));
}

TEST_F(dht_impl_test, TestGetRPC_min_seq) {
	impl->Enable(true, 0);
	init_dht_id();
	add_node("abababababababababab");

	// put a mutable item for us to get
	std::vector<unsigned char> token;
	fetch_token(token);
	len = bencoder(message, 1024)
		.d()
			("a").d()
				("id")("abcdefghij0123456789")
				("k")("12345678901234567890123456789012")
				("salt")("test salt")
				("seq")(int64(2))
				("sig")("1234567890123456789012345678901234567890123456789012345678901234")
				("token")(token)
				("v")("mutable get test").e()
			("q")("put")
			("t")("aa")
			("y")("q")
		.e() ();

	impl->ProcessIncoming(message, len, bind_addr);
	ASSERT_NO_FATAL_FAILURE(fetch_dict());
	ASSERT_NO_FATAL_FAILURE(expect_response_type());
	expect_transaction_id("aa", 2);

	// issue a get but specify the same seq, the node should omit the value in the response
	sha1_hash target = sha1_callback(
			reinterpret_cast<const unsigned char*>("12345678901234567890123456789012test salt"), DHT_KEY_SIZE+9);
	Buffer hashInfo;
	hashInfo.b = (unsigned char*)target.value;
	hashInfo.len = SHA1_DIGESTSIZE;

	len = bencoder(message, 1024)
		.d()
			("a").d()
				("id")("abcdefghij0123456789")
				("seq")(int64(2))
				("target")(hashInfo.b, hashInfo.len).e()
			("q")("get")
			("t")("aa")
			("y")("q")
		.e() ();
	// parse and send the message constructed above
	socket4.Reset();
	impl->ProcessIncoming(message, len, bind_addr);

	do {
		ASSERT_NO_FATAL_FAILURE(fetch_dict());
		socket4.popPacket();
	} while (!test_transaction_id("aa", 2));

	ASSERT_NO_FATAL_FAILURE(expect_response_type());
	expect_transaction_id("aa", 2);
	expect_reply_id();
	// check that there is a token
	Buffer tok;
	reply->GetString("token", &tok.len);
	EXPECT_TRUE(tok.len) << "There should have been a token of non-zero length";

	// check that there is a sequence number
	int64 seq = reply->GetInt64("seq", -1);
	EXPECT_EQ(2, seq);

	// check that there is no v
	Buffer value;
	value.b = (unsigned char*)reply->GetString("v", &value.len);
	ASSERT_EQ(0, value.len) << "Got a value when none was expected";
}

TEST_F(dht_impl_test, TestPutRPC_ipv4) {
	// prepare the object for use
	impl->Enable(true, 0);
	init_dht_id();
	add_node("abababababababababab");

	// put a peer into the dht for it to work with
	impl->Update(peer_id, 0, false);

	DhtID target;
	target.id[0] = 'FFFF'; // FFFF
	target.id[1] = 'GGGG'; // GGGG
	target.id[2] = 'HHHH'; // HHHH
	target.id[3] = 'IIII'; // IIII
	target.id[4] = 'JJJJ'; // JJJJ

	// *****************************************************
	// Make the dht emit an announce message (the get_peers rpc)
	// Just tell it that the target is only 16 bytes long (instead of 20)
	// *****************************************************
	EXPECT_FALSE(impl->IsBusy()) << "The dht should not be busy yet";
	int64 seq_result = 0;
	impl->Put(pkey, skey, &put_callback, NULL, NULL, &seq_result, 0);
	ASSERT_NO_FATAL_FAILURE(fetch_dict());
	ASSERT_NO_FATAL_FAILURE(expect_query_type());
	ASSERT_NO_FATAL_FAILURE(expect_command("get"));

	// get the transaction ID to use later
	Buffer tid;
	tid.b = (unsigned char*)dict->GetString("t" , &tid.len);
	EXPECT_EQ(4, tid.len);

	// now look into the query data
	expect_reply_id();
	expect_target();

	int64 seq = 0;
	const char* v = "sample";
	len = bencoder(message, 1024)
		.d()
			("ip")("abcdxy") ("r").d()
				("id")((unsigned char*)&peer_id.id.id[0], 20) ("nodes")("")
				("token")(response_token) ("seq")(seq) ("v")(v).e()
			("t")(tid.b, tid.len) ("y")("r")
		.e() ();
	
	// clear the socket and "send" the reply
	socket4.Reset();
	impl->ProcessIncoming(message, len, peer_id.addr);
	EXPECT_TRUE(impl->IsBusy()) << "The dht should still be busy";

	//Checking the put messages
	ASSERT_NO_FATAL_FAILURE(fetch_dict());
	ASSERT_NO_FATAL_FAILURE(expect_query_type());
	ASSERT_NO_FATAL_FAILURE(expect_command("put"));
	expect_transaction_id(NULL, 4);

	// now look into the query data
	expect_reply_id();
	EXPECT_EQ(seq + 1, reply->GetInt("seq"));
	expect_signature();
	expect_token(response_token);
	expect_value(v, strlen(v));
	EXPECT_EQ(int64(1), seq_result);
}

TEST_F(dht_impl_test, TestPutRPC_ipv4_cas) {
	// prepare the object for use
	impl->Enable(true, 0);
	init_dht_id();

	add_node("abababababababababab");

	// put a peer into the dht for it to work with
	impl->Update(peer_id, 0, false);

	DhtID target;
	target.id[0] = 'FFFF'; // FFFF
	target.id[1] = 'GGGG'; // GGGG
	target.id[2] = 'HHHH'; // HHHH
	target.id[3] = 'IIII'; // IIII
	target.id[4] = 'JJJJ'; // JJJJ

	EXPECT_FALSE(impl->IsBusy()) << "The dht should not be busy yet";
	int64 seq = 1337;
	impl->Put(pkey, skey, &put_callback, NULL, NULL, NULL, IDht::with_cas, seq);
	ASSERT_NO_FATAL_FAILURE(fetch_dict());
	ASSERT_NO_FATAL_FAILURE(expect_query_type());
	ASSERT_NO_FATAL_FAILURE(expect_command("get"));
	expect_transaction_id(NULL, 4);
	Buffer tid;
	tid.b = (unsigned char*)dict->GetString("t" , &tid.len);
	EXPECT_EQ(4, tid.len);

	// now look into the query data
	expect_reply_id();
	expect_target();

	const char* v = "sample";

	len = bencoder(message, 1024)
		.d()
			("ip")("abcdxy") ("r").d()
				("id")((unsigned char*)&peer_id.id.id[0], 20) ("nodes")("")
				("token")(response_token) ("seq")(seq) ("v")(v).e()
			("t")(tid.b, tid.len) ("y")("r")
		.e() ();

	printf("ProcessIncoming: %s\n", message);
	socket4.Reset();
	impl->ProcessIncoming(message, len, peer_id.addr);
	EXPECT_TRUE(impl->IsBusy()) << "The dht should still be busy";

	ASSERT_NO_FATAL_FAILURE(fetch_dict());
	ASSERT_NO_FATAL_FAILURE(expect_query_type());
	ASSERT_NO_FATAL_FAILURE(expect_command("put"));
	expect_transaction_id(NULL, 4);

	expect_cas(seq);
	expect_reply_id();
	EXPECT_EQ(seq + 1, reply->GetInt("seq"));
	expect_signature();
	expect_token(response_token);
	expect_value(v, strlen(v));
}

TEST_F(dht_impl_test, TestPutRPC_ipv4_seq_fail) {
	// prepare the object for use
	impl->Enable(true, 0);
	init_dht_id();

	add_node("ababababababababababab");

	DhtID target;
	target.id[0] = 'FFFF'; // FFFF
	target.id[1] = 'GGGG'; // GGGG
	target.id[2] = 'HHHH'; // HHHH
	target.id[3] = 'IIII'; // IIII
	target.id[4] = 'JJJJ'; // JJJJ

	EXPECT_FALSE(impl->IsBusy()) << "The dht should not be busy yet";
	int64 seq = 42;
	impl->Put(pkey, skey, &put_callback, NULL, NULL, NULL, IDht::with_cas, seq);
	ASSERT_NO_FATAL_FAILURE(fetch_dict());
	ASSERT_NO_FATAL_FAILURE(expect_query_type());
	ASSERT_NO_FATAL_FAILURE(expect_command("get"));
	expect_transaction_id(NULL, 4);
	Buffer tid;
	tid.b = (unsigned char*)dict->GetString("t" , &tid.len);
	EXPECT_EQ(4, tid.len);

	expect_reply_id();
	expect_target();

	len = bencoder(message, 1024)
		.d()
			("ip")("abcdxy") ("r").d()
				("id")((unsigned char*)&peer_id.id.id[0], 20) ("nodes")("")
				("token")(response_token) ("seq")(seq) ("v")(v).e()
			("t")(tid.b, tid.len) ("y")("r")
		.e() ();

	printf("ProcessIncoming: %s\n", message);
	socket4.Reset();
	impl->ProcessIncoming(message, len, peer_id.addr);
	EXPECT_TRUE(impl->IsBusy()) << "The dht should still be busy";

	ASSERT_NO_FATAL_FAILURE(fetch_dict());
	ASSERT_NO_FATAL_FAILURE(expect_query_type());
	ASSERT_NO_FATAL_FAILURE(expect_command("put"));
	tid.b = (unsigned char*)dict->GetString("t" , &tid.len);
	EXPECT_EQ(4, tid.len) << "transaction ID is wrong size";

	expect_cas(seq);
	expect_reply_id();
	EXPECT_EQ(seq + 1, reply->GetInt("seq"));
	expect_signature();
	expect_token(response_token);
	expect_value(v, strlen(v));

	// oh no we have a higher sequence number now and thus we shall complain
	len = bencoder(message, 1024)
		.d()
			("e").l()(static_cast<int64>(302))("error message!").e()
			("ip")("abcdxy") ("r").d()
				("id")((unsigned char*)&peer_id.id.id[0], 20).e()
			("t")(tid.b, tid.len) ("y")("e")
		.e() ();

	socket4.Reset();
	EXPECT_TRUE(impl->ProcessIncoming(message, len, peer_id.addr));
	EXPECT_TRUE(impl->IsBusy()) << "The dht should still be busy";
	ASSERT_NO_FATAL_FAILURE(fetch_dict());
	ASSERT_NO_FATAL_FAILURE(expect_query_type());
	ASSERT_NO_FATAL_FAILURE(expect_command("get"));
	expect_transaction_id(NULL, 4);
	expect_reply_id();
	expect_target();
}

TEST_F(dht_impl_test, TestAnnouncePeerRPC_ipv4) {
	// before we can announce_peer, we must use get_peers to obtain a token
	// use this to get a token
	std::string bEncodedGetPeers("d1:ad2:id20:abcdefghij01010101019:info_hash"
			"20:mnopqrstuvwxyz123456e1:q9:get_peers1:t2:aa1:y1:qe");

	// insert the token between these two strings
	std::string testDataPart1("d1:ad2:id20:abcdefghij01234567899:info_hash"
			"20:mnopqrstuvwxyz1234564:porti6881e5:token");
	std::string testDataPart2("e1:q13:announce_peer1:t2:aa1:y1:qe");
	std::string testData;

	// prepare the object for use
	impl->Enable(true, 0);
	init_dht_id();

	// first do the GetPeers to obtain a token
	ASSERT_NO_FATAL_FAILURE(fetch_response_to_message(&bEncodedGetPeers));
	get_reply();
	Buffer token;
	token.b = (unsigned char*)reply->GetString("token", &token.len);
	EXPECT_TRUE(token.len);

	// build the announce_peer test string with the token
	fill_test_data(testData, token, testDataPart1, testDataPart2);

	socket4.Reset();
	impl->Tick();

	// now we can start testing the response to announce_peer
	// Send the announce_peer query
	ASSERT_NO_FATAL_FAILURE(fetch_response_to_message(&testData));
	expect_transaction_id("aa", 2);
	expect_reply_id();
}

TEST_F(dht_impl_test, TestAnnouncePeerWithImpliedport) {
	set_port(0x0101);

	// before we can announce_peer, we must use get_peers to obtain a token
	// use this to get a token
	std::string bEncodedGetPeers("d1:ad2:id20:abcdefghij01010101019:info_hash"
			"20:mnopqrstuvwxyz123456e1:q9:get_peers1:t2:aa1:y1:qe");

	// insert the token between these two strings
	std::string testDataPart1("d1:ad2:id20:abcdefghij012345678912:implied_port"
			"i1e9:info_hash20:mnopqrstuvwxyz1234564:porti6881e5:token");
	std::string testDataPart2("e1:q13:announce_peer1:t2:aa1:y1:qe");
	std::string testData;

	// prepare the object for use
	impl->Enable(true, 0);
	init_dht_id();

	// first do the GetPeers to obtain a token
	ASSERT_NO_FATAL_FAILURE(fetch_response_to_message(&bEncodedGetPeers));
	get_reply();
	Buffer token;
	token.b = (unsigned char*)reply->GetString("token", &token.len);
	EXPECT_TRUE(token.len);

	// build the announce_peer test string with the token
	fill_test_data(testData, token, testDataPart1, testDataPart2);
	socket4.Reset();
	impl->Tick();
	impl->ProcessIncoming((unsigned char*)&testData[0],
			testData.size(), bind_addr);

	DhtID id;
	// grab the id typed into the string at the top
	CopyBytesToDhtID(id, (unsigned char*)(&(testDataPart1.c_str()[12])));

	std::vector<StoredContainer>::iterator it = impl->GetStorageForID(id);
	ASSERT_TRUE(it != impl->_peer_store.end()) << "The item was not stored";
	ASSERT_EQ(1, it->peers.size()) <<
			"there should be exactly one item in the store";

	EXPECT_EQ(0x01, it->peers[0].port[0]) <<
		"The port low unsigned char is wrong";
	EXPECT_EQ(0x01, it->peers[0].port[1]) <<
		"The port high unsigned char is wrong";
}

TEST_F(dht_impl_test, TestAnnouncePeerWithOutImpliedport) {
	set_port(0xF0F0);
	std::string bEncodedGetPeers("d1:ad2:id20:abcdefghij01010101019:info_hash"
			"20:mnopqrstuvwxyz123456e1:q9:get_peers1:t2:aa1:y1:qe");
	std::string testDataPart1("d1:ad2:id20:abcdefghij01234567899:info_hash"
			"20:mnopqrstuvwxyz1234564:porti514e5:token");
	std::string testDataPart2("e1:q13:announce_peer1:t2:aa1:y1:qe");
	std::string testData;

	// prepare the object for use
	impl->Enable(true, 0);
	init_dht_id();

	// first do the GetPeers to obtain a token
	ASSERT_NO_FATAL_FAILURE(fetch_response_to_message(&bEncodedGetPeers));
	get_reply();
	Buffer token;
	token.b = (unsigned char*)reply->GetString("token", &token.len);
	EXPECT_TRUE(token.len);

	// build the announce_peer test string with the token
	fill_test_data(testData, token, testDataPart1, testDataPart2);
	socket4.Reset();
	impl->Tick();
	impl->ProcessIncoming((unsigned char*)&testData[0],
			testData.size(), bind_addr);

	DhtID id;
	// grab the id typed into the string at the top
	CopyBytesToDhtID(id, (unsigned char*)(&(testDataPart1.c_str()[12])));

	std::vector<StoredContainer>::iterator it = impl->GetStorageForID(id);
	ASSERT_TRUE(it != impl->_peer_store.end()) << "The item was not stored";
	ASSERT_EQ(1, it->peers.size()) <<
			"there should be exactly one item in the store";

	EXPECT_EQ(0x02, it->peers[0].port[0]) <<
		"The port low unsigned char is wrong";
	EXPECT_EQ(0x02, it->peers[0].port[1]) <<
		"The port High unsigned char is wrong";
}

TEST_F(dht_impl_test, TestVoteRPC_ipv4) {
	impl->Enable(true, 0);
	init_dht_id();

	// get a token to use
	std::vector<unsigned char> token;
	fetch_token(token);

	len = bencoder(message, 1024)
		.d()
			("a").d()
				("id")("abcdefghij0123456789")
				("target")(make_random_key_20())
				("token")(token)
				("vote")(int64(1)).e()
			("q")("vote")
			("t")("aa")
			("y")("q")
		.e() ();

	ASSERT_NO_FATAL_FAILURE(fetch_response_to_message());
	expect_transaction_id("aa", 2);

	expect_reply_id();
	BencodedList *voteList = reply->GetList("v");
	ASSERT_TRUE(voteList);
	ASSERT_EQ(5, voteList->GetCount());

	// expect 1, 0, 0, 0, 0
	EXPECT_EQ(1, voteList->GetInt(0)) <<
			"Expected 1 0 0 0 0 but received 0 - - - -";
	EXPECT_EQ(0, voteList->GetInt(1)) <<
			"Expected 1 0 0 0 0 but received 1 1 - - -";
	EXPECT_EQ(0, voteList->GetInt(2)) <<
			"Expected 1 0 0 0 0 but received 1 0 1 - -";
	EXPECT_EQ(0, voteList->GetInt(3)) <<
			"Expected 1 0 0 0 0 but received 1 0 0 1 -";
	EXPECT_EQ(0, voteList->GetInt(4)) <<
			"Expected 1 0 0 0 0 but received 1 0 0 0 1";
}

// verify that multiple votes to the same target are recorded
TEST_F(dht_impl_test, TestVoteRPC_ipv4_MultipleVotes) {
	impl->Enable(true, 0);
	init_dht_id();

	// get a token to use
	std::vector<unsigned char> token;
	fetch_token(token);

	std::vector<unsigned char> target = make_random_key_20();

	// vote 5
	len = bencoder(message, 1024)
		.d()
			("a").d()
				("id")("abcdefghij0123456789")
				("target")(target)
				("token")(token)
				("vote")(int64(5)).e()
			("q")("vote")
			("t")("aa")
			("y")("q")
		.e() ();

	// parse and send the first vote message
	impl->ProcessIncoming(message, len, bind_addr);

	// prepare to send the second vote message
	impl->Tick();
	socket4.Reset();

	// make the second vote message with a vote of 2
	len = bencoder(message, 1024)
		.d()
			("a").d()
				("id")("abcdefghij0123456789")
				("target")(target)
				("token")(token)
				("vote")(int64(2)).e()
			("q")("vote")
			("t")("aa")
			("y")("q")
		.e() ();

	// parse and send the second vote message
	ASSERT_NO_FATAL_FAILURE(fetch_response_to_message());
	expect_transaction_id("aa", 2);
	expect_reply_id();

	BencodedList *voteList = reply->GetList("v");
	ASSERT_TRUE(voteList);
	ASSERT_EQ(5, voteList->GetCount());

	// expect 0, 1, 0, 0, 1
	EXPECT_EQ(0, voteList->GetInt(0)) <<
			"Expected 0 1 0 0 1 but received 1 - - - -";
	EXPECT_EQ(1, voteList->GetInt(1)) <<
			"Expected 0 1 0 0 1 but received 0 0 - - -";
	EXPECT_EQ(0, voteList->GetInt(2)) <<
			"Expected 0 1 0 0 1 but received 0 1 1 - -";
	EXPECT_EQ(0, voteList->GetInt(3)) <<
			"Expected 0 1 0 0 1 but received 0 1 0 1 -";
	EXPECT_EQ(1, voteList->GetInt(4)) <<
			"Expected 0 1 0 0 1 but received 0 1 0 0 0";
}

TEST_F(dht_impl_test, TestDHTScrapeSeed0_ipv4) {
	init_dht_id();
	impl->Enable(true, 0);

	// get a token to use
	std::vector<unsigned char> token;
	fetch_token(token);

	// make a random info_hash key to use
	std::vector<unsigned char> infoHashKey = make_random_key_20();

	// prepare the first anounce_peer with seed = 0
	len = bencoder(message, 1024)
		.d()
			("a").d()
				("id")("abcdefghij0101010101")
				("info_hash")(infoHashKey)
				("port")(int64(6881))
				("seed")(int64(0))
				("token")(token)
				("name")("test torrent").e()
			("q")("announce_peer")
			("t")("aa")
			("y")("q")
		.e() ();

	announce_and_verify();

	len = bencoder(message, 1024)
		.d()
			("a").d()
				("id")("abcdefghij0101010101")
				("info_hash")(infoHashKey)
				("port")(int64(6881))
				("scrape")(int64(1)).e()
			("q")("get_peers")
			("t")("aa")
			("y")("q")
		.e() ();

	ASSERT_NO_FATAL_FAILURE(fetch_response_to_message());
	expect_reply_id();

	// verify that BFsd and BFpe are present
	// see BEP #33 for details of BFsd & BFpe
	Buffer bfsd;
	bfsd.b = (unsigned char*)reply->GetString("BFsd", &bfsd.len);
	ASSERT_TRUE(bfsd.b && bfsd.len == 256);
	EXPECT_EQ(0, count_set_bits(bfsd)) << "ERROR:  Expected exactly 0 bits to be"
		" set in the seeds bloom filter 'BFsd'";
	Buffer bfpe;
	bfpe.b = (unsigned char*)reply->GetString("BFpe", &bfpe.len);
	ASSERT_TRUE(bfpe.b && bfpe.len == 256);
	EXPECT_EQ(2, count_set_bits(bfpe)) << "ERROR:  Expected exactly 2 bits to be"
		" set in the peers bloom filter 'BFpe'";
}

TEST_F(dht_impl_test, TestDHTScrapeSeed1_ipv4) {
	init_dht_id();
	impl->Enable(true, 0);

	// get a token to use
	std::vector<unsigned char> token;
	fetch_token(std::string("abcdefghij0123456789"), token);

	// make a random info_hash key to use
	std::vector<unsigned char> infoHashKey = make_random_key_20();

	// prepare the first anounce_peer with seed = 0
	len = bencoder(message, 1024)
		.d()
			("a").d()
				("id")("abcdefghij0123456789")
				("info_hash")(infoHashKey)
				("port")(int64(6881))
				("seed")(int64(1))
				("token")(token)
				("name")("test torrent").e()
			("q")("announce_peer")
			("t")("aa")
			("y")("q")
		.e() ();

	announce_and_verify();

	len = bencoder(message, 1024)
		.d()
			("a").d()
				("id")("abcdefghij0123456789")
				("info_hash")(infoHashKey)
				("port")(int64(6881))
				("scrape")(int64(1)).e()
			("q")("get_peers")
			("t")("aa")
			("y")("q")
		.e() ();

	ASSERT_NO_FATAL_FAILURE(fetch_response_to_message());
	expect_reply_id();

	// verify that BFsd and BFpe are present
	// see BEP #33 for details of BFsd & BFpe
	Buffer bfsd;
	bfsd.b = (unsigned char*)reply->GetString("BFsd", &bfsd.len);
	ASSERT_TRUE(bfsd.b && bfsd.len == 256);
	EXPECT_EQ(2, count_set_bits(bfsd)) << "ERROR:  Expected exactly 2 bits to be"
		" set in the seeds bloom filter 'BFsd'";
	Buffer bfpe;
	bfpe.b = (unsigned char*)reply->GetString("BFpe", &bfpe.len);
	ASSERT_TRUE(bfpe.b && bfpe.len == 256);
	ASSERT_EQ(0, count_set_bits(bfpe)) << "ERROR:  Expected exactly 0 bits to be"
		" set in the peers bloom filter 'BFpe'";
}

TEST_F(dht_impl_test, TestDHTForNonexistantPeers_ipv4) {
	impl->Enable(true, 0);
	std::vector<unsigned char> token;
	int port = 6881;
	std::string id("abcdefghij0123456789");

	char itoa_buf[3];
	for(int i = 1; i <= 13; i++) {
		sprintf(itoa_buf, "%02d", i);
		fetch_token(token);
		len = bencoder(message, 1024)
			.d()
				("a").d()
					("id")(id)
					("info_hash")(make_random_key_20())
					("port")(int64(port))
					("name")(std::string("name") + itoa_buf)
					("token")(token).e()
				("q")("announce_peer")
				("t")("zz")
				("y")("q")
			.e() ();
		ASSERT_NO_FATAL_FAILURE(fetch_response_to_message());
		expect_transaction_id("zz", 2);
		get_reply();
		EXPECT_TRUE(reply->GetString("id", 20));
		impl->Tick();
		socket4.Reset();
	}
	// now make a get_peers message with a nonexistant hash
	len = bencoder(message, 1024)
		.d()
			("a").d()
				("id")("abcdefghij0123456789")
				("info_hash")("__nonexistenthash___")
				("port")(int64(port)).e()
			("q")("get_peers")
			("t")("aa")
			("y")("q")
		.e() ();
	ASSERT_NO_FATAL_FAILURE(fetch_response_to_message());
	get_reply();
	cstr values = reply->GetString("values", 6);
	EXPECT_FALSE(values) << "ERROR:  There is a 'values' key in the reply"
		" dictionary for a non-existent hash";
}

TEST_F(dht_impl_test, TestFutureCmdAsFindNode01_ipv4) {
	// unknown messages with either a 'target'
	// or an 'info-hash' argument are treated
	// as a find node to not block future extensions

	impl->Enable(true, 0);
	init_dht_id();

	add_node("abcdefghij0123456789");

	// specify, parse, and send the message
	// Set a TARGET with a 'future_cmd' command in this test
	// it sould be treated as a find_node command
	std::string testData("d1:ad2:id20:abcdefghij01234567896:target"
			"20:mnopqrstuvwxyz123456e1:q10:future_cmd1:t2:aa1:y1:qe");
	ASSERT_NO_FATAL_FAILURE(fetch_response_to_message(&testData));
	expect_transaction_id("aa", 2);
	expect_reply_id();

	// There should be a single node - this one
	// expect back the id provided in the query, ip=zzzz port=xx (since the querying node and this node are the same in this test)
	Buffer nodes;
	nodes.b = (unsigned char*)reply->GetString("nodes", &nodes.len);
	ASSERT_EQ(26, nodes.len) << "ERROR:  The length of the 26 unsigned char"
		" node info extracted from the response arguments is the wrong size";
	EXPECT_FALSE(memcmp((const void*)nodes.b,
			(const void *)"abcdefghij0123456789", 20));
}

TEST_F(dht_impl_test, TestFutureCmdAsFindNode02_ipv4) {
	// unknown messages with either a 'target'
	// or an 'info-hash' argument are treated
	// as a find node to not block future extensions
	impl->Enable(true, 0);
	init_dht_id();
	add_node("abcdefghij0123456789");

	// specify, parse, and send the message
	// Set an INFO_HASH with a 'future_cmd' command in this test
	// it sould be treated as a find_node command
	std::string testData("d1:ad2:id20:abcdefghij01234567899:info_hash"
			"20:mnopqrstuvwxyz123456e1:q10:future_cmd1:t2:aa1:y1:qe");
	ASSERT_NO_FATAL_FAILURE(fetch_response_to_message(&testData));
	expect_transaction_id("aa", 2);
	expect_reply_id();

	// There should be a single node - this one
	// expect back the id provided in the query, ip=zzzz port=xx (since the querying node and this node are the same in this test)
	Buffer nodes;
	nodes.b = (unsigned char*)reply->GetString("nodes", &nodes.len);
	ASSERT_EQ(26, nodes.len) << "ERROR:  The length of the 26 unsigned char"
		" node info extracted from the response arguments is the wrong size";
	EXPECT_FALSE(memcmp((const void*)nodes.b,
			(const void *)"abcdefghij0123456789", 20));
}

TEST_F(dht_impl_test, TestUnknownCmdNotProcessed_ipv4) {
	// unknown messages with either a 'target'
	// or an 'info-hash' argument are treated
	// as a find node to not block future extensions

	impl->Enable(true, 0);
	init_dht_id();

	// specify, parse, and send the message
	// DO NOT set a target or info_hash with this 'unknown_cmd' command in this test
	// it sould NOT be treated as anything
	std::string testData("d1:ad2:id20:abcdefghij012345678911:unknown_arg"
			"20:mnopqrstuvwxyz123456e1:q11:unknown_cmd1:t2:aa1:y1:qe");
	impl->ProcessIncoming((unsigned char*)testData.c_str(), testData.size(),
			bind_addr);

	// get the bencoded string out of the socket
	std::string bencMessage = socket4.GetSentDataAsString();
	EXPECT_STREQ(bencMessage.c_str(), "");
}

TEST_F(dht_impl_test, TestImmutablePutRPC_ipv4) {
	impl->Enable(true, 0);
	init_dht_id();

	std::vector<unsigned char> token;
	fetch_token(token);
	
	len = bencoder(message, 1024)
		.d()
			("a").d()
				("id")("abcdefghij0123456789")
				("token")(token)
				("v")("Immutable put test").e()
			("q")("put")
			("t")("aa")
			("y")("q")
		.e() ();

	impl->ProcessIncoming(message, len, bind_addr);
	ASSERT_NO_FATAL_FAILURE(fetch_dict());
	ASSERT_NO_FATAL_FAILURE(expect_response_type());
	expect_transaction_id("aa", 2);
	expect_reply_id();
}

TEST_F(dht_impl_test, TestImmutableGetRPC_ipv4) {
	impl->Enable(true, 0);
	init_dht_id();
	add_node("abababababababababab");

	std::vector<unsigned char> token;
	fetch_token(token);
	len = bencoder(message, 1024)
		.d()
			("a").d()
				("id")("abcdefghij0123456789")
				("token")(token)
				("v")("Immutable get test").e()
			("q")("put")
			("t")("aa")
			("y")("q")
		.e() ();

	impl->ProcessIncoming(message, len, bind_addr);
	ASSERT_NO_FATAL_FAILURE(fetch_dict());
	ASSERT_NO_FATAL_FAILURE(expect_response_type());
	expect_transaction_id("aa", 2);

	// *** SECOND: get something out ***
	sha1_hash target = sha1_callback(
			reinterpret_cast<const unsigned char*>("18:Immutable get test"), 21);
	Buffer hashInfo;
	hashInfo.b = (unsigned char*)target.value;
	hashInfo.len = 20;

	len = bencoder(message, 1024)
		.d()
			("a").d()
				("id")("abcdefghij0123456789")
				("target")(hashInfo.b, hashInfo.len).e()
			("q")("get")
			("t")("aa")
			("y")("q")
		.e() ();
	// parse and send the message constructed above
	socket4.Reset();
	impl->ProcessIncoming(message, len, bind_addr);

	do {
		ASSERT_NO_FATAL_FAILURE(fetch_dict());
		socket4.popPacket();
	} while (!test_transaction_id("aa", 2));

	ASSERT_NO_FATAL_FAILURE(expect_response_type());
	expect_transaction_id("aa", 2);
	expect_reply_id();
	// check that there is a token
	Buffer tok;
	reply->GetString("token", &tok.len);
	EXPECT_TRUE(tok.len) << "There should have been a token of non-zero length";

	// get the nodes
	Buffer nodes;
	nodes.b = (unsigned char*)reply->GetString("nodes", &nodes.len);
	EXPECT_TRUE(nodes.len) << "There should have been a node";

	// get the value "v"
	// v should be an bencentity of "18:Immutable get test".  Using the GetString will strip out the 18 and just return the text.
	Buffer value;
	value.b = (unsigned char*)reply->GetString("v", &value.len);
	ASSERT_EQ(18, value.len) << "The value is the wrong length";
	EXPECT_FALSE(memcmp((const void*)value.b, (const void *)"Immutable get test",
				18));
}

TEST_F(dht_impl_test, TestMultipleImmutablePutRPC_ipv4) {
	impl->Enable(true, 0);
	init_dht_id();

	// if the same thing gets put multiple times there should only be one
	// copy of it stored 
	//                                                 20_byte_dhtid_val_
	ASSERT_NO_FATAL_FAILURE(immutable_put(std::string("20_byte_dhtid_val_00"),
				"i-1e"));
	ASSERT_NO_FATAL_FAILURE(immutable_put(std::string("20_byte_dhtid_val_01"),
				"i-1e"));
	ASSERT_NO_FATAL_FAILURE(immutable_put(std::string("20_byte_dhtid_val_02"),
				"i-1e"));
	ASSERT_NO_FATAL_FAILURE(immutable_put(std::string("20_byte_dhtid_val_03"),
				"i-1e"));
	ASSERT_NO_FATAL_FAILURE(immutable_put(std::string("20_byte_dhtid_val_04"),
				"i-1e"));
	EXPECT_EQ(1, impl->GetNumPutItems()) <<
			"ERROR:  multiple instances of the same thing stored";

	// now add different things and see the count increase
	ASSERT_NO_FATAL_FAILURE(immutable_put(std::string("20_byte_dhtid_val_00"),
				"i2e"));
	ASSERT_NO_FATAL_FAILURE(immutable_put(std::string("20_byte_dhtid_val_01"),
				"i3e"));
	ASSERT_NO_FATAL_FAILURE(immutable_put(std::string("20_byte_dhtid_val_02"),
				"i4e"));
	ASSERT_NO_FATAL_FAILURE(immutable_put(std::string("20_byte_dhtid_val_03"),
				"i5e"));
	ASSERT_NO_FATAL_FAILURE(immutable_put(std::string("20_byte_dhtid_val_04"),
				"i6e"));
	EXPECT_EQ(6, impl->GetNumPutItems()) <<
			"ERROR:  several different thinigs did not get stored";
}

TEST_F(dht_impl_test, TestMultipleImmutablePutAndGetRPC_ipv4) {
	std::vector<unsigned char> hashes[5];
	std::string putValues[5];

	// prepare the object for use
	impl->Enable(true, 0);
	init_dht_id();

	putValues[0] = ("i5e"); // test an integer
	putValues[1] = ("l4:spam4:eggse"); // list
	putValues[2] = ("d4:spaml1:a1:bee"); // dictionary with list
	putValues[3] = ("4:spam"); // string
	putValues[4] = ("d3:cow3:moo4:spam4:eggse"); // dictionary

	for(int x = 0; x < 5; ++x) {
		sha1_hash hash = sha1_callback(reinterpret_cast<const unsigned char*>
				(putValues[x].c_str()), putValues[x].size());
		hashes[x].insert(hashes[x].end(), hash.value, hash.value + 20);
	}

	ASSERT_NO_FATAL_FAILURE(immutable_put(std::string("20_byte_dhtid_val_00"),
				putValues[0].c_str()));
	ASSERT_NO_FATAL_FAILURE(immutable_put(std::string("20_byte_dhtid_val_01"),
				putValues[1].c_str()));
	ASSERT_NO_FATAL_FAILURE(immutable_put(std::string("20_byte_dhtid_val_02"),
				putValues[2].c_str()));
	ASSERT_NO_FATAL_FAILURE(immutable_put(std::string("20_byte_dhtid_val_03"),
				putValues[3].c_str()));
	ASSERT_NO_FATAL_FAILURE(immutable_put(std::string("20_byte_dhtid_val_04"),
				putValues[4].c_str()));
	EXPECT_EQ(5, impl->GetNumPutItems()) <<
			"ERROR:  several different thinigs did not get stored";

	// get the data out and see that it matches what was put
	BencEntity* entity;
	for(int x = 0; x < 5; ++x) {
		len = bencoder(message, 1024)
			.d()
				("a").d()
					("id")("abcdefghij0123456789")
					("target")(&(hashes[x][0]), 20).e()
				("q")("get")
				("t")("aa")
				("y")("q")
			.e() ();
		socket4.Reset();
		impl->Tick();
		impl->ProcessIncoming(message, len, bind_addr);
		ASSERT_NO_FATAL_FAILURE(fetch_dict());
		ASSERT_NO_FATAL_FAILURE(expect_response_type());
		get_reply();
		entity = reply->Get("v");
		ASSERT_TRUE(entity);
		std::string serialized_entity = SerializeBencEntity(entity);
		EXPECT_EQ(putValues[x], serialized_entity);
		EXPECT_FALSE(reply->GetString("key"));
		EXPECT_FALSE(reply->GetString("sig"));
	}
}
