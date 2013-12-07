#include <bitset>
#include <stdio.h>

#include "TestDHT.h"
#include "bencoder.h"

static const unsigned char * pkey = reinterpret_cast<const unsigned char *>
			("dhuieheuu383y8yr7yy3hd3hdh3gfhg3");
static const unsigned char * skey = reinterpret_cast<const unsigned char *>
			("dhuieheuu383y8yr7yy3hd3hdh3gfhg3dhuieheuu383y8yr7yy3hd3hdh3gfhg3");

void put_callback(void* ctx, std::vector<char>& buffer, int64_t seq) {
	if (ctx != NULL) {
		*(reinterpret_cast<int64_t*>(ctx)) = seq;
	}
	buffer = { '6', ':', 's', 'a', 'm', 'p', 'l', 'e' };
}

void ed25519_callback(unsigned char * sig, const unsigned char * v,
		unsigned long long size, const unsigned char * key) {
	for(int i = 0; i < 64; i++) {
		sig[i] = 'a';
	}
}

std::vector<byte> MakeRandomByteString(unsigned int numBytesLong) {
	std::vector<byte> key;
	for(unsigned int x=0; x<numBytesLong; ++x){
		key.push_back(rand()%74 + 48); // make something in the alphanumeric range
	}
	return key;
}

std::vector<byte> MakeRandomKey20() {
	return MakeRandomByteString(20);
}

unsigned int CountSetBits(Buffer &data) {
	unsigned int count = 0;
	for(unsigned int x = 0; x < data.len; ++x) {
		count += std::bitset<8>(data.b[x]).count();
	}
	return count;
}

void fillTestDataBytes(std::vector<byte> &result, const Buffer &token,
		const std::string &one, const std::string &two) {
	char itoa_string[50];
	snprintf(itoa_string, 50, "%u", static_cast<unsigned int>(token.len));

	result.insert(result.end(), one.c_str(), one.c_str() + one.length());
	result.insert(result.end(), itoa_string, itoa_string + strlen(itoa_string));
	result.push_back(':');
	result.insert(result.end(), token.b, token.b + token.len);
	result.insert(result.end(), two.c_str(), two.c_str() + two.length());
}

class dht_impl_test : public dht_test {
	protected:
		SockAddr sAddr;
		std::string sAddr_AddressAsString;
		std::string sAddr_PortAsString;

		UnitTestUDPSocket socket4;
		UnitTestUDPSocket socket6;
		DhtImpl* impl;
		DhtPeerID peerID;

		unsigned char message_bytes[1024];

		virtual void SetUp() override {
			sAddr.set_addr4('zzzz');
			sAddr.set_port(('x' << 8) + 'x');
			// TODO: purge this insanity; setting these manually is imbecilic
			sAddr_AddressAsString = "zzzz";
			sAddr_PortAsString = "xx";

			impl = new DhtImpl(&socket4, &socket6);
			impl->SetSHACallback(&sha1_callback);
			impl->SetEd25519SignCallback(&ed25519_callback);

			peerID.id.id[0] = '1111'; // 1111
			peerID.id.id[1] = 'BBBB'; // BBBB
			peerID.id.id[2] = 'CCCC'; // CCCC
			peerID.id.id[3] = 'DDDD'; // DDDD
			peerID.id.id[4] = '0000'; // 0000
			peerID.addr.set_port(128);
			peerID.addr.set_addr4(0xf0f0f0f0);
		}

		virtual void TearDown() override {
			delete impl;
		}

		void init_dht_id() {
			impl->SetId((unsigned char*)DHTID_BYTES.c_str());
		}

		void fetch_dict(BencodedDict& result) {
			std::string bencMessage = socket4.GetSentDataAsString();
			BencEntity::Parse((const unsigned char *)bencMessage.c_str(), result,
					(const unsigned char *)(bencMessage.c_str() + bencMessage.length()));
			ASSERT_TRUE(result.bencType == BENC_DICT);
		}

		static void expect_response_type(BencodedDict& result) {
			cstr type = result.GetString("y", 1);
			ASSERT_TRUE(type);
			ASSERT_EQ('r', *type);
		}

		static void expect_query_type(BencodedDict& result) {
			cstr type = result.GetString("y", 1);
			ASSERT_TRUE(type);
			ASSERT_EQ('q', *type);
		}

		static void expect_command(BencodedDict& result, const char* command) {
			cstr c = result.GetString("q", strlen(command));
			ASSERT_TRUE(c);
			ASSERT_STREQ(command, c);
		}

		void fetch_response_to_message(BencodedDict& result,
				unsigned char* message, int64_t message_len) {
			impl->ProcessIncoming(message, message_len, sAddr);
			fetch_dict(result);
			expect_response_type(result);

			Buffer ip;
			ip.b = (unsigned char*)result.GetString("ip", &ip.len);
			ASSERT_EQ(6, ip.len);
			EXPECT_FALSE(memcmp((const void*)ip.b,
						(const void *)sAddr_AddressAsString.c_str(), 4));
			EXPECT_FALSE(memcmp((const void*)(ip.b + 4),
						(const void *)sAddr_PortAsString.c_str(), 2));
		}

		static void expect_transaction_id(BencodedDict& dict, const char* id,
				int id_len) {
			Buffer tid;
			tid.b = (unsigned char*)dict.GetString("t", &tid.len);
			ASSERT_EQ(id_len, tid.len);
			if (id != NULL) {
				EXPECT_FALSE(memcmp((const void*)tid.b, (const void *)id, id_len));
			}
		}

		static void expect_reply_id(BencodedDict* reply) {
			unsigned char *id = (unsigned char*)reply->GetString("id", 20);
			ASSERT_TRUE(id);
			EXPECT_FALSE(memcmp((const void*)id, (const void *)DHTID_BYTES.c_str(),
						20));
		}

		static void expect_token(BencodedDict* reply, const char* response_token) {
			Buffer token;
			token.b = (unsigned char*)reply->GetString("token" , &token.len);
			EXPECT_EQ(20, token.len);
			EXPECT_FALSE(memcmp(response_token, token.b, 20)) <<
				"ERROR: announced token is wrong";
		}

		static void expect_signature(BencodedDict* reply) {
			Buffer sig;
			sig.b = (unsigned char*)reply->GetString("sig" , &sig.len);
			EXPECT_EQ(64, sig.len);
		}

		static void expect_value(BencodedDict* reply, const char* value,
				int value_len) {
			Buffer v_out;
			v_out.b = (unsigned char*)reply->GetString("v" , &v_out.len);
			EXPECT_EQ(value_len, v_out.len);
			EXPECT_FALSE(memcmp(value, v_out.b, value_len)) << "ERROR: v is wrong";
		}

		static void expect_cas(BencodedDict* reply, const unsigned char* cas) {
			Buffer cas_buf;
			cas_buf.b = (unsigned char*)reply->GetString("cas", &cas_buf.len);
			ASSERT_NE(nullptr, cas_buf.b);
			EXPECT_EQ(20, cas_buf.len);
			EXPECT_FALSE(memcmp(cas, cas_buf.b, 20)) << "ERROR: wrong cas";
		}

		static void expect_target(BencodedDict* reply) {
			Buffer pkey_buf;
			pkey_buf.b = (unsigned char*)reply->GetString("target" , &pkey_buf.len);
			EXPECT_EQ(20, pkey_buf.len);
			EXPECT_FALSE(memcmp(sha1_callback(pkey, 32).value, pkey_buf.b, 20)) <<
				"ERROR: pkey is not the correct target";
		}

		void fetch_token(std::vector<byte> &token) {
			return fetch_token(std::string("abcdefghij0101010101"), token);
		}

		void fetch_token(const std::string &id, std::vector<byte> &token_bytes) {
			assert(id.size() == 20);
			Buffer token;

			std::string get_peers = "d1:ad2:id20:" + id +
				"9:info_hash20:mnopqrstuvwxyz123456e1:q9:get_peers1:t2:aa1:y1:qe";

			socket4.Reset();
			impl->ProcessIncoming((byte*)get_peers.c_str(),
					get_peers.size(), sAddr);
			BencodedDict dict;
			fetch_dict(dict);
			BencodedDict *reply = dict.GetDict("r");
			ASSERT_TRUE(reply);
			token.b = (byte*)reply->GetString("token", &token.len);
			ASSERT_TRUE(token.len);
			token_bytes.assign(token.b, token.b + token.len);
			impl->Tick();
			socket4.Reset();
		}

		void announce_and_verify(unsigned char* message, int64_t message_len) {
			BencodedDict dict;
			BencodedDict* reply;
			fetch_response_to_message(dict, message, message_len);
			reply = dict.GetDict("r");
			ASSERT_TRUE(reply);
			expect_reply_id(reply);
			impl->Tick();
			socket4.Reset();
		}

		void immutable_put(const std::string &id, char const *v) {
			// get a token to use
			std::vector<unsigned char> token;
			socket4.Reset();
			fetch_token(id, token);
			int64_t len = bencoder(message_bytes, 1024)
				.d()
					("a").d()
						("id")(id)
						("token")(token)
						("v").raw(v).e()
					("q")("put")
					("t")("aa")
					("y")("q")
				.e() () - message_bytes;
			socket4.Reset();
			BencodedDict dict;
			impl->ProcessIncoming(message_bytes, len, sAddr);
			fetch_dict(dict);
			expect_response_type(dict);
			BencodedDict *reply = dict.GetDict("r");
			ASSERT_TRUE(reply);
			impl->Tick();
			socket4.Reset();
		}
};

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

	DhtID correct_info_hash_id;
	memset(correct_info_hash_id.id, 0, 5);
	int info_hash_len = SHA1_DIGESTSIZE;
	str file_name = NULL;
	std::vector<StoredPeer> *peers = impl->GetPeersFromStore(id, info_hash_len,
			&correct_info_hash_id, &file_name, 200);
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
	std::string totalData = testData + additionalData;

	// "send" some data
	TestSocket.Send(DummySockAddr, "", (const unsigned char*)(testData.c_str()),
			testData.size());
	TestSocket.Send(DummySockAddr, "",
			(const unsigned char*)(additionalData.c_str()), additionalData.size());

	// see that the test socket faithfully represents the data.
	resultData = TestSocket.GetSentDataAsString();
	EXPECT_TRUE(resultData == totalData);
}

TEST_F(dht_impl_test, TestSendTo) {
	// the test data must be a valid bencoded string
	std::string
		testData("d1:ad2:id20:abcdefghij0123456789e1:q4:ping1:t2:aa1:y1:qe");

	impl->Enable(true, 0);

	impl->SendTo(peerID,
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
	BencodedDict dict;
	fetch_response_to_message(dict, (unsigned char*)testData.c_str(),
			testData.size());
	expect_transaction_id(dict, "aa", 2);

	// now look into the response data
	BencodedDict *reply = dict.GetDict("r");
	ASSERT_TRUE(reply);
	expect_reply_id(reply);
}

TEST_F(dht_impl_test, TestPingRPC_ipv4_ParseKnownPackets) {
	// this test is aimed at the ParseKnownPackets member function that is optimized for a specific ping message format
	// as quoted from the code itself:
	//
	// currently we only know one packet type, the most common uT ping:
	// 'd1:ad2:id20:\t9\x93\xd4\xb7G\x10,Q\x9b\xf4\xc5\xfc\t\x87\x89\xeb\x93Q,e1:q4:ping1:t4:\x95\x00\x00\x001:v4:UT#\xa31:y1:qe'

	// prepare the object for use
	impl->Enable(true, 0);
	init_dht_id();

	// specify, parse, and send the message
	std::string testData("d1:ad2:id20:abcdefghij0123456789e1:q4:ping1:t4:wxyz"
			"1:v4:UTUT1:y1:qe");
	BencodedDict dict;
	fetch_response_to_message(dict, (unsigned char*)testData.c_str(),
			testData.size());
	expect_transaction_id(dict, "wxyz", 4);

	// now look into the response data
	BencodedDict *reply = dict.GetDict("r");
	ASSERT_TRUE(reply);
	expect_reply_id(reply);
}

TEST_F(dht_impl_test, TestGetPeersRPC_ipv4) {
	// prepare the object for use
	impl->Enable(true, 0);
	init_dht_id();

	// specify, parse, and send the message
	std::string testData("d1:ad2:id20:abcdefghij01010101019:info_hash"
			"20:mnopqrstuvwxyz123456e1:q9:get_peers1:t2:aa1:y1:qe");
	BencodedDict dict;
	fetch_response_to_message(dict, (unsigned char*)testData.c_str(),
			testData.size());
	expect_transaction_id(dict, "aa", 2);
	BencodedDict *reply = dict.GetDict("r");
	ASSERT_TRUE(reply);
	expect_reply_id(reply);

	// in the test environment there are no peers.  There should however be a node - this one
	// expect back the id provided in the query, ip=zzzz port=xx (since the querying node and this node are the same in this test)
	Buffer nodes;
	nodes.b = (unsigned char*)reply->GetString("nodes", &nodes.len);
	ASSERT_EQ(26, nodes.len) << "ERROR:  The length of the 26 unsigned char"
		" node info extracted from the response arguments is the wrong size";
	EXPECT_FALSE(memcmp((const void*)nodes.b,
			(const void *)"abcdefghij0101010101zzzzxx", nodes.len));

	// check that there is a token
	Buffer token;
	token.b = (unsigned char*)reply->GetString("token", &token.len);
	EXPECT_TRUE(token.len) << "There should have been a token of non-zero length";
}

TEST_F(dht_impl_test, TestFindNodeRPC_ipv4) {
	// prepare the object for use
	impl->Enable(true, 0);
	init_dht_id();

	// specify, parse, and send the message
	std::string testData("d1:ad2:id20:abcdefghij01234567896:target"
			"20:mnopqrstuvwxyz123456e1:q9:find_node1:t2:aa1:y1:qe");
	BencodedDict dict;
	fetch_response_to_message(dict, (unsigned char*)testData.c_str(),
			testData.size());
	expect_transaction_id(dict, "aa", 2);
	BencodedDict *reply = dict.GetDict("r");
	ASSERT_TRUE(reply);
	expect_reply_id(reply);
	
	// There should be a single node - this one
	// expect back the id provided in the query, ip=zzzz port=xx (since the querying node and this node are the same in this test)
	Buffer nodes;
	nodes.b = (unsigned char*)reply->GetString("nodes", &nodes.len);
	ASSERT_EQ(26, nodes.len) << "ERROR:  The length of the 26 unsigned char"
		" node info extracted from the response arguments is the wrong size";
	EXPECT_FALSE(memcmp((const void*)nodes.b,
			(const void *)"abcdefghij0123456789zzzzxx", nodes.len));
}

TEST_F(dht_impl_test, TestPutRPC_ipv4) {
	// prepare the object for use
	impl->Enable(true, 0);
	init_dht_id();

	// put a peer into the dht for it to work with
	impl->Update(peerID, 0, false);

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
	int64_t seq_result = 0;
	impl->Put(pkey, skey, &put_callback, &seq_result, 0);
	
	// *****************************************************
	// grab from the socket the emitted message and extract
	// the transaction ID and verify the remainder of the
	// message
	// *****************************************************
	BencodedDict dictForGet;
	fetch_dict(dictForGet);
	expect_query_type(dictForGet);
	expect_command(dictForGet, "get");

	// get the transaction ID to use later
	Buffer tid;
	tid.b = (unsigned char*)dictForGet.GetString("t" , &tid.len);
	EXPECT_EQ(4, tid.len);

	// now look into the query data
	BencodedDict *getQuery = dictForGet.GetDict("a");
	ASSERT_TRUE(getQuery);
	expect_reply_id(getQuery);
	expect_target(getQuery);

	int64_t seq = 0;
	const char* responseToken = "20_byte_reply_token.";
	const char* v = "sample";
	unsigned char message_bytes[1024];
	int64_t len = bencoder(message_bytes, 1024)
		.d()
			("ip")("abcdxy") ("r").d()
				("id")((unsigned char*)&peerID.id.id[0], 20) ("nodes")("")
				("token")(responseToken) ("seq")(seq) ("v")(v).e()
			("t")(tid.b, tid.len) ("y")("r")
		.e() () - message_bytes;
	
	// clear the socket and "send" the reply
	socket4.Reset();
	impl->ProcessIncoming(message_bytes, len, peerID.addr);

	EXPECT_TRUE(impl->IsBusy()) << "The dht should still be busy";

	//Checking the put messages

	BencodedDict dictForPut;
	fetch_dict(dictForPut);
	expect_query_type(dictForPut);
	expect_command(dictForPut, "put");
	expect_transaction_id(dictForPut, NULL, 4);

	// now look into the query data
	BencodedDict *putQuery = dictForPut.GetDict("a");
	ASSERT_TRUE(putQuery);
	expect_reply_id(putQuery);
	EXPECT_EQ(seq + 1, putQuery->GetInt("seq"));
	expect_signature(putQuery);
	expect_token(putQuery, responseToken);
	expect_value(putQuery, v, strlen(v));
	EXPECT_EQ(int64_t(1), seq_result);
}

TEST_F(dht_impl_test, TestPutRPC_ipv4_cas) {
	// prepare the object for use
	impl->Enable(true, 0);
	init_dht_id();

	// put a peer into the dht for it to work with
	impl->Update(peerID, 0, false);

	DhtID target;
	target.id[0] = 'FFFF'; // FFFF
	target.id[1] = 'GGGG'; // GGGG
	target.id[2] = 'HHHH'; // HHHH
	target.id[3] = 'IIII'; // IIII
	target.id[4] = 'JJJJ'; // JJJJ

	EXPECT_FALSE(impl->IsBusy()) << "The dht should not be busy yet";
	int64_t seq = 2;
	impl->Put(pkey, skey, &put_callback, NULL, IDht::with_cas, seq);
	BencodedDict dictForGet;
	fetch_dict(dictForGet);
	expect_query_type(dictForGet);
	expect_command(dictForGet, "get");
	expect_transaction_id(dictForGet, NULL, 4);
	Buffer tid;
	tid.b = (unsigned char*)dictForGet.GetString("t" , &tid.len);
	EXPECT_EQ(4, tid.len);

	// now look into the query data
	BencodedDict *getQuery = dictForGet.GetDict("a");
	ASSERT_TRUE(getQuery);
	expect_reply_id(getQuery);
	expect_target(getQuery);

	const char* responseToken = "20_byte_reply_token.";
	const char* v = "sample";

	unsigned char to_hash[800];
	int written = snprintf(reinterpret_cast<char*>(to_hash), 800,
			"3:seqi%" PRId64 "e1:v%lu:", seq, strlen(v));
	memcpy(to_hash + written, v, strlen(v));
	sha1_hash cas = sha1_callback(to_hash, written + strlen(v));
	Buffer cas_buf(cas.value, 20);

	unsigned char message_bytes[1024];
	int64_t len = bencoder(message_bytes, 1024)
		.d()
			("ip")("abcdxy") ("r").d()
				("cas")(cas_buf.b, cas_buf.len)
				("id")((unsigned char*)&peerID.id.id[0], 20) ("nodes")("")
				("token")(responseToken) ("seq")(seq) ("v")(v).e()
			("t")(tid.b, tid.len) ("y")("r")
		.e() () - message_bytes;

	// clear the socket and "send" the reply
	socket4.Reset();
	impl->ProcessIncoming(message_bytes, len, peerID.addr);

	EXPECT_TRUE(impl->IsBusy()) << "The dht should still be busy";

	//Checking the put messages
	BencodedDict dictForPut;
	fetch_dict(dictForPut);
	expect_query_type(dictForPut);
	expect_command(dictForPut, "put");
	expect_transaction_id(dictForPut, NULL, 4);

	// now look into the query data
	BencodedDict *putQuery = dictForPut.GetDict("a");
	ASSERT_TRUE(putQuery);
	expect_cas(putQuery, cas.value);
	expect_reply_id(putQuery);
	EXPECT_EQ(seq + 1, putQuery->GetInt("seq"));
	expect_signature(putQuery);
	expect_token(putQuery, responseToken);
	expect_value(putQuery, v, strlen(v));
}

TEST_F(dht_impl_test, TestPutRPC_ipv4_seq_fail) {
	// prepare the object for use
	impl->Enable(true, 0);
	init_dht_id();

	// put a peer into the dht for it to work with
	impl->Update(peerID, 0, false);

	DhtID target;
	target.id[0] = 'FFFF'; // FFFF
	target.id[1] = 'GGGG'; // GGGG
	target.id[2] = 'HHHH'; // HHHH
	target.id[3] = 'IIII'; // IIII
	target.id[4] = 'JJJJ'; // JJJJ

	EXPECT_FALSE(impl->IsBusy()) << "The dht should not be busy yet";
	int64_t seq = 2;
	impl->Put(pkey, skey, &put_callback, NULL, IDht::with_cas, seq);
	BencodedDict dictForGet;
	fetch_dict(dictForGet);
	expect_query_type(dictForGet);
	expect_command(dictForGet, "get");
	expect_transaction_id(dictForGet, NULL, 4);
	Buffer tid;
	tid.b = (unsigned char*)dictForGet.GetString("t" , &tid.len);
	EXPECT_EQ(4, tid.len);

	// now look into the query data
	BencodedDict *getQuery = dictForGet.GetDict("a");
	ASSERT_TRUE(getQuery);
	expect_reply_id(getQuery);
	expect_target(getQuery);

	const char* responseToken = "20_byte_reply_token.";
	const char* v = "sample";

	unsigned char to_hash[800];
	int written = snprintf(reinterpret_cast<char*>(to_hash), 800,
			"3:seqi%" PRId64 "e1:v%lu:", seq, strlen(v));
	memcpy(to_hash + written, v, strlen(v));
	sha1_hash cas = sha1_callback(to_hash, written + strlen(v));
	Buffer cas_buf(cas.value, 20);

	unsigned char message_bytes[1024];
	int64_t len = bencoder(message_bytes, 1024)
		.d()
			("ip")("abcdxy") ("r").d()
				("cas")(cas_buf.b, cas_buf.len)
				("id")((unsigned char*)&peerID.id.id[0], 20) ("nodes")("")
				("token")(responseToken) ("seq")(seq) ("v")(v).e()
			("t")(tid.b, tid.len) ("y")("r")
		.e() () - message_bytes;

	// clear the socket and "send" the reply
	socket4.Reset();
	impl->ProcessIncoming(message_bytes, len, peerID.addr);

	EXPECT_TRUE(impl->IsBusy()) << "The dht should still be busy";

	//Checking the put messages
	BencodedDict dictForPut;
	fetch_dict(dictForPut);
	expect_query_type(dictForPut);
	expect_command(dictForPut, "put");
	tid.b = (unsigned char*)dictForPut.GetString("t" , &tid.len);
	EXPECT_EQ(4, tid.len) << "transaction ID is wrong size";

	// now look into the query data
	BencodedDict *putQuery = dictForPut.GetDict("a");
	ASSERT_TRUE(putQuery);
	expect_cas(putQuery, cas.value);
	expect_reply_id(putQuery);
	EXPECT_EQ(seq + 1, putQuery->GetInt("seq"));
	expect_signature(putQuery);
	expect_token(putQuery, responseToken);
	expect_value(putQuery, v, strlen(v));

	// oh no we have a higher sequence number now and thus we shall complain
	len = bencoder(message_bytes, 1024)
		.d()
			("e").l()(static_cast<int64_t>(302))("error message!").e()
			("ip")("abcdxy") ("r").d()
				("id")((unsigned char*)&peerID.id.id[0], 20).e()
			("t")(tid.b, tid.len) ("y")("e")
		.e() () - message_bytes;

	socket4.Reset();
	EXPECT_TRUE(impl->ProcessIncoming(message_bytes, len, peerID.addr));
	EXPECT_TRUE(impl->IsBusy()) << "The dht should still be busy";
	fetch_dict(dictForGet);
	expect_query_type(dictForGet);
	expect_command(dictForGet, "get");
	expect_transaction_id(dictForGet, NULL, 4);
	getQuery = dictForGet.GetDict("a");
	ASSERT_TRUE(getQuery);
	expect_reply_id(getQuery);
	expect_target(getQuery);
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

	std::vector<unsigned char> testDataBytes;

	// prepare the object for use
	impl->Enable(true, 0);
	init_dht_id();

	// first do the GetPeers to obtain a token
	BencodedDict dictForPeer;
	fetch_response_to_message(dictForPeer,
			(unsigned char*)bEncodedGetPeers.c_str(), bEncodedGetPeers.size());
	// now look into the response data
	BencodedDict *replyGetPeer = dictForPeer.GetDict("r");
	ASSERT_TRUE(replyGetPeer);
	Buffer token;
	token.b = (unsigned char*)replyGetPeer->GetString("token", &token.len);
	EXPECT_TRUE(token.len);

	// build the announce_peer test string with the token
	fillTestDataBytes(testDataBytes, token, testDataPart1, testDataPart2);

	socket4.Reset();
	impl->Tick();

	// now we can start testing the response to announce_peer
	// Send the announce_peer query
	BencodedDict dict;
	fetch_response_to_message(dict, (unsigned char*)&testDataBytes.front(),
			testDataBytes.size());
	expect_transaction_id(dict, "aa", 2);

	// now look into the response data
	BencodedDict *reply = dict.GetDict("r");
	ASSERT_TRUE(reply);
	expect_reply_id(reply);
}

TEST_F(dht_impl_test, TestAnnouncePeerWithImpliedport) {
	sAddr.set_port(0x0101);
	sAddr_PortAsString = "\x1\x1";

	// before we can announce_peer, we must use get_peers to obtain a token
	// use this to get a token
	std::string bEncodedGetPeers("d1:ad2:id20:abcdefghij01010101019:info_hash"
			"20:mnopqrstuvwxyz123456e1:q9:get_peers1:t2:aa1:y1:qe");

	// insert the token between these two strings
	std::string testDataPart1("d1:ad2:id20:abcdefghij012345678912:implied_port"
			"i1e9:info_hash20:mnopqrstuvwxyz1234564:porti6881e5:token");
	std::string testDataPart2("e1:q13:announce_peer1:t2:aa1:y1:qe");
	std::string testData;

	std::vector<unsigned char> testDataBytes;

	// prepare the object for use
	impl->Enable(true, 0);
	init_dht_id();

	// first do the GetPeers to obtain a token
	BencodedDict dictForPeer;
	fetch_response_to_message(dictForPeer,
			(unsigned char*)bEncodedGetPeers.c_str(), bEncodedGetPeers.size());
	// now look into the response data
	BencodedDict *replyGetPeer = dictForPeer.GetDict("r");
	ASSERT_TRUE(replyGetPeer);
	Buffer token;
	token.b = (unsigned char*)replyGetPeer->GetString("token", &token.len);
	EXPECT_TRUE(token.len);

	// build the announce_peer test string with the token
	fillTestDataBytes(testDataBytes, token, testDataPart1, testDataPart2);
	socket4.Reset();
	impl->Tick();
	impl->ProcessIncoming((unsigned char*)&testDataBytes.front(),
			testDataBytes.size(), sAddr);

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
	sAddr.set_port(0xF0F0);
	sAddr_PortAsString = "\xF0\xF0";
	std::string bEncodedGetPeers("d1:ad2:id20:abcdefghij01010101019:info_hash"
			"20:mnopqrstuvwxyz123456e1:q9:get_peers1:t2:aa1:y1:qe");
	std::string testDataPart1("d1:ad2:id20:abcdefghij01234567899:info_hash"
			"20:mnopqrstuvwxyz1234564:porti514e5:token");
	std::string testDataPart2("e1:q13:announce_peer1:t2:aa1:y1:qe");
	std::string testData;

	std::vector<unsigned char> testDataBytes;

	// prepare the object for use
	impl->Enable(true, 0);
	init_dht_id();

	// first do the GetPeers to obtain a token
	BencodedDict dictForPeer;
	fetch_response_to_message(dictForPeer,
			(unsigned char*)bEncodedGetPeers.c_str(), bEncodedGetPeers.size());
	// now look into the response data
	BencodedDict *replyGetPeer = dictForPeer.GetDict("r");
	ASSERT_TRUE(replyGetPeer);
	Buffer token;
	token.b = (unsigned char*)replyGetPeer->GetString("token", &token.len);
	EXPECT_TRUE(token.len);

	// build the announce_peer test string with the token
	fillTestDataBytes(testDataBytes, token, testDataPart1, testDataPart2);
	socket4.Reset();
	impl->Tick();
	impl->ProcessIncoming((unsigned char*)&testDataBytes.front(),
			testDataBytes.size(), sAddr);

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
	unsigned char message_bytes[1024];
	impl->Enable(true, 0);
	init_dht_id();

	// get a token to use
	std::vector<unsigned char> token;
	fetch_token(token);

	int64_t len = bencoder(message_bytes, 1024)
		.d()
			("a").d()
				("id")("abcdefghij0123456789")
				("target")(MakeRandomKey20())
				("token")(token)
				("vote")(int64_t(1)).e()
			("q")("vote")
			("t")("aa")
			("y")("q")
		.e() () - message_bytes;

	BencodedDict dict;
	fetch_response_to_message(dict, message_bytes, len);
	expect_transaction_id(dict, "aa", 2);

	// now look into the response data
	BencodedDict *reply = dict.GetDict("r");
	ASSERT_TRUE(reply);
	expect_reply_id(reply);
	// get the votes out of the dictionary
	BencodedList *voteList = reply->GetList("v");
	ASSERT_TRUE(voteList);
	// is the list the right length
	ASSERT_EQ(5, voteList->GetCount());

	// expect 1, 0, 0, 0, 0
	ASSERT_EQ(1, voteList->GetInt(0)) <<
			"Expected 1 0 0 0 0 but received 0 - - - -";
	ASSERT_EQ(0, voteList->GetInt(1)) <<
			"Expected 1 0 0 0 0 but received 1 1 - - -";
	ASSERT_EQ(0, voteList->GetInt(2)) <<
			"Expected 1 0 0 0 0 but received 1 0 1 - -";
	ASSERT_EQ(0, voteList->GetInt(3)) <<
			"Expected 1 0 0 0 0 but received 1 0 0 1 -";
	ASSERT_EQ(0, voteList->GetInt(4)) <<
			"Expected 1 0 0 0 0 but received 1 0 0 0 1";
}

// verify that multiple votes to the same target are recorded
TEST_F(dht_impl_test, TestVoteRPC_ipv4_MultipleVotes) {
	unsigned char	message_bytes[1024];
	impl->Enable(true, 0);
	init_dht_id();

	// get a token to use
	std::vector<unsigned char> token;
	fetch_token(token);

	std::vector<unsigned char> target = MakeRandomKey20();

	// vote 5
	int64_t len = bencoder(message_bytes, 1024)
		.d()
			("a").d()
				("id")("abcdefghij0123456789")
				("target")(target)
				("token")(token)
				("vote")(int64_t(5)).e()
			("q")("vote")
			("t")("aa")
			("y")("q")
		.e() () - message_bytes;

	// parse and send the first vote message
	impl->ProcessIncoming(message_bytes, len, sAddr);

	// prepare to send the second vote message
	impl->Tick();
	socket4.Reset();

	// make the second vote message with a vote of 2
	len = bencoder(message_bytes, 1024)
		.d()
			("a").d()
				("id")("abcdefghij0123456789")
				("target")(target)
				("token")(token)
				("vote")(int64_t(2)).e()
			("q")("vote")
			("t")("aa")
			("y")("q")
		.e() () - message_bytes;

	// parse and send the second vote message
	BencodedDict dict;
	fetch_response_to_message(dict, message_bytes, len);
	expect_transaction_id(dict, "aa", 2);
	BencodedDict *reply = dict.GetDict("r");
	ASSERT_TRUE(reply);
	expect_reply_id(reply);

	// get the votes out of the dictionary
	BencodedList *voteList = reply->GetList("v");
	ASSERT_TRUE(voteList);
	// is the list the right length
	ASSERT_EQ(5, voteList->GetCount());

	// expect 0, 1, 0, 0, 1
	ASSERT_EQ(0, voteList->GetInt(0)) <<
			"Expected 0 1 0 0 1 but received 1 - - - -";
	ASSERT_EQ(1, voteList->GetInt(1)) <<
			"Expected 0 1 0 0 1 but received 0 0 - - -";
	ASSERT_EQ(0, voteList->GetInt(2)) <<
			"Expected 0 1 0 0 1 but received 0 1 1 - -";
	ASSERT_EQ(0, voteList->GetInt(3)) <<
			"Expected 0 1 0 0 1 but received 0 1 0 1 -";
	ASSERT_EQ(1, voteList->GetInt(4)) <<
			"Expected 0 1 0 0 1 but received 0 1 0 0 0";
}

TEST_F(dht_impl_test, TestDHTScrapeSeed0_ipv4) {
	unsigned char message_bytes[1024];
	init_dht_id();
	impl->Enable(true, 0);

	// get a token to use
	std::vector<unsigned char> token;
	fetch_token(token);

	// make a random info_hash key to use
	std::vector<unsigned char> infoHashKey = MakeRandomKey20();

	// prepare the first anounce_peer with seed = 0
	int64_t len = bencoder(message_bytes, 1024)
		.d()
			("a").d()
				("id")("abcdefghij0101010101")
				("info_hash")(infoHashKey)
				("port")(int64_t(6881))
				("seed")(int64_t(0))
				("token")(token)
				("name")("test torrent").e()
			("q")("announce_peer")
			("t")("aa")
			("y")("q")
		.e() () - message_bytes;

	announce_and_verify(message_bytes, len);

	len = bencoder(message_bytes, 1024)
		.d()
			("a").d()
				("id")("abcdefghij0101010101")
				("info_hash")(infoHashKey)
				("port")(int64_t(6881))
				("scrape")(int64_t(1)).e()
			("q")("get_peers")
			("t")("aa")
			("y")("q")
		.e() () - message_bytes;

	BencodedDict dict;
	fetch_response_to_message(dict, message_bytes, len);
	BencodedDict* reply = dict.GetDict("r");
	ASSERT_TRUE(reply);
	expect_reply_id(reply);

	// verify that BFsd and BFpe are present
	// see BEP #33 for details of BFsd & BFpe
	Buffer bfsd;
	bfsd.b = (unsigned char*)reply->GetString("BFsd", &bfsd.len);
	ASSERT_TRUE(bfsd.b && bfsd.len == 256);
	EXPECT_EQ(0, CountSetBits(bfsd)) << "ERROR:  Expected exactly 0 bits to be"
		" set in the seeds bloom filter 'BFsd'";
	Buffer bfpe;
	bfpe.b = (unsigned char*)reply->GetString("BFpe", &bfpe.len);
	ASSERT_TRUE(bfpe.b && bfpe.len == 256);
	EXPECT_EQ(2, CountSetBits(bfpe)) << "ERROR:  Expected exactly 2 bits to be"
		" set in the peers bloom filter 'BFpe'";
}

TEST_F(dht_impl_test, TestDHTScrapeSeed1_ipv4) {
	unsigned char message_bytes[1024];
	init_dht_id();
	impl->Enable(true, 0);

	// get a token to use
	std::vector<unsigned char> token;
	fetch_token(std::string("abcdefghij0123456789"), token);

	// make a random info_hash key to use
	std::vector<unsigned char> infoHashKey = MakeRandomKey20();

	// prepare the first anounce_peer with seed = 0
	int64_t len = bencoder(message_bytes, 1024)
		.d()
			("a").d()
				("id")("abcdefghij0123456789")
				("info_hash")(infoHashKey)
				("port")(int64_t(6881))
				("seed")(int64_t(1))
				("token")(token)
				("name")("test torrent").e()
			("q")("announce_peer")
			("t")("aa")
			("y")("q")
		.e() () - message_bytes;

	announce_and_verify(message_bytes, len);

	len = bencoder(message_bytes, 1024)
		.d()
			("a").d()
				("id")("abcdefghij0123456789")
				("info_hash")(infoHashKey)
				("port")(int64_t(6881))
				("scrape")(int64_t(1)).e()
			("q")("get_peers")
			("t")("aa")
			("y")("q")
		.e() () - message_bytes;

	BencodedDict dict;
	fetch_response_to_message(dict, message_bytes, len);
	// now extract the reply data dictionary
	BencodedDict *reply = dict.GetDict("r");
	ASSERT_TRUE(reply);
	expect_reply_id(reply);

	// verify that BFsd and BFpe are present
	// see BEP #33 for details of BFsd & BFpe
	Buffer bfsd;
	bfsd.b = (unsigned char*)reply->GetString("BFsd", &bfsd.len);
	ASSERT_TRUE(bfsd.b && bfsd.len == 256);
	EXPECT_EQ(2, CountSetBits(bfsd)) << "ERROR:  Expected exactly 2 bits to be"
		" set in the seeds bloom filter 'BFsd'";
	Buffer bfpe;
	bfpe.b = (unsigned char*)reply->GetString("BFpe", &bfpe.len);
	ASSERT_TRUE(bfpe.b && bfpe.len == 256);
	ASSERT_EQ(0, CountSetBits(bfpe)) << "ERROR:  Expected exactly 0 bits to be"
		" set in the peers bloom filter 'BFpe'";
}

TEST_F(dht_impl_test, TestDHTForNonexistantPeers_ipv4) {
	unsigned char message_bytes[1024];
	impl->Enable(true, 0);
	std::vector<unsigned char> token;
	int port = 6881;
	std::string id("abcdefghij0123456789");

	char itoa_buf[3];
	int64_t len;
	BencodedDict dict;
	BencodedDict* reply;
	for(int i = 1; i <= 13; i++) {
		sprintf(itoa_buf, "%02d", i);
		fetch_token(token);
		len = bencoder(message_bytes, 1024)
			.d()
				("a").d()
					("id")(id)
					("info_hash")(MakeRandomKey20())
					("port")(int64_t(port))
					("name")(std::string("name") + itoa_buf)
					("token")(token).e()
				("q")("announce_peer")
				("t")("zz")
				("y")("q")
			.e() () - message_bytes;
		fetch_response_to_message(dict, message_bytes, len);
		expect_transaction_id(dict, "zz", 2);
		reply = dict.GetDict("r");
		ASSERT_TRUE(reply);
		EXPECT_TRUE(reply->GetString("id", 20));
		impl->Tick();
		socket4.Reset();
	}
	// now make a get_peers message with a nonexistant hash
	len = bencoder(message_bytes, 1024)
		.d()
			("a").d()
				("id")("abcdefghij0123456789")
				("info_hash")("__nonexistenthash___")
				("port")(int64_t(port)).e()
			("q")("get_peers")
			("t")("aa")
			("y")("q")
		.e() () - message_bytes;
	fetch_response_to_message(dict, message_bytes, len);
	reply = dict.GetDict("r");
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

	// specify, parse, and send the message
	// Set a TARGET with a 'future_cmd' command in this test
	// it sould be treated as a find_node command
	std::string testData("d1:ad2:id20:abcdefghij01234567896:target"
			"20:mnopqrstuvwxyz123456e1:q10:future_cmd1:t2:aa1:y1:qe");
	BencodedDict dict;
	fetch_response_to_message(dict, (unsigned char*)testData.c_str(),
			testData.size());
	expect_transaction_id(dict, "aa", 2);
	BencodedDict *reply = dict.GetDict("r");
	ASSERT_TRUE(reply);
	expect_reply_id(reply);

	// There should be a single node - this one
	// expect back the id provided in the query, ip=zzzz port=xx (since the querying node and this node are the same in this test)
	Buffer nodes;
	nodes.b = (unsigned char*)reply->GetString("nodes", &nodes.len);
	ASSERT_EQ(26, nodes.len) << "ERROR:  The length of the 26 unsigned char"
		" node info extracted from the response arguments is the wrong size";
	EXPECT_FALSE(memcmp((const void*)nodes.b,
			(const void *)"abcdefghij0123456789zzzzxx", nodes.len));
}

TEST_F(dht_impl_test, TestFutureCmdAsFindNode02_ipv4) {
	// unknown messages with either a 'target'
	// or an 'info-hash' argument are treated
	// as a find node to not block future extensions
	impl->Enable(true, 0);
	init_dht_id();

	// specify, parse, and send the message
	// Set an INFO_HASH with a 'future_cmd' command in this test
	// it sould be treated as a find_node command
	std::string testData("d1:ad2:id20:abcdefghij01234567899:info_hash"
			"20:mnopqrstuvwxyz123456e1:q10:future_cmd1:t2:aa1:y1:qe");
	BencodedDict dict;
	fetch_response_to_message(dict, (unsigned char*)testData.c_str(),
			testData.size());
	expect_transaction_id(dict, "aa", 2);
	BencodedDict *reply = dict.GetDict("r");
	ASSERT_TRUE(reply);
	expect_reply_id(reply);

	// There should be a single node - this one
	// expect back the id provided in the query, ip=zzzz port=xx (since the querying node and this node are the same in this test)
	Buffer nodes;
	nodes.b = (unsigned char*)reply->GetString("nodes", &nodes.len);
	ASSERT_EQ(26, nodes.len) << "ERROR:  The length of the 26 unsigned char"
		" node info extracted from the response arguments is the wrong size";
	EXPECT_FALSE(memcmp((const void*)nodes.b,
			(const void *)"abcdefghij0123456789zzzzxx", nodes.len));
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
			sAddr);

	// get the bencoded string out of the socket
	std::string bencMessage = socket4.GetSentDataAsString();
	EXPECT_STREQ(bencMessage.c_str(), "");
}

TEST_F(dht_impl_test, TestImmutablePutRPC_ipv4) {
	unsigned char message_bytes[1024];
	impl->Enable(true, 0);
	init_dht_id();

	std::vector<unsigned char> token;
	fetch_token(token);
	
	int64_t len = bencoder(message_bytes, 1024)
		.d()
			("a").d()
				("id")("abcdefghij0123456789")
				("token")(token)
				("v")("Immutable put test").e()
			("q")("put")
			("t")("aa")
			("y")("q")
		.e() () - message_bytes;

	BencodedDict dict;
	impl->ProcessIncoming(message_bytes, len, sAddr);
	fetch_dict(dict);
	expect_response_type(dict);
	expect_transaction_id(dict, "aa", 2);
	BencodedDict *reply = dict.GetDict("r");
	ASSERT_TRUE(reply);
	expect_reply_id(reply);
}

TEST_F(dht_impl_test, TestImmutableGetRPC_ipv4) {
	impl->Enable(true, 0);
	init_dht_id();

	std::vector<unsigned char> token;
	fetch_token(token);
	int64_t len = bencoder(message_bytes, 1024)
		.d()
			("a").d()
				("id")("abcdefghij0123456789")
				("token")(token)
				("v")("Immutable get test").e()
			("q")("put")
			("t")("aa")
			("y")("q")
		.e() () - message_bytes;

	BencodedDict dict;
	impl->ProcessIncoming(message_bytes, len, sAddr);
	fetch_dict(dict);
	expect_response_type(dict);
	expect_transaction_id(dict, "aa", 2);

	// *** SECOND: get something out ***
	sha1_hash target = sha1_callback(
			reinterpret_cast<const unsigned char*>("18:Immutable get test"), 21);
	Buffer hashInfo;
	hashInfo.b = (unsigned char*)target.value;
	hashInfo.len = 20;

	len = bencoder(message_bytes, 1024)
		.d()
			("a").d()
				("id")("abcdefghij0123456789")
				("target")(hashInfo.b, hashInfo.len).e()
			("q")("get")
			("t")("aa")
			("y")("q")
		.e() () - message_bytes;
	// parse and send the message constructed above
	socket4.Reset();
	impl->ProcessIncoming(message_bytes, len, sAddr);
	fetch_dict(dict);
	expect_response_type(dict);
	expect_transaction_id(dict, "aa", 2);
	BencodedDict *reply = dict.GetDict("r");
	ASSERT_TRUE(reply);
	expect_reply_id(reply);
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
	immutable_put(std::string("20_byte_dhtid_val_00"), "i-1e");
	immutable_put(std::string("20_byte_dhtid_val_01"), "i-1e");
	immutable_put(std::string("20_byte_dhtid_val_02"), "i-1e");
	immutable_put(std::string("20_byte_dhtid_val_03"), "i-1e");
	immutable_put(std::string("20_byte_dhtid_val_04"), "i-1e");
	EXPECT_EQ(1, impl->GetNumPutItems()) <<
			"ERROR:  multiple instances of the same thing stored";

	// now add different things and see the count increase
	immutable_put(std::string("20_byte_dhtid_val_00"), "i2e");
	immutable_put(std::string("20_byte_dhtid_val_01"), "i3e");
	immutable_put(std::string("20_byte_dhtid_val_02"), "i4e");
	immutable_put(std::string("20_byte_dhtid_val_03"), "i5e");
	immutable_put(std::string("20_byte_dhtid_val_04"), "i6e");
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

	immutable_put(std::string("20_byte_dhtid_val_00"), putValues[0].c_str());
	immutable_put(std::string("20_byte_dhtid_val_01"), putValues[1].c_str());
	immutable_put(std::string("20_byte_dhtid_val_02"), putValues[2].c_str());
	immutable_put(std::string("20_byte_dhtid_val_03"), putValues[3].c_str());
	immutable_put(std::string("20_byte_dhtid_val_04"), putValues[4].c_str());
	EXPECT_EQ(5, impl->GetNumPutItems()) <<
			"ERROR:  several different thinigs did not get stored";

	// get the data out and see that it matches what was put
	int64_t len;
	BencodedDict dict;
	BencodedDict* reply;
	BencEntity* entity;
	Buffer serialized_entity;
	for(int x = 0; x < 5; ++x) {
		len = bencoder(message_bytes, 1024)
			.d()
				("a").d()
					("id")("abcdefghij0123456789")
					("target")(&(hashes[x][0]), 20).e()
				("q")("get")
				("t")("aa")
				("y")("q")
			.e() () - message_bytes;
		socket4.Reset();
		impl->Tick();
		impl->ProcessIncoming(message_bytes, len, sAddr);
		fetch_dict(dict);
		expect_response_type(dict);
		reply = dict.GetDict("r");
		ASSERT_TRUE(reply);
		entity = reply->Get("v");
		ASSERT_TRUE(entity);
		serialized_entity.b = SerializeBencEntity(entity, &serialized_entity.len);
		EXPECT_FALSE(memcmp(putValues[x].c_str(), serialized_entity.b,
					serialized_entity.len));
		EXPECT_FALSE(reply->GetString("key"));
		EXPECT_FALSE(reply->GetString("sig"));
	}
}
