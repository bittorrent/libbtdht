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

#include "TestDhtImpl.h"

class dht_impl_response_test : public dht_impl_test {
	protected:
		DhtID target;
		const char* compact_ip;

		virtual void SetUp() override {
			socket4.SetBindAddr(bind_addr);
			dht_impl_test::SetUp();
			impl->Enable(true, 0);
			init_dht_id();

			target.id[0] = 'FFFF'; // FFFF
			target.id[1] = 'GGGG'; // GGGG
			target.id[2] = 'HHHH'; // HHHH
			target.id[3] = 'IIII'; // IIII
			target.id[4] = 'JJJJ'; // JJJJ

			compact_ip = "aaaa88";
		}

		void expect_info_hash(const unsigned char* expected = NULL) {
			ASSERT_NO_FATAL_FAILURE(get_reply());
			Buffer infoHash;
			infoHash.b = (byte*)reply->GetString("info_hash" , &infoHash.len);
			EXPECT_EQ(20, infoHash.len);
			if (expected == NULL) {
				EXPECT_FALSE(memcmp("FFFFGGGGHHHHIIIIJJJJ", infoHash.b, 20)) <<
					"ERROR: info_hash is not the correct target";
			} else {
				EXPECT_FALSE(memcmp(expected, infoHash.b, 20)) <<
					"ERROR: info_hash is not the correct target";
			}
		}

		void expect_target(const char* target) {
			ASSERT_NO_FATAL_FAILURE(get_reply());
			Buffer buf;
			buf.b = (unsigned char*)reply->GetString("target" , &buf.len);
			EXPECT_EQ(strlen(target), buf.len);
			EXPECT_FALSE(memcmp(target, buf.b, buf.len)) <<
				"ERROR: pkey is not the correct target";
		}

		void expect_name(const std::string &expected) {
			ASSERT_NO_FATAL_FAILURE(get_reply());
			Buffer name;
			name.b = (byte*)reply->GetString("name" , &name.len);
			EXPECT_EQ(expected.size(), name.len);
			EXPECT_FALSE(strcmp(expected.c_str(), (char*)name.b));
		}

		void expect_port(int16 expected) {
			ASSERT_NO_FATAL_FAILURE(get_reply());
			int16 port;
			port = reply->GetInt("port");
			EXPECT_EQ(expected, port);
		}

		void expect_seed(int seed) {
			ASSERT_NO_FATAL_FAILURE(get_reply());
			EXPECT_EQ(seed, reply->GetInt("seed"));
		}

		void expect_implied_port(int16 port) {
			ASSERT_NO_FATAL_FAILURE(get_reply());
			EXPECT_EQ(port, reply->GetInt("implied_port"));
		}

		void expect_request_queued(Buffer& tid) {
			ASSERT_TRUE(impl->LookupRequest(Read32(tid.b))) <<
				"The outstanding transaction id does not exist";
		}

		void expect_request_removed(Buffer& tid) {
			EXPECT_FALSE(impl->LookupRequest(Read32(tid.b))) <<
				"The outstanding transaction id was not removed by the response";
		}

		void fetch_announce(const DhtID &target, std::string &filename,
				std::vector<byte> &tid_out) {
			impl->DoAnnounce(target, &AddNodesCallbackDummy::Callback, NULL,
					filename.c_str(), NULL, 0);
			ASSERT_NO_FATAL_FAILURE(fetch_dict());
			Buffer tid;
			tid.b = (byte*)dict->GetString("t" , &tid.len);
			EXPECT_EQ(4, tid.len);
			ASSERT_TRUE(tid.b);
			tid_out.assign(tid.b, tid.b + tid.len);
		}

		void fetch_announce(const DhtID &target, std::string &filename,
				std::vector<std::vector<byte> > &tids_out) {
			const unsigned int bytes_per_peer = 106;
			tids_out.clear();

			impl->DoAnnounce(target, &AddNodesCallbackDummy::Callback, NULL,
					filename.c_str(), NULL, 0);

			// see how many strings went out.
			// expect 106 characters output for each peer in the dht's list
			// for example:
			// "d1:ad2:id20:AAAABBBBCCCCDDDDEEEE9:info_hash20:FFFFGGGGHHHHIIII0000e
			// 1:q9:get_peers1:t4:köÇn1:v4:UTê`1:y1:qe"

			int packets = socket4.numPackets();
			for (int i = 0; i < packets; ++i) {
				std::string out = socket4.GetSentDataAsString(i);

				BencEntity::Parse((const byte *)out.c_str(), output,
						(const byte *)(out.c_str()) + out.size());
				ASSERT_EQ(BENC_DICT, output.bencType);
				dict = BencodedDict::AsDict(&output);
				ASSERT_TRUE(dict);
				ASSERT_EQ(BENC_DICT, dict->bencType);
				reply = NULL;
				Buffer tid;
				tid.b = (byte*)dict->GetString("t" , &tid.len);
				ASSERT_EQ(4, tid.len);
				std::vector<byte> tid_bytes;
				tid_bytes.assign(tid.b, tid.b + tid.len);
				tids_out.push_back(tid_bytes);
			}
		}

		void fetch_peers_reply(const DhtPeerID &peer_id,
				const std::string &response_token,
				const std::vector<std::string> &values,
				const std::vector<byte> &transactionID,
				std::vector<byte> &tid_out, bool expect_response = true) {
			Buffer peer_id_buffer;
			peer_id_buffer.len = 20;
			peer_id_buffer.b = (byte*)&peer_id.id.id[0];

			bencoder b(message, 1024);
			b.d()
				("r").d()
					("id")(peer_id_buffer.b, peer_id_buffer.len)
					("token")(response_token)
					("values").l();
			for(unsigned int x = 0; x < values.size(); ++x) {
				b(values[x]);
			}
			len = b.e().e() // end list, end dict
					("t")(transactionID)
					("y")("r")
				.e() ();
			socket4.Reset();
			message[len] = '\0';
			fprintf(stderr, "%s\n", message);
			impl->ProcessIncoming(message, len, peer_id.addr);
			if (!expect_response)
				return;
			ASSERT_NO_FATAL_FAILURE(fetch_dict());
			Buffer tid;
			tid.b = (byte*)dict->GetString("t" , &tid.len);
			EXPECT_EQ(4, tid.len);
			ASSERT_TRUE(tid.b);
			tid_out.assign(tid.b, tid.b + tid.len);
		}
};

// TODO: this would ideally live elsewhere
std::vector<AddNodesCallBackDataItem> AddNodesCallbackDummy::callbackData;

class PartialHashCallbackDummy {
	public:
		static int callbackCtr;
		// contains the 20 bytes of info_hash from the last invocation of
		// PartialHashCallback()
		static byte hash[20];

		PartialHashCallbackDummy() {}
		~PartialHashCallbackDummy() {}
		static void PartialHashCallback(void *ctx, const byte* info_hash);
		static void Reset();
};

int PartialHashCallbackDummy::callbackCtr;
byte PartialHashCallbackDummy::hash[20];

// info_hash should be 20 bytes
void PartialHashCallbackDummy::PartialHashCallback(void *ctx,
		const byte* info_hash) {
	callbackCtr++;
	for(int x = 0; x < 20; ++x) {
		hash[x] = info_hash[x];
	}
}

void PartialHashCallbackDummy::Reset() {
	callbackCtr = 0;
}

class FindNodeCallbackDummy : public IDhtProcessCallbackListener {
	public:
		int callbackCount;
		FindNodeCallbackDummy() {
			callbackCount = 0;
		}
		~FindNodeCallbackDummy() {}
		virtual void ProcessCallback();
};

void FindNodeCallbackDummy::ProcessCallback() {
	++callbackCount;
}

class VoteCallbackDummy {
	public:
		static int callbackCtr;
		VoteCallbackDummy() {}
		~VoteCallbackDummy() {}
		static void VoteCallback(void *ctx, const byte* info_hash,
				int const* votes);
		static void Reset();
};

int VoteCallbackDummy::callbackCtr;

void VoteCallbackDummy::VoteCallback(void *ctx, const byte* info_hash,
		int const* votes) {
	callbackCtr++;
}

void VoteCallbackDummy::Reset() {
	callbackCtr = 0;
}

/**
 the input bencoded string should be delineated with "d1:ad" for each set of dht
 output bytes for which a transaction id is to be extracted.
*/
bool extract_transaction_ids(const std::string &bstring,
		std::vector<std::vector<byte> > &tids_out) {
	size_t index = 0;
	tids_out.clear();

	do {
		index = bstring.find("d1:ad", index);
		if(index == std::string::npos) {
			continue;
		}

		BencEntity bEntityAnounceQuery;
		// verify the bencoded string that went out the socket
		BencEntity::Parse((const byte *)&bstring[index], bEntityAnounceQuery,
				(const byte *)(&bstring[index] + bstring.length() - index));

		// get the query dictionary
		BencodedDict *dict = BencodedDict::AsDict(&bEntityAnounceQuery);
		if (!dict) {
			return false;
		}

		// get the transaction ID to return to the user
		Buffer tid;
		tid.b = (byte*)dict->GetString("t" , &tid.len);
		if(tid.len != 4) {
			return false;
		}

		std::vector<byte> tid_bytes;
		tid_bytes.assign(tid.b, tid.b + tid.len);
		tids_out.push_back(tid_bytes);
		index++;
	} while(index != std::string::npos);
	return true;
}

class ScrapeCallbackDummy {
	public:
		static byte infoHash[20];
		static int numDownloaders;
		static int numSeeds;

		ScrapeCallbackDummy() {}
		~ScrapeCallbackDummy() {}
		static void Callback(void *ctx, const byte *info_hash, int downloaders,
				int seeds);
		static void Reset();
};

byte ScrapeCallbackDummy::infoHash[20];
int ScrapeCallbackDummy::numDownloaders;
int ScrapeCallbackDummy::numSeeds;

void ScrapeCallbackDummy::Callback(void *ctx, const byte *info_hash,
		int downloaders, int seeds) {
	for(unsigned int x = 0; x < 20; ++x) {
		infoHash[x] = info_hash[x];
	}
	numDownloaders = downloaders;
	numSeeds = seeds;
}

void ScrapeCallbackDummy::Reset() {
	for(unsigned int x = 0; x < 20; ++x) {
		infoHash[x] = 0;
	}
	numDownloaders = numSeeds = 0;
}

class ResolveNameCallbackDummy {
	public:
		static byte infoHash[20];
		static std::string name;
		static void Clear();
		static void Callback(void *ctx, const byte *info_hash, const byte *file_name);
};

byte ResolveNameCallbackDummy::infoHash[20];
std::string ResolveNameCallbackDummy::name;
void ResolveNameCallbackDummy::Callback(void *ctx, const byte *info_hash,
		const byte *filename) {
	for(unsigned int x = 0; x < 20; ++x) {
		infoHash[x] = info_hash[x];
	}
	name = (const char*)filename;
}

void ResolveNameCallbackDummy::Clear() {
	for(unsigned int x = 0; x < 20; ++x) {
		infoHash[x] = 0;
	}
	name.clear();
}

// TESTS START HERE

TEST_F(dht_impl_response_test, TestSendPings) {

	// essentially disable any maintanence, to just have our test messages
	// be sent
	impl->SetPingFrequency(60);

	// put a peer into the dht for it to work with
	DhtPeer *pTestPeer = impl->Update(peer_id, 0, true, 10);

	// Check that our node is in there
	ASSERT_EQ(1, impl->GetNumPeers());
	Buffer peer_id_buffer;
	peer_id_buffer.len = 20;
	peer_id_buffer.b = (byte*)&peer_id.id.id[0];
	// Send a NICE (non-bootstrap) ping to our fake node
	impl->PingStalestNode();
	ASSERT_NO_FATAL_FAILURE(fetch_dict());
	// check the transaction ID:  length=2
	Buffer tid;
	tid.b = (byte*)dict->GetString("t", &tid.len);
	ASSERT_FALSE(!tid.b || tid.len > 16);

	// specify and send the fake response
	unsigned char buf[256];
	smart_buffer sb(buf, 256);
	sb("d1:rd2:id20:")(20, (const byte*)peer_id.id.id);
	sb("e1:t%lu:", tid.len)(tid);
	sb("1:v4:UTê`1:y1:re");

	// -2 means we think we have completed bootstrapping
	impl->_dht_bootstrap = -2;
	// prevent restart due to exgternal IP voting
	impl->_lastLeadingAddress = bind_addr;
	// Here, we send a response right away
	ASSERT_TRUE(impl->ProcessIncoming((byte *) buf, sb.length(), peer_id.addr));

	for (int i = 0; i < FAIL_THRES; ++i) {
		// Now, ping the same peer, but pretend it is slow and/or doesn't answer
		DhtRequest *req = impl->SendPing(peer_id);
		req->_pListener = new DhtRequestListener<DhtImpl>(impl.get()
			, &DhtImpl::OnPingReply);
		req->time -= 1100;
		impl->Tick();
		// Between 1 and 5 second is considered slow, not yet an error
		ASSERT_TRUE(req->slow_peer);

		// Now pretend it has taken longer than 5 seconds
		req->time -= 4000;
		impl->Tick();

		// Ensure the error count has increased
		ASSERT_EQ(i + 1, pTestPeer->num_fail);
	}

	// Make sure our peer has been deleted due to the errors
	ASSERT_EQ(0, impl->GetNumPeers());
}

/**
          Test                    |                  DHT
----------------------------------|--------------------------------------------
1) invoke doAnnounce()            |
                                  | Responds by emitting a 'get_peers' query
								  |
2) Fabricate and "send" a         |
   response to get_peers that     |
   has only compact node info     |
                                  | Responds by emitting another 'get_peers' query
								  |
*/
TEST_F(dht_impl_response_test, Announce_ReplyWithNodes) {
	// put a peer into the dht for it to work with
	impl->Update(peer_id, 0, true, 10);
	Buffer peer_id_buffer;
	peer_id_buffer.len = 20;
	peer_id_buffer.b = (byte*)&peer_id.id.id[0];

	// make sure the callback dummy is clear
	AddNodesCallbackDummy::Reset();

	// *****************************************************
	// make the dht emit an announce message (the get_peers rpc)
	// *****************************************************
	EXPECT_FALSE(impl->IsBusy()) << "The dht should not be busy yet";
	impl->DoAnnounce(target, &AddNodesCallbackDummy::Callback, NULL,
			"filename.txt", NULL, 0);
	EXPECT_TRUE(impl->IsBusy()) << "The dht should be busy";

	// *****************************************************
	// grab from the socket the emitted message and extract
	// the transaction ID and verify the remainder of the
	// message
	// *****************************************************
	ASSERT_NO_FATAL_FAILURE(fetch_dict());
	ASSERT_NO_FATAL_FAILURE(expect_query_type());
	ASSERT_NO_FATAL_FAILURE(expect_command("get_peers"));
	// get the transaction ID to use later
	Buffer tid;
	tid.b = (byte*)dict->GetString("t" , &tid.len);
	unsigned char* temp = static_cast<unsigned char*>(malloc(tid.len));
	memcpy(temp, tid.b, tid.len);
	tid.b = temp;
	EXPECT_EQ(4, tid.len);
	expect_reply_id();
	ASSERT_NO_FATAL_FAILURE(expect_info_hash());

	// *****************************************************
	// now fabricate a nodes response message using the
	// transaction ID extracted above and include a token
	// *****************************************************
	std::string nearest_node("26_byte_nearest_node_addr.");

	// construct the message bytes
	len = bencoder(message, 1024)
		.d()
			("r").d()
				("id")(peer_id_buffer.b, peer_id_buffer.len)
				("nodes")(nearest_node)
				("token")(response_token).e()
			("t")(tid.b, tid.len)
			("y")("r")
		.e() ();
	socket4.Reset();
	impl->ProcessIncoming(message, len, peer_id.addr);
	EXPECT_TRUE(impl->IsBusy()) << "The dht should still be busy";

	// *****************************************************
	// get the bencoded string out of the socket and verify
	// it.
	// *****************************************************
	ASSERT_NO_FATAL_FAILURE(fetch_dict());
	ASSERT_NO_FATAL_FAILURE(expect_query_type());
	ASSERT_NO_FATAL_FAILURE(expect_command("get_peers"));
	expect_reply_id();
	ASSERT_NO_FATAL_FAILURE(expect_info_hash());

	// *****************************************************
	// look in the addnodes call back dummy to see what was
	// passed through (should be nothing)
	// *****************************************************
	EXPECT_EQ(0, AddNodesCallbackDummy::callbackData.size()) <<
			"no callback events should have been made";
	EXPECT_TRUE(impl->IsBusy()) << "The dht should still be busy";

	ASSERT_NO_FATAL_FAILURE(expect_request_removed(tid));
	free(tid.b);
}

/**
          Test                    |                  DHT
----------------------------------|--------------------------------------------
1) invoke doAnnounce()            |
                                  | Responds by emitting a 'get_peers' query
								  |
2) Fabricate and "send" a         |
   response to get_peers that     |
   has compact IP-address/port    |
   info for a peer                |
                                  | Responds by emitting 'announce_peer' query
								  |
*/
TEST_F(dht_impl_response_test, Announce_ReplyWithPeers) {
	// put a peer into the dht for it to work with
	peer_id.addr.set_port(('8' << 8) + '8'); // 88
	peer_id.addr.set_addr4('aaaa'); // aaaa
	impl->Update(peer_id, 0, true, 10);
	Buffer peer_id_buffer;
	peer_id_buffer.len = 20;
	peer_id_buffer.b = (byte*)&peer_id.id.id[0];

	// make sure the callback dummy is clear
	AddNodesCallbackDummy::Reset();

	EXPECT_EQ(1, impl->GetNumPeers());
	EXPECT_EQ(0, impl->GetNumPeersTracked());

	DhtPeerID *ids[16];
	// Find 8 good ones and 8 bad ones
	uint num = impl->FindNodes(target, ids, 8, 8, 0);
	EXPECT_EQ(1, num) << "Num Nodes: " << num;
	EXPECT_FALSE(impl->IsBusy()) << "The dht should not be busy yet";

	// *****************************************************
	// make the dht emit an announce message (the get_peers rpc)
	// *****************************************************
	std::string filenameTxt("This is a filaname that is very long like a file"
			" name that would be found in the wild.txt");
	impl->DoAnnounce(target, &AddNodesCallbackDummy::Callback, NULL,
			filenameTxt.c_str(), NULL, 0);
	EXPECT_TRUE(impl->IsBusy()) << "The dht should be busy";

	// *****************************************************
	// grab from the socket the emitted message and extract
	// the transaction ID and verify the remainder of the
	// message
	// *****************************************************
	ASSERT_NO_FATAL_FAILURE(fetch_dict());
	ASSERT_NO_FATAL_FAILURE(expect_query_type());
	ASSERT_NO_FATAL_FAILURE(expect_command("get_peers"));
	// get the transaction ID to use later
	Buffer tid;
	tid.b = (byte*)dict->GetString("t" , &tid.len);
	EXPECT_EQ(4, tid.len) << "transaction ID is wrong size";
	expect_reply_id();
	ASSERT_NO_FATAL_FAILURE(expect_info_hash());
	int noseed = reply->GetInt("noseed");
	EXPECT_EQ(0, noseed) << "'noseed' is set when it should not be.";

	// *****************************************************
	// now fabricate a nodes response message using the
	// transaction ID extracted above and include a token
	// that the dht should return to us.  Provide the compact IP
	// of a peer for the dht to use in the 'announce_peer'
	// message it should emit next
	// *****************************************************


	// construct the message bytes
	len = bencoder(message, 1024)
		.d()
			("r").d()
				("id")(peer_id_buffer.b, peer_id_buffer.len)
				("token")(response_token)
				("values").l()
					(compact_ip).e().e()
			("t")(tid.b, tid.len)
			("y")("r")
		.e() ();
	socket4.Reset();
	impl->ProcessIncoming(message, len, peer_id.addr);
	ASSERT_NO_FATAL_FAILURE(fetch_dict());
	ASSERT_NO_FATAL_FAILURE(expect_query_type());
	ASSERT_NO_FATAL_FAILURE(expect_command("announce_peer"));
	tid.b = (byte*)dict->GetString("t" , &tid.len);
	EXPECT_EQ(4, tid.len) << "transaction ID is wrong size";
	expect_reply_id();
	ASSERT_NO_FATAL_FAILURE(expect_info_hash());
	ASSERT_NO_FATAL_FAILURE(expect_name(filenameTxt));
	ASSERT_NO_FATAL_FAILURE(expect_port(0x7878));
	expect_token(response_token);
	ASSERT_NO_FATAL_FAILURE(expect_seed(0));
	// if no port callback is specified, default is to enable implied port
	ASSERT_NO_FATAL_FAILURE(expect_implied_port(1));

	// *****************************************************
	// create and send a response to the 'announce_peer
	// message
	// *****************************************************
	// construct the message bytes
	len = bencoder(message, 1024)
		.d()
			("r").d()
				("id")(peer_id_buffer.b, peer_id_buffer.len).e()
			("t")(tid.b, tid.len)
			("y")("r")
		.e() ();
	socket4.Reset();
	impl->ProcessIncoming(message, len, peer_id.addr);
	// check that nothing went out the socket.
	EXPECT_EQ(0, socket4.GetSentByteVector().size()) << "Nothing should be sent"
		" out the socket in response to the reply to the dht's 'announce_peer'"
		" query";

	// *****************************************************
	// look in the addnodes call back dummy to see what was
	// passed through
	// *****************************************************
	ASSERT_EQ(2, AddNodesCallbackDummy::callbackData.size()) <<
			"Expected two callback events";

	// verify the first callback event
	EXPECT_FALSE(memcmp("FFFFGGGGHHHHIIIIJJJJ",
			AddNodesCallbackDummy::callbackData[0].infoHash, 20));
	EXPECT_EQ(1, AddNodesCallbackDummy::callbackData[0].numPeers);
	EXPECT_FALSE(memcmp(compact_ip,
			&AddNodesCallbackDummy::callbackData[0].compactPeerAddressBytes[0],
			strlen(compact_ip)));

	// verify the second callback event
	EXPECT_FALSE(memcmp("FFFFGGGGHHHHIIIIJJJJ",
			AddNodesCallbackDummy::callbackData[1].infoHash, 20));
	EXPECT_EQ(0, AddNodesCallbackDummy::callbackData[1].numPeers);
	EXPECT_EQ(1, impl->GetNumPeers());
	EXPECT_EQ(0, impl->GetNumPeersTracked());
	// Find 8 good ones and 8 bad ones
	num = impl->FindNodes(target, ids, 8, 8, 0);
	EXPECT_EQ(1, num) << "Num Nodes: " << num;

	ASSERT_NO_FATAL_FAILURE(expect_request_removed(tid));
	EXPECT_FALSE(impl->IsBusy()) << "The dht should no longer be busy";
}


/**
          Test                    |                  DHT
----------------------------------|--------------------------------------------
1) invoke doAnnounce()            |
                                  | Responds by emitting a 'get_peers' query
								  |
2) Fabricate and "send" a         |
   response to get_peers that     |
   has no peer or node info       |
                                  | No response
								  |
*/
TEST_F(dht_impl_response_test, Announce_ReplyWithoutPeersOrNodes) {
	// put a peer into the dht for it to work with
	peer_id.addr.set_port(('8' << 8) + '8'); // 88
	peer_id.addr.set_addr4('aaaa'); // aaaa
	impl->Update(peer_id, 0, true, 10);
	Buffer peer_id_buffer;
	peer_id_buffer.len = 20;
	peer_id_buffer.b = (byte*)&peer_id.id.id[0];

	// make sure the callback dummy is clear
	AddNodesCallbackDummy::Reset();

	EXPECT_EQ(1, impl->GetNumPeers());
	EXPECT_EQ(0, impl->GetNumPeersTracked());

	DhtPeerID *ids[16];
	uint num = impl->FindNodes(target, ids, 8, 8,
			0); // Find 8 good ones and 8 bad ones
	EXPECT_EQ(1, num) << "Num Nodes: " << num;
	EXPECT_FALSE(impl->IsBusy()) << "The dht should not be busy yet";

	// *****************************************************
	// make the dht emit an announce message (the get_peers rpc)
	// *****************************************************
	std::string filenameTxt("filaname.txt");
	impl->DoAnnounce(target, &AddNodesCallbackDummy::Callback, NULL,
			filenameTxt.c_str(), NULL, 0);
	EXPECT_TRUE(impl->IsBusy()) << "The dht should be busy";

	// *****************************************************
	// grab from the socket the emitted message and extract
	// the transaction ID and verify the remainder of the
	// message
	// *****************************************************
	ASSERT_NO_FATAL_FAILURE(fetch_dict());
	ASSERT_NO_FATAL_FAILURE(expect_query_type());
	ASSERT_NO_FATAL_FAILURE(expect_command("get_peers"));
	Buffer tid;
	tid.b = (byte*)dict->GetString("t" , &tid.len);
	EXPECT_EQ(4, tid.len) << "transaction ID is wrong size";
	expect_reply_id();
	ASSERT_NO_FATAL_FAILURE(expect_info_hash());

	// *****************************************************
	// now fabricate a nodes response message using the
	// transaction ID extracted above and include a token
	// that the dht should return to us.
	//
	// Do not include compact IP or node info in the reply
	// *****************************************************


	// construct the message bytes
	len = bencoder(message, 1024)
		.d()
			("r").d()
				("id")(peer_id_buffer.b, peer_id_buffer.len)
				("token")(response_token).e()
			("t")(tid.b, tid.len)
			("y")("r")
		.e() ();
	socket4.Reset();
	impl->ProcessIncoming(message, len, peer_id.addr);
	std::string announceString = socket4.GetSentDataAsString();

	EXPECT_TRUE(announceString == "") <<
			"Nothing should have been sent out.  The response with a filename should terminate this process.";
	EXPECT_FALSE(impl->IsBusy()) << "The dht should not be busy";

	// *****************************************************
	// look in the addnodes call back dummy to see what was
	// passed through
	// *****************************************************
	ASSERT_EQ(1, AddNodesCallbackDummy::callbackData.size()) <<
			"Expected two callback events";

	// verify the first callback event
	EXPECT_FALSE(memcmp("FFFFGGGGHHHHIIIIJJJJ",
			AddNodesCallbackDummy::callbackData[0].infoHash, 20));
	EXPECT_EQ(0, AddNodesCallbackDummy::callbackData[0].numPeers);

	EXPECT_EQ(1, impl->GetNumPeers());
	EXPECT_EQ(0, impl->GetNumPeersTracked());
	num = impl->FindNodes(target, ids, 8, 8,
			0); // Find 8 good ones and 8 bad ones
	EXPECT_EQ(1, num) << "Num Nodes: " << num;

	ASSERT_NO_FATAL_FAILURE(expect_request_removed(tid));
	EXPECT_FALSE(impl->IsBusy()) << "The dht should no longer be busy";
}

/**
          Test                    |                  DHT
----------------------------------|--------------------------------------------
1) invoke doAnnounce()            |
                                  | Responds by emitting a 'get_peers' query
								  |
2) Capture the outputted bencoded |
   string and feed it back to the |
   DHT via ParseIncommingICMP     |
                                  | Ceases pursuing the request
								  |
*/
TEST_F(dht_impl_response_test, Announce_ReplyWith_ICMP) {
	// put a peer into the dht for it to work with
	impl->Update(peer_id, 0, true, 10);
	Buffer peer_id_buffer;
	peer_id_buffer.len = 20;
	peer_id_buffer.b = (byte*)&peer_id.id.id[0];

	// make sure the callback dummy is clear
	AddNodesCallbackDummy::Reset();

	// *****************************************************
	// make the dht emit an announce message (the get_peers rpc)
	// *****************************************************
	EXPECT_FALSE(impl->IsBusy()) << "The dht should not be busy yet";
	impl->DoAnnounce(target, &AddNodesCallbackDummy::Callback, NULL,
			"filename.txt", NULL, 0);
	EXPECT_TRUE(impl->IsBusy()) << "The dht should be busy";

	// *****************************************************
	// grab from the socket the emitted message and turn it
	// into a bencentity.  Feed it back to the dht as an
	// ICMP message
	// *****************************************************
	ASSERT_NO_FATAL_FAILURE(fetch_dict());
	Buffer tid;
	tid.b = (byte*)dict->GetString("t" , &tid.len);

	EXPECT_TRUE(impl->ParseIncomingICMP(output, peer_id.addr));

	// *****************************************************
	// look in the addnodes call back dummy to see what was
	// passed through (should be nothing)
	// *****************************************************
	EXPECT_EQ(1, AddNodesCallbackDummy::callbackData.size()) <<
			"ONE callback event should have been made";

	ASSERT_NO_FATAL_FAILURE(expect_request_removed(tid));
	EXPECT_FALSE(impl->IsBusy()) << "The dht should no longer be busy";
}

TEST_F(dht_impl_response_test, Announce_ReplyWith_ICMP_AfterAnnounce) {
	// put a peer into the dht for it to work with
	impl->Update(peer_id, 0, true, 10);
	Buffer peer_id_buffer;
	peer_id_buffer.len = 20;
	peer_id_buffer.b = (byte*)&peer_id.id.id[0];

	// make sure the callback dummy is clear
	AddNodesCallbackDummy::Reset();

	// *****************************************************
	// make the dht emit an announce message (the get_peers rpc)
	// *****************************************************
	EXPECT_FALSE(impl->IsBusy()) << "The dht should not be busy yet";
	impl->DoAnnounce(target, &AddNodesCallbackDummy::Callback, NULL,
			"filename.txt", NULL, 0);
	EXPECT_TRUE(impl->IsBusy()) << "The dht should be busy";

	// *****************************************************
	// grab from the socket the emitted message and extract
	// the transaction ID and verify the remainder of the
	// message
	// *****************************************************
	ASSERT_NO_FATAL_FAILURE(fetch_dict());
	ASSERT_NO_FATAL_FAILURE(expect_query_type());
	ASSERT_NO_FATAL_FAILURE(expect_command("get_peers"));
	Buffer tid;
	tid.b = (byte*)dict->GetString("t" , &tid.len);
	EXPECT_EQ(4, tid.len) << "transaction ID is wrong size";
	expect_reply_id();
	ASSERT_NO_FATAL_FAILURE(expect_info_hash());

	// *****************************************************
	// now fabricate a nodes response message using the
	// transaction ID extracted above and include a token
	// that the dht should return to us.  Provide the compact IP
	// of a peer for the dht to use in the 'announce_peer'
	// message it should emit next
	// *****************************************************


	// construct the message bytes
	len = bencoder(message, 1024)
		.d()
			("r").d()
				("id")(peer_id_buffer.b, peer_id_buffer.len)
				("token")(response_token)
				("values").l()
					(compact_ip).e().e()
			("t")(tid.b, tid.len)
			("y")("r")
		.e() ();
	socket4.Reset();
	impl->ProcessIncoming(message, len, peer_id.addr);
	EXPECT_TRUE(impl->IsBusy()) << "The dht should still be busy";
	ASSERT_NO_FATAL_FAILURE(fetch_dict());
	tid.b = (byte*)dict->GetString("t" , &tid.len);
	EXPECT_TRUE(impl->ParseIncomingICMP(output, peer_id.addr));

	// *****************************************************
	// look in the addnodes call back dummy to see what was
	// passed through (should be nothing)
	// *****************************************************
	EXPECT_EQ(2, AddNodesCallbackDummy::callbackData.size()) <<
			"Two callback events should have been made";

	ASSERT_NO_FATAL_FAILURE(expect_request_removed(tid));
	EXPECT_FALSE(impl->IsBusy()) << "The dht should no longer be busy";
}

/**
          Test                    |                  DHT
----------------------------------|--------------------------------------------
1) invoke doAnnounce()            |
                                  | Responds by emitting a 'get_peers' query
								  |
2) Fabricate and "send" a         |
   response to get_peers that     |
   has compact IP-address/port    |
   info for a peer                |
                                  | Responds by emitting 'announce_peer' query
								  |
*/
TEST_F(dht_impl_response_test, AnnounceSeed_ReplyWithPeers) {
	// put a peer into the dht for it to work with
	peer_id.addr.set_port(('8' << 8) + '8'); // 88
	peer_id.addr.set_addr4('aaaa'); // aaaa
	impl->Update(peer_id, 0, true, 10);
	Buffer peer_id_buffer;
	peer_id_buffer.len = 20;
	peer_id_buffer.b = (byte*)&peer_id.id.id[0];

	// make sure the callback dummy is clear
	AddNodesCallbackDummy::Reset();

	EXPECT_EQ(1, impl->GetNumPeers());
	EXPECT_EQ(0, impl->GetNumPeersTracked());

	DhtPeerID *ids[16];
	uint num = impl->FindNodes(target, ids, 8, 8,
			0); // Find 8 good ones and 8 bad ones
	EXPECT_EQ(1, num) << "Num Nodes: " << num;
	EXPECT_FALSE(impl->IsBusy()) << "The dht should not be busy yet";

	// *****************************************************
	// make the dht emit an announce message (the get_peers rpc)
	// *****************************************************
	std::string filenameTxt("filaname.txt");
	impl->DoAnnounce(target, &AddNodesCallbackDummy::Callback, NULL,
			filenameTxt.c_str(), NULL, IDht::announce_seed);
	EXPECT_TRUE(impl->IsBusy()) << "The dht should be busy";

	ASSERT_NO_FATAL_FAILURE(fetch_dict());
	ASSERT_NO_FATAL_FAILURE(expect_query_type());
	ASSERT_NO_FATAL_FAILURE(expect_command("get_peers"));
	Buffer tid;
	tid.b = (byte*)dict->GetString("t" , &tid.len);
	EXPECT_EQ(4, tid.len) << "transaction ID is wrong size";
	expect_reply_id();
	ASSERT_NO_FATAL_FAILURE(expect_info_hash());
	int noseed = reply->GetInt("noseed");
	EXPECT_EQ(1, noseed) << "'noseed' is not set when it should be.";

	// *****************************************************
	// now fabricate a nodes response message using the
	// transaction ID extracted above and include a token
	// that the dht should return to us.  Provide the compact IP
	// of a peer for the dht to use in the 'announce_peer'
	// message it should emit next
	// *****************************************************


	// construct the message bytes
	len = bencoder(message, 1024)
		.d()
			("r").d()
				("id")(peer_id_buffer.b, peer_id_buffer.len)
				("token")(response_token)
				("values").l()
					(compact_ip).e().e()
			("t")(tid.b, tid.len)
			("y")("r")
		.e() ();
	socket4.Reset();
	impl->ProcessIncoming(message, len, peer_id.addr);
	ASSERT_NO_FATAL_FAILURE(fetch_dict());
	ASSERT_NO_FATAL_FAILURE(expect_query_type());
	ASSERT_NO_FATAL_FAILURE(expect_command("announce_peer"));
	// get the transaction ID to use later
	tid.b = (byte*)dict->GetString("t" , &tid.len);
	EXPECT_EQ(4, tid.len) << "transaction ID is wrong size";
	expect_reply_id();
	ASSERT_NO_FATAL_FAILURE(expect_info_hash());
	ASSERT_NO_FATAL_FAILURE(expect_name(filenameTxt));
	ASSERT_NO_FATAL_FAILURE(expect_port(0x7878));
	expect_token(response_token);
	int seed = reply->GetInt("seed");
	EXPECT_EQ(1, seed) << "'seed' is not set when it should be.";

	// *****************************************************
	// create and send a response to the 'announce_peer
	// message
	// *****************************************************

	// construct the message bytes
	len = bencoder(message, 1024)
		.d()
			("r").d()
				("id")(peer_id_buffer.b, peer_id_buffer.len).e()
			("t")(tid.b, tid.len)
			("y")("r")
		.e() ();
	socket4.Reset();
	impl->ProcessIncoming(message, len, peer_id.addr);

	// check that nothing went out the socket.
	EXPECT_EQ(0, socket4.GetSentByteVector().size()) << "Nothing should be sent"
		" out the socket in response to the reply to the dht's 'announce_peer'"
		" query";

	// *****************************************************
	// look in the addnodes call back dummy to see what was
	// passed through
	// *****************************************************
	ASSERT_EQ(2, AddNodesCallbackDummy::callbackData.size()) <<
			"Expected two callback events";

	// verify the first callback event
	EXPECT_FALSE(memcmp("FFFFGGGGHHHHIIIIJJJJ",
			AddNodesCallbackDummy::callbackData[0].infoHash, 20));
	EXPECT_EQ(1, AddNodesCallbackDummy::callbackData[0].numPeers);
	EXPECT_FALSE(memcmp(compact_ip,
			&AddNodesCallbackDummy::callbackData[0].compactPeerAddressBytes[0],
			strlen(compact_ip)));

	// verify the second callback event
	EXPECT_FALSE(memcmp("FFFFGGGGHHHHIIIIJJJJ",
			AddNodesCallbackDummy::callbackData[1].infoHash, 20));
	EXPECT_EQ(0, AddNodesCallbackDummy::callbackData[1].numPeers);
	EXPECT_EQ(1, impl->GetNumPeers());
	EXPECT_EQ(0, impl->GetNumPeersTracked());
	num = impl->FindNodes(target, ids, 8, 8,
			0); // Find 8 good ones and 8 bad ones
	EXPECT_EQ(1, num) << "Num Nodes: " << num;

	ASSERT_NO_FATAL_FAILURE(expect_request_removed(tid));
	EXPECT_FALSE(impl->IsBusy()) << "The dht should no longer be busy";
}

TEST_F(dht_impl_response_test, DoFindNodes_OnReplyCallback) {
	DhtRequest* req;

	// put a peer into the dht for it to work with
	impl->Update(peer_id, 0, true, 10);
	Buffer peer_id_buffer;
	peer_id_buffer.len = 20;
	peer_id_buffer.b = (byte*)&peer_id.id.id[0];

	// *****************************************************
	// tell the dht to issue a find_nodes request and
	// capture the query string that goes out the socket
	// *****************************************************
	EXPECT_FALSE(impl->IsBusy()) << "The dht should not be busy yet";
	FindNodeCallbackDummy CallbackObj;
	impl->DoFindNodes(target, &CallbackObj);
	ASSERT_NO_FATAL_FAILURE(fetch_dict());
	EXPECT_TRUE(impl->IsBusy()) << "The dht should be busy";
	ASSERT_NO_FATAL_FAILURE(expect_query_type());
	ASSERT_NO_FATAL_FAILURE(expect_command("find_node"));
	Buffer tid;
	tid.b = (byte*)dict->GetString("t" , &tid.len);
	EXPECT_EQ(4, tid.len) << "transaction ID is wrong size";
	// see that the request has been queued
	ASSERT_NO_FATAL_FAILURE(expect_request_queued(tid));
	expect_reply_id();
	ASSERT_NO_FATAL_FAILURE(expect_target("FFFFGGGGHHHHIIIIJJJJ"));

	// now fabricate a nodes response message using the transaction ID extracted above

	// *****************************************************
	// make a response message to the above query.  Use the
	// transaction id extracted above.  Note the "compact
	// node" information for later use
	// *****************************************************
	// encode the compact node with IP address: 'aaaa' , port: '88' (aaaa88) and use this in the second response below
	std::string compact_node("WWWWWXXXXXYYYYYZZZZZaaaa88");
	len = bencoder(message, 1024)
		.d()
			("r").d()
				("id")(peer_id_buffer.b, peer_id_buffer.len)
				("nodes")(compact_node)
				("token")(response_token).e()
			("t")(tid.b, tid.len)
			("y")("r")
		.e() ();
	socket4.Reset();
	impl->ProcessIncoming(message, len, peer_id.addr);
	ASSERT_NO_FATAL_FAILURE(fetch_dict());
	EXPECT_TRUE(impl->IsBusy()) << "The dht should be busy";
	ASSERT_NO_FATAL_FAILURE(expect_query_type());
	ASSERT_NO_FATAL_FAILURE(expect_command("find_node"));
	tid.b = (byte*)dict->GetString("t" , &tid.len);
	EXPECT_EQ(4, tid.len) << "transaction ID is wrong size";
	ASSERT_NO_FATAL_FAILURE(expect_request_queued(tid));
	expect_reply_id();
	ASSERT_NO_FATAL_FAILURE(expect_target("FFFFGGGGHHHHIIIIJJJJ"));
	EXPECT_TRUE(impl->IsBusy()) << "The dht should still be busy";

	// *****************************************************
	// now fabricate a nodes response message using the
	// transaction ID extracted above.  ALSO, use the IP
	// address and port that were returned to the dht
	// in the response to it's initial query (aaaa88)
	// *****************************************************
	// construct the message bytes
	len = bencoder(message, 1024)
		.d()
			("r").d()
				("id")("WWWWWXXXXXYYYYYZZZZZ")
				("nodes")(compact_node)
				("token")(response_token).e()
			("t")(tid.b, tid.len)
			("y")("r")
		.e() ();
	socket4.Reset();
	DhtPeerID secondPeerID;
	secondPeerID.addr.set_addr4('aaaa'); // aaaa
	secondPeerID.addr.set_port(('8' << 8) + '8'); //88
	impl->ProcessIncoming(message, len, secondPeerID.addr);

	// *****************************************************
	// The DhtProcess object that is internally called back to uses private members
	// and member functions with no access points.  So, only circumstantial evidence
	// can be used to see if things are working as they should.
	// *****************************************************

	// see that our call back was invoked (this may be invoked even if there is an internal error)
	EXPECT_EQ(1, CallbackObj.callbackCount) <<
			"Our callback object should have been invoked 1 time";

	req = impl->LookupRequest(Read32(tid.b));
	EXPECT_FALSE(req) <<
			"The outstanding transaction id was not removed by the response";
	EXPECT_FALSE(impl->IsBusy()) << "The dht should no longer be busy";
}

TEST_F(dht_impl_response_test, DoFindNodes_NoNodesInReply) {
	// put a peer into the dht for it to work with
	impl->Update(peer_id, 0, true, 10);
	Buffer peer_id_buffer;
	peer_id_buffer.len = 20;
	peer_id_buffer.b = (byte*)&peer_id.id.id[0];

	// *****************************************************
	// tell the dht to issue a find_nodes request and
	// capture the query string that goes out the socket
	// *****************************************************
	EXPECT_FALSE(impl->IsBusy()) << "The dht should not be busy yet";
	FindNodeCallbackDummy CallbackObj;
	impl->DoFindNodes(target, &CallbackObj);
	ASSERT_NO_FATAL_FAILURE(fetch_dict());
	EXPECT_TRUE(impl->IsBusy()) << "The dht should be busy";
	ASSERT_NO_FATAL_FAILURE(expect_query_type());
	ASSERT_NO_FATAL_FAILURE(expect_command("find_node"));
	// get the transaction ID to use later
	Buffer tid;
	tid.b = (byte*)dict->GetString("t" , &tid.len);
	EXPECT_EQ(4, tid.len) << "transaction ID is wrong size";
	ASSERT_NO_FATAL_FAILURE(expect_request_queued(tid));
	expect_reply_id();
	ASSERT_NO_FATAL_FAILURE(expect_target("FFFFGGGGHHHHIIIIJJJJ"));

	// now fabricate a nodes response message using the transaction ID extracted above

	// *****************************************************
	// make a response message to the above query.  Use the
	// transaction id extracted above.
	//
	// For this test, DO NOT include any "compact node"
	// information in the response
	// *****************************************************

	// construct the message bytes
	len = bencoder(message, 1024)
		.d()
			("r").d()
				("id")(peer_id_buffer.b, peer_id_buffer.len)
				("token")(response_token).e()
			("t")(tid.b, tid.len)
			("y")("r")
		.e() ();
	socket4.Reset();
	impl->ProcessIncoming(message, len, peer_id.addr);
	std::string secondtime = socket4.GetSentDataAsString();
	EXPECT_FALSE(impl->IsBusy()) << "The dht should no longer be busy";

	// *****************************************************
	// The DhtProcess object that is internally called back to uses private members
	// and member functions with no access points.  So, only circumstantial evidence
	// can be used to see if things are working as they should.
	// *****************************************************

	// see that our call back was invoked (this may be invoked even if there is an internal error)
	EXPECT_EQ(1, CallbackObj.callbackCount) <<
			"Our callback object should have been invoked 1 time";

	ASSERT_NO_FATAL_FAILURE(expect_request_removed(tid));
	EXPECT_FALSE(impl->IsBusy()) << "The dht should no longer be busy";
}

TEST_F(dht_impl_response_test, DoFindNodes_ReplyWith_ICMP) {
	// put a peer into the dht for it to work with
	impl->Update(peer_id, 0, true, 10);
	Buffer peer_id_buffer;
	peer_id_buffer.len = 20;
	peer_id_buffer.b = (byte*)&peer_id.id.id[0];

	// *****************************************************
	// tell the dht to issue a find_nodes request and
	// capture the query string that goes out the socket
	// *****************************************************
	EXPECT_FALSE(impl->IsBusy()) << "The dht should not be busy yet";
	FindNodeCallbackDummy CallbackObj;
	impl->DoFindNodes(target, &CallbackObj);
	EXPECT_TRUE(impl->IsBusy()) << "The dht should be busy";

	// *****************************************************
	// grab from the socket the emitted message and turn it
	// into a bencentity.  Feed it back to the dht as an
	// ICMP message
	// *****************************************************
	ASSERT_NO_FATAL_FAILURE(fetch_dict());
	Buffer tid;
	tid.b = (byte*)dict->GetString("t" , &tid.len);

	EXPECT_TRUE(impl->ParseIncomingICMP(output, peer_id.addr));

	// *****************************************************
	// The DhtProcess object that is internally called back to uses private members
	// and member functions with no access points.  So, only circumstantial evidence
	// can be used to see if things are working as they should.
	// *****************************************************

	// see that our call back was invoked (this may be invoked even if there is an internal error)
	EXPECT_EQ(1, CallbackObj.callbackCount) <<
			"Our callback object should have been invoked 1 time";

	ASSERT_NO_FATAL_FAILURE(expect_request_removed(tid));
	EXPECT_FALSE(impl->IsBusy()) << "The dht should no longer be busy";
}

/**
          Test                    |                  DHT
----------------------------------|--------------------------------------------
1) invoke DoVote()                |
                                  | Responds by emitting a 'get_peers' query
								  |
2) Fabricate and "send" a         |
   response to get_peers that     |
   has only compact node info     |
                                  | Responds by emitting another 'get_peers' query
								  |
*/
TEST_F(dht_impl_response_test, DoVoteWithNodeReply) {
	// put a peer into the dht for it to work with
	impl->Update(peer_id, 0, true, 10);
	Buffer peer_id_buffer;
	peer_id_buffer.len = 20;
	peer_id_buffer.b = (byte*)&peer_id.id.id[0];

	VoteCallbackDummy::Reset();

	// *****************************************************
	// make the dht emit an announce message (the get_peers rpc)
	// *****************************************************
	EXPECT_FALSE(impl->IsBusy()) << "The dht should not be busy yet";
	impl->DoVote(target, 1, &VoteCallbackDummy::VoteCallback, NULL);
	EXPECT_TRUE(impl->IsBusy()) << "The dht should be busy";
	ASSERT_NO_FATAL_FAILURE(fetch_dict());
	ASSERT_NO_FATAL_FAILURE(expect_query_type());
	ASSERT_NO_FATAL_FAILURE(expect_command("get_peers"));
	Buffer tid;
	tid.b = (byte*)dict->GetString("t" , &tid.len);
	EXPECT_EQ(4, tid.len) << "transaction ID is wrong size";
	expect_reply_id();
	ASSERT_NO_FATAL_FAILURE(expect_info_hash());

	// *****************************************************
	// now fabricate a nodes response message using the
	// transaction ID extracted above and include a token
	// *****************************************************

	std::string compact_node("WWWWWXXXXXYYYYYZZZZZaaaa88");
	len = bencoder(message, 1024)
		.d()
			("r").d()
				("id")(peer_id_buffer.b, peer_id_buffer.len)
				("nodes")(compact_node)
				("token")(response_token).e()
			("t")(tid.b, tid.len)
			("y")("r")
		.e() ();
	socket4.Reset();
	impl->ProcessIncoming(message, len, peer_id.addr);
	EXPECT_TRUE(impl->IsBusy()) << "The dht should be busy";

	// *****************************************************
	// get the bencoded string out of the socket and verify
	// it. (should be another 'get_peers')
	// *****************************************************
	ASSERT_NO_FATAL_FAILURE(fetch_dict());
	ASSERT_NO_FATAL_FAILURE(expect_query_type());
	ASSERT_NO_FATAL_FAILURE(expect_command("get_peers"));
	expect_reply_id();
	ASSERT_NO_FATAL_FAILURE(expect_info_hash());
	EXPECT_EQ(0, VoteCallbackDummy::callbackCtr) <<
			"no callback events should have been made";
	EXPECT_TRUE(impl->IsBusy()) << "The dht should still be busy";
}

/**
          Test                    |                  DHT
----------------------------------|--------------------------------------------
1) invoke DoVote()                |
                                  | Responds by emitting a 'get_peers' query
								  |
2) Fabricate and "send" a         |
   response to get_peers that     |
   has compact IP-address/port    |
   info for a peer                |
                                  | Responds by emitting 'vote' query
								  |
*/
TEST_F(dht_impl_response_test, DoVoteWithPeerReply) {
	impl->Update(peer_id, 0, true, 10);
	Buffer peer_id_buffer;
	peer_id_buffer.len = 20;
	peer_id_buffer.b = (byte*)&peer_id.id.id[0];

	VoteCallbackDummy::Reset();

	// *****************************************************
	// make the dht emit an announce message (the get_peers rpc)
	// note that the value of '3' should be retrieved from
	// the 'vote' message
	// *****************************************************
	EXPECT_FALSE(impl->IsBusy()) << "The dht should not be busy yet";
	impl->DoVote(target, 3, &VoteCallbackDummy::VoteCallback, NULL);
	EXPECT_TRUE(impl->IsBusy()) << "The dht should be busy";

	// *****************************************************
	// grab from the socket the emitted message and extract
	// the transaction ID and verify the remainder of the
	// message
	// *****************************************************
	ASSERT_NO_FATAL_FAILURE(fetch_dict());
	ASSERT_NO_FATAL_FAILURE(expect_query_type());
	ASSERT_NO_FATAL_FAILURE(expect_command("get_peers"));
	Buffer tid;
	tid.b = (byte*)dict->GetString("t" , &tid.len);
	EXPECT_EQ(4, tid.len) << "transaction ID is wrong size";
	expect_reply_id();
	ASSERT_NO_FATAL_FAILURE(expect_info_hash());
	len = bencoder(message, 1024)
		.d()
			("r").d()
				("id")(peer_id_buffer.b, peer_id_buffer.len)
				("token")(response_token)
				("values").l()
					(compact_ip).e().e()
			("t")(tid.b, tid.len)
			("y")("r")
		.e() ();
	socket4.Reset();
	impl->ProcessIncoming(message, len, peer_id.addr);
	EXPECT_TRUE(impl->IsBusy()) << "The dht should be busy";
	ASSERT_NO_FATAL_FAILURE(fetch_dict());
	ASSERT_NO_FATAL_FAILURE(expect_query_type());
	ASSERT_NO_FATAL_FAILURE(expect_command("vote"));
	tid.b = (byte*)dict->GetString("t" , &tid.len);
	EXPECT_EQ(4, tid.len) << "transaction ID is wrong size";
	expect_reply_id();
	ASSERT_NO_FATAL_FAILURE(expect_target("FFFFGGGGHHHHIIIIJJJJ"));
	expect_token(response_token);
	EXPECT_EQ(3, reply->GetInt("vote"));

	len = bencoder(message, 1024)
		.d()
			("r").d()
				("id")(peer_id_buffer.b, peer_id_buffer.len).e()
			("t")(tid.b, tid.len)
			("y")("r")
		.e() ();
	socket4.Reset();
	impl->ProcessIncoming(message, len, peer_id.addr);
	EXPECT_EQ(0, socket4.GetSentByteVector().size()) << "Nothing should be sent"
		" out the socket in response to the reply to the dht's 'announce_peer'"
		" query";
	EXPECT_EQ(1, VoteCallbackDummy::callbackCtr) <<
			"1 callback should have been made";
	EXPECT_FALSE(impl->IsBusy()) << "The dht should no longer be busy";
}

/**
          Test                    |                  DHT
----------------------------------|--------------------------------------------
1) invoke DoVote()                |
                                  | Responds by emitting a 'get_peers' query
								  |
2) Capture the outputted bencoded |
   string and feed it back to the |
   DHT via ParseIncommingICMP     |
                                  | Ceases pursuing the request
								  |
*/
TEST_F(dht_impl_response_test, DoVote_ReplyWith_ICMP) {
	impl->Update(peer_id, 0, true, 10);
	Buffer peer_id_buffer;
	peer_id_buffer.len = 20;
	peer_id_buffer.b = (byte*)&peer_id.id.id[0];

	VoteCallbackDummy::Reset();

	// *****************************************************
	// make the dht emit an announce message (the get_peers rpc)
	// note that the value of '3' should be retrieved from
	// the 'vote' message
	// *****************************************************
	EXPECT_FALSE(impl->IsBusy()) << "The dht should not be busy yet";
	impl->DoVote(target, 3, &VoteCallbackDummy::VoteCallback, NULL);
	EXPECT_TRUE(impl->IsBusy()) << "The dht should be busy";

	// *****************************************************
	// grab from the socket the emitted message and turn it
	// into a bencentity.  Feed it back to the dht as an
	// ICMP message
	// *****************************************************
	ASSERT_NO_FATAL_FAILURE(fetch_dict());
	Buffer tid;
	tid.b = (byte*)dict->GetString("t" , &tid.len);
	EXPECT_TRUE(impl->ParseIncomingICMP(output, peer_id.addr));

	// *****************************************************
	// look in the vote call back dummy for callback events
	// *****************************************************
	EXPECT_EQ(0, VoteCallbackDummy::callbackCtr) <<
			"NO callbacks should have been made";
	EXPECT_FALSE(impl->IsBusy()) << "The dht should no longer be busy";
	DhtRequest* req = impl->LookupRequest(Read32(tid.b));
	EXPECT_FALSE(req) <<
			"The outstanding transaction id was not removed by the response";
}

/**
          Test                    |                  DHT
----------------------------------|--------------------------------------------
1) invoke DoVote()                |
                                  | Responds by emitting a 'get_peers' query
								  |
2) Fabricate and "send" a         |
   response to get_peers that     |
   has compact IP-address/port    |
   info for a peer                |
                                  | Responds by emitting 'vote' query
								  |
3) Send an ICMP message back      |
                                  |
*/
TEST_F(dht_impl_response_test, DoVote_ReplyWith_ICMP_AfterVote) {
	impl->Update(peer_id, 0, true, 10);
	Buffer peer_id_buffer;
	peer_id_buffer.len = 20;
	peer_id_buffer.b = (byte*)&peer_id.id.id[0];

	VoteCallbackDummy::Reset();

	// *****************************************************
	// make the dht emit an announce message (the get_peers rpc)
	// note that the value of '3' should be retrieved from
	// the 'vote' message
	// *****************************************************
	EXPECT_FALSE(impl->IsBusy()) << "The dht should not be busy yet";
	impl->DoVote(target, 3, &VoteCallbackDummy::VoteCallback, NULL);
	EXPECT_TRUE(impl->IsBusy()) << "The dht should be busy";

	// *****************************************************
	// grab from the socket the emitted message and extract
	// the transaction ID and verify the remainder of the
	// message
	// *****************************************************
	ASSERT_NO_FATAL_FAILURE(fetch_dict());
	ASSERT_NO_FATAL_FAILURE(expect_query_type());
	ASSERT_NO_FATAL_FAILURE(expect_command("get_peers"));
	Buffer tid;
	tid.b = (byte*)dict->GetString("t" , &tid.len);
	EXPECT_EQ(4, tid.len) << "transaction ID is wrong size";
	expect_reply_id();
	ASSERT_NO_FATAL_FAILURE(expect_info_hash());

	len = bencoder(message, 1024)
		.d()
			("r").d()
				("id")(peer_id_buffer.b, peer_id_buffer.len)
				("token")(response_token)
				("values").l()
					(compact_ip).e().e()
			("t")(tid.b, tid.len)
			("y")("r")
		.e() ();
	socket4.Reset();
	impl->ProcessIncoming(message, len, peer_id.addr);
	EXPECT_TRUE(impl->IsBusy()) << "The dht should be busy";
	ASSERT_NO_FATAL_FAILURE(fetch_dict());
	tid.b = (byte*)dict->GetString("t" , &tid.len);
	EXPECT_TRUE(impl->ParseIncomingICMP(output, peer_id.addr));
	EXPECT_EQ(0, VoteCallbackDummy::callbackCtr) <<
			"NO callbacks should have been made";
	EXPECT_FALSE(impl->IsBusy()) << "The dht should no longer be busy";
	DhtRequest* req = impl->LookupRequest(Read32(tid.b));
	EXPECT_FALSE(req) <<
			"The outstanding transaction id was not removed by the response";
}

TEST_F(dht_impl_response_test, TestResponseToPing) {

	byte myId[] = {'v', 'v', 'v', 'v', 'v', 'v', 'v', 'v', 'v', 'v', 'v', 'v',
		'v', 'v', 'v', 'v', 'v', 'v', 'v', 'v'};
	impl->SetId(myId);

	// put a peer into the dht for it to work with
	impl->Update(peer_id, 0, true, 10);
	Buffer peer_id_buffer;
	peer_id_buffer.len = 20;
	peer_id_buffer.b = (byte*)&peer_id.id.id[0];

	// invoke AddNode to emit a ping message
	EXPECT_FALSE(impl->IsBusy()) << "The dht should not be busy yet";
	impl->AddNode(peer_id.addr, NULL, 0);
	// grab from the socket the emitted message and extract the transaction ID
	ASSERT_NO_FATAL_FAILURE(fetch_dict());
	ASSERT_NO_FATAL_FAILURE(expect_query_type());

	// we use find_node to ping peers now
	ASSERT_NO_FATAL_FAILURE(expect_command("find_node"));
	Buffer tid;
	tid.b = (byte*)dict->GetString("t" , &tid.len);
	EXPECT_EQ(4, tid.len) << "transaction ID is wrong size";
	expect_reply_id("vvvvvvvvvvvvvvvvvvvv");
	// construct the reply message
	len = bencoder(message, 1024)
		.d()
			("r").d()
				("id")("qqqqqqqqqqqqqqqqqqqq").e()
			("t")(tid.b, tid.len)
			("y")("r")
		.e() ();
	socket4.Reset();
	impl->ProcessIncoming(message, len, peer_id.addr);
}

TEST_F(dht_impl_response_test, TestResponseToPing_ReplyWith_ICMP) {
	byte myId[] = {'v', 'v', 'v', 'v', 'v', 'v', 'v', 'v', 'v', 'v', 'v', 'v',
		'v', 'v', 'v', 'v', 'v', 'v', 'v', 'v'};
	impl->SetId(myId);

	// put a peer into the dht for it to work with
	impl->Update(peer_id, 0, true, 10);
	Buffer peer_id_buffer;
	peer_id_buffer.len = 20;
	peer_id_buffer.b = (byte*)&peer_id.id.id[0];

	// invoke AddNode to emit a bootstrap ping message
	EXPECT_FALSE(impl->IsBusy()) << "The dht should not be busy yet";
	impl->AddNode(peer_id.addr, NULL, 0);
	ASSERT_NO_FATAL_FAILURE(fetch_dict());
	socket4.Reset();
	EXPECT_TRUE(impl->ParseIncomingICMP(output, peer_id.addr));
	std::string emptyStr = socket4.GetSentDataAsString();
	EXPECT_EQ(0, emptyStr.size()) << "Nothing should have gone out the socket";
	EXPECT_FALSE(impl->IsBusy()) << "The dht should NOT be busy";
}

/**
          Test                    |                  DHT
----------------------------------|--------------------------------------------
1) invoke DoScrape()              |
                                  | Responds by emitting a 'get_peers' query
								  |
2) Fabricate and "send" a         |
   response to get_peers that     |
   has only compact node info     |
                                  | Responds by emitting another 'get_peers' query
								  |
*/
TEST_F(dht_impl_response_test, DoScrape_ReplyWithNodes) {
	impl->Update(peer_id, 0, true, 10);
	Buffer peer_id_buffer;
	peer_id_buffer.len = 20;
	peer_id_buffer.b = (byte*)&peer_id.id.id[0];

	ScrapeCallbackDummy::Reset();

	EXPECT_FALSE(impl->IsBusy()) << "The dht should not be busy yet";
	impl->DoScrape(target, &ScrapeCallbackDummy::Callback, NULL);
	EXPECT_TRUE(impl->IsBusy()) << "The dht should be busy";

	ASSERT_NO_FATAL_FAILURE(fetch_dict());
	ASSERT_NO_FATAL_FAILURE(expect_query_type());
	ASSERT_NO_FATAL_FAILURE(expect_command("get_peers"));
	Buffer tid;
	tid.b = (byte*)dict->GetString("t" , &tid.len);
	EXPECT_EQ(4, tid.len) << "transaction ID is wrong size";
	expect_reply_id();
	ASSERT_NO_FATAL_FAILURE(expect_info_hash());
	EXPECT_EQ(1, reply->GetInt("scrape"));

	std::string nearest_node("26_byte_nearest_node_addr.");

	len = bencoder(message, 1024)
		.d()
			("r").d()
				("id")(peer_id_buffer.b, peer_id_buffer.len)
				("nodes")(nearest_node)
				("token")(response_token).e()
			("t")(tid.b, tid.len)
			("y")("r")
		.e() ();
	socket4.Reset();
	impl->ProcessIncoming(message, len, peer_id.addr);
	EXPECT_TRUE(impl->IsBusy()) << "The dht should be busy";
	ASSERT_NO_FATAL_FAILURE(fetch_dict());
	ASSERT_NO_FATAL_FAILURE(expect_query_type());
	ASSERT_NO_FATAL_FAILURE(expect_command("get_peers"));
	expect_reply_id();
	ASSERT_NO_FATAL_FAILURE(expect_info_hash(reinterpret_cast<unsigned char*>(target.id)));
	EXPECT_EQ(1, reply->GetInt("scrape"));

	// *****************************************************
	// look in the addnodes call back dummy to see what was
	// passed through (should be nothing)
	// *****************************************************
	EXPECT_FALSE(memcmp("\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
			ScrapeCallbackDummy::infoHash,
			20)) << "The callback should not have been invoked";
	EXPECT_EQ(0, ScrapeCallbackDummy::numDownloaders) <<
			"The callback should not have been invoked";
	EXPECT_EQ(0, ScrapeCallbackDummy::numSeeds) <<
			"The callback should not have been invoked";
	EXPECT_TRUE(impl->IsBusy()) << "The dht should still be busy";
}

/**
          Test                    |                  DHT
----------------------------------|--------------------------------------------
1) invoke DoScrape()              |
                                  | Responds by emitting a 'get_peers' query
								  |
2) Fabricate and "send" a         |
   response to get_peers that     |
   has compact IP-address/port    |
   info for a peer                |
                                  | no output response expected from dht
								  |

Note:  The values estimated for the number of downloaders and the number of seeds
       that are examined in the callback at end of the test may change if the
	   algorithm in the bloom filter for estimating those numbers changes.  They
	   will also change if the "BFpe" and "BFsd" byte strings are altered.
*/
TEST_F(dht_impl_response_test, Scrape_ReplyWithPeers) {
	// put a peer into the dht for it to work with
	peer_id.addr.set_port(('8' << 8) + '8'); // 88
	peer_id.addr.set_addr4('aaaa'); // aaaa
	impl->Update(peer_id, 0, true, 10);
	Buffer peer_id_buffer;
	peer_id_buffer.len = 20;
	peer_id_buffer.b = (byte*)&peer_id.id.id[0];

	// make sure the callback dummy is clear
	ScrapeCallbackDummy::Reset();

	EXPECT_EQ(1, impl->GetNumPeers());
	EXPECT_EQ(0, impl->GetNumPeersTracked());

	// *****************************************************
	// make the dht emit a scrape message (the get_peers rpc)
	// *****************************************************
	EXPECT_FALSE(impl->IsBusy()) << "The dht should not be busy yet";
	impl->DoScrape(target, &ScrapeCallbackDummy::Callback, NULL);
	EXPECT_TRUE(impl->IsBusy()) << "The dht should be busy";
	ASSERT_NO_FATAL_FAILURE(fetch_dict());
	ASSERT_NO_FATAL_FAILURE(expect_query_type());
	ASSERT_NO_FATAL_FAILURE(expect_command("get_peers"));
	Buffer tid;
	tid.b = (byte*)dict->GetString("t" , &tid.len);
	EXPECT_EQ(4, tid.len) << "transaction ID is wrong size";
	expect_reply_id();
	ASSERT_NO_FATAL_FAILURE(expect_info_hash());
	EXPECT_EQ(1, reply->GetInt("scrape"));

	len = bencoder(message, 1024)
		.d()
			("r").d()
				("BFpe")(std::vector<byte>(256, 'b'))
				("BFsd")(std::vector<byte>(256, 'B'))
				("id")(peer_id_buffer.b, peer_id_buffer.len)
				("token")(response_token)
				("values").l()
					(compact_ip).e().e()
			("t")(tid.b, tid.len)
			("y")("r")
		.e() ();
	socket4.Reset();
	impl->ProcessIncoming(message, len, peer_id.addr);
	EXPECT_FALSE(impl->IsBusy()) << "The dht should no longer be busy";

	std::string emptyString = socket4.GetSentDataAsString();
	EXPECT_TRUE(emptyString == "") << "A response message was sent for a scrape"
		" reply when no response message was expected.";
	EXPECT_FALSE(memcmp("FFFFGGGGHHHHIIIIJJJJ", ScrapeCallbackDummy::infoHash,
				20));
	EXPECT_EQ(481, ScrapeCallbackDummy::numDownloaders) << "(NOTE if the"
		" estimate_count() algorithm changes for Bloom Filters, this value may"
		" change.";
	EXPECT_EQ(294, ScrapeCallbackDummy::numSeeds) <<
			"(NOTE if the estimate_count() algorithm changes for Bloom Filters,"
			" this value may change.";
	EXPECT_EQ(1, impl->GetNumPeers());
	EXPECT_EQ(0, impl->GetNumPeersTracked());
}

/**
          Test                    |                  DHT
----------------------------------|--------------------------------------------
1) invoke DoScrape()              |
                                  | Responds by emitting a 'get_peers' query
								  |
2) Capture the outputted bencoded |
   string and feed it back to the |
   DHT via ParseIncommingICMP     |
                                  | Ceases pursuing the request
								  |
*/
TEST_F(dht_impl_response_test, Scrape_ReplyWith_ICMP) {
	peer_id.addr.set_port(('8' << 8) + '8'); // 88
	peer_id.addr.set_addr4('aaaa'); // aaaa
	impl->Update(peer_id, 0, true, 10);
	Buffer peer_id_buffer;
	peer_id_buffer.len = 20;
	peer_id_buffer.b = (byte*)&peer_id.id.id[0];

	// make sure the callback dummy is clear
	ScrapeCallbackDummy::Reset();

	EXPECT_EQ(1, impl->GetNumPeers());
	EXPECT_EQ(0, impl->GetNumPeersTracked());

	// *****************************************************
	// make the dht emit a scrape message (the get_peers rpc)
	// *****************************************************
	EXPECT_FALSE(impl->IsBusy()) << "The dht should not be busy yet";
	impl->DoScrape(target, &ScrapeCallbackDummy::Callback, NULL);
	EXPECT_TRUE(impl->IsBusy()) << "The dht should be busy";

	// *****************************************************
	// grab from the socket the emitted message and turn it
	// into a bencentity.  Feed it back to the dht as an
	// ICMP message
	// *****************************************************
	ASSERT_NO_FATAL_FAILURE(fetch_dict());
	Buffer tid;
	tid.b = (byte*)dict->GetString("t" , &tid.len);
	socket4.Reset();
	EXPECT_TRUE(impl->ParseIncomingICMP(output, peer_id.addr));
	std::string emptyString = socket4.GetSentDataAsString();
	EXPECT_EQ(0, emptyString.size()) << "A response message was sent for a"
		" scrape reply when no response message was expected.";
	EXPECT_FALSE(memcmp("FFFFGGGGHHHHIIIIJJJJ", ScrapeCallbackDummy::infoHash,
				20));
	EXPECT_EQ(0, ScrapeCallbackDummy::numDownloaders) << "(NOTE if the"
		" estimate_count() algorithm changes for Bloom Filters, this value may"
		" change.";
	EXPECT_EQ(0, ScrapeCallbackDummy::numSeeds) << "(NOTE if the"
		" estimate_count() algorithm changes for Bloom Filters, this value may"
		" change.";
	EXPECT_EQ(0, impl->GetNumPeers());
	EXPECT_EQ(0, impl->GetNumPeersTracked());
}

/**
          Test                    |                  DHT
----------------------------------|--------------------------------------------
1) invoke ResolveName()           |
                                  | Responds by emitting a 'get_peers' query
								  |
2) Fabricate and "send" a         |
   response to get_peers that     |
   has the 'n' argument in the    |
   dictionary set to a file name  |
                                  | no output response expected from dht
								  |
*/
TEST_F(dht_impl_response_test, TestResolveName) {
	peer_id.addr.set_port(('8' << 8) + '8'); // 88
	peer_id.addr.set_addr4('aaaa'); // aaaa
	impl->Update(peer_id, 0, true, 10);
	Buffer peer_id_buffer;
	peer_id_buffer.len = 20;
	peer_id_buffer.b = (byte*)&peer_id.id.id[0];

	// make sure the callback dummy is clear
	AddNodesCallbackDummy::Reset();

	EXPECT_EQ(1, impl->GetNumPeers());
	EXPECT_EQ(0, impl->GetNumPeersTracked());

	DhtPeerID *ids[16];
	uint num = impl->FindNodes(target, ids, 8, 8,
			0); // Find 8 good ones and 8 bad ones
	EXPECT_EQ(1, num) << "Num Nodes: " << num;

	// *****************************************************
	// make the dht emit an announce message (the get_peers rpc)
	// *****************************************************
	EXPECT_FALSE(impl->IsBusy()) << "The dht should not be busy yet";
	ResolveNameCallbackDummy::Clear();
	impl->ResolveName(target, &ResolveNameCallbackDummy::Callback, NULL);
	EXPECT_TRUE(impl->IsBusy()) << "The dht should be busy";

	ASSERT_NO_FATAL_FAILURE(fetch_dict());
	ASSERT_NO_FATAL_FAILURE(expect_query_type());
	ASSERT_NO_FATAL_FAILURE(expect_command("get_peers"));
	Buffer tid;
	tid.b = (byte*)dict->GetString("t" , &tid.len);
	EXPECT_EQ(4, tid.len) << "transaction ID is wrong size";
	expect_reply_id();
	ASSERT_NO_FATAL_FAILURE(expect_info_hash());

	std::string filename("test_filename.txt");
	len = bencoder(message, 1024)
		.d()
			("r").d()
				("id")(peer_id_buffer.b, peer_id_buffer.len)
				("n")(filename)
				("token")(response_token).e()
			("t")(tid.b, tid.len)
			("y")("r")
		.e() ();
	socket4.Reset();
	impl->ProcessIncoming(message, len, peer_id.addr);
	std::string announceString = socket4.GetSentDataAsString();
	EXPECT_TRUE(announceString == "") << "Nothing should have been sent out."
		"  The response with a filename should terminate this process.";
	EXPECT_TRUE(ResolveNameCallbackDummy::name == filename)
		<< "ERROR:  received:  " << ResolveNameCallbackDummy::name <<
		"\nInstead of:  " << filename;
	EXPECT_FALSE(memcmp("FFFFGGGGHHHHIIIIJJJJ",
				ResolveNameCallbackDummy::infoHash, 20)) << "the target did not match";
	EXPECT_EQ(1, impl->GetNumPeers());
	EXPECT_EQ(0, impl->GetNumPeersTracked());
	// Find 8 good ones and 8 bad ones
	num = impl->FindNodes(target, ids, 8, 8, 0);
	EXPECT_EQ(1, num) << "Num Nodes: " << num;
	EXPECT_FALSE(impl->IsBusy()) << "The dht should no longer be busy";
}

/**
          Test                    |                  DHT
----------------------------------|--------------------------------------------
1) invoke ResolveName()           |
                                  | Responds by emitting a 'get_peers' query
								  |
2) Fabricate and "send" a         |
   response to get_peers that     |
   has no 'n' argument            |
                                  | no output response expected from dht
								  |
*/
TEST_F(dht_impl_response_test, TestResolveName_NoNameInReply) {
	peer_id.addr.set_port(('8' << 8) + '8'); // 88
	peer_id.addr.set_addr4('aaaa'); // aaaa
	impl->Update(peer_id, 0, true, 10);
	Buffer peer_id_buffer;
	peer_id_buffer.len = 20;
	peer_id_buffer.b = (byte*)&peer_id.id.id[0];

	// make sure the callback dummy is clear
	AddNodesCallbackDummy::Reset();

	EXPECT_EQ(1, impl->GetNumPeers());
	EXPECT_EQ(0, impl->GetNumPeersTracked());

	DhtPeerID *ids[16];
	uint num = impl->FindNodes(target, ids, 8, 8,
			0); // Find 8 good ones and 8 bad ones
	EXPECT_EQ(1, num) << "Num Nodes: " << num;

	// *****************************************************
	// make the dht emit an announce message (the get_peers rpc)
	// *****************************************************
	EXPECT_FALSE(impl->IsBusy()) << "The dht should not be busy yet";
	ResolveNameCallbackDummy::Clear();
	impl->ResolveName(target, &ResolveNameCallbackDummy::Callback, NULL);
	EXPECT_TRUE(impl->IsBusy()) << "The dht should be busy";
	ASSERT_NO_FATAL_FAILURE(fetch_dict());
	ASSERT_NO_FATAL_FAILURE(expect_query_type());
	ASSERT_NO_FATAL_FAILURE(expect_command("get_peers"));
	Buffer tid;
	tid.b = (byte*)dict->GetString("t" , &tid.len);
	EXPECT_EQ(4, tid.len) << "transaction ID is wrong size";
	expect_reply_id();
	ASSERT_NO_FATAL_FAILURE(expect_info_hash());

	len = bencoder(message, 1024)
		.d()
			("r").d()
				("id")(peer_id_buffer.b, peer_id_buffer.len)
				("token")(response_token).e()
			("t")(tid.b, tid.len)
			("y")("r")
		.e() ();
	socket4.Reset();
	impl->ProcessIncoming(message, len, peer_id.addr);
	std::string announceString = socket4.GetSentDataAsString();
	EXPECT_TRUE(announceString == "") << "Nothing should have been sent out."
		"  The response with a filename should terminate this process.";

	// *****************************************************
	// verify the callback was set with the file name
	// *****************************************************
	EXPECT_TRUE(ResolveNameCallbackDummy::name == "") << "ERROR:  received:  "
		<< ResolveNameCallbackDummy::name << "\nInstead of:  \"\"";
	EXPECT_FALSE(memcmp("\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
			ResolveNameCallbackDummy::infoHash, 20)) << "the target did not match";

	EXPECT_EQ(1, impl->GetNumPeers());
	EXPECT_EQ(0, impl->GetNumPeersTracked());
	// Find 8 good ones and 8 bad ones
	num = impl->FindNodes(target, ids, 8, 8, 0);
	EXPECT_EQ(1, num) << "Num Nodes: " << num;
	EXPECT_FALSE(impl->IsBusy()) << "The dht should no longer be busy";
}

/**
          Test                    |                  DHT
----------------------------------|--------------------------------------------
1) invoke ResolveName()           |
                                  | Responds by emitting a 'get_peers' query
								  |
2) Capture the outputted bencoded |
   string and feed it back to the |
   DHT via ParseIncommingICMP     |
                                  | no output response expected from dht
								  |
*/
TEST_F(dht_impl_response_test, TestResolveName_ReplyWith_ICMP) {
	peer_id.addr.set_port(('8' << 8) + '8'); // 88
	peer_id.addr.set_addr4('aaaa'); // aaaa
	impl->Update(peer_id, 0, true, 10);
	Buffer peer_id_buffer;
	peer_id_buffer.len = 20;
	peer_id_buffer.b = (byte*)&peer_id.id.id[0];

	// make sure the callback dummy is clear
	AddNodesCallbackDummy::Reset();

	EXPECT_EQ(1, impl->GetNumPeers());
	EXPECT_EQ(0, impl->GetNumPeersTracked());

	DhtPeerID *ids[16];
	uint num = impl->FindNodes(target, ids, 8, 8,
			0); // Find 8 good ones and 8 bad ones
	EXPECT_EQ(1, num) << "Num Nodes: " << num;

	// *****************************************************
	// make the dht emit an announce message (the get_peers rpc)
	// *****************************************************
	EXPECT_FALSE(impl->IsBusy()) << "The dht should not be busy yet";
	ResolveNameCallbackDummy::Clear();
	impl->ResolveName(target, &ResolveNameCallbackDummy::Callback, NULL);
	EXPECT_TRUE(impl->IsBusy()) << "The dht should be busy";
	ASSERT_NO_FATAL_FAILURE(fetch_dict());
	Buffer tid;
	tid.b = (byte*)dict->GetString("t" , &tid.len);
	socket4.Reset();
	EXPECT_TRUE(impl->ParseIncomingICMP(output, peer_id.addr));
	std::string announceString = socket4.GetSentDataAsString();
	EXPECT_TRUE(announceString == "") << "Nothing should have been sent out."
		"  The response with a filename should terminate this process.";
	EXPECT_TRUE(ResolveNameCallbackDummy::name == "") << "ERROR:  received:  "
		<< ResolveNameCallbackDummy::name << "\nInstead of:  \"\"";
	EXPECT_FALSE(memcmp("\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
			ResolveNameCallbackDummy::infoHash, 20)) << "the target did not match";

	EXPECT_EQ(0, impl->GetNumPeers());
	EXPECT_EQ(0, impl->GetNumPeersTracked());
	num = impl->FindNodes(target, ids, 8, 8, 0);
	EXPECT_EQ(0, num) << "Num Nodes: " << num;
	EXPECT_FALSE(impl->IsBusy()) << "The dht should no longer be busy";
}

/**
          Test                    |                  DHT
----------------------------------|--------------------------------------------
1) invoke doAnnounce() several    |
   times                          |
                                  | Responds by emitting a 'get_peers' query
								  | for each doAnnounce()
								  |
2) Fabricate and "send" a         |
   response to get_peers that     |
   has compact IP-address/port    |
   info for a peer                |
                                  | Responds by emitting 'announce_peer' query
								  | and invoking the callback twice for each
								  | target
*/
TEST_F(dht_impl_response_test, MultipleAnnounce_ReplyWithSinglePeer) {
	// put a peer into the dht for it to work with
	peer_id.addr.set_port(('8' << 8) + '8'); // 88
	peer_id.addr.set_addr4('aaaa'); // aaaa
	impl->Update(peer_id, 0, true, 10);
	Buffer peer_id_buffer;
	peer_id_buffer.len = 20;
	peer_id_buffer.b = (byte*)&peer_id.id.id[0];

	const unsigned int numTargets = 5;
	std::vector<byte> transactionIDs[numTargets];
	std::string filenamesTxt[numTargets];
	DhtID targets[numTargets];

	for(unsigned int x = 0; x < numTargets; ++x) {
		targets[x].id[0] = 'FFFF'; // FFFF
		targets[x].id[1] = 'GGGG'; // GGGG
		targets[x].id[2] = 'HHHH'; // HHHH
		targets[x].id[3] = 'IIII'; // IIII
		targets[x].id[4] = ((((((x + 0x30) << 8) + x + 0x30) << 8) + x + 0x30)
				<< 8) + x + 0x30; //
	}

	for(unsigned int x = 0; x < numTargets; ++x) {
		filenamesTxt[x] = "filename_";
		std::string LastChar("0");
		LastChar[0] += (char)x;
		filenamesTxt[x] += LastChar;
	}

	// make sure the callback dummy is clear
	AddNodesCallbackDummy::Reset();

	// *****************************************************
	// make the dht emit an announce message (the get_peers rpc)
	// and capture the transaction ID
	// *****************************************************

	for(unsigned int x = 0; x < numTargets; ++x) {
		socket4.Reset();
		ASSERT_NO_FATAL_FAILURE(fetch_announce(targets[x], filenamesTxt[x],
					transactionIDs[x]));
	}

	std::string response_tokens[numTargets];
	for(unsigned int x = 0; x < numTargets; ++x) {
		response_tokens[x] = "20_byte_reply_token";
		std::string LastChar("0");
		LastChar[0] += (char)x;
		response_tokens[x] += LastChar;
	}

	// make a list of compact IPs (in this case only one ip)
	std::vector<std::string> values;
	values.push_back(compact_ip);

	Buffer tid;
	for(unsigned int x = 0; x < numTargets; ++x) {
		ASSERT_NO_FATAL_FAILURE(fetch_peers_reply(peer_id, response_tokens[x],
					values, transactionIDs[x], transactionIDs[x]));

		EXPECT_TRUE(impl->IsBusy()) << "The dht should still be busy";

		ASSERT_NO_FATAL_FAILURE(fetch_dict());
		ASSERT_NO_FATAL_FAILURE(expect_query_type());
		ASSERT_NO_FATAL_FAILURE(expect_command("announce_peer"));
		tid.b = (byte*)dict->GetString("t" , &tid.len);
		EXPECT_EQ(4, tid.len) << "transaction ID is wrong size";
		expect_reply_id();
		expect_info_hash(reinterpret_cast<const unsigned char*>
				(&(targets[x].id[0])));
		ASSERT_NO_FATAL_FAILURE(expect_name(filenamesTxt[x]));
		ASSERT_NO_FATAL_FAILURE(expect_port(0x7878));
		expect_token(response_tokens[x].c_str());
	}

	for(unsigned int x = 0; x < numTargets; ++x) {
		len = bencoder(message, 1024)
			.d()
				("r").d()
					("id")(peer_id_buffer.b, peer_id_buffer.len).e()
				("t")(transactionIDs[x])
				("y")("r")
			.e() ();
		socket4.Reset();
		impl->ProcessIncoming(message, len, peer_id.addr);
		EXPECT_EQ(0, socket4.GetSentByteVector().size()) <<
				"Nothing should be sent out the socket in response to the reply to"
				" the dht's 'announce_peer' query";
	}
	ASSERT_EQ(2 * numTargets, AddNodesCallbackDummy::callbackData.size());
	for(unsigned int x = 0; x < numTargets; ++x) {
		// verify the first callback events
		EXPECT_FALSE(memcmp(&(targets[x].id[0]),
				AddNodesCallbackDummy::callbackData[x].infoHash,
				20)) << "first callback, iteration:  " << x;
		EXPECT_EQ(1, AddNodesCallbackDummy::callbackData[x].numPeers) <<
				"first callback, iteration:  " << x;
		EXPECT_FALSE(memcmp(compact_ip,
				&AddNodesCallbackDummy::callbackData[x].compactPeerAddressBytes[0],
				strlen(compact_ip))) << "first callback, iteration:  " << x;

		// verify the second callback event
		EXPECT_FALSE(memcmp(&(targets[x].id[0]),
				AddNodesCallbackDummy::callbackData[x + numTargets].infoHash,
				20)) << "second callback, iteration:  " << x;
		EXPECT_EQ(0, AddNodesCallbackDummy::callbackData[x + numTargets].numPeers)
			<< "second callback, iteration:  " << x;
	}
	EXPECT_FALSE(impl->IsBusy()) << "The dht should no longer be busy";
}

/**
          Test                    |                  DHT
----------------------------------|--------------------------------------------
1) invoke doAnnounce() once       |
                                  | Responds by emitting a 'get_peers' query
								  | for each doAnnounce()
								  |
2) Fabricate and "send" a         |
   response to get_peers that     |
   has compact IP-address/port    |
   info for multiple peers       |
                                  | Responds by emitting 'announce_peer' query
								  | and invoking the callback with all of the
								  | compact node info.
*/
TEST_F(dht_impl_response_test, SingleAnnounce_ReplyWithMultiplePeers) {
	std::string compact_ip = this->compact_ip;
	// put a peer into the dht for it to work with
	peer_id.addr.set_port(('8' << 8) + '8'); // 88
	peer_id.addr.set_addr4('aaaa'); // aaaa
	impl->Update(peer_id, 0, true, 10);
	Buffer peer_id_buffer;
	peer_id_buffer.len = 20;
	peer_id_buffer.b = (byte*)&peer_id.id.id[0];

	const unsigned int numTargets = 1;
	const unsigned int numPeers = 3;

	std::vector<byte> transactionIDs[numTargets];
	std::string filenamesTxt[numTargets];
	DhtID targets[numTargets];

	for(unsigned int x = 0; x < numTargets; ++x) {
		targets[x].id[0] = 'FFFF'; // FFFF
		targets[x].id[1] = 'GGGG'; // GGGG
		targets[x].id[2] = 'HHHH'; // HHHH
		targets[x].id[3] = 'IIII'; // IIII
		targets[x].id[4] = ((((((x + 0x30) << 8) + x + 0x30) << 8) + x + 0x30) << 8) + x
				+ 0x30; //
	}

	for(unsigned int x = 0; x < numTargets; ++x) {
		filenamesTxt[x] = "filename_";
		std::string LastChar("0");
		LastChar[0] += (char)x;
		filenamesTxt[x] += LastChar;
	}

	// make sure the callback dummy is clear
	AddNodesCallbackDummy::Reset();

	// *****************************************************
	// make the dht emit an announce message (the get_peers rpc)
	// and capture the transaction ID
	// *****************************************************

	for(unsigned int x = 0; x < numTargets; ++x) {
		socket4.Reset();
		ASSERT_NO_FATAL_FAILURE(fetch_announce(targets[x], filenamesTxt[x],
					transactionIDs[x]));
	}

	// *****************************************************
	// now fabricate a nodes response message using the
	// transaction ID extracted above and include a token
	// that the dht should return to us.  Provide the compact IP
	// of a peer for the dht to use in the 'announce_peer'
	// message it should emit next
	// *****************************************************

	// make the response tokens
	std::string response_tokens[numTargets];
	for(unsigned int x = 0; x < numTargets; ++x) {
		response_tokens[x] = "20_byte_reply_token";
		std::string LastChar("0");
		LastChar[0] += (char)x;
		response_tokens[x] += LastChar;
	}

	// make a list of compact IPs (in this case only one ip)
	std::vector<std::string> values;

	for(unsigned int x = 0; x < numPeers; ++x) {
		values.push_back(compact_ip);
		compact_ip[0] += 1;
	}

	Buffer tid;
	for(unsigned int x = 0; x < numTargets; ++x) {
		ASSERT_NO_FATAL_FAILURE(fetch_peers_reply(peer_id, response_tokens[x],
					values, transactionIDs[x], transactionIDs[x]));
		EXPECT_TRUE(impl->IsBusy()) << "The dht should still be busy";
		ASSERT_NO_FATAL_FAILURE(fetch_dict());
		ASSERT_NO_FATAL_FAILURE(expect_query_type());
		ASSERT_NO_FATAL_FAILURE(expect_command("announce_peer"));
		tid.b = (byte*)dict->GetString("t" , &tid.len);
		EXPECT_EQ(4, tid.len) << "transaction ID is wrong size";
		expect_reply_id();
		expect_info_hash(reinterpret_cast<const unsigned char*>
				(&(targets[x].id[0])));
		ASSERT_NO_FATAL_FAILURE(expect_name(filenamesTxt[x]));
		ASSERT_NO_FATAL_FAILURE(expect_port(0x7878));
		expect_token(response_tokens[x].c_str());
	}

	for(unsigned int x = 0; x < numTargets; ++x) {
		len = bencoder(message, 1024)
			.d()
				("r").d()
					("id")(peer_id_buffer.b, peer_id_buffer.len).e()
				("t")(tid.b, tid.len)
				("y")("r")
			.e() ();
		socket4.Reset();
		impl->ProcessIncoming(message, len, peer_id.addr);
		EXPECT_EQ(0, socket4.GetSentByteVector().size()) << "Nothing should be"
			" sent out the socket in response to the reply to the dht's"
			" 'announce_peer' query";
	}
	ASSERT_EQ(2 * numTargets, AddNodesCallbackDummy::callbackData.size()) <<
		"Expected " << 2 * numTargets << " callback events";

	for(unsigned int x = 0; x < numTargets; ++x) {
		// verify the first callback events
		EXPECT_FALSE(memcmp(&(targets[x].id[0]),
				AddNodesCallbackDummy::callbackData[x].infoHash,
				20)) << "first callback, iteration:  " << x;
		EXPECT_EQ(numPeers, AddNodesCallbackDummy::callbackData[x].numPeers) <<
				"first callback, iteration:  " << x;
		for(unsigned int y = 0; y < numPeers; ++y) {
			EXPECT_FALSE(memcmp(values[y].c_str(),
					&AddNodesCallbackDummy::callbackData[x].
					compactPeerAddressBytes[y * 6], 6))
				<<"first callback, iteration:  " << x;
		}

		// verify the second callback event
		EXPECT_FALSE(memcmp(&(targets[x].id[0]),
				AddNodesCallbackDummy::callbackData[x + numTargets].infoHash,
				20)) << "second callback, iteration:  " << x;
		EXPECT_EQ(0, AddNodesCallbackDummy::callbackData[x + numTargets].numPeers)
			<< "second callback, iteration:  " << x;
	}
	EXPECT_FALSE(impl->IsBusy()) << "The dht should no longer be busy";
}

/**
          Test                    |                  DHT
----------------------------------|--------------------------------------------
1) invoke doAnnounce() several    |
   times                          |
                                  | Responds by emitting a 'get_peers' query
								  | for each doAnnounce()
								  |
2) Fabricate and "send" a         |
   response to get_peers that     |
   has compact IP-address/port    |
   info for a peer                |
                                  | Responds by emitting 'announce_peer' query
								  | and invoking the callback twice for each
								  | target
*/

TEST_F(dht_impl_response_test, AnnounceWithMultiplePeers_ReplyWithSinglePeer) {
	// put the FIRST peer into the dht for it to work with
	peer_id.addr.set_port(('8' << 8) + '8'); // 88
	peer_id.addr.set_addr4('aaaa'); // aaaa
	impl->Update(peer_id, 0, true, 10);
	Buffer peer_id_buffer;
	peer_id_buffer.len = 20;
	peer_id_buffer.b = (byte*)&peer_id.id.id[0];

	// put a SECOND peer into the dht for it to work with
	DhtPeerID peer_id_2;
	peer_id_2.id.id[0] = '1111'; // 1111
	peer_id_2.id.id[1] = 'BBBB'; // BBBB
	peer_id_2.id.id[2] = 'CCCC'; // CCCC
	peer_id_2.id.id[3] = 'DDDD'; // DDDD
	peer_id_2.id.id[4] = '7777'; // 7777
	peer_id_2.addr.set_port(('8' << 8) + '8'); // 88
	peer_id_2.addr.set_addr4('aaab'); // aaaa
	impl->Update(peer_id_2, 0, true, 10);
	Buffer peer_id_buffer2;
	peer_id_buffer2.len = 20;
	peer_id_buffer2.b = (byte*)&peer_id_2.id.id[0];

	const unsigned int numTargets = 1;
	std::vector<std::vector<byte> > transactionIDs; // produced by the dht
	std::string filenamesTxt[numTargets];
	DhtID targets[numTargets];

	for(unsigned int x = 0; x < numTargets; ++x) {
		targets[x].id[0] = 'FFFF'; // FFFF
		targets[x].id[1] = 'GGGG'; // GGGG
		targets[x].id[2] = 'HHHH'; // HHHH
		targets[x].id[3] = 'IIII'; // IIII
		targets[x].id[4] = ((((((x + 0x30) << 8) + x + 0x30) << 8) + x + 0x30)
				<< 8) + x + 0x30; //
	}

	for(unsigned int x = 0; x < numTargets; ++x) {
		filenamesTxt[x] = "filename_";
		std::string LastChar("0");
		LastChar[0] += (char)x;
		filenamesTxt[x] += LastChar;
	}

	// make sure the callback dummy is clear
	AddNodesCallbackDummy::Reset();

	// *****************************************************
	// make the dht emit an announce message (the get_peers rpc)
	// and capture the transaction ID
	// *****************************************************

	for(unsigned int x = 0; x < numTargets; ++x) {
		socket4.Reset();
		ASSERT_NO_FATAL_FAILURE(fetch_announce(targets[x], filenamesTxt[x],
					transactionIDs));
	}
	ASSERT_GT(transactionIDs.size(), 1);

	// *****************************************************
	// now fabricate response messages using the
	// transaction IDs extracted above and include a token
	// that the dht should return to us.  Provide the compact IP
	// of a peer for the dht to use in the 'announce_peer'
	// message it should emit next
	// *****************************************************

	// make the response tokens
	std::string* response_tokens = new std::string[transactionIDs.size()];
	for(unsigned int x = 0; x < transactionIDs.size(); ++x) {
		response_tokens[x] = "20_byte_reply_token";
		std::string LastChar("0");
		LastChar[0] += (char)x;
		response_tokens[x] += LastChar;
	}

	// make a list of compact IPs (in this case only one ip)
	std::vector<std::string> values;
	values.push_back(compact_ip);

	// The current dht implementation only issues the announce_peer rpc's once
	// all of the get_peers have responded (or maybe timed out).  Future implementatios
	// may issue announces incrementally, so the sent string is capture after
	// each response to a get_peer

	std::vector<byte> tidout;
	std::string announceString;
	ASSERT_NO_FATAL_FAILURE(fetch_peers_reply(peer_id, response_tokens[0],
				values, transactionIDs[0], tidout, false));
	announceString += socket4.GetSentDataAsString();

	ASSERT_NO_FATAL_FAILURE(fetch_peers_reply(peer_id_2, response_tokens[1],
				values, transactionIDs[1], tidout));
	announceString += socket4.GetSentDataAsString();

	// look to see if the response tokens are in the sent data string
	// ONCE AND ONLY ONCE.  If this is so, then assume the remainder of the output is good
	for(unsigned int x = 0; x < transactionIDs.size(); ++x) {
		std::string::size_type index = announceString.find(response_tokens[x]);
		ASSERT_NE(index, std::string::npos) << "response token '"
			<< response_tokens[x]
			<< "' was NOT found in the announce_peer output string";
		if(index == std::string::npos) {
			continue;
		}
		index = announceString.find(response_tokens[x], index + 1);
		ASSERT_EQ(index, std::string::npos) << "response token '"
			<< response_tokens[x]
			<< "' was found MORE THAN ONCE in the announce_peer output string";
	}
	delete[] response_tokens;
}

TEST_F(dht_impl_response_test, DoFindNodesWithMultipleNodesInDHT) {
	// put the FIRST peer into the dht for it to work with
	peer_id.addr.set_port(('8' << 8) + '8'); // 88
	peer_id.addr.set_addr4('aaaa'); // aaaa
	impl->Update(peer_id, 0, true, 10);
	Buffer peer_id_buffer;
	peer_id_buffer.len = 20;
	peer_id_buffer.b = (byte*)&peer_id.id.id[0];

	// put a SECOND peer into the dht for it to work with
	DhtPeerID peer_id_2;
	peer_id_2.id.id[0] = '1111'; // 1111
	peer_id_2.id.id[1] = 'BBBB'; // BBBB
	peer_id_2.id.id[2] = 'CCCC'; // CCCC
	peer_id_2.id.id[3] = 'DDDD'; // DDDD
	peer_id_2.id.id[4] = '7777'; // 7777
	peer_id_2.addr.set_port(('8' << 8) + '8'); // 88
	peer_id_2.addr.set_addr4('aaab'); // aaab
	impl->Update(peer_id_2, 0, true, 10);
	Buffer peer_id_buffer2;
	peer_id_buffer2.len = 20;
	peer_id_buffer2.b = (byte*)&peer_id_2.id.id[0];

	// *****************************************************
	// tell the dht to issue a find_nodes request and
	// capture the query string that goes out the socket
	// *****************************************************
	EXPECT_FALSE(impl->IsBusy()) << "The dht should not be busy yet";
	FindNodeCallbackDummy CallbackObj;
	impl->DoFindNodes(target, &CallbackObj);
	std::string doFindNodesOutput = socket4.GetSentDataAsString();
	EXPECT_TRUE(impl->IsBusy()) << "The dht should be busy";

	// extract the transaction id's to use in the replys back to the dht
	std::vector<std::vector<byte> > transactionIDs;
	ASSERT_TRUE(extract_transaction_ids(doFindNodesOutput,
			transactionIDs)) << "There was a problem extracting transaction ID's";
	ASSERT_GT(transactionIDs.size(), 1) <<
			"No transaction IDs were emitted, test can not continue.";

	// send the same node info back from both queried nodes
	std::string compact_node("WWWWWXXXXXYYYYYZZZZZcaac88");
	len = bencoder(message, 1024)
		.d()
			("r").d()
				("id")(peer_id_buffer.b, peer_id_buffer.len)
				("nodes")(compact_node)
				("token")(response_token).e()
			("t")(transactionIDs[0])
			("y")("r")
		.e() ();
	socket4.Reset();
	impl->ProcessIncoming(message, len, peer_id.addr);
	std::string secondtime;
	secondtime += socket4.GetSentDataAsString();
	
	// construct the message bytes (for the SECOND node)
	std::string response_token2("20_byte_reply_token2");
	len = bencoder(message, 1024)
		.d()
			("r").d()
				("id")(peer_id_buffer2.b, peer_id_buffer2.len)
				("nodes")(compact_node)
				("token")(response_token2).e()
			("t")(transactionIDs[1])
			("y")("r")
		.e() ();
	socket4.Reset();
	impl->ProcessIncoming(message, len, peer_id_2.addr);
	secondtime += socket4.GetSentDataAsString();

	EXPECT_TRUE(impl->IsBusy()) << "The dht should be busy";

	ASSERT_TRUE(extract_transaction_ids(secondtime,
			transactionIDs)) << "There was a problem extracting transaction ID's";
	ASSERT_EQ(1, transactionIDs.size()) <<
			"There should only be one transaction ID";

	// *****************************************************
	// now fabricate a nodes response message using the
	// transaction ID extracted above.  ALSO, use the IP
	// address and port that were returned to the dht
	// in the response to it's initial query (aaaa88)
	// *****************************************************
	compact_node = std::string((char*)peer_id_buffer.b, peer_id_buffer.len) + "aaaa88";
	len = bencoder(message, 1024)
		.d()
			("r").d()
			("id")("WWWWWXXXXXYYYYYZZZZZ")
				("nodes")(compact_node)
				("token")(response_token).e()
			("t")(transactionIDs[0])
			("y")("r")
		.e() ();
	socket4.Reset();
	DhtPeerID secondPeerID;
	secondPeerID.addr.set_addr4('caac'); // "caac"
	secondPeerID.addr.set_port(('8' << 8) + '8'); //88
	impl->ProcessIncoming(message, len, secondPeerID.addr);

	// *****************************************************
	// The DhtProcess object that is internally called back to uses private members
	// and member functions with no access points.  So, only circumstantial evidence
	// can be used to see if things are working as they should.
	// *****************************************************

	// see that our call back was invoked (this may be invoked even if there is an internal error)
	EXPECT_EQ(1, CallbackObj.callbackCount) <<
			"Our callback object should have been invoked 1 time";
	EXPECT_FALSE(impl->IsBusy()) << "The dht should no longer be busy";
}

/**
This test is designed to exercise the scheduling aspect of the dht lookup process.
When first doing the dht lookup using "get_peers" the dht process should issue
an initial burst of 4 queries.  When peer values are received, additional get-peers
queries are issued in such a way as to always keep the 4 closest nodes in the
developing nodes list occupied with queries.  This rule trumps the rule that no more
than 4 get_peers queries can be in flight at a time.  Otherwise, there should be no more
than 4 active queries in flight at a time (slow peers are excepted).  Once all of the
get_peers queries are complete then the dht switches to issuing "announce_peer" queries.
An initial burst of 3 queries should be issued followed by additional queries
as replys are received.  No more than 3 announce queries should be in flight at
a time.

          Test                    |                  DHT
----------------------------------|--------------------------------------------
1) invoke doAnnounce()            |
                                  | Responds by emitting a 'get_peers' query
								  |
2) Fabricate and "send" a         |
   response to get_peers that     |
   has only compact node values   |
   for 8 nodes close to the target|
                                  | Responds by emitting 'get_peers' querys
								  | (an initial group of 4)
								  |
3) Fabricate and "send" a         |
   response to one of the queries |
   that has compact node value    |
   information that is CLOSER to  |
   the target than step 2 above   |
                                  | Responds by emitting 'get_peers' querys
								  | (an additional group of 4 in addition to
								  | the three that are still outstanding for
								  | a total of 7 outstanding)
								  |
3) Send a "values" response back  |
   to the dht for each transaction|
   ID that the dht outputs        |
                                  | Issues another get_peers for each response until
								  | all nodes have been contacted.  Then it switches
								  | to issuing "announce_peer" queries (an initial
								  | group of 3)
4) responds with a acknowledgement|
   reply for each announce query  |
                                  |
*/
TEST_F(dht_impl_response_test, Announce_ReplyWithMultipleNodes) {
	impl->_dht_utversion[2] = 'x';
	impl->_dht_utversion[3] = 'x';

	// put a peer into the dht for it to work with
	impl->Update(peer_id, 0, true, 10);
	Buffer peer_id_buffer;
	peer_id_buffer.len = 20;
	peer_id_buffer.b = (byte*)&peer_id.id.id[0];

	DhtID target;
	target.id[0] = 'zzzz';
	target.id[1] = 'zzzz';
	target.id[2] = 'zzzz';
	target.id[3] = 'zzzz';
	target.id[4] = 'zzzz';

	// make sure the callback dummy is clear
	AddNodesCallbackDummy::Reset();

	// *****************************************************
	// make the dht emit an announce message (the get_peers rpc)
	// *****************************************************
	EXPECT_FALSE(impl->IsBusy()) << "The dht should not be busy yet";
	impl->DoAnnounce(target, &AddNodesCallbackDummy::Callback, NULL,
			"filename.txt", NULL, 0);
	EXPECT_TRUE(impl->IsBusy()) << "The dht should be busy";

	// *****************************************************
	// grab from the socket the emitted message and extract
	// the transaction ID and verify the remainder of the
	// message
	// *****************************************************
	ASSERT_NO_FATAL_FAILURE(fetch_dict());
	ASSERT_NO_FATAL_FAILURE(expect_query_type());
	ASSERT_NO_FATAL_FAILURE(expect_command("get_peers"));
	Buffer tid;
	tid.b = (byte*)dict->GetString("t" , &tid.len);
	EXPECT_EQ(4, tid.len) << "transaction ID is wrong size";
	expect_reply_id();
	expect_info_hash(reinterpret_cast<const unsigned char*>
			("zzzzzzzzzzzzzzzzzzzz"));

	// *****************************************************
	// now fabricate a nodes response message using the
	// transaction ID extracted above and include a token
	// *****************************************************
	const char* compactIPs[] = {"bbbb..", "cccc..", "dddd..", "eeee..", "ffff..",
		"gggg..", "hhhh..", "iiii..", "bbbc..", "cccd..", "ddde..", "eeef..",
		"fffg..", "gggh..", "hhhi..", "iiij.."};

	// make a string of 8 compact nodes (based on what was designed above)
	std::string nearest_node("zzzzzzzzzzzzzzzzzzAAbbbb..zzzzzzzzzzzzzzzzzzBBcccc"
			"..zzzzzzzzzzzzzzzzzzCCdddd..zzzzzzzzzzzzzzzzzzDDeeee..zzzzzzzzzzzzzzzzzz"
			"EEffff..zzzzzzzzzzzzzzzzzzFFgggg..zzzzzzzzzzzzzzzzzzGGhhhh.."
			"zzzzzzzzzzzzzzzzzzHHiiii..");
	std::string closer_nodes("zzzzzzzzzzzzzzzzzzzybbbc..zzzzzzzzzzzzzzzzzzzxcccd"
			"..zzzzzzzzzzzzzzzzzzzwddde..zzzzzzzzzzzzzzzzzzzveeef.."
			"zzzzzzzzzzzzzzzzzzzufffg..zzzzzzzzzzzzzzzzzzztgggh.."
			"zzzzzzzzzzzzzzzzzzzshhhi..zzzzzzzzzzzzzzzzzzzriiij..");
	// construct the message bytes for sending just the near nodes
	len = bencoder(message, 1024)
		.d()
			("r").d()
				("id")(peer_id_buffer.b, peer_id_buffer.len)
				("nodes")(nearest_node)
				("token")(response_token).e()
			("t")(tid.b, tid.len)
			("y")("r")
		.e() ();
	socket4.Reset();
	impl->ProcessIncoming(message, len, peer_id.addr);
	EXPECT_TRUE(impl->IsBusy()) << "The dht should still be busy";

	// *****************************************************
	// get the bencoded string(s) out of the socket and extract
	// the transaction id's.  The dht should issue an initial burst of queries
	// that are throttled back to one new query for each response received
	// until all nodes have been queried.
	// *****************************************************

	// we are only interested in the transaction ID's
	std::string bencMessage = socket4.GetSentDataAsString();
	std::vector<std::vector<byte> > transactionIDs;
	ASSERT_TRUE(extract_transaction_ids(bencMessage, transactionIDs));
	// at this time there should be "#define KADEMLIA_LOOKUP_OUTSTANDING 4" transaction id's for 4 outstanding messages
	EXPECT_EQ(KADEMLIA_LOOKUP_OUTSTANDING, transactionIDs.size())
		<< "Expected KADEMLIA_LOOKUP_OUTSTANDING (4) transaction IDs but found "
		<< transactionIDs.size() << " instead.";

	byte bufferBytes[20];
	Buffer nodeID;
	nodeID.b = (byte*)bufferBytes;
	nodeID.len = 20;

	// send a reply back to the dht with closer nodes; see that 4 more are issued
	// construct the message bytes for sending just the near nodes
	DhtRequest *req2 = impl->LookupRequest(Read32(&transactionIDs[0][0]));
	DhtIDToBytes(nodeID.b, req2->peer.id);
	len = bencoder(message, 1024)
		.d()
			("r").d()
				("id")(nodeID.b, nodeID.len)
				("nodes")(closer_nodes)
				("token")(response_token).e()
			("t")(transactionIDs[0])
			("y")("r")
		.e() ();
	socket4.Reset();
	impl->ProcessIncoming(message, len, req2->peer.addr);
	std::string bencMessage2 = socket4.GetSentDataAsString();
	std::vector<std::vector<byte> > transactionIDs2;
	ASSERT_TRUE(extract_transaction_ids(bencMessage2, transactionIDs2));
	// at this time there should be "#define KADEMLIA_LOOKUP_OUTSTANDING 4" transaction id's for 4 outstanding messages
	EXPECT_EQ(KADEMLIA_LOOKUP_OUTSTANDING, transactionIDs2.size());

	for(int x = 0; x < transactionIDs2.size(); ++x) {
		transactionIDs.push_back(transactionIDs2[x]);
	}

	// feed responses back to the dht.
	for(int x = 0; x < transactionIDs.size(); ++x) {
		socket4.Reset();
		DhtRequest *req = impl->LookupRequest(Read32(&transactionIDs[x][0]));
		if(req) {
			DhtIDToBytes(nodeID.b, req->peer.id);

			// construct a response with a "value"
			len = bencoder(message, 1024)
				.d()
					("r").d()
						("id")(nodeID.b, nodeID.len)
						("token")(response_token)
						("values").l()
							(compactIPs[x]).e().e()
					("t")(transactionIDs[x])
					("y")("r")
				.e() ();
			impl->ProcessIncoming(message, len, req->peer.addr);
		}
		std::string nextString = socket4.GetSentDataAsString();
		if((nextString.size() != 0) && (x < transactionIDs.size() - 1)) {
			std::vector<std::vector<byte> > thisTransactionID;
			ASSERT_TRUE(extract_transaction_ids(nextString, thisTransactionID));
			transactionIDs.push_back(thisTransactionID[0]);
		}
	}
	// there should now be 12 transaction id's (the first 4 from the initial
	// request and then 8 more for the "closer" nodes
	EXPECT_EQ(12, transactionIDs.size());

	// after the final reply to the get_peers request is made, since we are
	// responding with "values" the dht will emit the first set of
	// "announce_peer" queries.
	// These should be sitting in the socket
	std::string announceString = socket4.GetSentDataAsString();

	ASSERT_TRUE(extract_transaction_ids(announceString, transactionIDs));
	// at this time there should be "#define KADEMLIA_BROADCAST_OUTSTANDING 3" transaction id's for 4 outstanding messages
	EXPECT_EQ(KADEMLIA_BROADCAST_OUTSTANDING, transactionIDs.size());
	// Again, feed responses back to the dht. (this time, replys to the "announce_peers" queries
	for(int x = 0; x < transactionIDs.size(); ++x) {
		socket4.Reset();
		// get the request info out of the dht (since we can)
		DhtRequest *req = impl->LookupRequest(Read32(&transactionIDs[x][0]));

		if(req) {
			DhtIDToBytes(nodeID.b, req->peer.id);
			// construct a response with a "value"
			len = bencoder(message, 1024)
				.d()
					("r").d()
						("id")(nodeID.b, nodeID.len).e()
					("t")(transactionIDs[x])
					("y")("r")
				.e() ();
			impl->ProcessIncoming(message, len, req->peer.addr);
		}
		std::string nextString = socket4.GetSentDataAsString();
		if((nextString.size() != 0) && (x < transactionIDs.size() - 1)) {
			std::vector<std::vector<byte> > thisTransactionID;
			ASSERT_TRUE(extract_transaction_ids(nextString, thisTransactionID))
				<< "There was a problem extracting transaction ID's";
			transactionIDs.push_back(thisTransactionID[0]);
		}
	}
	// see that the correct number of announces were emitted
	EXPECT_EQ(KADEMLIA_K_ANNOUNCE, transactionIDs.size());
	EXPECT_EQ(12, AddNodesCallbackDummy::callbackData.size()) <<
			"12 callback events were expected but there were:  " <<
			AddNodesCallbackDummy::callbackData.size();
}

/**
          Test                    |                  DHT
----------------------------------|--------------------------------------------
1) invoke doAnnounce()            |
                                  | Responds by emitting a 'get_peers' query
								  |
2) Adjust the timestamp of the    |
   query to make it look "slow"   |
								  | The dht should internally keep mark the node
								  | as slow.  Nothing is output.
								  |
2) Fabricate and "send" a         |
   response to get_peers that     |
   has compact IP-address/port    |
   info for a peer                |
                                  | Responds by emitting 'announce_peer' query
								  |
*/
TEST_F(dht_impl_response_test, Announce_Slow_ReplyWithPeers) {
	// put a peer into the dht for it to work with
	peer_id.addr.set_port(('8' << 8) + '8'); // 88
	peer_id.addr.set_addr4('aaaa'); // aaaa
	impl->Update(peer_id, 0, true, 10);
	Buffer peer_id_buffer;
	peer_id_buffer.len = 20;
	peer_id_buffer.b = (byte*)&peer_id.id.id[0];

	// make sure the callback dummy is clear
	AddNodesCallbackDummy::Reset();

	EXPECT_EQ(1, impl->GetNumPeers());
	EXPECT_EQ(0, impl->GetNumPeersTracked());

	DhtPeerID *ids[16];
	uint num = impl->FindNodes(target, ids, 8, 8,
			0); // Find 8 good ones and 8 bad ones
	EXPECT_EQ(1, num) << "Num Nodes: " << num;
	EXPECT_FALSE(impl->IsBusy()) << "The dht should not be busy yet";

	// *****************************************************
	// make the dht emit an announce message (the get_peers rpc)
	// *****************************************************
	std::string filenameTxt("filaname.txt");
	impl->DoAnnounce(target, &AddNodesCallbackDummy::Callback, NULL,
			filenameTxt.c_str(), NULL, 0);
	EXPECT_TRUE(impl->IsBusy()) << "The dht should be busy";

	// *****************************************************
	// grab from the socket the emitted message and extract
	// the transaction ID and verify the remainder of the
	// message
	// *****************************************************
	ASSERT_NO_FATAL_FAILURE(fetch_dict());
	ASSERT_NO_FATAL_FAILURE(expect_query_type());
	ASSERT_NO_FATAL_FAILURE(expect_command("get_peers"));
	Buffer tid;
	tid.b = (byte*)dict->GetString("t" , &tid.len);
	EXPECT_EQ(4, tid.len) << "transaction ID is wrong size";
	expect_reply_id();
	ASSERT_NO_FATAL_FAILURE(expect_info_hash());
	EXPECT_EQ(0, reply->GetInt("noseed"));

	// *********************************************************************************
	// get the request info and make it look like enough time has passed to call it slow
	// *********************************************************************************
	DhtRequest* req = impl->LookupRequest(Read32(tid.b));
	req->time -= 1100;
	impl->Tick();

	// *****************************************************
	// now fabricate a nodes response message using the
	// transaction ID extracted above and include a token
	// that the dht should return to us.  Provide the compact IP
	// of a peer for the dht to use in the 'announce_peer'
	// message it should emit next
	// *****************************************************

	// construct the message bytes
	len = bencoder(message, 1024)
		.d()
			("r").d()
				("id")(peer_id_buffer.b, peer_id_buffer.len)
				("token")(response_token)
				("values").l()
					(compact_ip).e().e()
			("t")(tid.b, tid.len)
			("y")("r")
		.e() ();
	socket4.Reset();
	impl->ProcessIncoming(message, len, peer_id.addr);
	ASSERT_NO_FATAL_FAILURE(fetch_dict());
	ASSERT_NO_FATAL_FAILURE(expect_query_type());
	ASSERT_NO_FATAL_FAILURE(expect_command("announce_peer"));
	tid.b = (byte*)dict->GetString("t" , &tid.len);
	EXPECT_EQ(4, tid.len) << "transaction ID is wrong size";
	expect_reply_id();
	ASSERT_NO_FATAL_FAILURE(expect_info_hash());
	ASSERT_NO_FATAL_FAILURE(expect_name(filenameTxt));
	ASSERT_NO_FATAL_FAILURE(expect_port(0x7878));
	expect_token(response_token);
	EXPECT_EQ(0, reply->GetInt("seed"));

	// *****************************************************
	// create and send a response to the 'announce_peer
	// message
	// *****************************************************
	len = bencoder(message, 1024)
		.d()
			("r").d()
				("id")(peer_id_buffer.b, peer_id_buffer.len).e()
			("t")(tid.b, tid.len)
			("y")("r")
		.e() ();
	socket4.Reset();
	impl->ProcessIncoming(message, len, peer_id.addr);
	EXPECT_EQ(0, socket4.GetSentByteVector().size());

	// *****************************************************
	// look in the addnodes call back dummy to see what was
	// passed through
	// *****************************************************
	ASSERT_EQ(2, AddNodesCallbackDummy::callbackData.size());
	EXPECT_FALSE(memcmp("FFFFGGGGHHHHIIIIJJJJ",
			AddNodesCallbackDummy::callbackData[0].infoHash, 20));
	EXPECT_EQ(1, AddNodesCallbackDummy::callbackData[0].numPeers);
	EXPECT_FALSE(memcmp(compact_ip,
			&AddNodesCallbackDummy::callbackData[0].compactPeerAddressBytes[0],
			strlen(compact_ip)));

	// verify the second callback event
	EXPECT_FALSE(memcmp("FFFFGGGGHHHHIIIIJJJJ",
			AddNodesCallbackDummy::callbackData[1].infoHash, 20));
	EXPECT_EQ(0, AddNodesCallbackDummy::callbackData[1].numPeers);
	EXPECT_EQ(1, impl->GetNumPeers());
	EXPECT_EQ(0, impl->GetNumPeersTracked());
	// Find 8 good ones and 8 bad ones
	num = impl->FindNodes(target, ids, 8, 8, 0);
	EXPECT_EQ(1, num) << "Num Nodes: " << num;
	DhtRequest* req2 = impl->LookupRequest(Read32(tid.b));
	EXPECT_FALSE(req2) <<
			"The outstanding transaction id was not removed by the response";
}


/**
This test is designed to exercise the scheduling aspect of the dht process with
a "slow" node.

When first doing the dht lookup using "get_peers" the dht process should issue
an initial burst of 4 queries and follow it up with additional queries and replys
are received until the nodes list is exausted.  There should be no more than 4
active queries in flight at a time (slow peers are excepted).  Once all of the
get_peers queries are complete then it switched to issuing "announce_peer" queries.
An initial burst of 3 queries should be issued followed by additional queries
as replys are received.  No more than 3 announce queries should be in flight at
a time.

          Test                    |                  DHT
----------------------------------|--------------------------------------------
1) invoke doAnnounce()            |
                                  | Responds by emitting a 'get_peers' query
								  |
2) Fabricate and "send" a         |
   response to get_peers that     |
   has only compact node info     |
   for 8 nodes                    |
                                  | Responds by emitting another 'get_peers' querys
								  | (an initial group of 4)
								  |
3) pick a node and adjust its time|
   to make it look slow; then     |
   call Tick()                    |
                                  | dht internally notes the slow node and emits
								  | an additional query.
								  |
4) Send a "values" response back  |
   to the dht for each transaction|
   ID that the dht outputs        |
                                  | Issues another get_peers for each response until
								  | all nodes have been contacted.  Then it switches
								  | to issuing "announce_peer" queries (an initial
								  | group of 3)
5) responds with a acknowledgement|
   reply for each announce query  |
                                  |
*/
TEST_F(dht_impl_response_test, Announce_Slow_ReplyWithMultipleNodes) {
	impl->_dht_utversion[2] = 'x';
	impl->_dht_utversion[3] = 'x';


	// put a peer into the dht for it to work with
	impl->Update(peer_id, 0, true, 10);
	Buffer peer_id_buffer;
	peer_id_buffer.len = 20;
	peer_id_buffer.b = (byte*)&peer_id.id.id[0];

	// do this to have the bootstrap ping messages be emitted now.
	// (instead of having them get mixed in with the test data later)
	impl->Tick();
	socket4.Reset();

	// make sure the callback dummy is clear
	AddNodesCallbackDummy::Reset();

	// *****************************************************
	// make the dht emit an announce message (the get_peers rpc)
	// *****************************************************
	impl->DoAnnounce(target, &AddNodesCallbackDummy::Callback, NULL,
			"filename.txt", NULL, IDht::announce_non_aggressive);
	EXPECT_TRUE(impl->IsBusy()) << "The dht should be busy";

	// *****************************************************
	// grab from the socket the emitted message and extract
	// the transaction ID and verify the remainder of the
	// message
	// *****************************************************
	ASSERT_NO_FATAL_FAILURE(fetch_dict());
	ASSERT_NO_FATAL_FAILURE(expect_query_type());
	ASSERT_NO_FATAL_FAILURE(expect_command("get_peers"));
	Buffer tid;
	tid.b = (byte*)dict->GetString("t" , &tid.len);
	EXPECT_EQ(4, tid.len) << "transaction ID is wrong size";
	expect_reply_id();
	ASSERT_NO_FATAL_FAILURE(expect_info_hash());
	// *****************************************************
	// now fabricate a nodes response message using the
	// transaction ID extracted above and include a token
	// *****************************************************

	const char* compactIPs[] = {"bbbb..", "cccc..", "dddd..", "eeee..", "ffff..",
		"gggg..", "hhhh..", "iiii.."};

	// make a string of 8 compact nodes (based on what was designed above)
	std::string nearest_node("26_byte_nearest_n008bbbb..26_byte_nearest_n007cccc"
			"..26_byte_nearest_n006dddd..26_byte_nearest_n005eeee.."
			"26_byte_nearest_n004ffff..26_byte_nearest_n003gggg.."
			"26_byte_nearest_n002hhhh..26_byte_nearest_n001iiii..");
	len = bencoder(message, 1024)
		.d()
			("r").d()
				("id")(peer_id_buffer.b, peer_id_buffer.len)
				("nodes")(nearest_node)
				("token")(response_token).e()
			("t")(tid.b, tid.len)
			("y")("r")
		.e() ();
	socket4.Reset();
	impl->ProcessIncoming(message, len, peer_id.addr);
	EXPECT_TRUE(impl->IsBusy()) << "The dht should still be busy";

	// *****************************************************
	// get the bencoded string(s) out of the socket and extract
	// the transaction id's.  The dht should issue an initial burst of queries
	// that are throttled back to one new query for each response received
	// until all nodes have been queried.
	// *****************************************************

	// we are only interested in the transaction ID's
	std::string bencMessage = socket4.GetSentDataAsString();
	std::vector<std::vector<byte> > transactionIDs;
	ASSERT_TRUE(extract_transaction_ids(bencMessage, transactionIDs));
	// at this time there should be "#define KADEMLIA_LOOKUP_OUTSTANDING 4"
	// transaction id's for 4 outstanding messages
	EXPECT_EQ(KADEMLIA_LOOKUP_OUTSTANDING + KADEMLIA_LOOKUP_OUTSTANDING_DELTA,
			transactionIDs.size())
		<< "Expected (KADEMLIA_LOOKUP_OUTSTANDING +"
		" KADEMLIA_LOOKUP_OUTSTANDING_DELTA) transaction IDs but found "
		<< transactionIDs.size() << " instead.";

	// *********************************************************************************
	// Get the request info and make it look like enough time has passed to call it slow.
	// An additional request should be issued.
	// *********************************************************************************
	socket4.Reset();
	DhtRequest* req0 = impl->LookupRequest(Read32(&transactionIDs[0][0]));
	req0->time -= 1100;
	impl->Tick();

	// get the transaction id out of the additional message
	std::string additionalMessage = socket4.GetSentDataAsString();
	ASSERT_TRUE(additionalMessage.size() != 0) <<
			"no additional message was issued for a slow node";
	std::vector<std::vector<byte> > additionalTid;
	ASSERT_TRUE(extract_transaction_ids(additionalMessage,
			additionalTid)) <<
					"There was a problem extracting the transaction id from the additional message";
	ASSERT_EQ(1, additionalTid.size()) <<
			"expected only one additional message for the slow node";
	transactionIDs.push_back(additionalTid[0]);

	byte bufferBytes[20];
	Buffer nodeID;
	nodeID.b = (byte*)bufferBytes;
	nodeID.len = 20;

	// feed responses back to the dht.
	for(int x = 0; x < transactionIDs.size(); ++x) {
		socket4.Reset();
		DhtRequest *req = impl->LookupRequest(Read32(&transactionIDs[x][0]));
		if(req) {
			DhtIDToBytes(nodeID.b, req->peer.id);
			len = bencoder(message, 1024)
				.d()
					("r").d()
						("id")(nodeID.b, nodeID.len)
						("token")(response_token)
						("values").l()
							(compactIPs[x]).e().e()
					("t")(transactionIDs[x])
					("y")("r")
				.e() ();
			impl->ProcessIncoming(message, len, req->peer.addr);
		}
		std::string nextString = socket4.GetSentDataAsString();
		if((nextString.size() != 0) && (x < transactionIDs.size() - 1)) {
			std::vector<std::vector<byte> > thisTransactionID;
			ASSERT_EQ(true, extract_transaction_ids(nextString, thisTransactionID))
				<< "There was a problem extracting transaction ID's";
			transactionIDs.push_back(thisTransactionID[0]);
		}
	}
	// there should now be 8 (KADEMLIA_K) transaction id's
	EXPECT_EQ(KADEMLIA_K, transactionIDs.size());

	// after the final reply to the get_peers request is made, since we are responding
	// with "values" the dht will emit the first set of "announce_peer" queries.
	// These should be sitting in the socket
	std::string announceString = socket4.GetSentDataAsString();
	ASSERT_TRUE(extract_transaction_ids(announceString, transactionIDs));
	// at this time there should be "#define KADEMLIA_BROADCAST_OUTSTANDING 3" transaction id's for 4 outstanding messages
	EXPECT_EQ(KADEMLIA_BROADCAST_OUTSTANDING, transactionIDs.size());

	// Again, feed responses back to the dht. (this time, replys to the "announce_peers" queries
	for(int x = 0; x < transactionIDs.size(); ++x) {
		socket4.Reset();
		DhtRequest *req = impl->LookupRequest(Read32(&transactionIDs[x][0]));
		if(req) {
			DhtIDToBytes(nodeID.b, req->peer.id);
			len = bencoder(message, 1024)
				.d()
					("r").d()
						("id")(nodeID.b, nodeID.len).e()
					("t")(transactionIDs[x])
					("y")("r")
				.e() ();
			impl->ProcessIncoming(message, len, req->peer.addr);
		}
		std::string nextString = socket4.GetSentDataAsString();
		if((nextString.size() != 0) && (x < transactionIDs.size() - 1)) {
			std::vector<std::vector<byte> > thisTransactionID;
			ASSERT_TRUE(extract_transaction_ids(nextString, thisTransactionID));
			transactionIDs.push_back(thisTransactionID[0]);
		}
	}
	// see that the correct number of announces were emitted
	EXPECT_EQ(KADEMLIA_K_ANNOUNCE, transactionIDs.size());
	EXPECT_EQ(9, AddNodesCallbackDummy::callbackData.size());
}


/**
This test is designed to exercise the scheduling aspect of the dht process with
a "slow" node that then delays to the point of a time-out error.

When first doing the dht lookup using "get_peers" the dht process shoulc issue
an initial burst of 4 queries and follow it up with additional queries and replys
are received until the nodes list is exausted.  There should be no more than 4
active queries in flight at a time (slow peers are excepted).  Once all of the
get_peers queries are complete then it switched to issuing "announce_peer" queries.
An initial burst of 3 queries should be issued followed by additional queries
as replys are received.  No more than 3 announce queries should be in flight at
a time.

          Test                    |                  DHT
----------------------------------|--------------------------------------------
1) invoke doAnnounce()            |
                                  | Responds by emitting a 'get_peers' query
								  |
2) Fabricate and "send" a         |
   response to get_peers that     |
   has only compact node info     |
   for 8 nodes                    |
                                  | Responds by emitting another 'get_peers' querys
								  | (an initial group of 4)
								  |
3) pick a node and adjust its time|
   to make it look slow; then     |
   call Tick()                    |
                                  | dht intarnally notes the slow node and emits
								  | an additional query.
								  |
4) adjust the time of the same    |
   node to have it time-out       |
                                  | dht marks the node as errored.  it should not
								  | issue another request since it should have 4
								  | outstanding good (non-slow) requests in flight
								  |
3) Send a "values" response back  |
   to the dht for each transaction|
   ID that the dht outputs        |
                                  | Issues another get_peers for each response until
								  | all nodes have been contacted.  Then it switches
								  | to issuing "announce_peer" queries (an initial
								  | group of 3)
4) responds with a acknowledgement|
   reply for each announce query  |
                                  |
*/
TEST_F(dht_impl_response_test, Announce_TimeOut_ReplyWithMultipleNodes) {
	impl->_dht_utversion[2] = 'x';
	impl->_dht_utversion[3] = 'x';

	// put a peer into the dht for it to work with
	impl->Update(peer_id, 0, true, 10);
	Buffer peer_id_buffer;
	peer_id_buffer.len = 20;
	peer_id_buffer.b = (byte*)&peer_id.id.id[0];

	// do this to have the bootstrap ping messages be emitted now.
	// (instead of having them get mixed in with the test data later)
	impl->Tick();
	socket4.Reset();

	// make sure the callback dummy is clear
	AddNodesCallbackDummy::Reset();

	// *****************************************************
	// make the dht emit an announce message (the get_peers rpc)
	// *****************************************************
	impl->DoAnnounce(target, &AddNodesCallbackDummy::Callback, NULL,
			"filename.txt", NULL, 0);
	EXPECT_TRUE(impl->IsBusy()) << "The dht should be busy";

	// *****************************************************
	// grab from the socket the emitted message and extract
	// the transaction ID and verify the remainder of the
	// message
	// *****************************************************
	ASSERT_NO_FATAL_FAILURE(fetch_dict());
	ASSERT_NO_FATAL_FAILURE(expect_query_type());
	ASSERT_NO_FATAL_FAILURE(expect_command("get_peers"));
	Buffer tid;
	tid.b = (byte*)dict->GetString("t" , &tid.len);
	EXPECT_EQ(4, tid.len) << "transaction ID is wrong size";
	expect_reply_id();
	ASSERT_NO_FATAL_FAILURE(expect_info_hash());
	// *****************************************************
	// now fabricate a nodes response message using the
	// transaction ID extracted above and include a token
	// *****************************************************

	const char* compactIPs[] = {"bbbb..", "cccc..", "dddd..", "eeee..", "ffff..",
		"gggg..", "hhhh..", "iiii.."};

	// make a string of 8 compact nodes (based on what was designed above)
	std::string nearest_node("26_byte_nearest_n008bbbb..26_byte_nearest_n007cccc"
			"..26_byte_nearest_n006dddd..26_byte_nearest_n005eeee.."
			"26_byte_nearest_n004ffff..26_byte_nearest_n003gggg.."
			"26_byte_nearest_n002hhhh..26_byte_nearest_n001iiii..");
	len = bencoder(message, 1024)
		.d()
			("r").d()
				("id")(peer_id_buffer.b, peer_id_buffer.len)
				("nodes")(nearest_node)
				("token")(response_token).e()
			("t")(tid.b, tid.len)
			("y")("r")
		.e() ();
	socket4.Reset();
	impl->ProcessIncoming(message, len, peer_id.addr);
	EXPECT_TRUE(impl->IsBusy()) << "The dht should still be busy";

	// *****************************************************
	// get the bencoded string(s) out of the socket and extract
	// the transaction id's.  The dht should issue an initial burst of queries
	// that are throttled back to one new query for each response received
	// until all nodes have been queried.
	// *****************************************************

	// we are only interested in the transaction ID's
	std::string bencMessage = socket4.GetSentDataAsString();
	std::vector<std::vector<byte> > transactionIDs;
	ASSERT_TRUE(extract_transaction_ids(bencMessage, transactionIDs));
	EXPECT_EQ(KADEMLIA_LOOKUP_OUTSTANDING, transactionIDs.size());

	// *********************************************************************************
	// Get the request info and make it look like enough time has passed to call it slow.
	// An additional request should be issued.
	// *********************************************************************************
	socket4.Reset();
	DhtRequest* req0 = impl->LookupRequest(Read32(&transactionIDs[0][0]));
	req0->time -= 1100;
	impl->Tick();

	// get the transaction id out of the additional message
	std::string additionalMessage = socket4.GetSentDataAsString();
	ASSERT_TRUE(additionalMessage.size() != 0) <<
			"no additional message was issued for a slow node";
	std::vector<std::vector<byte> > additionalTid;
	ASSERT_TRUE(extract_transaction_ids(additionalMessage, additionalTid));
	ASSERT_EQ(1, additionalTid.size());
	transactionIDs.push_back(additionalTid[0]);

	// now make it look like the request timed out (an additonal message should be sent)
	socket4.Reset();
	req0->time -= 4000;
	impl->Tick();

	// get the transaction id out of the additional message
	std::string additionalMessage2 = socket4.GetSentDataAsString();
	ASSERT_EQ(0, additionalMessage2.size()) << "An additional message was issued"
		" for a timed-out node when no message was expected";

	// now follow through with the regular feeding of node info back to the dht
	byte bufferBytes[20];
	Buffer nodeID;
	nodeID.b = (byte*)bufferBytes;
	nodeID.len = 20;
	// feed responses back to the dht.
	for(int x = 0; x < transactionIDs.size(); ++x) {
		socket4.Reset();
		DhtRequest *req = impl->LookupRequest(Read32(&transactionIDs[x][0]));
		if(req) {
			DhtIDToBytes(nodeID.b, req->peer.id);
			len = bencoder(message, 1024)
				.d()
					("r").d()
						("id")(nodeID.b, nodeID.len)
						("token")(response_token)
						("values").l()
							(compactIPs[x]).e().e()
					("t")(transactionIDs[x])
					("y")("r")
				.e() ();
			impl->ProcessIncoming(message, len, req->peer.addr);
		}
		std::string nextString = socket4.GetSentDataAsString();
		if((nextString.size() != 0) && (x < transactionIDs.size() - 1)) {
			std::vector<std::vector<byte> > thisTransactionID;
			ASSERT_EQ(true, extract_transaction_ids(nextString, thisTransactionID));
			transactionIDs.push_back(thisTransactionID[0]);
		}
	}
	EXPECT_EQ(KADEMLIA_K, transactionIDs.size());

	// after the final reply to the get_peers request is made, since we are responding
	// with "values" the dht will emit the first set of "announce_peer" queries.
	// These should be sitting in the socket
	std::string announceString = socket4.GetSentDataAsString();
	ASSERT_TRUE(extract_transaction_ids(announceString, transactionIDs));
	// at this time there should be "#define KADEMLIA_BROADCAST_OUTSTANDING 3" transaction id's for 4 outstanding messages
	EXPECT_EQ(KADEMLIA_BROADCAST_OUTSTANDING, transactionIDs.size());

	// Again, feed responses back to the dht. (this time, replys to the "announce_peers" queries
	for(int x = 0; x < transactionIDs.size(); ++x) {
		socket4.Reset();
		// get the request info out of the dht (since we can)
		DhtRequest *req = impl->LookupRequest(Read32(&transactionIDs[x][0]));
		if(req) {
			DhtIDToBytes(nodeID.b, req->peer.id);
			len = bencoder(message, 1024)
				.d()
					("r").d()
						("id")(nodeID.b, nodeID.len).e()
					("t")(transactionIDs[x])
					("y")("r")
				.e() ();
			impl->ProcessIncoming(message, len, req->peer.addr);
		}
		std::string nextString = socket4.GetSentDataAsString();
		if((nextString.size() != 0) && (x < transactionIDs.size() - 1)) {
			std::vector<std::vector<byte> > thisTransactionID;
			ASSERT_TRUE(extract_transaction_ids(nextString, thisTransactionID));
			transactionIDs.push_back(thisTransactionID[0]);
		}
	}
	EXPECT_EQ(KADEMLIA_K_ANNOUNCE, transactionIDs.size());
	// since we caused one node to have a time-out error, there should only be
	// 8 callback events (instead of 9)
	EXPECT_EQ(8, AddNodesCallbackDummy::callbackData.size());
}

/**
This test is designed to exercise the scheduling aspect of the dht process with
a "slow" node.

When first doing the dht lookup using "get_peers" the dht process shoulc issue
an initial burst of 4 queries and follow it up with additional queries and replys
are received until the nodes list is exausted.  There should be no more than 4
active queries in flight at a time (slow peers are excepted).  Once all of the
get_peers queries are complete then it switched to issuing "announce_peer" queries.
An initial burst of 3 queries should be issued followed by additional queries
as replys are received.  No more than 3 announce queries should be in flight at
a time.

          Test                    |                  DHT
----------------------------------|--------------------------------------------
1) invoke doAnnounce()            |
                                  | Responds by emitting a 'get_peers' query
								  |
2) Fabricate and "send" a         |
   response to get_peers that     |
   has only compact node info     |
   for 8 nodes                    |
                                  | Responds by emitting another 'get_peers' querys
								  | (an initial group of 4)
								  |
3) pick a node and submit an ICMP |
   error as a response.           |
                                  | dht intarnally notes the errored node and emits
								  | an additional query.
								  |
4) Send a "values" response back  |
   to the dht for each transaction|
   ID that the dht outputs        |
                                  | Issues another get_peers for each response until
								  | all nodes have been contacted.  Then it switches
								  | to issuing "announce_peer" queries (an initial
								  | group of 3)
5) responds with a acknowledgement|
   reply for each announce query  |
                                  |
*/
TEST_F(dht_impl_response_test, Announce_ICMPerror_ReplyWithMultipleNodes) {
	impl->_dht_utversion[2] = 'x';
	impl->_dht_utversion[3] = 'x';

	// put a peer into the dht for it to work with
	impl->Update(peer_id, 0, true, 10);
	Buffer peer_id_buffer;
	peer_id_buffer.len = 20;
	peer_id_buffer.b = (byte*)&peer_id.id.id[0];

	// do this to have the bootstrap ping messages be emitted now.
	// (instead of having them get mixed in with the test data later)
	impl->Tick();
	socket4.Reset();

	// make sure the callback dummy is clear
	AddNodesCallbackDummy::Reset();

	// *****************************************************
	// make the dht emit an announce message (the get_peers rpc)
	// *****************************************************
	impl->DoAnnounce(target, &AddNodesCallbackDummy::Callback, NULL,
			"filename.txt", NULL, 0);
	EXPECT_TRUE(impl->IsBusy()) << "The dht should be busy";

	// *****************************************************
	// grab from the socket the emitted message and extract
	// the transaction ID and verify the remainder of the
	// message
	// *****************************************************
	ASSERT_NO_FATAL_FAILURE(fetch_dict());
	ASSERT_NO_FATAL_FAILURE(expect_query_type());
	ASSERT_NO_FATAL_FAILURE(expect_command("get_peers"));
	Buffer tid;
	tid.b = (byte*)dict->GetString("t" , &tid.len);
	EXPECT_EQ(4, tid.len) << "transaction ID is wrong size";
	expect_reply_id();
	ASSERT_NO_FATAL_FAILURE(expect_info_hash());

	// *****************************************************
	// now fabricate a nodes response message using the
	// transaction ID extracted above and include a token
	// *****************************************************

	const char* compactIPs[] = {"bbbb..", "cccc..", "dddd..", "eeee..", "ffff..",
		"gggg..", "hhhh..", "iiii.."};

	// make a string of 8 compact nodes (based on what was designed above)
	std::string nearest_node("26_byte_nearest_n008bbbb..26_byte_nearest_n007cccc"
			"..26_byte_nearest_n006dddd..26_byte_nearest_n005eeee.."
			"26_byte_nearest_n004ffff..26_byte_nearest_n003gggg.."
			"26_byte_nearest_n002hhhh..26_byte_nearest_n001iiii..");
	len = bencoder(message, 1024)
		.d()
			("r").d()
				("id")(peer_id_buffer.b, peer_id_buffer.len)
				("nodes")(nearest_node)
				("token")(response_token).e()
			("t")(tid.b, tid.len)
			("y")("r")
		.e() ();
	socket4.Reset();
	impl->ProcessIncoming(message, len, peer_id.addr);
	EXPECT_TRUE(impl->IsBusy()) << "The dht should still be busy";

	// *****************************************************
	// get the bencoded string(s) out of the socket and extract
	// the transaction id's.  The dht should issue an initial burst of queries
	// that are throttled back to one new query for each response received
	// until all nodes have been queried.
	// *****************************************************

	// we are only interested in the transaction ID's
	std::string bencMessage = socket4.GetSentDataAsString();
	std::vector<std::vector<byte> > transactionIDs;
	ASSERT_TRUE(extract_transaction_ids(bencMessage, transactionIDs));
	EXPECT_EQ(KADEMLIA_LOOKUP_OUTSTANDING, transactionIDs.size());

	// *********************************************************************************
	// Get the request info and make it look like enough time has passed to call it slow.
	// An additional request should be issued.  Capture this additional request and
	// feed it back as an ICMP error
	// *********************************************************************************
	socket4.Reset();
	DhtRequest* req0 = impl->LookupRequest(Read32(&transactionIDs[0][0]));
	req0->time -= 1100;
	impl->Tick();

	// get the transaction id out of the additional message
	std::string additionalMessage = socket4.GetSentDataAsString();
	ASSERT_TRUE(additionalMessage.size() != 0) <<
			"no additional message was issued for a slow node";
	std::vector<std::vector<byte> > additionalTid;
	ASSERT_TRUE(extract_transaction_ids(additionalMessage, additionalTid));
	ASSERT_EQ(1, additionalTid.size()) <<
			"expected only one additional message for the slow node";
	// this should be ignored after the icmp error
	transactionIDs.push_back(additionalTid[0]);
	// do the ICMP error
	DhtRequest* reqICMP = impl->LookupRequest(Read32(&additionalTid[0][0]));
	BencEntity::Parse((const byte *)additionalMessage.c_str(), output,
			(const byte *)(additionalMessage.c_str() + additionalMessage.length()));
	socket4.Reset();
	EXPECT_TRUE(impl->ParseIncomingICMP(output, reqICMP->peer.addr));
	// get the tid out of the message issued in response to the icmp error
	std::string additionalMessage2 = socket4.GetSentDataAsString();
	ASSERT_TRUE(additionalMessage2.size() != 0) <<
			"no additional message was issued for an ICMP error";
	std::vector<std::vector<byte> > additionalTid2;
	ASSERT_TRUE(extract_transaction_ids(additionalMessage2, additionalTid2));
	ASSERT_EQ(1, additionalTid2.size()) <<
			"expected only one additional message for the ICMP error";
	transactionIDs.push_back(additionalTid2[0]);

	// follow through responding to the remainder of the requests
	byte bufferBytes[20];
	Buffer nodeID;
	nodeID.b = (byte*)bufferBytes;
	nodeID.len = 20;
	// feed responses back to the dht.
	for(int x = 0; x < transactionIDs.size(); ++x) {
		socket4.Reset();
		DhtRequest *req = impl->LookupRequest(Read32(&transactionIDs[x][0]));
		if(req) {
			DhtIDToBytes(nodeID.b, req->peer.id);
			len = bencoder(message, 1024)
				.d()
					("r").d()
						("id")(nodeID.b, nodeID.len)
						("token")(response_token)
						("values").l()
							(compactIPs[x]).e().e()
					("t")(transactionIDs[x])
					("y")("r")
				.e() ();
			impl->ProcessIncoming(message, len, req->peer.addr);
		}
		std::string nextString = socket4.GetSentDataAsString();
		if((nextString.size() != 0) && (x < transactionIDs.size() - 1)) {
			std::vector<std::vector<byte> > thisTransactionID;
			ASSERT_EQ(true, extract_transaction_ids(nextString, thisTransactionID));
			transactionIDs.push_back(thisTransactionID[0]);
		}
	}
	// there should now be 8 (KADEMLIA_K) transaction id's
	EXPECT_EQ(KADEMLIA_K, transactionIDs.size());
	// after the final reply to the get_peers request is made, since we are responding
	// with "values" the dht will emit the first set of "announce_peer" queries.
	// These should be sitting in the socket
	std::string announceString = socket4.GetSentDataAsString();
	ASSERT_TRUE(extract_transaction_ids(announceString, transactionIDs));
	// at this time there should be "#define KADEMLIA_BROADCAST_OUTSTANDING 3" transaction id's for 4 outstanding messages
	EXPECT_EQ(KADEMLIA_BROADCAST_OUTSTANDING, transactionIDs.size());

	// Again, feed responses back to the dht. (this time, replys to the "announce_peers" queries
	for(int x = 0; x < transactionIDs.size(); ++x) {
		socket4.Reset();
		DhtRequest *req = impl->LookupRequest(Read32(&transactionIDs[x][0]));
		if(req) {
			DhtIDToBytes(nodeID.b, req->peer.id);
			len = bencoder(message, 1024)
				.d()
					("r").d()
						("id")(nodeID.b, nodeID.len).e()
					("t")(transactionIDs[x])
					("y")("r")
				.e() ();
			impl->ProcessIncoming(message, len, req->peer.addr);
		}
		std::string nextString = socket4.GetSentDataAsString();
		if((nextString.size() != 0) && (x < transactionIDs.size() - 1)) {
			std::vector<std::vector<byte> > thisTransactionID;
			ASSERT_TRUE(extract_transaction_ids(nextString, thisTransactionID));
			transactionIDs.push_back(thisTransactionID[0]);
		}
	}
	// see that the correct number of announces were emitted
	EXPECT_EQ(KADEMLIA_K_ANNOUNCE, transactionIDs.size());
	// since we caused one node to have an ICMP error, there should only be 8 callback events (instead of 9)
	EXPECT_EQ(8, AddNodesCallbackDummy::callbackData.size());
}
