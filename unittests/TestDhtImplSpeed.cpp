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

//TODO: why are most messages sent twice?!?

const unsigned int speedTestFactor = 10;
const unsigned long maxIterations = 25 * speedTestFactor;

class dht_impl_speed_test : public dht_impl_test {
	protected:
		virtual void SetUp() override {
			dht_impl_test::SetUp();
			init_dht();
		}

		void init_dht() {
			impl->Enable(true, 2000);
			init_dht_id();
			impl->Tick();
		}

		void process_message(std::string* message_string = NULL) {
			if (message_string != NULL) {
				len = message_string->size();
				memcpy(message, message_string->c_str(), len);
			}
			impl->ProcessIncoming(message, len, bind_addr);
			impl->Tick();
			ASSERT_TRUE(socket4.GetSentByteVector().size());
			socket4.Reset();
		}
};

TEST_F(dht_impl_speed_test, PingKnownPacketSpeedTest) {
	std::string known_ping_string("d1:ad2:id20:abcdefghij0123456789e1:q4:ping1:t"
			"4:wxyz1:v4:UTUT1:y1:qe");

	for(unsigned long x = 0; x < maxIterations; ++x) {
		ASSERT_NO_FATAL_FAILURE(process_message(&known_ping_string));
		ASSERT_NO_FATAL_FAILURE(process_message(&known_ping_string));
	}
}

TEST_F(dht_impl_speed_test, PingArbitraryPacketSpeedTest) {
	std::string ping_string("d1:ad2:id20:abcdefghij0123456789e1:q4:ping1:t2:aa"
			"1:y1:qe");

	for(unsigned long x = 0; x < maxIterations; ++x) {
		ASSERT_NO_FATAL_FAILURE(process_message(&ping_string));
		ASSERT_NO_FATAL_FAILURE(process_message(&ping_string));
	}
}

TEST_F(dht_impl_speed_test, PingQueriesSpeedTest) {
	std::string ping_string("d1:ad2:id20:abcdefghij0123456789e1:q4:ping1:t2:aa"
			"1:y1:qe");
	std::string known_ping_string("d1:ad2:id20:abcdefghij0123456789e1:q4:ping1:t"
			"4:wxyz1:v4:UTUT1:y1:qe");

	for(unsigned long x = 0; x < maxIterations; ++x) {
		ASSERT_NO_FATAL_FAILURE(process_message(&ping_string));
		ASSERT_NO_FATAL_FAILURE(process_message(&known_ping_string));
	}
}

TEST_F(dht_impl_speed_test, FindNodeSpeedTest) {
	std::string find_node_string("d1:ad2:id20:abcdefghij01234567896:target"
			"20:mnopqrstuvwxyz123456e1:q9:find_node1:t2:aa1:y1:qe");

	for(unsigned long x = 0; x < maxIterations; ++x) {
		ASSERT_NO_FATAL_FAILURE(process_message(&find_node_string));
		ASSERT_NO_FATAL_FAILURE(process_message(&find_node_string));
	}
}

TEST_F(dht_impl_speed_test, GetPeersSpeedTest) {
	std::string get_peers_string("d1:ad2:id20:abcdefghij01010101019:info_hash"
			"20:mnopqrstuvwxyz123456e1:q9:get_peers1:t2:aa1:y1:qe");

	for(unsigned long x = 0; x < maxIterations; ++x) {
		ASSERT_NO_FATAL_FAILURE(process_message(&get_peers_string));
		ASSERT_NO_FATAL_FAILURE(process_message(&get_peers_string));
	}
}

TEST_F(dht_impl_speed_test, AnnouncePeerSpeedTest) {
	std::vector<byte> token;

	std::string test_data_1("d1:ad2:id20:abcdefghij01234567899:info_hash"
			"20:mnopqrstuvwxyz1234564:porti6881e5:token");
	std::string test_data_2("e1:q13:announce_peer1:t2:aa1:y1:qe");
	std::string test_data;

	// use this since the string will be modified as it is processed
	std::string buffer;
	for(unsigned long x = 0; x < maxIterations; ++x) {
		if(!(x & 0x0000007f)) { // the token needs to be refreshed periodically
			// get a new token and re-generate the test data
			socket4.Reset();
			fetch_token(token);
			test_data.clear();
			fill_test_data(test_data, Buffer(&token[0], token.size()), test_data_1,
					test_data_2);
		}
		buffer = test_data;
		ASSERT_NO_FATAL_FAILURE(process_message(&buffer));
		ASSERT_NO_FATAL_FAILURE(process_message(&buffer));
	}
}

TEST_F(dht_impl_speed_test, VoteSpeedTest) {
	std::vector<byte> token;

	std::string buffer;
	for(unsigned long x = 0; x < maxIterations; ++x) {
		if(!(x & 0x0000007f)) { // the token needs to be refreshed periodically
			// get a new token and re-generate the test data
			socket4.Reset();
			fetch_token(token);
			std::vector<byte> target = make_random_key_20();

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
			ASSERT_NO_FATAL_FAILURE(process_message());

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
			ASSERT_NO_FATAL_FAILURE(process_message());
		}
	}
}

TEST_F(dht_impl_speed_test, Announce_ReplyWithNodes_Speed) {
	DhtID target;
	target.id[0] = 'FFFF'; // FFFF
	target.id[1] = 'GGGG'; // GGGG
	target.id[2] = 'HHHH'; // HHHH
	target.id[3] = 'IIII'; // IIII
	target.id[4] = 'JJJJ'; // JJJJ

	const char* compact_ip = "aaaa88";

	// put a peer into the dht for it to work with
	peer_id.addr.set_port(('8' << 8) + '8'); // 88
	peer_id.addr.set_addr4('aaaa'); // aaaa
	impl->Update(peer_id, 0, true, 10);
	Buffer peer_id_buffer;
	peer_id_buffer.len = 20;
	peer_id_buffer.b = (byte*)&peer_id.id.id[0];

	std::string filenameTxt("filaname.txt");

	for(unsigned int x = 0; x < 20 * speedTestFactor; ++x) {
		// make sure the callback dummy is clear
		AddNodesCallbackDummy::Reset();

		// *****************************************************
		// make the dht emit an announce message (the get_peers rpc)
		// *****************************************************
		impl->DoAnnounce(target, &AddNodesCallbackDummy::Callback, NULL,
				filenameTxt.c_str(), NULL, 0);
		ASSERT_NO_FATAL_FAILURE(fetch_dict());
		ASSERT_NO_FATAL_FAILURE(expect_query_type());
		ASSERT_NO_FATAL_FAILURE(expect_command("get_peers"));
		Buffer tid;
		tid.b = (byte*)dict->GetString("t" , &tid.len);
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

		len = bencoder(message, 1024)
			.d()
				("r").d()
					("id")(peer_id_buffer.b, peer_id_buffer.len).e()
				("t")(tid.b, tid.len)
				("y")("r")
			.e() ();
		socket4.Reset();
		impl->ProcessIncoming(message, len, peer_id.addr);
	}
}
