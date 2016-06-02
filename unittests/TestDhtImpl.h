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

#include "TestDHT.h"
#include "bencoder.h"
#include "snprintf.h"
#include "sockaddr.h"
#include "utypes.h"

static const unsigned char * pkey = reinterpret_cast<const unsigned char *>
			("dhuieheuu383y8yr7yy3hd3hdh3gfhg3");
static const unsigned char * skey = reinterpret_cast<const unsigned char *>
			("dhuieheuu383y8yr7yy3hd3hdh3gfhg3dhuieheuu383y8yr7yy3hd3hdh3gfhg3");

inline void fill_test_data(std::string &result, const Buffer &token,
		const std::string &one, const std::string &two) {
	char itoa_string[50];
	snprintf(itoa_string, 50, "%u", static_cast<unsigned int>(token.len));

	result.clear();
	result += one;
	result.append(itoa_string, itoa_string + strlen(itoa_string));
	result.push_back(':');
	result.append(token.b, token.b + token.len);
	result += two;
}

inline std::vector<byte> make_random_byte_string(unsigned int count) {
	std::vector<byte> key;
	for(unsigned int x = 0; x < count; ++x) {
		key.push_back(rand()%74 + 48); // make something in the alphanumeric range
	}
	return key;
}

inline std::vector<byte> make_random_key_20() {
	return make_random_byte_string(20);
}

inline void ed25519_callback(unsigned char * sig, const unsigned char * v,
		size_t size, const unsigned char * key) {
	for(int i = 0; i < 64; i++) {
		sig[i] = 'a';
	}
}

inline bool ed25519_verify(const unsigned char *signature,
		const unsigned char *message, size_t message_len,
		const unsigned char *key)
{
	return true;
}

class dht_impl_test : public dht_test {
	protected:
		SockAddr bind_addr;
		std::string addr_string;
		std::string port_string;

		UnitTestUDPSocket socket4;
		UnitTestUDPSocket socket6;
		smart_ptr<DhtImpl> impl;
		DhtPeerID peer_id;

		// used by fetch_*, set by using bencoder
		unsigned char message[1024];
		int64 len;
		BencEntity output;
		// retrieved by fetch_*
		BencodedDict* dict;
		// set by all methods that use it, can manually be retrieved by calling
		// get_reply
		BencodedDict* reply;

		const char* response_token;
		const char* v;

		virtual void SetUp() override {
			set_addr('zzzz');
			set_port(('x' << 8) + 'x');
			socket4.SetBindAddr(bind_addr);

			impl = new DhtImpl(&socket4, &socket6);
			impl->SetSHACallback(&sha1_callback);
			impl->SetEd25519SignCallback(&ed25519_callback);
			impl->SetEd25519VerifyCallback(&ed25519_verify);
			impl->EnableQuarantine(false);

			peer_id.id.id[0] = '1111'; // 1111
			peer_id.id.id[1] = 'BBBB'; // BBBB
			peer_id.id.id[2] = 'CCCC'; // CCCC
			peer_id.id.id[3] = 'DDDD'; // DDDD
			peer_id.id.id[4] = '0000'; // 0000
			peer_id.addr.set_port(128);
			peer_id.addr.set_addr4(0xf0f0f0f0);

			dict = NULL;
			reply = NULL;

			response_token = "20_byte_reply_token.";
			v = "sample";
		}

		void add_node(char const* id) {

			extern void CopyBytesToDhtID(DhtID &id, const byte *b);

			// add one peer whose first_seen is old enough to include in a node
			// response
			DhtPeerID tmp;
			CopyBytesToDhtID(tmp.id, (const byte*)id);
			tmp.addr.set_port(128);
			tmp.addr.set_addr4(0xf0f0f0f0);
			impl->Update(tmp, IDht::DHT_ORIGIN_UNKNOWN, true, 10);
		}

		virtual void TearDown() override {
		}

		void set_addr(int32 v) {
			bind_addr.set_addr4(v);
			addr_string.clear();
#if BT_LITTLE_ENDIAN
			for(int i = 3; i >= 0; i--)
#else
			for(int i = 0; i <= 3; i++)
#endif
			{
				addr_string.push_back(reinterpret_cast<const char*>(&v)[i]);
			}
		}

		void set_port(int16 v) {
			bind_addr.set_port(v);
			port_string.clear();
#if BT_LITTLE_ENDIAN
			port_string.push_back(reinterpret_cast<const char*>(&v)[1]);
			port_string.push_back(reinterpret_cast<const char*>(&v)[0]);
#else
			port_string.push_back(reinterpret_cast<const char*>(&v)[0]);
			port_string.push_back(reinterpret_cast<const char*>(&v)[1]);
#endif
		}

		void init_dht_id() {
			impl->SetId((unsigned char*)DHTID_BYTES.c_str());
		}

		void fetch_dict() {
			std::string benc_message = socket4.GetSentDataAsString(socket4.numPackets()-1);
			// should not store expected dict in a BencodedDict because if the output
			// is somehow not a dict that will trigger a non-unittest assert, and we
			// wish to handle that case ourselves
			BencEntity::Parse((const unsigned char *)benc_message.c_str(), output,
					(const unsigned char *)
						(benc_message.c_str() + benc_message.length()));
			ASSERT_EQ(BENC_DICT, output.bencType);
			dict = BencEntity::AsDict(&output);
			ASSERT_TRUE(dict);
			ASSERT_EQ(BENC_DICT, dict->bencType);
			reply = NULL;
		}

		inline void get_reply() {
			if (reply == NULL) {
				cstr type = dict->GetString("y", 1);
				ASSERT_TRUE(type);
				if (type[0] == 'r') {
					reply = dict->GetDict("r");
				} else if (type[0] == 'q') {
					reply = dict->GetDict("a");
				} else {
					FAIL() << "message has unknown type";
				}
				ASSERT_TRUE(reply);
			}
		}

		void expect_response_type() {
			cstr type = dict->GetString("y", 1);
			ASSERT_TRUE(type);
			ASSERT_EQ('r', *type);
		}

		void expect_query_type() {
			cstr type = dict->GetString("y", 1);
			ASSERT_TRUE(type);
			ASSERT_EQ('q', *type);
		}

		void expect_command(const char* command) {
			cstr c = dict->GetString("q", strlen(command));
			ASSERT_TRUE(c);
			ASSERT_STREQ(command, c);
		}

		void expect_ip() {
			Buffer ip;
			ip.b = (unsigned char*)dict->GetString("ip", &ip.len);
			ASSERT_EQ(6, ip.len);
			EXPECT_FALSE(memcmp((const void*)ip.b,
						(const void *)addr_string.c_str(), 4));
			EXPECT_FALSE(memcmp((const void*)(ip.b + 4),
						(const void *)port_string.c_str(), 2));
		}

		void fetch_response_to_message(std::string* data = NULL) {
			if (data != NULL) {
				len = data->size();
				assert(len <= 1024);
				memcpy(message, data->c_str(), len);
			}
			socket4.Reset();
			impl->ProcessIncoming(message, len, bind_addr);
			ASSERT_NO_FATAL_FAILURE(fetch_dict());
			ASSERT_NO_FATAL_FAILURE(expect_response_type());
			ASSERT_NO_FATAL_FAILURE(expect_ip());
		}

		bool test_transaction_id(const char* id, int id_len) {
			Buffer tid;
			tid.b = (unsigned char*)dict->GetString("t", &tid.len);
			if (tid.b == NULL) return false;
			if (id_len != tid.len) return false;

			return memcmp((const void*)tid.b, (const void *)id, id_len) == 0;
		}

		void expect_transaction_id(const char* id, int id_len) {
			Buffer tid;
			tid.b = (unsigned char*)dict->GetString("t", &tid.len);
			ASSERT_EQ(id_len, tid.len);
			if (id != NULL) {
				EXPECT_FALSE(memcmp((const void*)tid.b, (const void *)id, id_len));
			}
		}

		void expect_reply_id(const char* expected = NULL) {
			ASSERT_NO_FATAL_FAILURE(get_reply());
			unsigned char *id = (unsigned char*)reply->GetString("id", 20);
			ASSERT_TRUE(id);
			if (expected == NULL) {
				EXPECT_FALSE(memcmp((const void*)id, (const void *)DHTID_BYTES.c_str(),
							20));
			} else {
				EXPECT_FALSE(memcmp((const void*)id, (const void *)expected, 20));
			}
		}

		void expect_token(const char* response_token) {
			ASSERT_NO_FATAL_FAILURE(get_reply());
			Buffer token;
			token.b = (unsigned char*)reply->GetString("token" , &token.len);
			EXPECT_EQ(20, token.len);
			if (response_token != NULL) {
				EXPECT_FALSE(memcmp(response_token, token.b, 20)) <<
					"ERROR: announced token is wrong";
			}
		}

		void expect_signature() {
			ASSERT_NO_FATAL_FAILURE(get_reply());
			Buffer sig;
			sig.b = (unsigned char*)reply->GetString("sig" , &sig.len);
			EXPECT_EQ(64, sig.len);
		}

		void expect_value(const char* value, int value_len) {
			ASSERT_NO_FATAL_FAILURE(get_reply());
			Buffer v_out;
			v_out.b = (unsigned char*)reply->GetString("v" , &v_out.len);
			EXPECT_EQ(value_len, v_out.len);
			EXPECT_FALSE(memcmp(value, v_out.b, value_len)) << "ERROR: v is wrong";
		}

		void expect_cas(uint64 expected_cas) {
			ASSERT_NO_FATAL_FAILURE(get_reply());
			uint64 cas;
			cas = reply->GetInt("cas", 0);
			EXPECT_EQ(expected_cas, cas);
		}

		void expect_target() {
			ASSERT_NO_FATAL_FAILURE(get_reply());
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
			impl->ProcessIncoming(reinterpret_cast<unsigned char*>
					(const_cast<char*>(get_peers.c_str())),
					get_peers.size(), bind_addr);
			ASSERT_NO_FATAL_FAILURE(fetch_dict());
			ASSERT_NO_FATAL_FAILURE(get_reply());
			token.b = (byte*)reply->GetString("token", &token.len);
			ASSERT_TRUE(token.len);
			token_bytes.assign(token.b, token.b + token.len);
			impl->Tick();
			socket4.Reset();
		}

		void announce_and_verify() {
			ASSERT_NO_FATAL_FAILURE(fetch_response_to_message());
			expect_reply_id();
			impl->Tick();
			socket4.Reset();
		}

		void immutable_put(const std::string &id, char const *v) {
			// get a token to use
			std::vector<unsigned char> token;
			socket4.Reset();
			fetch_token(id, token);
			len = bencoder(message, 1024)
				.d()
					("a").d()
						("id")(id)
						("token")(token)
						("v").raw(v).e()
					("q")("put")
					("t")("aa")
					("y")("q")
				.e() ();
			socket4.Reset();
			impl->ProcessIncoming(message, len, bind_addr);
			ASSERT_NO_FATAL_FAILURE(fetch_dict());
			ASSERT_NO_FATAL_FAILURE(expect_response_type());
			ASSERT_NO_FATAL_FAILURE(get_reply());
			impl->Tick();
			socket4.Reset();
		}
};

class AddNodesCallBackDataItem {
	public:
		byte infoHash[20];
		unsigned int numPeers;
		std::vector<byte> compactPeerAddressBytes;

		bool operator==(AddNodesCallBackDataItem &right);
};

inline bool AddNodesCallBackDataItem::operator==(
		AddNodesCallBackDataItem &right) {
	if(memcmp(infoHash, right.infoHash, 20) == 0
		 && numPeers == right.numPeers
		 && compactPeerAddressBytes == right.compactPeerAddressBytes) {
		return true;
	}
	return false;
}

class AddNodesCallbackDummy {
	public:
		static std::vector<AddNodesCallBackDataItem> callbackData;

		AddNodesCallbackDummy() {}
		~AddNodesCallbackDummy() {}
		static void Callback(void *ctx, const byte *info_hash, const byte *peers,
				uint num_peers);
		static void Reset();
};

inline void AddNodesCallbackDummy::Callback(void *ctx, const byte *info_hash,
		const byte *peers, uint num_peers) {
	AddNodesCallBackDataItem data;
	unsigned int x;

	for(x = 0; x < 20; ++x) {
		data.infoHash[x] = info_hash[x];
	}

	data.numPeers = num_peers;
	// 6 bytes of compact address per peer
	for(x = 0; x < 6 * data.numPeers; ++x) {
		data.compactPeerAddressBytes.push_back(peers[x]);
	}

	callbackData.push_back(data);
}

inline void AddNodesCallbackDummy::Reset() {
	callbackData.clear();
}
