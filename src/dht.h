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

#ifndef __DHT_H__
#define __DHT_H__

/**
 * @ingroup dht
 */

#include <stddef.h> // for size_t
#include <vector> 
#include "utypes.h"
#include "sha1_hash.h"
#include "sockaddr.h"
#include "RefBase.h"
#include "smart_ptr.h"

class UDPSocketInterface;
class ExternalIPCounter;
class BencEntity;

// callback types used in the DHT
typedef void DhtVoteCallback(void *ctx, const byte *target, int const* votes);
typedef void DhtHashFileNameCallback(void *ctx, const byte *info_hash, const byte *file_name);
typedef void DhtAddNodesCallback(void *ctx, const byte *info_hash, const byte *peers, uint num_peers);
typedef void DhtAddNodeResponseCallback(void*& userdata, bool is_response, SockAddr const& addr);
typedef void DhtScrapeCallback(void *ctx, const byte *target, int downloaders, int seeds);
typedef int DhtPutCallback(void * ctx, std::vector<char>& buffer, int64& seq, SockAddr src);
typedef int DhtPutDataCallback(void * ctx, std::vector<char> const& buffer, int64 seq, SockAddr src);
typedef void DhtPutCompletedCallback(void * ctx);
typedef void DhtGetCallback(void* ctx, std::vector<char> const& buffer);
typedef void DhtLogCallback(char const* str);

// asks the client to save the DHT state
typedef void DhtSaveCallback(const byte* buf, int len);

// asks the client to load the DHT state into ent
typedef void DhtLoadCallback(BencEntity* ent);

// called for all incoming and outgoing packets
typedef void DhtPacketCallback(void const* buffer, size_t len, bool incoming);

// should return the listen port to use for announce_peer. Return -1 to
// use the implied_port feature (where the port is the same as for the DHT)
typedef int DhtPortCallback();

// allows the dht client to define what SHA-1 implementation to use
typedef sha1_hash DhtSHACallback(byte const* buf, int len);

// callback to ed25519 crypto_sign_open used for message verification
typedef bool Ed25519VerifyCallback(const unsigned char *signature,
		const unsigned char *message, size_t message_len,
		const unsigned char *key);

typedef void Ed25519SignCallback(unsigned char *signature,
		const unsigned char *message, size_t message_len,
		const unsigned char *key);

/**
 * DHT public interface
 */

class IDht : public RefBase
{
public:
	// Resolve gcc warning about nonvirtual destructor with virtual methods
	virtual ~IDht();

	enum announce_flags_t
	{
		announce_seed = 1,
		announce_non_aggressive = 2,
		announce_only_get = 4,
		with_cas = 8, // use cas for DHT put
	};

	virtual bool handleReadEvent(UDPSocketInterface *socket, byte *buffer, size_t len, const SockAddr& addr) = 0;
	virtual bool handleICMP(UDPSocketInterface *socket, byte *buffer, size_t len, const SockAddr& addr) = 0;
	virtual void Tick() = 0;
	virtual void Vote(void *ctx, const sha1_hash* info_hash, int vote, DhtVoteCallback* callb) = 0;
	
	virtual void Put(
		//pkey points to a 32-byte ed25519 public.
		const byte * pkey,
		const byte * skey,

		// This method is called in DhtSendRPC for Put. It takes v (from get
		// responses) as an input and may or may not change v to place in Put
		// messages. if the callback function returns a non-zero value, the
		// DhtProcess is aborted and the value is not stored back in the DHT.
		DhtPutCallback* put_callback,

		//called in CompleteThisProcess
		DhtPutCompletedCallback * put_completed_callback,

		// called every time we receive a blob from a node. This cannot be used
		// to modify and write back the data, this is just a sneak-peek of what's
		// likely to be in the final blob that's passed to put_callback if the
		// callback function returns a non-zero value, the DhtProcess is aborted
		// and the value is not stored back in the DHT.
		DhtPutDataCallback* put_data_callback,
		void *ctx,
		int flags = 0,

		// seq is an optional provided monotonically increasing sequence number to be
		// used in a Put request if the requester is keeping sequence number state
		// this number will be used if higher than any numbers gotten from peers
		int64 seq = 0) = 0;

	virtual sha1_hash ImmutablePut(
			const byte * data,
			size_t data_len,
			DhtPutCompletedCallback* put_completed_callback = nullptr,
			void *ctx = nullptr) = 0;

	virtual void ImmutableGet(sha1_hash target, DhtGetCallback* cb
		, void* ctx = nullptr) = 0;

	virtual void AnnounceInfoHash(
		const byte *info_hash,
		DhtAddNodesCallback *addnodes_callback,
		DhtPortCallback* pcb,
		cstr file_name,
		void *ctx,
		int flags = 0) = 0;


	virtual void SetId(byte new_id_bytes[20]) = 0;
	virtual void Enable(bool enabled, int rate) = 0;

	enum {
		DHT_ORIGIN_UNKNOWN = 0,
		DHT_ORIGIN_INITIAL,
		DHT_ORIGIN_IS_PEER,
		DHT_ORIGIN_FROM_PEER, // Introduced via FindPeers
		DHT_ORIGIN_INCOMING, // Contacted us first
		DHT_ORIGIN_COUNT
	};

	virtual void SetVersion(char const* client, int major, int minor) = 0;
	virtual void SetRate(int bytes_per_second) = 0;

	virtual void SetExternalIPCounter(ExternalIPCounter* ip) = 0;
	virtual void SetPacketCallback(DhtPacketCallback* cb) = 0;
	virtual void SetAddNodeResponseCallback(DhtAddNodeResponseCallback* cb) = 0;
	virtual void SetSHACallback(DhtSHACallback* cb) = 0;
	virtual void SetEd25519VerifyCallback(Ed25519VerifyCallback* cb) = 0;
	virtual void SetEd25519SignCallback(Ed25519SignCallback* cb) = 0;
	virtual void AddBootstrapNode(SockAddr const& addr) = 0;
	
	// userdata pointer is passed on to the AddNodeReponseCallback
	virtual void AddNode(const SockAddr& addr, void* userdata, uint origin) = 0;
	virtual bool CanAnnounce() = 0;
	virtual void Close() = 0;
	virtual void Shutdown() = 0;
	virtual void Initialize(UDPSocketInterface *, UDPSocketInterface *) = 0;
	virtual bool IsEnabled() = 0;
	virtual void ForceRefresh() = 0;
	// do not respond to queries - for mobile nodes with data constraints
	virtual void SetReadOnly(bool readOnly) = 0;
	virtual void SetPingFrequency(int seconds) = 0;
	virtual void SetPingBatching(int num_pings) = 0;
	virtual void EnableQuarantine(bool e) = 0;

	virtual bool ProcessIncoming(byte *buffer, size_t len, const SockAddr& addr) = 0;
#ifdef _DEBUG_MEM_LEAK
	virtual int FreeRequests() = 0;
#endif
	virtual void DumpTracked() = 0;
	virtual void DumpBuckets() = 0;

#ifdef DHT_SEARCH_TEST
	void RunSearches() = 0;
#endif

	//
	// Linker
	//
	virtual int GetProbeQuota() = 0;
	virtual bool CanAddNode() = 0;
	virtual int GetNumPeers() = 0;
	virtual bool IsBusy() = 0;
	virtual int GetBootstrapState() = 0;
	virtual int GetRate() = 0;
	virtual int GetQuota() = 0;
	virtual int GetProbeRate() = 0;
	virtual int GetNumPeersTracked() = 0;
	virtual void Restart() = 0;
	virtual void GenerateId() = 0;

	// So we can be pointed to by a smart pointer.
	// Implementation can derive from RefBase.
	virtual ULONG STDMETHODCALLTYPE AddRef(void) = 0;
	virtual ULONG STDMETHODCALLTYPE Release(void) = 0;
};

smart_ptr<IDht> create_dht(UDPSocketInterface *udp_socket_mgr, UDPSocketInterface *udp6_socket_mgr
	, DhtSaveCallback* save, DhtLoadCallback* load, ExternalIPCounter* eip = NULL);

void set_log_callback(DhtLogCallback* log);

#endif //__DHT_H__

