#ifndef __DHT_H__
#define __DHT_H__

/**
 * @ingroup dht
 */

#include <stddef.h> // for size_t
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
typedef void DhtPartialHashCompletedCallback(void *ctx, const byte *info_hash);
typedef void DhtHashFileNameCallback(void *ctx, const byte *info_hash, const byte *file_name);
typedef void DhtAddNodesCallback(void *ctx, const byte *info_hash, const byte *peers, uint num_peers);
typedef void DhtAddNodeResponseCallback(void*& userdata, bool is_response, SockAddr const& addr);
typedef void DhtScrapeCallback(void *ctx, const byte *target, int downloaders, int seeds);

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
	};

	virtual bool handleReadEvent(UDPSocketInterface *socket, byte *buffer, size_t len, const SockAddr& addr) = 0;
	virtual bool handleICMP(UDPSocketInterface *socket, byte *buffer, size_t len, const SockAddr& addr) = 0;
	virtual void Tick() = 0;
	virtual void Vote(void *ctx, const sha1_hash* info_hash, int vote, DhtVoteCallback* callb) = 0;
	virtual void AnnounceInfoHash(
		const byte *info_hash,
		int info_hash_len,
		DhtPartialHashCompletedCallback *partial_callback,
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
	virtual void AddBootstrapNode(SockAddr const& addr) = 0;
	
	// userdata pointer is passed on to the AddNodeReponseCallback
	virtual void AddNode(const SockAddr& addr, void* userdata, uint origin) = 0;
	virtual bool CanAnnounce() = 0;
	virtual void Shutdown() = 0;
	virtual void Initialize(UDPSocketInterface *, UDPSocketInterface *) = 0;
	virtual bool IsEnabled() = 0;
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
	virtual int GetNumOutstandingAddNodes() = 0;
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
	, DhtSaveCallback* save, DhtLoadCallback* load);

#endif //__DHT_H__

