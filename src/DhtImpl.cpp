#define _DISABLE_NONSTANDARD_SWAP
/**
 * @ingroup dht
 */

// Once we move everything over to ed25519, we can drop this
// dependency

#include "bencoding.h"
#include "DhtImpl.h"
#include "snprintf.h"
#include "RefBase.h"
#include "tailqueue.h"
#include "get_microseconds.h"
#include "udp_utils.h"
#include "bloom_filter.h"
#include "endian_utils.h"
#include "ExternalIPCounter.h"
#include <string.h> // for strlen
#include <algorithm> // for std::min
#include <math.h>
#include <stdarg.h>
#include <cstdint>

#define lenof(x) (sizeof(x)/sizeof(x[0]))
#define MUTABLE_PAYLOAD_FORMAT "3:seqi%" PRId64 "e1:v"

#define MESSAGE_TOO_BIG 205
#define INVALID_SIGNATURE 206
#define CAS_MISMATCH 301
#define LOWER_SEQ 302

bool DhtVerifyHardenedID(const SockAddr& addr, byte const* node_id, DhtSHACallback* sha);
void DhtCalculateHardenedID(const SockAddr& addr, byte *node_id, DhtSHACallback* sha);

int clamp(int v, int min, int max)
{
	if (v < min) return min;
	if (v > max) return max;
	return v;
}

#if g_log_dht

uint prebitcmp(const uint32 *a, const uint32 *b, size_t size) { // Simple dirty "count bit prefix in common" function
	uint result = 0;
	for(int c = 0; c < size; c++) {
		uint32 x = a[c] ^ b[c];
		for(int d = 0; d < 32; d++) {
			if (!( (1 << (31-d)) & x ) )
				result++;
			else
				return result;
		}
	}
	return result;
}

uint g_dht_peertype_count[IDht::DHT_ORIGIN_COUNT] = {0,0,0,0,0};

void dht_log(char const* fmt, ...)
{
	// TODO: log to a file or something
}

#endif // g_log_dht

static void do_log(char const* fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	char buf[1000];
	vsnprintf(buf, sizeof(buf), fmt, args);

	fprintf(stderr, "DHT: %s\n", buf);
	// TODO: call callback or something
}

#if defined(_DEBUG_DHT)
static void debug_log(char const* fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	char buf[1000];
	vsnprintf(buf, sizeof(buf), fmt, args);
	fprintf(stderr, "DHT: %s\n", buf);
	va_end(args);
	// TODO: call callback or something
}
#endif

const char *format_dht_id(const DhtID &id)
{
	static char buf[100];
	snprintf(buf, sizeof(buf), "%.8X%.8X%.8X%.8X%.8X",
		 id.id[0], id.id[1], id.id[2], id.id[3], id.id[4]);
	return buf;
}

//--------------------------------------------------------------------------------
//
//
// DhtImpl public interface
//
//
//--------------------------------------------------------------------------------

DhtImpl::DhtImpl(UDPSocketInterface *udp_socket_mgr, UDPSocketInterface *udp6_socket_mgr
	, DhtSaveCallback* save, DhtLoadCallback* load)
{
	_ip_counter = NULL;
	_add_node_callback = NULL;
	_save_callback = save;
	_load_callback = load;
	_packet_callback = NULL;
	_peers_tracked = 0;
	_dht_enabled = false;
	_udp_socket_mgr = NULL;
	_udp6_socket_mgr = NULL;
	_dht_busy = 0;

	_dht_bootstrap = 1;
	_dht_bootstrap_failed = 0;
	_allow_new_job = false;
	_refresh_bucket = 0;
	_refresh_bucket_force = false;
	_refresh_buckets_counter = -1;
	_outstanding_add_node = 0;
	_dht_peers_count = 0;

	_dht_utversion[0] = 'U';
	_dht_utversion[1] = 'T';
	_dht_utversion[2] = 0;
	_dht_utversion[3] = 0;

	// allocators
	_dht_bucket_allocator._size = sizeof(DhtBucket);
	_dht_bucket_allocator._grow = 50;
	_dht_bucket_allocator._free = NULL;

	_dht_peer_allocator._size = sizeof(DhtPeer);
	_dht_peer_allocator._grow = 100;
	_dht_peer_allocator._free = NULL;

	_dht_quota = 0;

#ifdef _DEBUG_MEM_LEAK
	_dhtprocesses_init = 0;
#endif

	Initialize(udp_socket_mgr, udp6_socket_mgr);

	// initialize the put/get data stores
	_immutablePutStore.SetCurrentTime(time(NULL));
	_immutablePutStore.SetMaximumAge(7200); // 2 hours
	_immutablePutStore.SetMaximumSize(1000);

	_mutablePutStore.SetCurrentTime(time(NULL));
	_mutablePutStore.SetMaximumAge(7200); // 2 hours
	_mutablePutStore.SetMaximumSize(1000);
}

DhtImpl::~DhtImpl()
{
	for(int i = 0; i < _buckets.size(); i++) {
		for (DhtPeer **peer = &_buckets[i]->peers.first(); *peer;) {
			DhtPeer *p = *peer;
			// unlinknext will make peer point the following entry
			// in the linked list, so there's no need to step forward
			// explicitly.
			_buckets[i]->peers.unlinknext(peer);
			_dht_peer_allocator.Free(p);
		}
		for (DhtPeer **peer = &_buckets[i]->replacement_peers.first(); *peer;) {
			DhtPeer *p = *peer;
			_buckets[i]->replacement_peers.unlinknext(peer);
			_dht_peer_allocator.Free(p);
		}
		_dht_bucket_allocator.Free(_buckets[i]);
	}
	for (std::vector<StoredContainer>::iterator it = _peer_store.begin(); it != _peer_store.end(); it++) {
		free(it->file_name);
	}
#ifdef _DEBUG_MEM_LEAK
	FreeRequests();
#endif
}

void DhtImpl::SetVersion(char const* client, int major, int minor)
{
	_dht_utversion[0] = client[0];
	_dht_utversion[1] = client[1];
	_dht_utversion[2] = major;
	_dht_utversion[3] = minor;
}

/**
 * UDP handler
 */
bool DhtImpl::handleReadEvent(UDPSocketInterface *socket, byte *buffer, size_t len, const SockAddr& addr)
{
	// Check if it appears to be a DHT message. If so, call the DHT handler.
	if (len > 10 && buffer[0] == 'd' && buffer[len-1] == 'e' && buffer[2] == ':') {
		return ProcessIncoming(buffer, len, addr);
	}
	return false;
}


/**
 * Initialize DHT
 */
void DhtImpl::Initialize(UDPSocketInterface *udp_socket_mgr, UDPSocketInterface *udp6_socket_mgr )
{
	_udp_socket_mgr = udp_socket_mgr;
	_udp6_socket_mgr = udp6_socket_mgr;

	// Initialize the buckets
	for (int i = 0; i < 32; ++i) {
		DhtBucket *bucket = CreateBucket(i);
		bucket->span = 155;
		memset(&bucket->first, 0, sizeof(bucket->first));
		// map the [0, 32) range onto the top of
		// the first word in the ID
		bucket->first.id[0] = uint(i) << (32 - 5);
	}

	// Initialize the request list
	_requests.init();

	GenerateId();

	// Need to do this twice so prev_token becomes random too
	RandomizeWriteToken();
	RandomizeWriteToken();

	// Load the DHT state
#ifndef _DEBUG_DHT
	LoadState();
#endif
}

/**
 * Save the DHT state and disable DHT.
 */
void DhtImpl::Shutdown()
{
	SaveState();
	Enable(0,0); // Stop Dht
}

/**
 * Start or Stop DHT
 */
void DhtImpl::Enable(bool enabled, int rate)
{
	// rate too low?
	if (rate < 1024)
		rate = 1024;

	_dht_rate = rate;
	_dht_probe_rate = 5;
	if (_dht_enabled != enabled) {
		_dht_enabled = enabled;
		_dht_bootstrap = 1;
	}
}



/**
 * Check if DHT is enabled
 */
bool DhtImpl::IsEnabled()
{
	return _dht_enabled;
}

/**
 * Return true once bootstrap is complete every 4 seconds   // 4 seconds limits the amount of DHT traffic
 */
bool DhtImpl::CanAnnounce()
{
	if (_dht_bootstrap != -2  || !_allow_new_job)
		return false;
	return true;
}

/**
 * Set the ID of this DHT client
 */
void DhtImpl::SetId(byte new_id_bytes[20])
{
	CopyBytesToDhtID(_my_id, new_id_bytes);
	DhtIDToBytes(_my_id_bytes, _my_id);
	Restart();
}

void DhtImpl::SetId(DhtID id) {
	DhtIDToBytes(_my_id_bytes, id);
	CopyBytesToDhtID(_my_id, _my_id_bytes);
	Restart();
}

void DhtImpl::GenerateId()
{
	SockAddr externIp;
	byte id_bytes[20];

	if(_ip_counter && _ip_counter->GetIP(externIp)){
		DhtCalculateHardenedID(externIp, id_bytes, _sha_callback);
	} else {
		uint32 *pTemp = (uint32 *) id_bytes;
		// Generate a random ID
		for(uint i=0; i<5; i++)
			*pTemp++ = rand();
	}
	SetId(id_bytes);
}

//--------------------------------------------------------------------------------
//
// Member accessor methods
//
//--------------------------------------------------------------------------------

/**
 * Get the probe count
 */
int DhtImpl::GetProbeQuota()
{
	return _dht_probe_quota;
}
/**
 * Decrement the probe count and return true if it's greater than zero
 */
bool DhtImpl::CanAddNode()
{
	return ( _dht_probe_quota-- > 0 );
}


/**
 *
 */
int DhtImpl::GetNumPeers()
{
	return _dht_peers_count;
}

/**
 *
 */
bool DhtImpl::IsBusy()
{
	return _dht_busy;
}

/**
 *
 */
int DhtImpl::GetBootstrapState()
{
	return _dht_bootstrap;
}

/**
 *
 */
int DhtImpl::GetRate()
{
	return _dht_rate;
}

/**
 *
 */
int DhtImpl::GetQuota()
{
	return _dht_quota;
}

/**
 *
 */
int DhtImpl::GetNumOutstandingAddNodes()
{
	return _outstanding_add_node;
}

/**
 *
 */
int DhtImpl::GetProbeRate()
{
	return _dht_probe_rate;
}

/**
 *
 */
int DhtImpl::GetNumPeersTracked()
{
	return _peers_tracked;
}


//--------------------------------------------------------------------------------
//
//  Dht
//
//--------------------------------------------------------------------------------

void DhtImpl::Account(int slot, int size)
{
	DhtAccounting &acct = _dht_accounting[slot];
	acct.count++;
	acct.size += size;
}

#if !STABLE_VERSION || defined _DEBUG || defined BRANDED_MAC

bool DhtImpl::ValidateEncoding( const void * data, uint len )
{
	BencodedDict dict;
	bool bReturn = false;
	if( BencEntity::Parse((const byte*) data, dict, ((const byte*) data ) + len)) {
		size_t parselen = 0;
		byte *b = dict.Serialize(&parselen);
		if (b) {
			bReturn = (memcmp(data, b, len) == 0);
			free(b);
		}
	}
	assert(bReturn);
	return bReturn;
}

#endif

void DhtImpl::SendTo(const DhtPeerID &peer, const void *data, uint len)
{
	if (!_dht_enabled) return;

	assert(ValidateEncoding(data, len));
	Account(DHT_BW_OUT_TOTAL, len);

	if (_packet_callback) {
		_packet_callback(data, len, false);
	}

	_dht_quota -= len;

	//Need replace by the new WinRT udp socket implementation
	UDPSocketInterface *socketMgr = (peer.addr.isv4())?_udp_socket_mgr:
		_udp6_socket_mgr;
	assert(socketMgr);
	socketMgr->Send(peer.addr, (byte*)data, len);
}

bool CopyBytesToDhtID(DhtID &id, const byte *b)
{
	if (!b) return false;
	// Only works if machine is little endian.
	for(uint i=0; i!=20; i++)
		((byte*)&id)[i] = b[i^3];
	return true;
}

int CompareDhtIDToTarget(const DhtID &a, const DhtID &b, const DhtID &target)
{
	for(uint i=0; i<5; i++) {
		uint32 lhs = a.id[i] ^ target.id[i];
		uint32 rhs = b.id[i] ^ target.id[i];
		if (lhs > rhs) return 1;
		if (lhs < rhs) return -1;
	}
	return 0;
}

int CompareDhtID(const DhtID &a, const DhtID &b)
{
	for(uint i=0; i<5; i++) {
		if (a.id[i] > b.id[i]) return 1;
		if (a.id[i] < b.id[i]) return -1;
	}
	return 0;
}

int CompareDhtIDBytes(const DhtID &a, const DhtID &b, int num)
{
	//these bytes are in little endian. don't mess with them.
	byte abytes[20];
	byte bbytes[20];
	DhtIDToBytes(abytes, a);
	DhtIDToBytes(bbytes, b);
	return memcmp(abytes, bbytes, num);
}

void DhtIDToBytes(byte *b, const DhtID &id)
{
	for(uint i=0; i!=20; i++)
		b[i] = ((byte*)&id)[i^3];
}

/**
determine which bucket an id belongs to
*/
int DhtImpl::GetBucket(const DhtID &id)
{
	int left = -1;
	int right = _buckets.size();

	while (right - left > 1) {
		int mid = (left + right) >> 1;
		if (CompareDhtID(_buckets[mid]->first, id) <= 0)
			left = mid;
		else
			right = mid;
	}
	return left;
}

void DhtImpl::DumpAccountingInfo()
{
	DhtAccounting *acct = _dht_accounting;

	do_log("Received: %Lu requests (%#Z), %Lu replies (%#Z), %Lu no quota (%#Z), %Lu invalid (%#Z)",
		 acct[DHT_BW_IN_REQ].count,
		 acct[DHT_BW_IN_REQ].size,
		 acct[DHT_BW_IN_REPL].count,
		 acct[DHT_BW_IN_REPL].size,
		 acct[DHT_BW_IN_NO_QUOTA].count,
		 acct[DHT_BW_IN_NO_QUOTA].size,
		 acct[DHT_BW_IN_TOTAL].count-acct[DHT_BW_IN_REQ].count-acct[DHT_BW_IN_REPL].count,
		 acct[DHT_BW_IN_TOTAL].size-acct[DHT_BW_IN_REQ].size-acct[DHT_BW_IN_REPL].size);

	do_log("Sent: %Lu requests (%#Z), %Lu replies (%#Z)",
		acct[DHT_BW_OUT_TOTAL].count-acct[DHT_BW_OUT_REPL].count,acct[DHT_BW_OUT_TOTAL].size-acct[DHT_BW_OUT_REPL].size,
		acct[DHT_BW_OUT_REPL].count,acct[DHT_BW_OUT_REPL].size);

#if defined(_DEBUG_DHT)
	for (int i = DHT_INVALID_BASE+1; i < DHT_INVALID_END; i++) {
		do_log("Invalid type %d: %Lu occurances (%#Z)", i, acct[i].count, acct[i].size);
	}
#endif
}

void DhtImpl::DumpBuckets()
{
	int total = 0;
	int total_cache = 0;
	do_log("Num buckets: %d. My DHT ID: %s", _buckets.size(), format_dht_id(_my_id));

	for(uint i=0; i<_buckets.size(); i++) {
		DhtBucket &bucket = *_buckets[i];

		int cache_nodes = 0;
		for (DhtPeer **peer = &bucket.replacement_peers.first(); *peer; peer=&(*peer)->next) {
			cache_nodes++;
			total_cache++;
		}
		int main_nodes = 0;
		for (DhtPeer **peer = &bucket.peers.first(); *peer; peer=&(*peer)->next) {
			main_nodes++;
			total++;
		}

		do_log("Bucket %d: %.8X%.8X%.8X%.8X%.8X (nodes: %d replacement-nodes: %d, span: %d)", i,
			 bucket.first.id[0], bucket.first.id[1], bucket.first.id[2],
			 bucket.first.id[3], bucket.first.id[4], main_nodes, cache_nodes, bucket.span);
		for (DhtPeer **peer = &bucket.peers.first(); *peer; peer=&(*peer)->next) {
			DhtPeer *p = *peer;
			char age[64];
			if (p->first_seen) {
				size_t d = time(NULL) - p->first_seen;
				snprintf(age, sizeof(age), "%dm %ds", int(d / 60), int(d % 60));
			} else {
				strcpy(age, "?");
			}
//			do_log("    %s %A fail:%d seen:%d age:%s ver:%s rtt:%d",
//				 format_dht_id(p->id.id),
//				 &p->id.addr,  p->num_fail, p->lastContactTime, age,
//				 p->client.str(), p->rtt);
		}
	}
	do_log("Total peers: %d (in replacement cache %d)", total, total_cache);
	do_log("Outstanding add nodes: %d", _outstanding_add_node);
	DumpAccountingInfo();
}

void DhtImpl::DumpTracked()
{
	do_log("List of tracked torrents:");
	for(uint i=0; i!=_peer_store.size(); i++) {
		StoredContainer &sc = _peer_store[i];
		do_log("%d: %s/%s: %d peers", i, format_dht_id(sc.info_hash), sc.file_name?sc.file_name:"", sc.peers.size());
	}
	do_log("Total peers: %d", _peers_tracked);
	do_log("Total torrents: %d", _peer_store.size());
}

DhtBucket *DhtImpl::CreateBucket(uint position)
{
	DhtBucket *bucket = _dht_bucket_allocator.Alloc();
	bucket->peers.init();
	bucket->replacement_peers.init();
	bucket->last_active = time(NULL);
	_buckets.insert(_buckets.begin() + position, bucket);

	// update currently refreshing bucket
	if ((int)position < _refresh_bucket)
		_refresh_bucket++;

	return bucket;
}

int DhtImpl::NumBuckets() const
{
	return _buckets.size();
}

void DhtImpl::SplitBucket(uint bucket_id)
{
	// Insert the new bucket AFTER the old one.
	DhtBucket &new_bucket = *CreateBucket(bucket_id + 1);
	DhtBucket &old_bucket = *_buckets[bucket_id];

#if defined(_DEBUG_DHT)
	debug_log("Splitting bucket %s (%d)", format_dht_id(old_bucket.first), old_bucket.span);
#endif

	if (old_bucket.span == 0)
		return;

	assert(old_bucket.span != 0);

	uint span = old_bucket.span - 1;

	new_bucket.span = old_bucket.span = span;
	new_bucket.first = old_bucket.first;
	uint mask = (1 << (span & 31));
	uint slot = 4 - (span >> 5);

	new_bucket.first.id[slot] |= mask;

	int nold = 0, nnew = 0;

	// Sort peers to the right bucket
	for (DhtPeer **peer = &old_bucket.peers.first(); *peer; ) {
		// switch to new_bucket?
		DhtPeer *p = *peer;
		p->ComputeSubPrefix(span, KADEMLIA_BUCKET_SIZE_POWER); // reset the sub-prefix info for routing table performance optimization for the new span
		if (p->id.id.id[slot] & mask) {
			old_bucket.peers.unlinknext(peer);
			new_bucket.peers.enqueue(p);
			nnew++;
		} else {
			peer=&(*peer)->next;
			nold++;
		}
	}

#if defined(_DEBUG_DHT)
	debug_log("  old bucket: %s. %d peers.", format_dht_id(old_bucket.first), nold);
	debug_log("  new bucket: %s. %d peers.", format_dht_id(new_bucket.first), nnew);
#endif

	// Sort replacement peers to the right bucket
	for (DhtPeer **peer = &old_bucket.replacement_peers.first(); *peer;) {
		// switch to new_bucket?
		DhtPeer *p = *peer;
		p->ComputeSubPrefix(span, KADEMLIA_BUCKET_SIZE_POWER); // reset the sub-prefix info for routing table performance optimization for the new span
		if (p->id.id.id[slot] & mask) {
			old_bucket.replacement_peers.unlinknext(peer);
			new_bucket.replacement_peers.enqueue(p);
		} else {
			peer=&(*peer)->next;
		}
	}
}

DhtRequest *DhtImpl::LookupRequest(uint tid)
{
	for(DhtRequest *req = _requests.first(); req; req=req->next)
		if (req->tid == tid)
			return req;
	return NULL;
}

void DhtImpl::UnlinkRequest(DhtRequest *to_delete)
{
	DhtRequest **req;
	for(req = &_requests.first(); *req != to_delete; req=&(*req)->next) {}
	_requests.unlinknext(req);
}

DhtRequest *DhtImpl::AllocateRequest(const DhtPeerID &peer_id)
{
	DhtRequest *req = new DhtRequest;
	do {
		req->tid = rand();
	} while (LookupRequest(req->tid));
	_requests.enqueue(req);
	req->has_id = true;
	req->slow_peer = false;
	req->peer = peer_id;
	req->time = get_milliseconds();
	req->_pListener = NULL;
#if g_log_dht
	req->origin = DHT_ORIGIN_UNKNOWN;
#endif
	return req;
}

DhtRequest *DhtImpl::SendPing(const DhtPeerID &peer_id)
{
	char buf[120];
	SimpleBencoder sb(buf);
	char const* end = buf + sizeof(buf);

	DhtRequest *req = AllocateRequest(peer_id);

#ifdef _DEBUG_DHT
	debug_log("SEND PING(%d): %A", req->tid, &peer_id.addr);
#endif

	sb.p += snprintf(sb.p, (end - sb.p), "d1:ad2:id20:");
	sb.put_buf(_my_id_bytes, 20);
	sb.p += snprintf(sb.p, (end - sb.p), "e1:q4:ping");
	put_transaction_id(sb, Buffer((byte*)&req->tid, 4), end);
	put_version(sb, end);
	sb.p += snprintf(sb.p, (end - sb.p), "1:y1:qe");

	SendTo(peer_id, buf, sb.p - buf);
	return req;
}


/**
	Increase the error counter for a peer
*/
void DhtImpl::UpdateError(const DhtPeerID &id)
{
	int bucket_id = GetBucket(id.id);
	if(bucket_id < 0) return;
	DhtBucket &bucket = *_buckets[bucket_id];

	for (DhtPeer **peer = &bucket.peers.first(); *peer; peer=&(*peer)->next) {
		DhtPeer *p = *peer;
		// Check if the peer is already in the bucket
		if (id != p->id) continue;

		if (++p->num_fail >= (p->lastContactTime ? FAIL_THRES : FAIL_THRES_NOCONTACT)
			|| !bucket.replacement_peers.empty()) {
			// failed plenty of times... delete
#if g_log_dht
			g_dht_peertype_count[(*peer)->origin]--;
#endif
			bucket.peers.unlinknext(peer);
			if (!bucket.replacement_peers.empty()) {
				// move one from the replacement_peers instead.
				bucket.peers.enqueue(bucket.replacement_peers.PopBestNode(p->GetSubprefixInt()));
			}
			_dht_peer_allocator.Free(p);
			_dht_peers_count--;
			assert(_dht_peers_count >= 0);
		}
		return; // nodes in the primary list and the reserve list should be mutually exclusive
	}

	// Also check if the peer is in the replacement cache already.
	for (DhtPeer **peer = &bucket.replacement_peers.first(); *peer; peer=&(*peer)->next) {
		DhtPeer *p = *peer;
		// Check if the peer is already in the bucket
		if (id != p->id) continue;
		if (++p->num_fail >= (p->lastContactTime ? FAIL_THRES : FAIL_THRES_NOCONTACT)) {
#if g_log_dht
			g_dht_peertype_count[(*peer)->origin]--;
#endif
			bucket.replacement_peers.unlinknext(peer);
			_dht_peer_allocator.Free(p);
			_dht_peers_count--;
			assert(_dht_peers_count >= 0);
		}
		break;
	}
}


uint DhtImpl::CopyPeersFromBucket(uint bucket_id, DhtPeerID **list, uint numwant, int &wantfail, time_t min_age)
{
	DhtBucketList &bucket = _buckets[bucket_id]->peers;
	uint n = 0;
	for(DhtPeer *peer = bucket.first(); peer && n < numwant; peer=peer->next) {
		if (time(NULL) - peer->first_seen < min_age) {
			continue;
		}
		if (peer->num_fail < (peer->lastContactTime ? FAIL_THRES : FAIL_THRES_NOCONTACT) || --wantfail >= 0) {
			// TODO: v6
			if (!peer->id.addr.isv4())
				continue;
			list[n++] = &peer->id;
		}
	}
	return n;
}

struct dht_node_comparator
{
	dht_node_comparator(DhtID t): target(t) {}
	bool operator()(DhtPeerID const* a, DhtPeerID const* b) const {
		return CompareDhtIDToTarget(a->id, b->id, target) < 0;
	}
	DhtID target;
};

// Given the source list and size, sort it and copy the destCount closest
// to the dest list
void FindNClosestToTarget( DhtPeerID *src[], uint srcCount, DhtPeerID *dest[], uint destCount, const DhtID &target ){
	// sort the list to find the closest peers.
	// Seems to only be used on lists of 30 or smaller
	std::vector<DhtPeerID*> sorted_list(src, src + srcCount);
	if (destCount > srcCount) destCount = srcCount;
	std::sort(sorted_list.begin(), sorted_list.end(), dht_node_comparator(target));
	for(int i = 0; i < destCount ; i++)
		dest[i] = sorted_list[i];
}

int DhtImpl::AssembleNodeList(const DhtID &target, DhtPeerID** ids, int numwant)
{
	// Find 8 good ones or bad ones (in case there are no good ones)
	int num = FindNodes(target, ids, (std::min)(8, numwant), (std::min)(8, numwant), 0);
	assert(num <= numwant);
	// And 8 definitely good ones.
	num += FindNodes(target, ids + num, numwant - num, 0, 0);
	assert(num <= numwant);
	return num;
}

/**
 Find the numwant nodes closest to target
 Returns the number of nodes found.
*/
uint DhtImpl::FindNodes(const DhtID &target, DhtPeerID **list, uint numwant, int wantfail, time_t min_age)
{
	int bucket_id = GetBucket(target);
	if(bucket_id < 0) return 0;

	const int tempsize = 64;
	DhtPeerID *temp[tempsize];
	uint n = 0;

	// first grab peers from bucket 'bucket_id'.
	n += CopyPeersFromBucket(bucket_id, temp + n, tempsize-n, wantfail, min_age);

	// find the closest peers (approximately)
	int minb = bucket_id;
	uint maxb = bucket_id;
	while (n < numwant) {
		minb--;
		maxb++;
		if (maxb < _buckets.size())
			n += CopyPeersFromBucket(maxb, temp + n, tempsize-n, wantfail, min_age);
		else if (minb < 0)
			break;

		if (minb >= 0)
			n += CopyPeersFromBucket(minb, temp + n, tempsize-n, wantfail, min_age);
	}

	int num = (std::min)(numwant, n);

	// Return the numwant closest peers.
	FindNClosestToTarget(temp, n, list, num, target);

	return num;
}


void SimpleBencoder::Out(cstr s)
{
	while (*s)
		*p++ = *s++;
}

void SimpleBencoder::put_buf(byte const* buf, int len)
{
	while (len)
	{
		*p++ = *buf++;
		--len;
	}
}

#ifdef _DEBUG_MEM_LEAK
// **** NOTE ****
#error DhtProcess no longer exists and these functions were created to assist\
 an old memory leak tool not spam the developer with false positives.\
 If that tool is to be used again, these functions will need to be updated\
 to use the new DhtProcessBase.  Better still, is to use a more effective\
 modern memory leak detection tool.

//void DhtImpl::AddDhtProcess(DhtProcess *p)
//{
//	if(0 == _dhtprocesses_init)
//	{
//		_dhtprocesses.Init();
//		_dhtprocesses_init = 1;
//	}
//	_dhtprocesses.Append(p);
//}
//
//void DhtImpl::RemoveDhtProcess(DhtProcess *p)
//{
//	size_t position = _dhtprocesses.LookupElement(p);
//	_dhtprocesses.RemoveElement(position);
//}
//
//int DhtImpl::FreeRequests()
//{
//	int i;
//	_requests.clean_up();
//	_requests.init();
//	if(1 == _dhtprocesses_init)//dump it only if it is initialized
//	{
//		for(i = 0; i < _dhtprocesses.size(); i++)
//		{
//			delete (DhtProcess*)_dhtprocesses[i];
//		}
//		_dhtprocesses.Free();
//	}
//	_peer_store.clear();
//	return 0;
//}
#endif


//--------------------------------------------------------------------------------



// d( "a"= d("id" = <hash>, "target" = <hash>), "q"="find_node", "t" = 0, "y" = "q")
// d( "r" = d( "id" = <hash>, "nodes" = <208 byte string>), "t" = 1, "y" = "r")

int DhtImpl::BuildFindNodesPacket(SimpleBencoder &sb, DhtID &target_id, int size)
{
	DhtPeerID *list[KADEMLIA_K];
	uint n = FindNodes(target_id, list, sizeof(list)/sizeof(list[0]), 0, CROSBY_E);

	// Send an array of peers.
	// Each peer is 20 byte id, 4 byte ip and 2 byte port, in big endian format.

	// don't write more nodes than what will fit in size
	// 11 bytes is the overhead of printing "5:nodesxxx:"
	// if we can't fit a single node, just skip it
	if (size < 11 + 20 + 4 + 2) return 0;
	n = (std::min)(n, uint(size - 11) / (20 + 4 + 2));
	// never try to send more than 8 nodes
	// since 8 is the K constant in our kademlia implementation
	// i.e. bucket size
	if (n > 8) n = 8;

	sb.p += snprintf(sb.p, 27, "5:nodes%d:", n * 26); // XXX size is arbitrary
	for(uint i=0; i!=n; i++) {
		DhtIDToBytes((byte*)sb.p, list[i]->id);
		sb.p += 20;
		sb.p += list[i]->addr.compact((byte*)sb.p, true);
	}
	return n;
}

//ONLY FOR USE WITH InfoHashLessThan and GetStorageForID
//_info_hash_compare_length is ONLY FOR USE WHEN HOLDING THE NETWORK LOCK
int DhtImpl::InfoHashCmp(const DhtID &id1, const DhtID &id2, int len) {
	byte scabytes[20];
	byte scbbytes[20];
	DhtIDToBytes(scabytes, id1);
	DhtIDToBytes(scbbytes, id2);
	return memcmp(scabytes, scbbytes, len);
}

// Get the storage container associated with a info_hash
std::vector<VoteContainer>::iterator DhtImpl::GetVoteStorageForID(DhtID const& key) {
	VoteContainer vc;
	vc.key = key;
	return lower_bound(_vote_store.begin(), _vote_store.end(), vc);
}

class DhtSearchFunctor {
public:
	DhtSearchFunctor(int len) : _info_hash_compare_length(len) {};

	bool operator() (const StoredContainer& a, const StoredContainer& b) {
		return DhtImpl::InfoHashCmp(a.info_hash, b.info_hash, _info_hash_compare_length) < 0;
	}

	int _info_hash_compare_length;
};

// Get the storage container associated with a info_hash
std::vector<StoredContainer>::iterator DhtImpl::GetStorageForID(const DhtID &info_hash, int len)
{
	StoredContainer sc;
	sc.info_hash = info_hash;
	if (len == 20) {
		return lower_bound(_peer_store.begin(), _peer_store.end(), sc);
	} else {
		return lower_bound(_peer_store.begin(), _peer_store.end(), sc, DhtSearchFunctor(len));
	}
}

// Retrieve N random peers.
std::vector<StoredPeer> *DhtImpl::GetPeersFromStore(const DhtID &info_hash, int info_hash_len, /*output param*/DhtID *correct_info_hash, str* file_name, uint n)
{
	std::vector<StoredContainer>::iterator it = GetStorageForID(info_hash, info_hash_len);
	if (it == _peer_store.end())
		return NULL;

	StoredContainer *sc = &(*it);

	if (InfoHashCmp(sc->info_hash, info_hash, info_hash_len) != 0)
		return NULL;

	//if we have an exact match we should return the hash (if a partial)
	//and also return the file name we have stored for it
	if(info_hash_len < 20) {
		memcpy(correct_info_hash->id, sc->info_hash.id, sizeof(correct_info_hash->id));
	}
	if(sc->file_name && sc->file_name[0] != '\0') {
		*file_name = sc->file_name;
	}

	//the compare here will ensure that the first info_hash_len bytes of the info hashes match
	//this allows both partials and full matches through
	if (sc->peers.size() == 0)
		return NULL;

	// If the internal list contains LESS than the threshold, there's no need to shuffle.
	// We just return everything.
	if (n >= sc->peers.size())
		return &sc->peers;

	// Otherwise shuffle the first peers against the full list.
	std::random_shuffle(sc->peers.begin(), sc->peers.end());

	return &sc->peers;
}

void DhtImpl::hash_ip(SockAddr const& ip, sha1_hash& h)
{
	uint32 addr = ip.get_addr4();
	h = _sha_callback((const byte*)&addr, 4);
}

#ifdef _DEBUG_MEM_LEAK
//our version of new can't handle new (ptr) Type
//we redefine it after this struct
#undef new
#endif //_DEBUG_MEM_LEAK

// add a vote to the vote store for 'target'. Fill in a vote
// response into sb.
void DhtImpl::AddVoteToStore(SimpleBencoder& sb, DhtID& target
	, SockAddr const& addr, int vote)
{
	std::vector<VoteContainer>::iterator it = GetVoteStorageForID(target);

	VoteContainer* vc = 0;
	if (it != _vote_store.end() && it->key == target) {
		vc = &(*it);
	} else if (vote != 0 && _vote_store.size() < 1000) {
		// we don't have a store for this key
		// but this node is casting a vote, so
		// create a new entry to capture it
		vc = &(*_vote_store.insert(it, VoteContainer()));
		vc->key = target;
	} else {
		// we don't have any votes for this key
		return;
	}

	if (vote != 0) {
		vote = clamp(vote, 1, 5);
		vc->last_use = time(NULL);
		// align the 1-5 votes to the 0-4 array index
		--vote;
		sha1_hash key;
		hash_ip(addr, key);
		if (!vc->votes[vote].test(key)) {
			vc->votes[vote].add(key);
			++vc->num_votes[vote];
		}
	}

	// add response
	sb.p += snprintf(sb.p, 120, "1:vli%dei%dei%dei%dei%dee"
		, vc->num_votes[0] , vc->num_votes[1] , vc->num_votes[2]
		, vc->num_votes[3] , vc->num_votes[4]);
}
#ifdef _DEBUG_MEM_LEAK
//redefine this...undefed above to handle new (ptr) Type
#define new new(__FILE__,__LINE__)
#endif //_DEBUG_MEM_LEAK

void DhtImpl::AddPeerToStore(const DhtID &info_hash, cstr file_name, const SockAddr& addr, bool seed)
{
	// TODO: v6
	assert(addr.isv4());
	if (!addr.isv4())
		return;

	std::vector<StoredContainer>::iterator it = GetStorageForID(info_hash);
	StoredContainer *sc = NULL;

	if (it != _peer_store.end() && it->info_hash == info_hash) {
		sc = &(*it);
	}

	if (!sc) {
		if (_peers_tracked > MAX_PEERS)
			return;

		sc = &(*_peer_store.insert(it, StoredContainer()));
		sc->info_hash = info_hash;
		sc->file_name = (char*)malloc(MAX_FILE_NAME_LENGTH);
	}

	strncpy(sc->file_name, file_name?file_name:"\0", MAX_FILE_NAME_LENGTH);

	// Check if the peer is already in the peer list.
	for (uint j=0; j != sc->peers.size(); ++j) {
		StoredPeer &sp = sc->peers[j];
		SockAddr spaddr;
		spaddr.from_compact(sp.ip, 6);
		if (addr == spaddr) {
			sp.time = time(NULL);
			sp.seed = seed;
			return;
		}
	}

	if (_peers_tracked > MAX_PEERS)
		return;

	StoredPeer sp;
	addr.compact(sp.ip, true);
	sp.time = time(NULL);
	sp.seed = seed;
	sc->peers.push_back(sp);
	_peers_tracked++;
}

void DhtImpl::ExpirePeersFromStore(time_t expire_before)
{
	for(std::vector<StoredContainer>::iterator it = _peer_store.begin(); it != _peer_store.end(); ++it) {
		std::vector<StoredPeer> &sp = it->peers;
		for(uint j=0; j != sp.size(); j++) {
			if (sp[j].time < expire_before) {
				sp[j] = sp[sp.size()-1];
				sp.resize(sp.size() - 1);
				j--;
				_peers_tracked--;
			}
		}
		if (sp.size() == 0) {
			free(it->file_name);
			_peer_store.erase(it);
			--it;
		}
	}

	for (std::vector<VoteContainer>::iterator it = _vote_store.begin(); it != _vote_store.end(); ++it) {
		// if nobody has voted for 2 hours, expire it!
		if (it->last_use + 2 * 60 * 60 > time(NULL)) continue;

		_vote_store.erase(it);
		--it;
	}
}

void DhtImpl::GenerateWriteToken(sha1_hash *token, const DhtPeerID &peer_id)
{
	// TODO: v6
	assert(peer_id.addr.isv4());
	uint32 tokendata[4] = {
		_cur_token[0],
		_cur_token[1],
		peer_id.addr.get_addr4(),
		peer_id.addr.get_port()
	};
	*token = _sha_callback((const byte*)tokendata, sizeof(tokendata));
}

bool DhtImpl::ValidateWriteToken(const DhtPeerID &peer_id, const byte *token)
{

	// TODO: v6
	assert(peer_id.addr.isv4());

	// see if it matches the current token.
	uint32 tokendata[4] = {
		_cur_token[0],
		_cur_token[1],
		peer_id.addr.get_addr4(),
		peer_id.addr.get_port()
	};
	sha1_hash digest = _sha_callback((const byte*)tokendata, sizeof(tokendata));
	if (digest == token)
		return true;

	// See if it matches the prev token
	tokendata[0] = _prev_token[0];
	tokendata[1] = _prev_token[1];
	digest = _sha_callback((const byte*)tokendata, sizeof(tokendata));
	return digest == token;
}

void DhtImpl::RandomizeWriteToken()
{
	memcpy(_prev_token, _cur_token, sizeof(_prev_token));
	_cur_token[0] = rand();
	_cur_token[1] = rand();
}

#if defined(_DEBUG_DHT)
// packet handling
char *DhtImpl::hexify(byte *b)
{
	char const static hex[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
	static char buff[41];
	for(int i=0; i!=20; i++) {
		buff[i*2] = hex[b[i]>>4];
		buff[i*2+1] = hex[b[i]&0xF];
	}
	return buff;
}
#endif

bool DhtImpl::ParseIncomingICMP(BencEntity &benc, const SockAddr& addr)
{
	BencodedDict *dict = BencodedDict::AsDict(&benc);
	if (!dict)
		return false;

	cstr type = dict->GetString("y", 1);
	if (!type)
		return false;

	size_t tidlen;
	byte *tid = (byte*)dict->GetString("t", &tidlen);
	if (!tid || tidlen != sizeof(uint32))
		return false; // bad/missing tid

#ifdef _DEBUG_DHT
//	debug_log("%A: ICMP error, DHT message type:%c command:%s", &addr, *type, *type=='q'?dict->GetString("q"):"unknown");
#endif

	DhtPeerID peer_id;
	peer_id.addr = addr;

	if (*type != 'q')
		return false;

	cstr command = dict->GetString("q");
	if (!command)
		return false; // bad/missing command.

	DhtRequest *req = LookupRequest(Read32(tid));
	if (!req) {
#if defined(_DEBUG_DHT)
		debug_log("Unknown transaction ID %d", Read32(tid));
#endif
		return false;
	}

	// Verify that the source IP is correct.
	if (!req->peer.addr.ip_eq(peer_id.addr))
		return false;

	// HMM: stats for ICMP errors?
	//Account(DHT_BW_IN_REPL, pkt_size);

#if defined(_DEBUG_DHT)
	debug_log("Got ICMP error (%d seconds) tid=%d", (get_milliseconds() - req->time) / 1000, Read32(tid));
#endif

	UnlinkRequest(req);

	if (!strcmp(command, "ping")
		|| !strcmp(command, "find_node")
		|| !strcmp(command, "get_peers")
		|| !strcmp(command, "announce_peer")
		|| !strcmp(command, "vote")
		) {

		req->_pListener->Callback(req->peer, req, DhtProcessBase::dummyMessage,
			(DhtProcessFlags)ICMP_ERROR);
		delete req->_pListener;
	}

	// Cleanup
	delete req;
	return true;
}


void DhtImpl::AddIP(SimpleBencoder& sb, byte const* id, SockAddr const& addr)
{
	//verify the ip here...we need to notify them if they're using a
	//peer id that doesn't match with their external ip

//	if (!DhtVerifyHardenedID(addr, id, _sha_callback)) {
		//We want to always notify nodes of their external IP and port, 
		//partly because it's a good idea to always know your external IP and port, 
		//but specifically for BT Chat we want to store our own IP port in an encrypted data blob, in a put request	
		if (addr.isv4()) {
			sb.p += snprintf(sb.p, 35, "2:ip6:");
			sb.p += addr.compact((byte*)sb.p, true);
		} else {
			sb.p += snprintf(sb.p, 35, "2:ip18:");
			sb.p += addr.compact((byte*)sb.p, true);
		}
	}
//}


//--------------------------------------------------------------------------------
//
// DHTFEED
//
//--------------------------------------------------------------------------------

#if USE_DHTFEED
void DhtImpl::dht_name_resolved_static(void *ctx, const byte *info_hash, const byte *file_name)
{
	DhtImpl *impl = (DhtImpl*)ctx;
	impl->dht_name_resolved(info_hash, file_name);
}

#error resolving a name should be promoted to a top level function, and this should be moved out of the DHT
void DhtImpl::dht_name_resolved(const byte *info_hash, const byte *file_name)
{
	DHTFeedItem i;
	memset(&i, 0, sizeof(i));
	memcpy(i.info_hash.value, info_hash, sizeof(i.info_hash));

	BtScopedLock l;

	int index = TorrentSession::_dht_feed_items.BisectLeft(i);

	// this shouldn't happen
	assert(index != TorrentSession::_dht_feed_items.size());
	if (index == TorrentSession::_dht_feed_items.size()) return;

	DHTFeedItem& item = TorrentSession::_dht_feed_items[index];
	if (item.name == 0) utf8_to_tstr(&item.name, (char const*)file_name);
	item.resolving_name = false;
	LoadDHTFeed();
}

void DhtImpl::dht_on_scrape_static(void *ctx, const byte *info_hash, int downloaders, int seeds)
{
	DhtImpl *impl = (DhtImpl*)ctx;
	impl->dht_on_scrape(info_hash, downloaders, seeds);
}

void DhtImpl::dht_on_scrape(const byte *info_hash, int downloaders, int seeds)
{
	DHTFeedItem i;
	memset(&i, 0, sizeof(i));
	memcpy(i.info_hash.value, info_hash, sizeof(i.info_hash));

	BtScopedLock l;

	int index = TorrentSession::_dht_feed_items.BisectLeft(i);

	// this shouldn't happen
	assert(index != TorrentSession::_dht_feed_items.size());
	if (index == TorrentSession::_dht_feed_items.size()) return;

	DHTFeedItem& item = TorrentSession::_dht_feed_items[index];
	item.downloaders = downloaders;
	item.seeds = seeds;
	item.scraping = false;
}

void DhtImpl::add_to_dht_feed_static(void *ctx, byte const* info_hash, char const* file_name)
{
	DhtImpl *impl = (DhtImpl*)ctx;
	impl->add_to_dht_feed(info_hash, file_name);
}

void DhtImpl::add_to_dht_feed(byte const* info_hash, char const* file_name)
{
	DHTFeedItem i;
	memset(&i, 0, sizeof(i));
	memcpy(i.info_hash.value, info_hash, sizeof(i.info_hash));

	BtScopedLock l;

	int index = TorrentSession::_dht_feed_items.BisectLeft(i);
	if (index == TorrentSession::_dht_feed_items.size()
		|| memcmp(TorrentSession::_dht_feed_items[index].info_hash.value, info_hash, 20) != 0) {
		if (file_name) utf8_to_tstr(&i.name, file_name);
		else i.resolving_name = true;
		i.scraping = true;
		TorrentSession::_dht_feed_items.Insort(i);

		DhtID target;
		CopyBytesToDhtID(target, info_hash);
		if (file_name == 0) {
			// resolve the name
			ResolveName(target, &dht_name_resolved_static, (void*)this);
		}
		DoScrape(target, &dht_on_scrape_static, (void*)this);
	} else if (file_name) {
		DHTFeedItem& item = TorrentSession::_dht_feed_items[index];
		if (item.name == 0) utf8_to_tstr(&item.name, file_name);
	}
	LoadDHTFeed();
}
#endif

void DhtImpl::put_transaction_id(SimpleBencoder& sb, Buffer tid, char const* end)
{
	sb.p += snprintf(sb.p, (end - sb.p), "1:t%d:", int(tid.len));
	sb.put_buf(tid.b, tid.len);
}

void DhtImpl::put_version(SimpleBencoder& sb, char const* end)
{
	sb.p += snprintf(sb.p, (end - sb.p), "1:v4:%c%c%c%c"
		, _dht_utversion[0]
		, _dht_utversion[1]
		, _dht_utversion[2]
		, _dht_utversion[3]);
}

bool DhtImpl::ProcessQueryAnnouncePeer(const SockAddr &thisNodeAddress, DHTMessage& message, DhtPeerID &peerID, int packetSize)
{
	char buf[256];
	char const* const end = buf + sizeof(buf);
	SimpleBencoder sb(buf);

	// read port
	if (message.portNum < 0 && !message.impliedPort) {
		Account(DHT_INVALID_PQ_BAD_PORT, packetSize);
		return false;
	}

	// read the info hash
	DhtID info_hash_id;
	if (!CopyBytesToDhtID(info_hash_id, message.infoHash.b)) {
		Account(DHT_INVALID_PQ_AP_BAD_INFO_HASH, packetSize);
		return false;
	}

	// read the token
	if (!message.token.len) {
#if defined(_DEBUG_DHT)
		debug_log("Bad write token");
#endif
		Account(DHT_INVALID_PQ_BAD_WRITE_TOKEN, packetSize);
		return false;
	}

#if defined(_DEBUG_DHT)
		//TODO: use static temp and strcpy into it
		char* temp = strdup(format_dht_id(info_hash_id));
		debug_log("ANNOUNCE_PEER: id='%s', info_hash='%s', host='%A', token='%s'", format_dht_id(peerID.id), temp, &peerID.addr, hexify(message.token.b)); //TODO: valgrind fishiness
		free(temp);
#endif

	// validate the token
	if (!ValidateWriteToken(peerID, message.token.b)) {
		Account(DHT_INVALID_PQ_INVALID_TOKEN, packetSize);
		return false;
	}

	// TODO: v6
	assert(peerID.addr.isv4());
	if (!peerID.addr.isv4()) {
		Account(DHT_INVALID_PQ_IPV6, packetSize);
		return false;
	}

	SockAddr addr2 = peerID.addr;
	addr2.set_port(message.impliedPort ? peerID.addr.get_port() : message.portNum);
	AddPeerToStore(info_hash_id, (cstr)message.filename.b, addr2, message.seed);

#if USE_DHTFEED
	if (_sett.collect_dht_feed) {
		add_to_dht_feed(message.infoHash.b, (const char *)message.filename.b);
	}
#endif

	// Send a simple reply with my ID
	sb.p += snprintf(sb.p, (end - sb.p), "d");
	
	AddIP(sb, message.id, thisNodeAddress);

	sb.p += snprintf(sb.p, (end - sb.p), "1:rd2:id20:");
	sb.put_buf(_my_id_bytes, 20);
	sb.p += snprintf(sb.p, (end - sb.p), "e");

	put_transaction_id(sb, message.transactionID, end);
	put_version(sb, end);
	sb.p += snprintf(sb.p, (end - sb.p), "1:y1:re");

	Account(DHT_BW_IN_REQ, packetSize);
	assert(sb.p < buf + sizeof(buf));
	Account(DHT_BW_OUT_REPL, sb.p - buf);

	// Send the reply to the peer.
	SendTo(peerID, buf, sb.p - buf);
	return true;
}

bool DhtImpl::ProcessQueryGetPeers(const SockAddr &addr, DHTMessage &message, DhtPeerID &peerID, int packetSize)
{
	char buf[8192];
	char const* const end = buf + sizeof(buf);
	SimpleBencoder sb(buf);

	DhtID info_hash_id;
	sha1_hash ttoken;
	const int num_peers = 100;// maximum number of peers to return; much more than this won't fit in an MTU

	if (!CopyBytesToDhtID(info_hash_id, message.infoHash.b)) {
		Account(DHT_INVALID_PQ_GP_BAD_INFO_HASH, packetSize);
		return false;
	}

#if USE_DHTFEED
		if (s_core.collect_dht_feed) {
			add_to_dht_feed(message.infoHash.b, 0);
		}
#endif

	// Make sure the num_peers first peers are shuffled.
	// correct_info_hash_id will be filled in if this is a partial search and
	// the masked version of info_hash_id is a match.
	DhtID correct_info_hash_id;
	DhtID null_id;
	memset(null_id.id, 0, sizeof(null_id.id));
	memset(correct_info_hash_id.id, 0, sizeof(correct_info_hash_id.id));
	str file_name = NULL;

	// start the output info
	sb.Out("d");

	AddIP(sb, message.id, addr);

	sb.Out("1:rd");

	const std::vector<StoredPeer> *sc = GetPeersFromStore(info_hash_id
			, message.infoHash.len, &correct_info_hash_id, &file_name, num_peers);

	if (sc != NULL && message.scrape) {
		// scrape instead of return peers
		bloom_filter seeds(2048, 2);
		bloom_filter downloaders(2048, 2);

		for (int i = 0; i < sc->size(); ++i) {
			StoredPeer const& p = (*sc)[i];
			sha1_hash h = _sha_callback(p.ip, sizeof(p.ip));
			if (p.seed) {
				seeds.add(h);
			}
			else downloaders.add(h);
		}

		sb.p += snprintf(sb.p, (end - sb.p), "4:BFpe256:");
		sb.put_buf(downloaders.get_set(), 256);
		sb.p += snprintf(sb.p, (end - sb.p), "4:BFsd256:");
		sb.put_buf(seeds.get_set(), 256);
	}

	GenerateWriteToken(&ttoken, peerID);
	sb.p += snprintf(sb.p, 35, "2:id20:");
	sb.put_buf(_my_id_bytes, 20);

	if (correct_info_hash_id != null_id) {
		byte correct_info_hash_id_bytes[20];
		DhtIDToBytes(correct_info_hash_id_bytes, correct_info_hash_id);
		sb.p += snprintf(sb.p, (end - sb.p), "9:info_hash20:");
		sb.put_buf(correct_info_hash_id_bytes, 20);
	}

	if (message.filename.len) {
		int len = (message.filename.len>50) ? 50 : message.filename.len;
		// the max filename length of 50 here is really to be
		// extra conservative with the quite limited MTU space.
		// nodes and peers are much more useful than the filename
		// and should get the vast majority of it
		sb.p += snprintf(sb.p, (end - sb.p), "1:n%d:%.*s", len, len, message.filename.b);
	}

	bool has_values = sc != NULL && !message.scrape;
	uint n = (std::min)((sc ? sc->size() : 0), size_t(num_peers));
	int size =
		(sb.p - buf) // written so far
		+ (has_values ? (10 + n * 8) : 0) // the values
		+ 30 // token
		+ 7 + message.transactionID.len + 18; // tail (t, v and y)

	const uint16 mtu = GetUDP_MTU(addr);
	assert(size <= mtu);

	BuildFindNodesPacket(sb, info_hash_id, mtu - size);
	sb.p += snprintf(sb.p, (end - sb.p), "5:token20:");
	sb.put_buf(ttoken.value, 20);

#if defined(_DEBUG_DHT)
	char const* temp = format_dht_id(info_hash_id);
	debug_log("GET_PEERS: id='%s', info_hash='%s', token='%s'",
			 format_dht_id(peerID.id), temp, hexify(ttoken.value));
#endif

	if (has_values) {
		int left = mtu - (sb.p - buf + 10);
		if (n > left / 8) n = left / 8;
		assert(sb.p - buf + 10 + 8 * n <= mtu);
		if (n > 0) {
			sb.p += snprintf(sb.p, end - sb.p, "6:valuesl");
			for(uint i=0; i!=n; i++) {
				sb.p += snprintf(sb.p, (end - sb.p), "6:");
				// This will print out the ip/port
				sb.put_buf((*sc)[i].ip, 4);
				sb.put_buf((*sc)[i].port, 2);
			}
			*sb.p++ = 'e';
		}
	}

	assert(sb.p - buf <= mtu);
	sb.p += snprintf(sb.p, (end - sb.p), "e");

	Account(DHT_BW_IN_REQ, packetSize);
	put_transaction_id(sb, message.transactionID, end);
	put_version(sb, end);

	sb.p += snprintf(sb.p, (end - sb.p), "1:y1:re");

	assert(sb.p < buf + sizeof(buf));
	Account(DHT_BW_OUT_REPL, sb.p - buf);

	// Send the reply to the peer.
	SendTo(peerID, buf, sb.p - buf);
	return true;
}

bool DhtImpl::ProcessQueryFindNode(const SockAddr &addr, DHTMessage &message, DhtPeerID &peerID, int packetSize)
{
	DhtID target_id;
	if (!CopyBytesToDhtID(target_id, message.target.b)) {
		Account(DHT_INVALID_PQ_BAD_TARGET_ID, packetSize);
		return false;
	}

	char buf[512];
	char const* const end = buf + sizeof(buf);
	SimpleBencoder sb(buf);

	// Send my own ID
	sb.p += snprintf(sb.p, (end - sb.p), "d");
	
	AddIP(sb, message.id, addr);
	
	sb.p += snprintf(sb.p, (end - sb.p), "1:rd2:id20:");
	sb.put_buf(_my_id_bytes, 20);

	int size =
		(sb.p - buf) // written so far
		+ 7 + message.transactionID.len + 18; // tail (t, v and y)

	const uint16 mtu = GetUDP_MTU(addr);
	assert(size <= mtu);

#if defined(_DEBUG_DHT)
	uint n =
#endif
		BuildFindNodesPacket(sb, target_id, mtu - size);

#if defined(_DEBUG_DHT)
	debug_log("FIND_NODE: %s. Found %d peers."
		, format_dht_id(target_id), n);
#endif

	assert(sb.p - buf <= mtu);

	Account(DHT_BW_IN_REQ, packetSize);
	sb.p += snprintf(sb.p, (end - sb.p), "e");

	put_transaction_id(sb, message.transactionID, end);
	put_version(sb, end);
	sb.p += snprintf(sb.p, (end - sb.p), "1:y1:re");

	assert(sb.p < buf + sizeof(buf));
	Account(DHT_BW_OUT_REPL, sb.p - buf);

	// Send the reply to the peer.
	SendTo(peerID, buf, sb.p - buf);
	return true;
}

void DhtImpl::send_put_response(SimpleBencoder& sb, char const* end,
		Buffer& transaction_id, int packetSize, DhtPeerID &peerID) {
	char const * const original = sb.p;
	sb.p += snprintf(sb.p, (end - sb.p), "d1:rd2:id20:");
	sb.put_buf(_my_id_bytes, 20);
	sb.p += snprintf(sb.p, (end - sb.p), "e");

	put_transaction_id(sb, transaction_id, end);
	put_version(sb, end);
	sb.p += snprintf(sb.p, (end - sb.p), "1:y1:re");
	assert(sb.p < end);
	Account(DHT_BW_IN_REQ, packetSize);
	Account(DHT_BW_OUT_REPL, sb.p - original);
	SendTo(peerID, original, sb.p - original);
}

void DhtImpl::send_put_response(SimpleBencoder& sb, char const* end,
		Buffer& transaction_id, int packetSize, DhtPeerID &peerID,
		unsigned int error_code, char const* error_message) {
	assert(error_message != NULL);
	char const * const original = sb.p;
	sb.p += snprintf(sb.p, (end - sb.p), "d1:eli%ue%zu:%se", error_code,
			strlen(error_message), error_message);
	sb.p += snprintf(sb.p, (end - sb.p), "1:rd2:id20:");
	sb.put_buf(_my_id_bytes, 20);
	sb.p += snprintf(sb.p, (end - sb.p), "e");

	put_transaction_id(sb, transaction_id, end);
	put_version(sb, end);
	sb.p += snprintf(sb.p, (end - sb.p), "1:y1:ee");
	assert(sb.p < end);
	Account(DHT_BW_IN_REQ, packetSize);
	Account(DHT_BW_OUT_REPL, sb.p - original);
	SendTo(peerID, original, sb.p - original);
}

bool DhtImpl::ProcessQueryPut(const SockAddr &addr, DHTMessage &message, DhtPeerID &peerID, int packetSize) {
	char buf[256];
	char const* const end = buf + sizeof(buf);
	SimpleBencoder sb(buf);
	DhtID targetDhtID;

	// read the token
	if (!message.token.len) {
#if defined(_DEBUG_DHT)
//		debug_log("Bad write token");
#endif
		Account(DHT_INVALID_PQ_BAD_WRITE_TOKEN, packetSize);
		return false;
	}

	// validate the token
	if (!ValidateWriteToken(peerID, message.token.b)) {
		Account(DHT_INVALID_PQ_INVALID_TOKEN, packetSize);
		return false;
	}

	// TODO: v6
	assert(peerID.addr.isv4());
	if (!peerID.addr.isv4()) {
		Account(DHT_INVALID_PQ_IPV6, packetSize);
		return true;
	}

	// make sure v is not larger than 1000 bytes or smaller than is possible for a bencoded element
	if(message.vBuf.len < 2 || message.vBuf.len > 1000)
	{	// v is too big or small
		Account(DHT_INVALID_PQ_BAD_PUT_BAD_V_SIZE, packetSize);
		send_put_response(sb, end, message.transactionID, packetSize, peerID,
				MESSAGE_TOO_BIG, "Message exceeds maximum size.");
		return true;
	}

	if(message.key.len && message.sequenceNum && message.signature.len)
	{ // mutable put

		if(message.key.len != 32 || message.signature.len != 64) {
			Account(DHT_INVALID_PQ_BAD_PUT_KEY, packetSize);
			return true;
		}
		if (!Verify(message.signature.b, message.vBuf.b, message.vBuf.len, message.key.b, message.sequenceNum)) {
			Account(DHT_INVALID_PQ_BAD_PUT_SIGNATURE, packetSize);
			send_put_response(sb, end, message.transactionID, packetSize, peerID,
					INVALID_SIGNATURE, "Invalid message signature.");
			return true;
		}

		// make a hash of the address for the DataStores to use to record usage of an item
		const sha1_hash addrHashPtr = _sha_callback((const byte*)addr.get_hash_key(), addr.get_hash_key_len());

		// at this point, the put request has been verified
		// store the data under a sha1 hash of the entire public key
		CopyBytesToDhtID(targetDhtID, _sha_callback((const byte*)message.key.b, message.key.len).value);
		PairContainerBase<MutableData>* containerPtr = NULL;
		if (_mutablePutStore.AddKeyToList(addrHashPtr, targetDhtID, &containerPtr, time(NULL)) == NEW_ITEM){
			// this is new to the store, set the sequence num, copy the 'v' bytes, store the signature and key
			containerPtr->value.sequenceNum = message.sequenceNum;
			for (int x=0; x<message.vBuf.len; ++x){
				containerPtr->value.v.push_back(message.vBuf.b[x]);
			}
			// store the signature
			containerPtr->value.rsaSignatureLen = message.signature.len;
			for (int x=0; x<message.signature.len; ++x){
				containerPtr->value.rsaSignature[x] = message.signature.b[x];
			}
			// store the key
			for (int x=0; x<message.key.len; ++x){
				containerPtr->value.rsaKey.push_back(message.key.b[x]);
			}
			byte to_hash[1040]; // 1000 byte message + seq + formatting
			int written = snprintf(reinterpret_cast<char*>(to_hash), 1040,
					MUTABLE_PAYLOAD_FORMAT, message.sequenceNum);
			assert((written + message.vBuf.len) <= 1040);
			memcpy(to_hash + written, message.vBuf.b, message.vBuf.len);

			//fprintf(stderr, "in put: %s\n", (char*)to_hash);
			containerPtr->value.cas = _sha_callback(to_hash, written + message.vBuf.len);
			// update the time
			containerPtr->lastUse = time(NULL);
		} else {
			// check that the sequence num is larger (newer) than what is currently in
			// the store, and update 'v' bytes, sequence num, and signature
			// No need to update the key here, we already have it and it is not changing.
			if (message.sequenceNum >= containerPtr->value.sequenceNum) {
				if (!(message.cas.is_all_zero()) &&
						message.cas != containerPtr->value.cas) {
					Account(DHT_INVALID_PQ_BAD_PUT_CAS, packetSize);
					send_put_response(sb, end, message.transactionID, packetSize, peerID,
							CAS_MISMATCH, "Invalid CAS.");
					return true;
				} else {
					if (message.sequenceNum > containerPtr->value.sequenceNum) {
						// update the sequence number
						containerPtr->value.sequenceNum = message.sequenceNum;
						// update the value stored
						containerPtr->value.v.clear();
						for (int x=0; x<message.vBuf.len; ++x){
							containerPtr->value.v.push_back(message.vBuf.b[x]);
						}
						// update the signature
						containerPtr->value.rsaSignatureLen = message.signature.len;
						for (int x=0; x<message.signature.len; ++x){
							containerPtr->value.rsaSignature[x] = message.signature.b[x];
						}
					}
					// update the last time accessed
					containerPtr->lastUse = time(NULL);
				}
			} else {
					send_put_response(sb, end, message.transactionID, packetSize, peerID,
							LOWER_SEQ, "Replacement sequence number is lower.");
					return true;
			}
		}
	} else {
		// immutable put
		// make a hash of the address for the DataStores to use to record usage of an item
		const sha1_hash addrHashPtr = _sha_callback((const byte*)addr.get_hash_key(), addr.get_hash_key_len());

		CopyBytesToDhtID(targetDhtID, _sha_callback((const byte*)message.vBuf.b, message.vBuf.len).value);
		PairContainerBase<std::vector<byte> >* containerPtr = NULL;
		// if the data length is 0 then this is a new container, copy the bytes to it.
		if (_immutablePutStore.AddKeyToList(addrHashPtr, targetDhtID, &containerPtr, time(NULL)) == NEW_ITEM) {
			for (int x=0; x<message.vBuf.len; ++x){
				containerPtr->value.push_back(message.vBuf.b[x]);
			}
			containerPtr->lastUse = time(NULL);
		}
	}

	// build a simple reply with this node's ID
	send_put_response(sb, end, message.transactionID, packetSize, peerID);
	return true;
}


bool DhtImpl::ProcessQueryGet(const SockAddr &addr, DHTMessage &message, DhtPeerID &peerID, int packetSize)
{
	char buf[8192];
	char const* const end = buf + sizeof(buf);
	SimpleBencoder sb(buf);

	DhtID targetId;
	sha1_hash ttoken;
	Buffer valueToReturn;    // constructor initializes buffers to NULL & 0
	Buffer signatureToReturn;
	Buffer keyToReturn;
	DataStore<DhtID, MutableData>::pair_iterator mutableStoreIterator;
	int64_t sequenceNum;
	// if there is no target, there is nothing to do
	if (message.target.len == 0){
		Account(DHT_INVALID_PQ_BAD_GET_TARGET, packetSize);
		return false;
	}

	// get a 'v' value to return and point the valuToReturn Buffer to those bytes if they exist
	//
	// 'target' will either be the:
	//   a) sha1 hash of a public key for mutable data
	//   b) sha1 hash of the immutable 'v' data
	//
	// The 'k' key element, if it is provided, can be used to avoid searching
	// the immutable store.  In either case, it is good to search the mutable store
	// regardless of whether a key is provided or not.

	CopyBytesToDhtID(targetId, message.target.b);

	// make a hash of the address for the DataStores to use to record usage of an item
	const sha1_hash hashPtr = _sha_callback((const byte*)addr.get_hash_key(), addr.get_hash_key_len());

	mutableStoreIterator = _mutablePutStore.FindInList(targetId, time(NULL), hashPtr); // look in the mutable table first
	if (mutableStoreIterator != _mutablePutStore.end()) {
		// we have found a match in the mutable table
		assert(mutableStoreIterator->first == targetId);
		valueToReturn.len = mutableStoreIterator->second.value.v.size();
		valueToReturn.b = &(mutableStoreIterator->second.value.v.front());
		signatureToReturn.len = mutableStoreIterator->second.value.rsaSignatureLen;
		signatureToReturn.b = (byte*)(mutableStoreIterator->second.value.rsaSignature);
		keyToReturn.len = mutableStoreIterator->second.value.rsaKey.size();
		keyToReturn.b = &(mutableStoreIterator->second.value.rsaKey.front());
		sequenceNum = mutableStoreIterator->second.value.sequenceNum;
		mutableStoreIterator->second.lastUse = time(NULL);
	}
	else if (message.key.len == 0)
	{
		// no key, look in the immutable table with the same target
		DataStore<DhtID, std::vector<byte> >::pair_iterator immutableStoreIterator;
		immutableStoreIterator = _immutablePutStore.FindInList(targetId, time(NULL), hashPtr);
		if (immutableStoreIterator != _immutablePutStore.end())
		{
			// we have a v value
			assert(immutableStoreIterator->first == targetId);
			valueToReturn.len = immutableStoreIterator->second.value.size();
			valueToReturn.b = &(immutableStoreIterator->second.value.front());
			immutableStoreIterator->second.lastUse = time(NULL);
		}
	}

	const uint16 mtu = GetUDP_MTU(addr);
	int size =
		(sb.p - buf) // written so far
		+ keyToReturn.len ? (5 + keyToReturn.len) : 0       // "4:key" + number of key bytes
		+ signatureToReturn.len ? 5 + signatureToReturn.len : 0 // "4:sig" + number of signature bytes
		+ valueToReturn.len ? 3 + valueToReturn.len : 0    // "1:v" + num bytes for value 'v'
		+ 30 // token
		+ 7 + message.transactionID.len + 18; // tail (t, v and y)
	assert(size <= mtu);

	// start the output info
	sb.Out("d1:rd");
	sb.p += snprintf(sb.p, 35, "2:id20:");
	sb.put_buf(_my_id_bytes, 20);

	if (keyToReturn.len){	// add a "key" field to the response, if there is one
		sb.p += snprintf(sb.p, (end-sb.p), "3:key%d:", int(keyToReturn.len));
		sb.put_buf((byte*)keyToReturn.b, keyToReturn.len);
	}

	BuildFindNodesPacket(sb, targetId, mtu - size);

	sb.p += snprintf(sb.p, (end - sb.p), "3:seqi");
	sb.p += snprintf(sb.p, (end - sb.p), "%" PRId64 "e", sequenceNum);

	if (signatureToReturn.len){	// add a "sig" field to the response, if there is one
		sb.p += snprintf(sb.p, (end-sb.p), "3:sig%d:", int(signatureToReturn.len));
		sb.put_buf((byte*)signatureToReturn.b, signatureToReturn.len);
	}

	GenerateWriteToken(&ttoken, peerID);
	sb.p += snprintf(sb.p, (end - sb.p), "5:token20:");
	sb.put_buf(ttoken.value, 20);

	if (valueToReturn.len){	// add a "v" field to the response, if there is one
		sb.p += snprintf(sb.p, (end-sb.p), "1:v");
		sb.put_buf(valueToReturn.b, valueToReturn.len);
	}

	assert(sb.p - buf <= mtu);
	Account(DHT_BW_IN_REQ, packetSize);

	sb.p += snprintf(sb.p, (end - sb.p), "e");
	put_transaction_id(sb, message.transactionID, end);
	put_version(sb, end);
	sb.p += snprintf(sb.p, (end - sb.p), "1:y1:re");

	assert(sb.p < buf + sizeof(buf));
	Account(DHT_BW_OUT_REPL, sb.p - buf);

	// Send the reply
	SendTo(peerID, buf, sb.p - buf);
	return true;
}


bool DhtImpl::ProcessQueryVote(const SockAddr &addr, DHTMessage &message, DhtPeerID &peerID, int packetSize)
{
	char buf[512];
	char const* const end = buf + sizeof(buf);
	SimpleBencoder sb(buf);

	// read the target
	DhtID target_id;
	if (!CopyBytesToDhtID(target_id, message.target.b)) {
		Account(DHT_INVALID_PQ_BAD_TARGET_ID, packetSize);
		return false;
	}

	// read the token
	if (!message.token.len) {
#if defined(_DEBUG_DHT)
		debug_log("Bad write token");
#endif
		Account(DHT_INVALID_PQ_BAD_WRITE_TOKEN, packetSize);
		return false;
	}

	// validate the token
	if (!ValidateWriteToken(peerID, message.token.b)) {
		Account(DHT_INVALID_PQ_INVALID_TOKEN, packetSize);
		return false;
	}

	// Send my own ID
	sb.p += snprintf(sb.p, (end - sb.p), "d");

	AddIP(sb, message.id, addr);

	sb.p += snprintf(sb.p, (end - sb.p), "1:rd2:id20:");
	sb.put_buf(_my_id_bytes, 20);

	if (message.vote > 5) message.vote = 5;
	else if (message.vote < 0) message.vote = 0;

	AddVoteToStore(sb, target_id, addr, message.vote);

	assert(sb.p - buf <= GetUDP_MTU(addr));

	Account(DHT_BW_IN_REQ, packetSize);

	sb.p += snprintf(sb.p, (end - sb.p), "e");

	put_transaction_id(sb, message.transactionID, end);
	put_version(sb, end);
	sb.p += snprintf(sb.p, (end - sb.p), "1:y1:re");

	assert(sb.p < buf + sizeof(buf));
	Account(DHT_BW_OUT_REPL, sb.p - buf);

	// Send the reply to the peer.
	SendTo(peerID, buf, sb.p - buf);
	return true;
}

bool DhtImpl::ProcessQueryPing(const SockAddr &addr, DHTMessage &message, DhtPeerID &peerID, int packetSize)
{
	char buf[256];
	char const* const end = buf + sizeof(buf);
	SimpleBencoder sb(buf);

#if defined(_DEBUG_DHT)
		debug_log("PING");
#endif

	sb.p += snprintf(sb.p, (end - sb.p), "d");

	AddIP(sb, message.id, addr);

	sb.p += snprintf(sb.p, (end - sb.p), "1:rd2:id20:");
	sb.put_buf(_my_id_bytes, 20);
	sb.p += snprintf(sb.p, (end - sb.p), "e");

	put_transaction_id(sb, message.transactionID, end);
	put_version(sb, end);
	sb.p += snprintf(sb.p, (end - sb.p), "1:y1:re");

	Account(DHT_BW_IN_REQ, packetSize);
	assert(sb.p < buf + sizeof(buf));
	Account(DHT_BW_OUT_REPL, sb.p - buf);

	// Send the reply to the peer.
	SendTo(peerID, buf, sb.p - buf);
	return true;
}

bool DhtImpl::ProcessQuery(const SockAddr& addr, DHTMessage &message, int packetSize)
{
	// Out of DHT quota.. No space to send a reply.
	if (_dht_quota < 0) {
		// we don't really know it was valid, but otherwise it's marked as invalid
		Account(DHT_BW_IN_REQ, packetSize);
		Account(DHT_BW_IN_NO_QUOTA, packetSize);
		return false;
	}

	DhtPeerID peerID;
	peerID.addr = addr;

	// Update the internal DHT tables with the ID
	if (!CopyBytesToDhtID(peerID.id, message.id)) {
		Account(DHT_INVALID_PQ_BAD_ID_FIELD, packetSize);
		return false; // bad/missing ID field
	}
	DhtPeer *peer = Update(peerID, IDht::DHT_ORIGIN_INCOMING, false);
	// Update version
	if (peer != NULL) {
		peer->client.from_compact(message.version.b, message.version.len);
	}

	switch(message.dhtCommand){
		case DHT_QUERY_PING: return ProcessQueryPing(addr, message, peerID, packetSize);
		case DHT_QUERY_FIND_NODE: return ProcessQueryFindNode(addr, message, peerID, packetSize);
		case DHT_QUERY_GET_PEERS: return ProcessQueryGetPeers(addr, message, peerID, packetSize);
		case DHT_QUERY_ANNOUNCE_PEER: return ProcessQueryAnnouncePeer(addr, message, peerID, packetSize);
		case DHT_QUERY_VOTE: return ProcessQueryVote(addr, message, peerID, packetSize);
		case DHT_QUERY_PUT: return ProcessQueryPut(addr, message, peerID, packetSize);
		case DHT_QUERY_GET: return ProcessQueryGet(addr, message, peerID, packetSize);
		case DHT_QUERY_UNDEFINED: return false;
	}

	return true;
}

bool DhtImpl::ProcessResponse(const SockAddr& addr,
	DHTMessage &message,
	int pkt_size)
{
	DhtPeerID peer_id;
	peer_id.addr = addr;

	// Handle a response to one of our requests.
	if (message.transactionID.len != 4) {
		Account(DHT_INVALID_PR_BAD_TID_LENGTH, pkt_size);
		return false; // invalid transaction id format?
	}

	DhtRequest *req = LookupRequest(Read32(message.transactionID.b));
	if (!req) {
#if defined(_DEBUG_DHT)
		debug_log("Invalid transaction ID tid:%d", Read32(message.transactionID.b));
#endif
		Account(DHT_INVALID_PR_UNKNOWN_TID, pkt_size);
		return false;	// invalid transaction id?
	}

	// Update the internal DHT tables with the ID
	byte *id = (byte*)message.replyDict->GetString("id", 20);
	if (!CopyBytesToDhtID(peer_id.id, id)) {
		Account(DHT_INVALID_PR_BAD_ID_FIELD, pkt_size);
		return false; // bad/missing ID field
	}

	// Verify that the id contained in the message matches with the peer id.
	if (req->has_id && !(req->peer.id == peer_id.id)) {
		Account(DHT_INVALID_PR_PEER_ID_MISMATCH, pkt_size);
		return false;
	}

	// Verify that the source IP is correct.
	if (!req->peer.addr.ip_eq(peer_id.addr)) {
		Account(DHT_INVALID_PR_IP_MISMATCH, pkt_size);
		return false;
	}

	Account(DHT_BW_IN_REPL, pkt_size);

	// It's possible that the peer uses a different port # for outgoing packets.
	// Report the port we sent the packet to.
	peer_id.addr.set_port(req->peer.addr.get_port());

#if defined(_DEBUG_DHT)
	debug_log("Got reply from (%d seconds) tid=%d",
		int32(get_milliseconds() - req->time) / 1000, Read32(message.transactionID.b));
#endif
#if g_log_dht
	dht_log("dlok replytime:%u\n", get_milliseconds() - req->time);
#endif

	UnlinkRequest(req);

	int rtt = (std::max)(int(get_milliseconds() - req->time), 1);

	// Update the internal tables with this peer's information
	// The contacted attribute is set because it replied to a query.
	DhtPeer *peer = Update(peer_id, IDht::DHT_ORIGIN_UNKNOWN, true, rtt);

	// Update version field
	if (peer != NULL) {
		peer->client.from_compact(message.version.b, message.version.len);
	}

	// Count the reported external IP address, if any
	if(message.dhtMessageType == DHT_RESPONSE){ // only if we have a valid "r" dictionary
		SockAddr myIp;
		if(message.external_ip.len == 6){
			myIp.set_addr4(*((uint32 *) message.external_ip.b));
			myIp.set_port(ReadBE16(message.external_ip.b+4));
		}else if(message.external_ip.len == 18){
			myIp.set_addr6(*((in6_addr *) message.external_ip.b));
			myIp.set_port(ReadBE16(message.external_ip.b+16));
		}
		if (!myIp.is_addr_any()){
			CountExternalIPReport(myIp, req->peer.addr);
		}
	}

	// Call the completion callback
	req->_pListener->Callback(req->peer, req, message, (DhtProcessFlags)NORMAL_RESPONSE);
	delete req->_pListener;
	// Cleanup
	delete req;
	return true;
}

bool DhtImpl::ProcessError(cstr e)
{
	// Handle an error for one of our requests.
#if defined(_DEBUG_DHT)
	debug_log("**** GOT ERROR '%s'", e);
#endif
	return true;
}

bool DhtImpl::InterpretMessage(DHTMessage &message, const SockAddr& addr, int pkt_size)
{
	if (!message.transactionID.b || message.transactionID.len > 16) {
		Account(DHT_INVALID_PI_BAD_TID, pkt_size);
		return false; // bad/missing tid
	}

	switch(message.dhtMessageType)
	{
		case DHT_QUERY:
		{
			// Handle a query from a peer
			if(message.dhtCommand == DHT_QUERY_UNDEFINED){
				Account(DHT_INVALID_PI_Q_BAD_COMMAND, pkt_size);
				return false; // bad/missing command.
			}

			if(!message.ValidArguments()){
				Account(DHT_INVALID_PI_Q_BAD_ARGUMENT, pkt_size);
				return false; // bad/missing argument.
			}
			return ProcessQuery(addr, message, pkt_size);
		}
		case DHT_RESPONSE:
		{
			assert(message.replyDict);
			return ProcessResponse(addr, message, pkt_size);
		}
		case DHT_ERROR:
		{
			Account(DHT_INVALID_PI_ERROR, pkt_size);
			return ProcessError(message.GetBencodedDictionary().GetString("e"));
		}
		default:
		{
			Account(DHT_INVALID_PI_NO_TYPE, pkt_size);
			return false;
		}
	}
	return false;
}

void DhtImpl::GenRandomIDInBucket(DhtID &target, DhtBucket &bucket)
{
	target = bucket.first;
	uint span = bucket.span;
	uint i = 4;
	while (span > 32) {
		target.id[i] = rand();
		span -= 32;
		i -= 1;
	}
	assert(i >= 0 && i <= 4);
	uint32 m = 1 << span;
	target.id[i] = (target.id[i] & ~(m - 1)) | (rand() & (m - 1));
}

void DhtImpl::GetStalestPeerInBucket(DhtPeer **ppeerFound, DhtBucket &bucket)
{
	time_t oldest = time(NULL);
	for(DhtPeer *peer = bucket.peers.first(); peer != NULL; peer=peer->next) {
		if(!peer->lastContactTime){
			*ppeerFound = peer;
			break;	// Never lastContactTime; consider most stale
		}
		if (peer->lastContactTime < oldest) {
			*ppeerFound = peer;
			oldest = peer->lastContactTime;
		}
	}
}

void DhtImpl::DoFindNodes(DhtID &target, int target_len, IDhtProcessCallbackListener *process_listener, bool performLessAgressiveSearch)
{
	int maxOutstanding = (performLessAgressiveSearch) ? KADEMLIA_LOOKUP_OUTSTANDING + KADEMLIA_LOOKUP_OUTSTANDING_DELTA : KADEMLIA_LOOKUP_OUTSTANDING;
	DhtPeerID *ids[32];
	int num = AssembleNodeList(target, ids, sizeof(ids)/sizeof(ids[0]));

	DhtProcessManager *dpm = new DhtProcessManager(ids, num, target);

#if defined(_DEBUG_DHT)
//	debug_log("DoFindNodes: %s",format_dht_id(target));
//	for(uint i=0; i!=num; i++)
//		debug_log(" %A", &ids[i]->addr);
#endif

	CallBackPointers cbPtrs;
	cbPtrs.processListener = process_listener;
	// get peers in those nodes
	DhtProcessBase* p = FindNodeDhtProcess::Create(this, *dpm, target, target_len, cbPtrs, maxOutstanding);
	dpm->AddDhtProcess(p);
	dpm->Start();
}

#ifdef DHT_SEARCH_TEST
void DhtImpl::RunSearches()
{
	static int started_searches = 0;
	if ( CanAnnounce() && started_searches < NUM_SEARCHES && !search_running ) {
		// keep from overloading the network
		//search_running = true;
		started_searches++;
		btprintf("%d\n", started_searches);
		DhtID target;
		for (size_t i = 0; i < 5; i++) {
			target.id[i] = rand();
		}
		DhtProcess* p = DoFindNodes(target);
		p->process_listener = (IDhtProcessCallbackListener *)5;
		_allow_new_job = false;
	}
}
#endif

void DhtImpl::DoVote(const DhtID &target, int vote, DhtVoteCallback* callb, void *ctx, int flags)
{
	// voting is a two stage process,
	//  1) perform a get_peers dht search to build a list of nearist nodes
	//  2) follow through with a broadcast stage to do the vote

	int maxOutstanding = (flags & announce_non_aggressive)
		? KADEMLIA_LOOKUP_OUTSTANDING + KADEMLIA_LOOKUP_OUTSTANDING_DELTA
		: KADEMLIA_LOOKUP_OUTSTANDING;
	DhtPeerID *ids[32];
	int num = AssembleNodeList(target, ids, sizeof(ids)/sizeof(ids[0]));

	DhtProcessManager *dpm = new DhtProcessManager(ids, num, target);
	CallBackPointers cbPtrs;
	cbPtrs.callbackContext = ctx;
	cbPtrs.voteCallback = callb;

	DhtProcessBase* getPeersProc = GetPeersDhtProcess::Create(this, *dpm, target, 20,
		cbPtrs, 0, maxOutstanding);
	DhtProcessBase* voteProc = VoteDhtProcess::Create(this, *dpm, target, 20,
		cbPtrs, vote);
	// processes will be exercised in the order they are added
	dpm->AddDhtProcess(getPeersProc); // add get_peers first
	dpm->AddDhtProcess(voteProc); // add vote second
	dpm->Start();
}

void DhtImpl::DoScrape(const DhtID &target, DhtScrapeCallback *callb, void *ctx, int flags)
{
	int maxOutstanding = (flags & announce_non_aggressive)
		? KADEMLIA_LOOKUP_OUTSTANDING + KADEMLIA_LOOKUP_OUTSTANDING_DELTA
		: KADEMLIA_LOOKUP_OUTSTANDING;
	DhtPeerID *ids[32];
	int num = AssembleNodeList(target, ids, sizeof(ids)/sizeof(ids[0]));

	DhtProcessManager *dpm = new DhtProcessManager(ids, num, target);

	CallBackPointers cbPtrs;
	cbPtrs.scrapeCallback = callb;
	DhtProcessBase* p = ScrapeDhtProcess::Create(this, *dpm, target, 20, cbPtrs, maxOutstanding);

	dpm->AddDhtProcess(p);
	dpm->Start();
}

void DhtImpl::ResolveName(DhtID const& target, DhtHashFileNameCallback* callb, void *ctx, int flags)
{
	int maxOutstanding = (flags & announce_non_aggressive)
		? KADEMLIA_LOOKUP_OUTSTANDING + KADEMLIA_LOOKUP_OUTSTANDING_DELTA
		: KADEMLIA_LOOKUP_OUTSTANDING;
	DhtPeerID *ids[32];
	int num = AssembleNodeList(target, ids, sizeof(ids)/sizeof(ids[0]));

	DhtProcessManager *dpm = new DhtProcessManager(ids, num, target);

	CallBackPointers cbPtrs;
	cbPtrs.callbackContext = ctx;
	cbPtrs.filenameCallback = callb;

	DhtProcessBase* getPeersProc = GetPeersDhtProcess::Create(this, *dpm, target, 20, cbPtrs, flags, maxOutstanding);
	dpm->AddDhtProcess(getPeersProc);
	dpm->Start();
}

/**
	If performLessAgressiveSearch is false, a more agressive dht lookup will be performed with a greater number of outstanding
	dht queries allowed.  If true, the number of outstanding dht queries allowed is reduced by the specified 
	delta.  See KademliaConstants enum for actual values.
*/
void DhtImpl::DoAnnounce(const DhtID &target,
	int target_len,
	DhtPartialHashCompletedCallback *pcallb,
	DhtAddNodesCallback *callb,
	DhtPortCallback *pcb,
	cstr file_name,
	void *ctx,
	int flags)
{
	// announcing is a two stage process,
	//  1) perform a get_peers dht search to build a list of nearist nodes
	//  2) follow through with a broadcast stage to announce to the nearist nodes

	int maxOutstanding = (flags & announce_non_aggressive)
		? KADEMLIA_LOOKUP_OUTSTANDING + KADEMLIA_LOOKUP_OUTSTANDING_DELTA
		: KADEMLIA_LOOKUP_OUTSTANDING;

	DhtPeerID *ids[32];
	int num = AssembleNodeList(target, ids, sizeof(ids)/sizeof(ids[0]));

	DhtProcessManager *dpm = new DhtProcessManager(ids, num, target);

	CallBackPointers cbPtrs;
	cbPtrs.partialCallback = pcallb;
	cbPtrs.addnodesCallback = callb;
	cbPtrs.callbackContext = ctx;
	cbPtrs.portCallback = pcb;

	DhtProcessBase* getPeersProc = GetPeersDhtProcess::Create(this, *dpm, target, target_len,
		cbPtrs, flags, maxOutstanding);
	// processes will be exercised in the order they are added
	dpm->AddDhtProcess(getPeersProc); // add get_peers first

	if ((flags & announce_only_get) == 0) {
		DhtProcessBase* announceProc = AnnounceDhtProcess::Create(this, *dpm, target, target_len,
			cbPtrs, file_name, flags);
		dpm->AddDhtProcess(announceProc); // add announce second
	}

	dpm->Start();
}

void DhtImpl::RefreshBucket(uint buck)
{
	DhtID target;
	DhtBucket &bucket = *_buckets[buck];

	bucket.last_active = time(NULL);
	// Generate a random ID in this bucket
	GenRandomIDInBucket(target, bucket);

#if defined(_DEBUG_DHT)
	debug_log("RB %2d: %s", buck, format_dht_id(bucket.first));
	debug_log("  target: %s", format_dht_id(target));
#endif

	// find the 8 closest nodes (allow up to 4 invalid nodes)
	DoFindNodes(target, 20);
}

uint DhtImpl::PingStalestInBucket(uint buck)
{
	DhtPeer *ptarget = NULL;
	DhtBucket &bucket = *_buckets[buck];

	bucket.last_active = time(NULL);	// TODO: isn't this updated on ping response?
	GetStalestPeerInBucket(&ptarget, bucket);

#if defined(_DEBUG_DHT)
	debug_log("RB %2d: %s", buck, format_dht_id(bucket.first));
	debug_log("  target: %s", ptarget ? format_dht_id(ptarget->id.id) : "(none)");
#endif

	if(ptarget){
		DhtRequest *req = SendPing(ptarget->id);
		req->_pListener = new DhtRequestListener<DhtImpl>(this, &DhtImpl::OnBootStrapPingReply);
		return req->tid;
	}
	return 0;
}

// Bootstrap complete.
void DhtImpl::ProcessCallback()
{
	_dht_bootstrap = -2;
	_dht_bootstrap_failed = 0;
	_refresh_bucket = 0;
	_refresh_buckets_counter = 0; // start forced bucket refresh
	_refresh_bucket_force = true;
}

void DhtImpl::SetExternalIPCounter(ExternalIPCounter* ip)
{
	_ip_counter = ip;
}

void DhtImpl::SetPacketCallback(DhtPacketCallback* cb)
{
	_packet_callback = cb;
}

void DhtImpl::SetSHACallback(DhtSHACallback* cb)
{
	_sha_callback = cb;
}

void DhtImpl::SetEd25519VerifyCallback(Ed25519VerifyCallback* cb)
{
	_ed25519_verify_callback = cb;
}

void DhtImpl::SetEd25519SignCallback(Ed25519SignCallback* cb)
{
	_ed25519_sign_callback = cb;
}

void DhtImpl::SetAddNodeResponseCallback(DhtAddNodeResponseCallback* cb)
{
	_add_node_callback = cb;
}

/**
 NOTE:  Currently the way to detect a failure is that the params argument is NULL.
        There is no way to distinguish between a time-out problem and an ICMP
		problem.

		TODO:  Correct the dht process to distinguish between these failure modes
		       and respond accordingly.
*/
void DhtImpl::OnBootStrapPingReply(void* &userdata, const DhtPeerID &peer_id, DhtRequest *req, DHTMessage &message, DhtProcessFlags flags)
{
	// if we are processing a reply to a non-slow peer (the "reply" could be in the
	// form of an error - ICMP, Timeout, ...) then decrease the count of non-slow
	// outstanding requests
	if(!req->slow_peer && (flags & (NORMAL_RESPONSE | ANY_ERROR))){
		--_outstanding_add_node;
	}

	// if this is a reply on bhalf of a slow peer, do nothing
	if(flags == PROCESS_AS_SLOW)
		return;

	if (_add_node_callback) {
		_add_node_callback(userdata, message.dhtMessageType == DHT_RESPONSE, peer_id.addr);
	}

	if (_dht_bootstrap >= 0) {
		if (message.dhtMessageType == DHT_RESPONSE && _dht_peers_count != 0) {
			_dht_bootstrap = -1;

			// refresh buckets in 30 seconds....
//			_refresh_buckets_counter = 30;
//			_refresh_bucket_force = true;

			// bootstrap successful. start the find node operation.
			DhtID target = _my_id;
			target.id[4] ^= 1;

			// Here, "this" is an IDhtProcessCallbackListener*, which leads
			// to DhtImpl::ProcessCallback(), necessary to complete bootstrapping
			DoFindNodes(target, 20, this, false); // use the agressive search for the first dht lookup
		} else {
			// bootstrapping failed. retry again soon.
			// 60s, 2m, 4m, 8m, 16m etc.
			// never wait more than 24 hours - 60 * 24 = 1440
			// so max for shift is 2 ^ 10 = 1024 or 1 << 10
			// Could have made a static lookup table of 13 ints,
			// but the conditional + shift code is probably smaller than that
			assert(_dht_bootstrap_failed >= 0 && _dht_bootstrap_failed <= 11);
			_dht_bootstrap_failed = (std::max)(0, _dht_bootstrap_failed);
			if (_dht_bootstrap_failed < 11) {
				_dht_bootstrap = 60 * (1 << _dht_bootstrap_failed);
				++_dht_bootstrap_failed;
			} else
				_dht_bootstrap = 60 * 60 * 24;
		}
	} else if (_dht_bootstrap == -2){
		// If we are here after bootstrap has completed, then this is a
		// NICE ping reply - we are just refreshing the table.
		// We need to handle the error case here.
		if (message.dhtMessageType == DHT_UNDEFINED_MESSAGE || message.dhtMessageType == DHT_ERROR) {
			// Mark that the peer errored
			UpdateError(peer_id);
		}
	}
}


/**
 *
 *
 * Do the bootstrapping...
 */
void DhtImpl::AddNode(const SockAddr& addr, void* userdata, uint origin)
{
	// TODO: remove the v6 check when uT supports v6 DHT
	assert(!addr.isv6());

	_outstanding_add_node++;

	DhtPeerID peer_id;
	peer_id.addr = addr;
	DhtRequest *req = SendPing(peer_id);
	req->has_id = false;
	req->_pListener = new DhtRequestListener<DhtImpl>(this, &DhtImpl::OnBootStrapPingReply, userdata);

#if g_log_dht
	req->origin = origin;
#endif
}

void DhtImpl::AddBootstrapNode(SockAddr const& addr)
{
	_bootstrap_routers.push_back(addr);
}

/**
 *
 */
void DhtImpl::Vote(void *ctx_ptr, const sha1_hash* info_hash, int vote, DhtVoteCallback* callb)
{
	assert(vote >= 0 && vote <= 5);

	byte buf[26];
	memcpy(buf, info_hash->value, 20);
	memcpy(buf + 20, "rating", 6);
	sha1_hash target = _sha_callback(buf, sizeof(buf));

	DhtID id;
	CopyBytesToDhtID(id, target.value);

	DoVote(id, vote, callb, ctx_ptr);
	_allow_new_job = false;
}

void DhtImpl::Put(const byte * pkey, const byte * skey,
		DhtPutCallback * put_callback, void *ctx, int flags, int64_t seq)
{

	int maxOutstanding = (flags & announce_non_aggressive)
		? KADEMLIA_LOOKUP_OUTSTANDING + KADEMLIA_LOOKUP_OUTSTANDING_DELTA
		: KADEMLIA_LOOKUP_OUTSTANDING;

	sha1_hash pkey_hash = _sha_callback(pkey, 32);
	DhtID target;
	CopyBytesToDhtID(target, pkey_hash.value);

	DhtPeerID *ids[32];
	int num = AssembleNodeList(target, ids, lenof(ids));


	DhtProcessManager *dpm = new DhtProcessManager(ids, num, target);
	dpm->set_seq(seq);

	CallBackPointers cbPtrs;
	cbPtrs.putCallback = put_callback;
	cbPtrs.callbackContext = ctx;

	DhtProcessBase* getProc = GetDhtProcess::Create(this, *dpm, target, 20, cbPtrs, flags, maxOutstanding);
	// processes will be exercised in the order they are added
	dpm->AddDhtProcess(getProc); // add get_peers first

	// announce_only_get appears to be worthless because peers will get queried
	// and then nothing will happen with the result, as the callback only happens
	// below
	if ((flags & announce_only_get) == 0) {
	DhtProcessBase* putProc = PutDhtProcess::Create(this, *dpm, pkey, skey,
		cbPtrs, flags);
		dpm->AddDhtProcess(putProc); // add announce second
	}
	dpm->Start();
}

/**
 * The BT code calls this to announce itself to the DHT network.
 */
void DhtImpl::AnnounceInfoHash(
	const byte *info_hash,
	int info_hash_len,
	DhtPartialHashCompletedCallback *partialcallback,
	DhtAddNodesCallback *addnodes_callback,
	DhtPortCallback* pcb,
	cstr file_name,
	void *ctx,
	int flags)
{
	DhtID id;
	CopyBytesToDhtID(id, info_hash);
	DoAnnounce(id, info_hash_len, partialcallback, addnodes_callback,
		pcb, file_name, ctx, flags);
	_allow_new_job = false;
}

void DhtImpl::SetRate(int bytes_per_second)
{
	_dht_rate = bytes_per_second;
}

/**
 * This is a tick function that should be called periodically.
 */
void DhtImpl::Tick()
{
	// TODO: make these members. and they could probably be collapsed to 1
	static int _5min_counter;
	static int _4_sec_counter;

	_dht_probe_quota = _dht_probe_rate;

	// May accumulate up to 3 second of DHT bandwidth.
	// the quota is allowed to be negative since our requests
	// don't test against it, but still drains it
	_dht_quota = clamp(_dht_quota + _dht_rate, -_dht_rate, 3 * _dht_rate);

	// Expire 30 second old requests
	for(DhtRequest **reqp = &_requests.first(), *req; (req = *reqp) != NULL; ) {
		int delay = (int)(get_milliseconds() - req->time);

		// Support time that goes backwards
		if (delay < 0) {
			req->time = get_milliseconds();
			reqp = &req->next;
			continue;
		}

		if ( delay >= 4000 ) {
			// 4 seconds passed with no reply.
			_requests.unlinknext(reqp);

			//req->_pListener->Callback(req->peer, NULL,
			req->_pListener->Callback(req->peer, req, DhtProcessBase::dummyMessage,
				(DhtProcessFlags)TIMEOUT_ERROR);
			delete req->_pListener;

			Account(DHT_BW_IN_TIMEOUT, 0);
#if g_log_dht
			dht_log("dlok replytime:-1\n");
#endif
			delete req;
		} else {
			// 1 second passed with no reply.
			// Mark the peer as a slow peer.
			if (delay >= 1000 && !req->slow_peer) {
				req->slow_peer = true;
				req->_pListener->Callback(req->peer, req, DhtProcessBase::dummyMessage,
					(DhtProcessFlags)(PROCESS_AS_SLOW));
			}
			reqp = &req->next;
		}
	}

	if (_dht_enabled == 0)
		return;

	// Do these every 5 minutes.
	if (++_5min_counter == 60 * 5) {
		_5min_counter = 0;
		RandomizeWriteToken();
		ExpirePeersFromStore(time(NULL) - 30 * 60);
		if (_dht_peers_count == 0)
			_dht_bootstrap = 1;
		_immutablePutStore.UpdateUsage(time(NULL));
		_mutablePutStore.UpdateUsage(time(NULL));
	}

	if (_dht_bootstrap > 0) {
		// Boot-strapping.
		if (--_dht_bootstrap == 0) {

			// add the bootstrap routers..
			for (std::vector<SockAddr>::iterator i = _bootstrap_routers.begin()
				, end(_bootstrap_routers.end()); i != end; ++i)
			{
				AddNode(*i, NULL, IDht::DHT_ORIGIN_INITIAL);
			}
		}

	} else if (_dht_bootstrap < -1 ){
		// Bootstrap finished. refresh buckets?
		if (--_refresh_buckets_counter < 0) {
			_refresh_buckets_counter = 6; // refresh buckets every 6 seconds
		}
	}

	if ( (_refresh_buckets_counter == 6 || _refresh_bucket_force) && _allow_new_job) {
		// Now that we regularly ping the stalest node in the bucket, this 13 1/2 minute case should
		// never happen.  We still "force" when first populating the DHT however.
		if ( (_refresh_bucket_force || (time(NULL) - _buckets[_refresh_bucket]->last_active) >= 15 * 60 - 90)) {
#ifdef _DEBUG_DHT
			debug_log("Refreshing bucket %d", _refresh_bucket);
#endif
			RefreshBucket(_refresh_bucket);
			_allow_new_job = false;
			// Stop forcing when all the buckets have been refreshed
			if(_refresh_bucket + 1 >= _buckets.size())
				_refresh_bucket_force = false;
		} else {
			PingStalestInBucket(_refresh_bucket);
			// todo: don't allow new job?
		}
		_refresh_bucket = (_refresh_bucket + 1) % _buckets.size();
	}

	// Allow a new job every 4 seconds.
	if ( (++_4_sec_counter & 3) == 0) {
#ifdef _DHT_STATS
		static DWORD last = get_milliseconds() - 4000;
		static int64 inrequests = 0;
		static int64 outrequests = 0;

		DhtAccounting *acct = _dht_accounting;
		int64 t_inrequests = acct[DHT_BW_IN_TOTAL].count;
		int64 t_outrequests = acct[DHT_BW_OUT_TOTAL].count;

		double t = (get_milliseconds() - last) / 1000.0;
		double iqps = (t_inrequests - inrequests) / t;
		double oqps = (t_outrequests - outrequests) / t;
		double known = acct[DHT_BW_IN_KNOWN].count * 100.0 / acct[DHT_BW_IN_TOTAL].count;
		do_log("QPS in: %d out: %d (known: %d%%)", (int)(iqps+0.5), (int)(oqps+0.5), (int)(known+0.5));

		last = get_milliseconds();
		inrequests = t_inrequests;
		outrequests = t_outrequests;
#endif

		_allow_new_job = true;
	}

#if g_log_dht
	{
	static DWORD last = get_milliseconds() - 1000;
	static int64 inrequests = 0;
	static int64 outrequests = 0;
	static int64 inrequests2 = 0;
	static int64 inrequests3 = 0;
	DhtAccounting *acct = _dht_accounting;
	int64 t_inrequests = acct[DHT_BW_IN_TOTAL].count;
	int64 t_outrequests = acct[DHT_BW_OUT_TOTAL].count;
	int64 t_inrequests2 = acct[DHT_BW_IN_REPL].count;
	int64 t_inrequests3 = acct[DHT_BW_IN_TIMEOUT].count;
	DWORD now = get_milliseconds();
	double t = (now - last) / 1000.0;
	double oqps = (t_outrequests - outrequests) / t;
	double iqps = (t_inrequests - inrequests) / t;
	double iqps2 = (t_inrequests2 - inrequests2) / t;
	double iqps3 = (t_inrequests3 - inrequests3) / t;

	outrequests = t_outrequests;
	inrequests = t_inrequests;
	inrequests2 = t_inrequests2;
	inrequests3 = t_inrequests3;
	last = now;

	dht_log("dlok peers:%d qpso:%lf qpsi:%lf repliesps:%lf timeoutps:%lf peersunknown:%d peersinit:%d peersbt:%d peersbt2:%d peersin:%d\n", _dht_peers_count, oqps, iqps, iqps2, iqps3, g_dht_peertype_count[0],g_dht_peertype_count[1],g_dht_peertype_count[2],g_dht_peertype_count[3],g_dht_peertype_count[4]);
	}
#endif
}



void DhtImpl::Restart() {
/**
*
*	Steps to restarting the dht.
*	1. Determine if the dht is enabled
*	2. Stop the dht
*	3. Clear the buckets
*	4. Randomize the write tokens
*	5. Restart if it was enabled to begin with
*
**/
	bool old_g_dht_enabled = _dht_enabled;
	Enable(0,0); // Stop Dht...this also enables the bootstrap process

	// clear the buckets
	for(int i = 0; i < _buckets.size(); i++) {
		for (DhtPeer **peer = &_buckets[i]->peers.first(); *peer;) {
			DhtPeer *p = *peer;
			// unlinknext will make peer point the following entry
			// in the linked list, so there's no need to step forward
			// explicitly.
			_buckets[i]->peers.unlinknext(peer);
			_dht_peer_allocator.Free(p);
		}
		for (DhtPeer **peer = &_buckets[i]->replacement_peers.first(); *peer;) {
			DhtPeer *p = *peer;
			_buckets[i]->replacement_peers.unlinknext(peer);
			_dht_peer_allocator.Free(p);
		}
		_dht_bucket_allocator.Free(_buckets[i]);
	}
	_buckets.clear();
	_refresh_buckets_counter = 0;
	_refresh_bucket = 0;
	_dht_peers_count = 0;
	_outstanding_add_node = 0;

	// Initialize the buckets
	for (int i = 0; i < 32; ++i) {
		DhtBucket *bucket = CreateBucket(i);
		bucket->span = 155;
		memset(&bucket->first, 0, sizeof(bucket->first));
		// map the [0, 32) range onto the top of
		// the first word in the ID
		bucket->first.id[0] = uint(i) << (32 - 5);
	}

	// Need to do this twice so prev_token becomes random too
	RandomizeWriteToken();
	RandomizeWriteToken();
	_dht_enabled = old_g_dht_enabled;
}

bool DhtImpl::handleICMP(UDPSocketInterface *socket, byte *buffer, size_t len, const SockAddr& addr)
{
	bool result = false;

	// Check if it appears to be a DHT message.
	if (! (len > 10 && buffer[0] == 'd' && buffer[len-1] == 'e' && buffer[2] == ':'))
		return false;

	if (_packet_callback) {
		_packet_callback(buffer, len, true);
	}

	// HMM: stats for ICMP errors?
	//Account(DHT_BW_IN_TOTAL, len);

	BencEntity benc;
	if (benc.ParseInPlace(buffer, benc, buffer + len)) {
		result = true;
		if (_dht_enabled && !ParseIncomingICMP(benc, addr)) {
		}
	}
	return result;
}

bool DhtImpl::ParseKnownPackets(const SockAddr& addr, byte *buf, int pkt_size)
{
	// currently we only know one packet type, the most common uT ping:
	// 'd1:ad2:id20:\t9\x93\xd4\xb7G\x10,Q\x9b\xf4\xc5\xfc\t\x87\x89\xeb\x93Q,e1:q4:ping1:t4:\x95\x00\x00\x001:v4:UT#\xa31:y1:qe'
	if (pkt_size != 67)
		return false;

	// compare the static portions of the packet
	static cstr a = "d1:ad2:id20:";
	static cstr b = "e1:q4:ping1:t4:";
	static cstr c = "1:v4:";
	static cstr d = "1:y1:qe";

	if (memcmp(buf, a, sizeof(a)-1))
		return false;
	if (memcmp(buf+32, b, sizeof(b)-1))
		return false;
	if (memcmp(buf+51, c, sizeof(c)-1))
		return false;
	if (memcmp(buf+60, d, sizeof(d)-1))
		return false;

	DHTMessage message;

	// process the packet using the dynamic parts
	// set only the minimum of elements needed by ProcessQuery
	message.transactionID.b = buf+47;
	message.transactionID.len = 4;

	message.version.b = buf+56;
	message.version.len = 4;

	message.dhtCommand = DHT_QUERY_PING;
	message.id = buf+12;

	return ProcessQuery(addr, message, pkt_size);
}

bool DhtImpl::ProcessIncoming(byte *buffer, size_t len, const SockAddr& addr)
{
	if (_packet_callback) {
		_packet_callback(buffer, len, true);
	}

	Account(DHT_BW_IN_TOTAL, len);

	// TODO: v6
	if (addr.isv6()) {
		Account(DHT_INVALID_IPV6, len);
		return true;
	}

	if (ParseKnownPackets(addr, buffer, len)) {
		Account(DHT_BW_IN_KNOWN, len);
		return true;
	}

	DHTMessage message(buffer, len);
	if(!message.ParseSuccessful()){
		Account(DHT_INVALID_PI_NO_DICT, len);
		return false;
	}
	if (_dht_enabled)
		return InterpretMessage(message, addr, len);

	return true;
}

// Save all non-failed peers.
// Save my peer id.
// Don't save announced stuff.

void DhtImpl::SaveState()
{
	BencodedDict base;
	BencodedDict *dict = &base;

	// Save all peers in the buckets.
	BencEntityMem beMemId(_my_id_bytes, 20);
	dict->Insert("id", beMemId);

	std::vector<PackedDhtPeer> peer_list(0);

	for(uint i=0; i<_buckets.size(); i++) {
		DhtBucket &bucket = *_buckets[i];
		for (DhtPeer *peer = bucket.peers.first(); peer; peer=peer->next) {
			if (peer->num_fail == 0 && peer->id.addr.isv4()) {
				PackedDhtPeer tmp;
				DhtIDToBytes(tmp.id, peer->id.id);
				peer->id.addr.compact(tmp.ip, true);
				peer_list.push_back(tmp);
			}
		}
	}

	size_t len;
	BencEntityMem beM;
	beM.SetMemOwn(&peer_list[0], peer_list.size() * sizeof(PackedDhtPeer));
	dict->Insert("nodes", beM);

	// CHECK: time(NULL) can be int64....
	dict->InsertInt("age", (int)time(NULL));

	byte *b = base.Serialize(&len);
	_save_callback(b, len);
	free(b);
}

void DhtImpl::LoadState()
{
	BencEntity base;

	_load_callback(&base);

	BencodedDict *dict = base.AsDict(&base);
	if (dict) {
		if ((uint)(time(NULL) - dict->GetInt("age", 0)) < 2 * 60 * 60) {
			// Load the ID
			if (CopyBytesToDhtID(_my_id, (byte*)dict->GetString("id", 20)))
				DhtIDToBytes(_my_id_bytes, _my_id);

			// Load nodes...
			size_t nodes_len;
			byte *nodes = (byte*)dict->GetString("nodes", &nodes_len);
			if (nodes && nodes_len % sizeof(PackedDhtPeer) == 0) {
				while (nodes_len >= sizeof(PackedDhtPeer)) {
					// Read into the peer struct
					DhtPeerID peer;
					CopyBytesToDhtID(peer.id, nodes);
					peer.addr.from_compact(nodes + 20, 6);
					nodes += sizeof(PackedDhtPeer);
					nodes_len -= sizeof(PackedDhtPeer);
					Update(peer, IDht::DHT_ORIGIN_UNKNOWN, false);
				}
			}
		}
	}
}

int DhtImpl::GetNumPutItems()
{
	return _immutablePutStore.pair_list.size();
}

// TODO: The external IP reports from non-DHT sources don't
// pass through here.  They are counted, but they just won't
// pass through here
void DhtImpl::CountExternalIPReport( const SockAddr& addr, const SockAddr& voter ){
	if (_ip_counter == NULL) return;

	SockAddr tempWinner;
	_ip_counter->CountIP(addr, voter);
	if(_ip_counter->GetIP(tempWinner) && tempWinner != _lastLeadingAddress){
		_lastLeadingAddress = tempWinner;
		GenerateId();
		Restart();
	}
}

/**
	Update the internal DHT tables with an id.  Generally, the algorithm attempts to add
	a candidate node to the main node list.  If not sucessful, the list is examined in more
	detail to see if the candidate should be added the list and a node for replacement is
	identified.  If a node for replacement is identified in the main list, there is an
	attempt to transfer that node to the replacement list before overwriting it with the
	candidate node.	If no node in the main node list is identified for replacement, then
	there is an attempt to put the candidate node into the replacement list in a fashion
	similar to how it was attempted to be put into the main list.

	Pseudo code:

	if (candidate node can be added to main node list)
		done
	else // the bucket is full
		if (my id is in the bucket)
			split bucket
			Update (id) // recursive call guaranteed to succede since the bucket of interest will no longer be full
			done
		else
			search the main node list for a replacement candidate
			if (a replacement candidate was found in the main list)
				move the replacement candidate to the replacement list (if appropriate)
				put candidate node into the main list
				done
			else // candidate was not suitable for the main list
				try to add the candidate node to the replacement list
				if (candidate was added to the replacement list)
					done
				else
					search the replacement list for a replacement candidate
					if (a replacement candidate was found in the replacement list)
						overwrite it with the candidate node
					else
						discard the candidate node

	Note:  the 'origin' argument is included here for historical and possible future
		   debugging purposes.  It is not currently used by Update().
*/
DhtPeer* DhtImpl::Update(const DhtPeerID &id, uint origin, bool seen, int rtt)
{
	// if seen == true, a true RTT must be provided
	assert(rtt != INT_MAX || seen == false);

	if (id.addr.get_port() == 0)
		return NULL;

	int bucket_id = GetBucket(id.id);

	// this will detect the -1 case
	if (bucket_id < 0) {
		return NULL;
	}

	DhtBucket &bucket = *_buckets[bucket_id];

#if defined(_DEBUG_DHT)
	debug_log("Update: %s.", format_dht_id(id.id));
#endif

	assert(bucket.TestForMatchingPrefix(id.id));

	DhtPeer* returnNode = NULL;

	DhtPeer candidateNode;
	candidateNode.id = id;
	candidateNode.rtt = rtt;
	candidateNode.num_fail = 0;
	candidateNode.first_seen = candidateNode.lastContactTime = seen ? time(NULL) : 0;

	// try putting the node in the active node list (or updating it if it's already there)
	bool added = bucket.InsertOrUpdateNode(this, candidateNode, DhtBucket::peer_list, &returnNode);

	// the node was already in or added to the main bucket
	if (added){
		return returnNode;
	}

	// The bucket is full.

	// If our own ID is in it split the bucket and try again; our ID being in the bucket is
	// a way to test whether or not this bucket is eligible for being split. Only the
	// last bucket is, and we're always in the last bucket
	if (bucket.TestForMatchingPrefix(_my_id)) {
		SplitBucket(bucket_id);
		// and retry insertion
		return Update(id, origin, seen, rtt);
	}

	// Otherwise, try replacing a node in the active peers list
	candidateNode.ComputeSubPrefix(bucket.span, KADEMLIA_BUCKET_SIZE_POWER);
	bool replacementAvailable = bucket.FindReplacementCandidate(this, candidateNode, DhtBucket::peer_list, &returnNode);

	if(replacementAvailable){

		// if the candidate node is in the replacement list, remove it (to prevent it from possibly being in both lists simultainously)
		bucket.RemoveFromList(this, candidateNode.id.id, DhtBucket::replacement_list);

		// a replacement candidate has been identified in the active peers list.

		// If the candidate for replacement in the active peer list is errored, just replace it
		if(returnNode->num_fail){
			(*returnNode).CopyAllButNext(candidateNode); // replace the node with the candidate
			return returnNode;
		}

		// The replacement candidate isn't errored, see if there is a place for it in the reserve list.
		DhtPeer* replaceNode = NULL;
		added = bucket.InsertOrUpdateNode(this, *returnNode, DhtBucket::replacement_list, &replaceNode);
		if(added){
			// the peer list node is now in the replacement list, put the new
			// node in the peer list
			(*returnNode).CopyAllButNext(candidateNode); // replace the node with the candidate
		}
		else{
			// the replacement candidate was not added directly to the replace list (full), see
			// if there is a sub-prefix or rtt that should be replaced
			replacementAvailable = bucket.FindReplacementCandidate(this, *returnNode, DhtBucket::replacement_list, &replaceNode);
			if(replacementAvailable){
				replaceNode = returnNode;
			}
			(*returnNode).CopyAllButNext(candidateNode); // replace the node with the candidate
		}
	}
	else{
		// no suitable replacement node was identified in the active peers list,
		// see if the candidate node belongs in the replacement list
		added = bucket.InsertOrUpdateNode(this, candidateNode, DhtBucket::replacement_list, &returnNode);
		if(!added){
			// The candidate node was not added to the bucket; see if a node in the replacement bucket
			// can be replaced with the candidate node to either improve the sub-prefix distribution
			// or significantly improve the rtt of the reserve.
			replacementAvailable = bucket.FindReplacementCandidate(this, candidateNode, DhtBucket::replacement_list, &returnNode);
			if(replacementAvailable){
				(*returnNode).CopyAllButNext(candidateNode); // replace the node with the candidate
				return returnNode;
			}
			else{
				return NULL; // the candidate node is being discarded
			}
		}
	}
	return returnNode;
}


//*****************************************************************************
//
// DhtLookupNodeList	A class to collect the nodes found during a dht lookup
//
//*****************************************************************************
DhtFindNodeEntry* DhtLookupNodeList::FindQueriedPeer(const DhtPeerID &peer_id)
{
	for(unsigned int i=0; i!=numNodes; i++) {
		if ((nodes[i].queried == QUERIED_YES || nodes[i].queried == QUERIED_SLOW) &&
			nodes[i].id.id == peer_id.id)
			return &nodes[i];
	}
	return NULL;
}

void DhtLookupNodeList::InsertPeer(const DhtPeerID &id, const DhtID &target)
{
	uint i;
	DhtFindNodeEntry *ep = nodes;

	// Locate the position where it should be inserted.
	for(i=0; i<numNodes; i++, ep++) {
		int r = CompareDhtIDToTarget(ep->id.id, id.id, target);
		if (r == 0)
			return; // duplicate ids?
		if (r > 0)
			break; // cur pos > id?
	}

	// Bigger than all of them?
	if (i >= lenof(nodes))
		return;

	if (numNodes < lenof(nodes)) {
		numNodes++;
	} else {
		FreeNodeEntry(nodes[lenof(nodes)-1]);
	}

	// Make space here?
	memmove(&ep[1], &ep[0], sizeof(ep[0]) * (numNodes - i - 1));

	ep->id = id;
	ep->queried = QUERIED_NO;
	ep->token.len = 0;
	ep->token.b = NULL;
}

DhtLookupNodeList::~DhtLookupNodeList()
{
	for(unsigned int x=0; x<numNodes; ++x)
		FreeNodeEntry(nodes[x]);
}

void DhtLookupNodeList::SetAllQueriedStatus(QueriedStatus status)
{
	for(unsigned int x=0; x<numNodes; ++x)
		SetQueriedStatus(x, status);
}

void DhtLookupNodeList::CompactList()
{
	// Compact the entry table. Only keep the 'replied' ones.
	unsigned int j = 0;
	for(int i=0; i<numNodes; i++) {
		if (nodes[i].queried != QUERIED_REPLIED) continue;
		nodes[i].queried = QUERIED_NO;
		if (j != i) {
			FreeNodeEntry(nodes[j]);
			nodes[j] = nodes[i];
			// zero out the copied item so we don't double-free
			memset(&nodes[i], 0, sizeof(DhtFindNodeEntry));
		}
		j++;
	}
	numNodes = j;
}

void DhtLookupNodeList::SetNodeIds(DhtPeerID** ids, unsigned int numId, const DhtID &target)
{
	for(unsigned int x=0; x<numId; ++x)
		InsertPeer(*ids[x], target);
}

void DhtLookupNodeList::set_data_blk(byte * v, int v_len)
{
	data_blk.assign(v, v + v_len);
}

//*****************************************************************************
//
// DhtProcessManager
//
//*****************************************************************************
DhtProcessManager::~DhtProcessManager()
{
	for(unsigned int x=0; x<_dhtProcesses.size(); ++x)
		delete _dhtProcesses[x];
}


//*****************************************************************************
//
// DhtProcessBase
//
//*****************************************************************************
DHTMessage DhtProcessBase::dummyMessage;


//*****************************************************************************
//
// DhtLookupScheduler
//
//*****************************************************************************
/**
	The goal is to keep requests out to the first 4 nodes (which should be the closest
	nodes in the list).  Initialy, the first 4 nodes in the list will be issued
	queries.  When a response comes in, the nodes it provides are put in the list
	in order of closest to farthest.  The scheduler then wants to issue additional
	queries that will meet the goal of keeping queries out to the first 4 closest
	nodes - nodes that have either errored or replied are not considered in the count
	of the first 4 closest nodes to have queries in flight.
*/
void DhtLookupScheduler::Schedule()
{
	int numOutstandingRequestsToClosestNodes = 0;
	int K = KADEMLIA_K;
	int nodeIndex=0;
	while(nodeIndex < processManager.size() // so long as the index is still within the size of the nodes array
		  && nodeIndex < K // and so long as we have not queried KADEMLIA_K (8) non-errored nodes (as a terminating condition)
		  && (numOutstandingRequestsToClosestNodes < maxOutstandingLookupQueries  // if the first 4 (default value) good nodes in the list do not yet have queries out to them - continue making queries
		      || numNonSlowRequestsOutstanding < maxOutstandingLookupQueries  // if the number of uncompromised outstanding queries is less than max outstanding allowed - continue making queries
			 )
		  ){
		switch(processManager[nodeIndex].queried){
			case QUERIED_NO:{
				IssueQuery(nodeIndex);
				// NOTE: break is intentionally omitted here
			}
			case QUERIED_YES:
			case QUERIED_SLOW:{  // if a node is marked as slow, a query to the next unqueried node has already been sent in its place.
				numOutstandingRequestsToClosestNodes++;
				break;
			}
			case QUERIED_ERROR:{
				++K;  // if a node has errored, advance how far down the list we are allowed to travel
				break;
			}
			case QUERIED_REPLIED:{
				break;
			}
			default:{
				assert(false); // an illegal status was set to a node
			}
		}
		++nodeIndex;
	}
	// No outstanding requests. Means we're finished.
	if (totalOutstandingRequests == 0){
		CompleteThisProcess();
	}
}

/**
	IssueOneAdditionalQuery() traverses the list of nodes and issues a query to the first
	un-queried node found.  This is primarily intended to issue a replacement query
	for a reply that is either slow or errored.
*/
void DhtLookupScheduler::IssueOneAdditionalQuery()
{
	for(int x=0; x<processManager.size(); ++x){
		if(processManager[x].queried == QUERIED_NO){
			IssueQuery(x);
			return;
		}
	}
	// No outstanding requests. Means we're finished.
	if (totalOutstandingRequests == 0)
		CompleteThisProcess();
}

/**
	Given the index to a node in the process manager, issue a query to that node.
*/
void DhtLookupScheduler::IssueQuery(int nodeIndex)
{
	DhtFindNodeEntry &nodeInfo = processManager[nodeIndex];
	nodeInfo.queried = QUERIED_YES;
	DhtRequest *req = impl->AllocateRequest(nodeInfo.id);
	DhtSendRPC(nodeInfo, req->tid);
	req->_pListener = new DhtRequestListener<DhtProcessBase>(this, &DhtProcessBase::OnReply);
	numNonSlowRequestsOutstanding++;
	totalOutstandingRequests++;
}

void DhtLookupScheduler::OnReply(void*& userdata, const DhtPeerID &peer_id, DhtRequest *req, DHTMessage &message, DhtProcessFlags flags)
{
	// if we are processing a reply to a non-slow peer then decrease the count of
	// non-slow outstanding requests
	if(!req->slow_peer){
		--numNonSlowRequestsOutstanding;
	}
	// If a "slow" problem, mark the node as slow and see if another query can be issued.
	if (flags & PROCESS_AS_SLOW){
		--numNonSlowRequestsOutstanding;
		DhtFindNodeEntry *dfnh = processManager.FindQueriedPeer(peer_id);
		if (dfnh) dfnh->queried = QUERIED_SLOW;
		// put another request in flight since this peer is slow to reply (and may time-out in the future)
		IssueOneAdditionalQuery();
		return;
	}

	// decrease the count of all outstanding requests (slow or normal)
	totalOutstandingRequests--;

	// if ICMP or timeout error
	if(flags & ANY_ERROR){
		DhtFindNodeEntry *dfnh = processManager.FindQueriedPeer(peer_id);
		if (dfnh) dfnh->queried = QUERIED_ERROR;
		impl->UpdateError(peer_id);

		// put another request in flight since this peer is dead from ICMP
		// (a slow peer that times-out already had a replacement query launched)
		if(flags & ICMP_ERROR){
			IssueOneAdditionalQuery();
		}
		// No outstanding requests. Means we're finished.
		else if (totalOutstandingRequests == 0){
			CompleteThisProcess();
		}
		return;
	}
	
	// a normal response, let the derived class handle it
#if g_log_dht
	dht_log("DhtLookupScheduler,normal_reply,id,%d,time,%d\n", target.id[0], get_milliseconds());
#endif
	ImplementationSpecificReplyProcess(userdata, peer_id, message, flags);

	// mark this node replied and schedule more queries
	DhtFindNodeEntry *dfnh = processManager.FindQueriedPeer(peer_id);
	if (dfnh) dfnh->queried = QUERIED_REPLIED;
	Schedule();
}

DhtFindNodeEntry* DhtLookupScheduler::ProcessMetadataAndPeer(const DhtPeerID &peer_id, DHTMessage &message, uint flags) {
	DhtFindNodeEntry *dfnh = NULL;
	bool errored = false;

	// extract the nodes from the reply
	if(flags & NORMAL_RESPONSE)
	{
		// extract the possible reply arguments
		Buffer nodes;
		Buffer info_hash;
		Buffer file_name;
		std::vector<Buffer> values;

		nodes.b = (byte*)message.replyDict->GetString("nodes", &nodes.len);
		info_hash.b = (byte*)message.replyDict->GetString("info_hash", &info_hash.len);
		file_name.b = (byte*)message.replyDict->GetString("n", &file_name.len);

		BencodedList *valuesList = message.replyDict->GetList("values");
		if (valuesList) {
			for(uint i=0; i!=valuesList->GetCount(); i++) {
				Buffer b;
				b.b = (byte*)valuesList->GetString(i, &b.len);
				if (!b.b)
					continue;
				values.push_back(b);
			}
		}

		if(callbackPointers.partialCallback && info_hash.len == 20 && info_hash.b) {
			//we should only call this once
			callbackPointers.partialCallback(callbackPointers.callbackContext, info_hash.b);
			callbackPointers.partialCallback = NULL;
		}

		if(callbackPointers.filenameCallback){ // if there is a filename callback, see if a filename is in the reply
			Buffer filename;
			filename.b = (byte*)message.replyDict->GetString("n", &filename.len);
			if(filename.b && filename.len){
				byte target_bytes[20];
				DhtIDToBytes(target_bytes, target);
				callbackPointers.filenameCallback(callbackPointers.callbackContext, target_bytes, filename.b);
			}
		}

		if(values.size()){
			byte bytes[20];
			DhtIDToBytes(bytes, target);

			int peers_size = values.size();
			DHTPackedPeer *peers = (DHTPackedPeer*)malloc(sizeof(DHTPackedPeer) * peers_size);
			uint numpeer = 0;
			for(uint i=0; i!=values.size(); i++) {
				int len = values[i].len;
				byte* s = values[i].b;

				if (len == 6) {
					// libtorrrent / uTorrent style peer
					peers[numpeer++] = *(DHTPackedPeer*)s;
				} else if ((len % 6) == 0) {

					// we need more space
					size_t peers2_size = peers_size + ((len / 6) - 1);
					peers = (DHTPackedPeer*)realloc(peers, sizeof(DHTPackedPeer) * peers2_size);
					peers_size = peers2_size;

					// parse mainline dht style peer list
					for (uint pos = 0; pos < len; pos += 6) {
						peers[numpeer++] = *(DHTPackedPeer*)(s + pos);
					}
				}
			}
			if (numpeer != 0 && callbackPointers.addnodesCallback != NULL){
#if g_log_dht
				dht_log("DhtLookupScheduler,callback,id,%d,time,%d\n", target.id[0], get_milliseconds());
#endif
				callbackPointers.addnodesCallback(callbackPointers.callbackContext, bytes, (byte*)peers, numpeer);
			}
			free(peers);
		}
		else if(nodes.b && nodes.len % 26 == 0){
			uint num_nodes = nodes.len / 26;
			// Insert all peers into my internal list.
			while (num_nodes != 0) {
				DhtPeerID peer;

				// Read into the peer struct
				CopyBytesToDhtID(peer.id, nodes.b);
				peer.addr.from_compact(nodes.b + 20, 6);
				nodes.b += 26;

				// Check if it's identical to myself?
				// Don't add myself to my internal list of peers.
				if (!(peer.id == impl->_my_id) && peer.addr.get_port() != 0) {
					// Insert into my list...
					processManager.InsertPeer(peer, target);
				}
				num_nodes--;
			}
		}
		else{
			errored = true;
		}
	}

	dfnh = processManager.FindQueriedPeer(peer_id);
	if(errored || (flags & ANY_ERROR)){
		// mark peer as errored
		if (dfnh) dfnh->queried = QUERIED_ERROR;
		impl->UpdateError(peer_id);
	}
	else if (dfnh) {
		// mark that the peer replied.
		dfnh->queried = QUERIED_REPLIED;
		// When getting peers, remember the write-token.
		// This is needed to be able to announce to the peers.
		// it's also required to cast votes
		Buffer token;
		token.b = (byte*)message.replyDict->GetString("token", &token.len);
		if (token.b && token.len <= 20) {
			dfnh->token.len = token.len;
			assert(dfnh->token.b == NULL);
			dfnh->token.b = (byte*)malloc(token.len);
			memcpy(dfnh->token.b, token.b, token.len);
		}
		return dfnh;
	}
	return NULL;
}

void DhtLookupScheduler::ImplementationSpecificReplyProcess(void *userdata, const DhtPeerID &peer_id, DHTMessage &message, uint flags) {
	ProcessMetadataAndPeer(peer_id, message, flags);
}

void GetDhtProcess::ImplementationSpecificReplyProcess(void *userdata, const DhtPeerID &peer_id, DHTMessage &message, uint flags) {
	DhtFindNodeEntry *dfnh = ProcessMetadataAndPeer(peer_id, message, flags);
	if (dfnh) {
		//We are looking for the response message with the maximum seq number.
		if(message.sequenceNum > processManager.seq()){ 
			if(message.signature.len > 0  && message.vBuf.len > 0 &&
					message.key.len > 0 &&
					impl->Verify(message.signature.b, message.vBuf.b, message.vBuf.len,
						message.key.b, message.sequenceNum)){
				//The maximum seq and the vBuf are saved by the processManager and will be used in creating Put messages.
				processManager.set_data_blk(message.vBuf.b, message.vBuf.len);
				processManager.set_seq(message.sequenceNum);
			}
		}
		if (_with_cas) { // _with_cas
			byte to_hash[1040];
			int written = snprintf(reinterpret_cast<char*>(to_hash), 1040, MUTABLE_PAYLOAD_FORMAT, message.sequenceNum);
			assert((written + message.vBuf.len) <= 1040);
			memcpy(to_hash + written, message.vBuf.b, message.vBuf.len);
			//fprintf(stderr, "in get: %s\n", (char*)to_hash);
			dfnh->cas = impl->_sha_callback(to_hash, written + message.vBuf.len);
		}
	}
}

//*****************************************************************************
//
// DhtBroadcastScheduler
//
//*****************************************************************************
void DhtBroadcastScheduler::Schedule()
{
	// Send rpc's up to a maximum of KADEMLIA_K_ANNOUNCE (usually 8).
	// Do not allow more than KADEMLIA_BROADCAST_OUTSTANDING (usually 3) to be
	// in flight an any given time.  Do not track "slow peers".  Once a peer times
	// out, then issue another rpc.
	int numReplies = 0, index = 0;
	while(index < processManager.size()
		  && outstanding < KADEMLIA_BROADCAST_OUTSTANDING
		  && (outstanding + numReplies) < KADEMLIA_K_ANNOUNCE)
	{
		switch(processManager[index].queried){
			case QUERIED_NO:
			{
				if (!aborted) {
					DhtFindNodeEntry &nodeInfo = processManager[index];
					nodeInfo.queried = QUERIED_YES;
					DhtRequest *req = impl->AllocateRequest(nodeInfo.id);
					DhtSendRPC(nodeInfo, req->tid);
					req->_pListener = new DhtRequestListener<DhtProcessBase>(this,
							&DhtProcessBase::OnReply);
					outstanding++;
				}
				break;
			}
			case QUERIED_REPLIED:
			{
				numReplies++;
				break;
			}
			default:;
		}
		++index;
	}
	// No outstanding requests. Means we're finished.
	if (outstanding == 0)
		CompleteThisProcess();
}

/**
Let slow peers continue until they either respond or timeout.
*/
void DhtBroadcastScheduler::OnReply(void*& userdata, const DhtPeerID &peer_id, DhtRequest *req, DHTMessage &message, DhtProcessFlags flags)
{
	if(flags & NORMAL_RESPONSE){
		// a normal response, let the derived class handle it
		if (!aborted) {
			ImplementationSpecificReplyProcess(userdata, peer_id, message, flags);
		}

		DhtFindNodeEntry *dfnh = processManager.FindQueriedPeer(peer_id);
		if (dfnh) dfnh->queried = QUERIED_REPLIED;
		outstanding--;
		Schedule();
	}
	else if(flags & ANY_ERROR){  // if ICMP or timeout error
		DhtFindNodeEntry *dfnh = processManager.FindQueriedPeer(peer_id);
		if (dfnh) dfnh->queried = QUERIED_ERROR;
		impl->UpdateError(peer_id);
		outstanding--;
		Schedule(); // put another request in flight since this peer is slow to reply (and may be dead)
		return;
	}
}

//*****************************************************************************
//
// FindNodeDhtProcess			find_node
//
//*****************************************************************************

void FindNodeDhtProcess::DhtSendRPC(const DhtFindNodeEntry &nodeInfo, const unsigned int transactionID)
{
	char buf[1024];
	SimpleBencoder sb(buf);
	char const* end = buf + sizeof(buf);

	// The find_node rpc
	sb.p += snprintf(sb.p, (end - sb.p), "d1:ad2:id20:");
	sb.put_buf(impl->_my_id_bytes, 20);
	sb.p += snprintf(sb.p, (end - sb.p), "6:target20:");
	sb.put_buf(target_bytes, 20);
	sb.p += snprintf(sb.p, (end - sb.p), "e1:q9:find_node");
	impl->put_transaction_id(sb, Buffer((byte*)&transactionID, 4), end);
	impl->put_version(sb, end);
	sb.p += snprintf(sb.p, (end - sb.p), "1:y1:qe");

	impl->SendTo(nodeInfo.id, buf, sb.p - buf);
}

/**
 Factory for creating FindNodeDhtProcess objects
*/
DhtProcessBase* FindNodeDhtProcess::Create(DhtImpl* pDhtImpl, DhtProcessManager &dpm,
	const DhtID &target2, int target2_len,
	CallBackPointers &cbPointers, int maxOutstanding)
{
	FindNodeDhtProcess* process = new FindNodeDhtProcess(pDhtImpl, dpm, target2, target2_len, time(NULL), cbPointers, maxOutstanding);
	return process;
}

void FindNodeDhtProcess::CompleteThisProcess()
{
#if g_log_dht
	dht_log("FindNodeDhtProcess,completed,id,%d,time,%d\n", target.id[0], get_milliseconds());
#endif
	// do our stuff
	if (callbackPointers.processListener)
		callbackPointers.processListener->ProcessCallback();

	// now let the base class do its stuff
	DhtProcessBase::CompleteThisProcess();
}


//*****************************************************************************
//
// GetPeersDhtProcess			get_peers
//
//*****************************************************************************

/**
	IMPORTANT:
    Be sure the strings are:
	  1) BENCODED
	  2) in alpha order
	  3) correspond to the enum they are paired with
*/
const char* const GetPeersDhtProcess::ArgsNamesStr[] =
{
	"2:id",
	"7:ifhpfxl",
	"9:info_hash",
	"4:name",
	"6:noseedi1e", // no need to set the corresponding value, it is encodede here
	"4:port",
	"6:scrapei1e", // no need to set the corresponding value, it is encodede here
	"5:token",
	"4:vote"
};

GetPeersDhtProcess::GetPeersDhtProcess(DhtImpl* pDhtImpl, DhtProcessManager &dpm
	, const DhtID &target2, int target2_len, time_t startTime, const CallBackPointers &consumerCallbacks, int maxOutstanding)
	: DhtLookupScheduler(pDhtImpl,dpm,target2,target2_len,startTime,consumerCallbacks,maxOutstanding)
{
	byte infoHashBytes[20];

	// allocate the argumenter
	gpArgumenterPtr = new Argumenter(ARGUMENTER_SIZE, (const char** const)ArgsNamesStr);

	// as an accelerator, use the statically allocated buffer in the ArgumenterValueInfo
	// so long as what we want to put into the buffer is shorter thatn the BUF_LEN
	// less 3 characters for the bencoding.  Give this buffer directly to snprintf to use
	// instead of making our own, printing into it, and then copying the bytes again.
	assert(ArgumenterValueInfo::BUF_LEN >=32);

	// since the ID and target info is constant, setup the argumenter bencoded bytes here
	// they are also short enough to fit into a statically allocated 32 byt buffer (asserted above)
	ArgumenterValueInfo& argBuf1 = gpArgumenterPtr->GetArgumenterValueInfo(a_id);
	char* buf = (char*)argBuf1.GetBufferPtr();
	snprintf(buf, ArgumenterValueInfo::BUF_LEN, "20:");
	memcpy(buf + 3, pDhtImpl->_my_id_bytes, 20);
	argBuf1.SetNumBytesUsed(20 + 3);
	gpArgumenterPtr->enabled[a_id] = true;

	DhtIDToBytes(infoHashBytes, target);
	ArgumenterValueInfo& argBuf2 = gpArgumenterPtr->GetArgumenterValueInfo(a_info_hash);
	buf = (char*)argBuf2.GetBufferPtr();
	snprintf(buf, ArgumenterValueInfo::BUF_LEN, "20:");
	memcpy(buf + 3, infoHashBytes, 20);
	argBuf2.SetNumBytesUsed(20 + 3);
	gpArgumenterPtr->enabled[a_info_hash] = true;

	if(target_len != 20){
		ArgumenterValueInfo& argBuf = gpArgumenterPtr->GetArgumenterValueInfo(a_ifhpfxl);
		gpArgumenterPtr->enabled[a_ifhpfxl] = true;
		argBuf.SetNumBytesUsed(snprintf((char*)argBuf.GetBufferPtr(), argBuf.GetArrayLength(), "i%de", target_len));
	}
#if g_log_dht
	dht_log("GetPeersDhtProcess,instantiated,id,%d,time,%d\n", target.id[0], get_milliseconds());
#endif
}

DhtProcessBase* GetPeersDhtProcess::Create(DhtImpl* pDhtImpl, DhtProcessManager &dpm,
	const DhtID &target2, int target2_len,
	CallBackPointers &cbPointers, int flags, int maxOutstanding)
{
	GetPeersDhtProcess* process = new GetPeersDhtProcess(pDhtImpl, dpm, target2, target2_len, time(NULL), cbPointers, maxOutstanding);

	// If flags & announce_seed is true, then we want to include noseed in the rpc arguments.
	// If seed is false, then noseed should also be false (just not included in the
	// rpc argument list)
	// This can coordinate with an announce with seed=1
	process->gpArgumenterPtr->enabled[a_noseed] = flags & IDht::announce_seed;

	return process;
}

void GetPeersDhtProcess::DhtSendRPC(const DhtFindNodeEntry &nodeInfo, const unsigned int transactionID)
{
	const int bufLen = 1024;
	char rpcArgsBuf[bufLen];
	char buf[bufLen];

	SimpleBencoder sb(buf);
	char const* end = buf + sizeof(buf);

	sb.p += snprintf(sb.p, (end - sb.p), "d1:ad");

	int args_len = gpArgumenterPtr->BuildArgumentBytes((byte*)rpcArgsBuf, bufLen);
	sb.put_buf((byte*)rpcArgsBuf, args_len);

	sb.p += snprintf(sb.p, (end - sb.p), "e1:q9:get_peers");
	impl->put_transaction_id(sb, Buffer((byte*)&transactionID, 4), end);
	impl->put_version(sb, end);
	sb.p += snprintf(sb.p, (end - sb.p), "1:y1:qe");

	impl->SendTo(nodeInfo.id, buf, sb.p - buf);
}


//*****************************************************************************
//
// AnnounceDhtProcess			announce
//
//*****************************************************************************

/**
	IMPORTANT:
    Be sure the strings are:
	  1) BENCODED
	  2) in alpha order
	  3) correspond to the enum they are paired with
*/
const char* const AnnounceDhtProcess::ArgsNamesStr[] =
{
	"2:id",
	"12:implied_porti1e",   // no need to set the corresponding value, it is encodede here (the i1e at the end)
	"9:info_hash",
	"4:name",
	"4:port",
	"4:seedi1e",   // no need to set the corresponding value, it is encodede here
	"5:token",
};

AnnounceDhtProcess::AnnounceDhtProcess(DhtImpl* pDhtImpl, DhtProcessManager &dpm, const DhtID &target2, int target2_len, time_t startTime, const CallBackPointers &consumerCallbacks)
	: DhtBroadcastScheduler(pDhtImpl,dpm,target2,target2_len,startTime,consumerCallbacks)
{
	byte infoHashBytes[20];

	// allocate the argumenter
	announceArgumenterPtr = new Argumenter(ARGUMENTER_SIZE, (const char** const)ArgsNamesStr);

	// as an accelerator, use the statically allocated buffer in the ArgumenterValueInfo
	// so long as what we want to put into the buffer is shorter thatn the BUF_LEN
	// less 3 characters for the bencoding.  Give this buffer directly to snprintf to use
	// instead of making our own, printing into it, and then copying the bytes again.
	assert(ArgumenterValueInfo::BUF_LEN >=32);

	// these componenets of the query string don't change during the life of the
	// object, so set them up here in the constructor
	// they are also short enough to fit into a statically allocated 32 byt buffer (asserted above)
	ArgumenterValueInfo& argBuf1 = announceArgumenterPtr->GetArgumenterValueInfo(a_id);
	char* buf = (char*)argBuf1.GetBufferPtr();
	snprintf(buf, ArgumenterValueInfo::BUF_LEN, "20:");
	memcpy(buf + 3, pDhtImpl->_my_id_bytes, 20);
	argBuf1.SetNumBytesUsed(20 + 3);
	announceArgumenterPtr->enabled[a_id] = true;

	DhtIDToBytes(infoHashBytes, target);
	ArgumenterValueInfo& argBuf2 = announceArgumenterPtr->GetArgumenterValueInfo(a_info_hash);
	buf = (char*)argBuf2.GetBufferPtr();
	snprintf(buf, ArgumenterValueInfo::BUF_LEN, "20:");
	memcpy(buf + 3, infoHashBytes, 20);
	argBuf2.SetNumBytesUsed(20 + 3);
	announceArgumenterPtr->enabled[a_info_hash] = true;

	int port = consumerCallbacks.portCallback ? consumerCallbacks.portCallback() : -1;

	ArgumenterValueInfo& argBuf3 = announceArgumenterPtr->GetArgumenterValueInfo(a_port);
	argBuf3.SetNumBytesUsed(snprintf((char*)argBuf3.GetBufferPtr(), argBuf3.GetArrayLength(), "i%de"
		, port != -1 ? port : impl->_udp_socket_mgr->GetBindAddr().get_port()));
	announceArgumenterPtr->enabled[a_port] = true;

	announceArgumenterPtr->enabled[a_implied_port] = port == -1;

	// enable the implied port argument.  This will be ignored by nodes that don't support it and used by those that do.
	announceArgumenterPtr->enabled[a_implied_port] = true;
}

DhtProcessBase* AnnounceDhtProcess::Create(DhtImpl* pDhtImpl, DhtProcessManager &dpm,
	const DhtID &target2, int target2_len,
	CallBackPointers &cbPointers,
	cstr file_name, int flags)
{
	AnnounceDhtProcess* process = new AnnounceDhtProcess(pDhtImpl, dpm, target2, target2_len, time(NULL), cbPointers);

	if(file_name){
		int len = strlen(file_name);
		if(len){
			// The file name may (and mostly will) be larger than the 32 bytes of statically
			// allocated buffer in ArgumenterValueInfo.  So use SetValueBytes() which will
			// dynamically allocate a larger buffer if needed.
			char buf[1024];
			process->announceArgumenterPtr->enabled[a_name] =  true;
			int numChars = snprintf((char*)buf, 1024, "%d:%s", len, file_name);
			process->announceArgumenterPtr->SetValueBytes(a_name, (byte*)buf, numChars);
		}
	}
	process->announceArgumenterPtr->enabled[a_seed] = flags & IDht::announce_seed;
	return process;
}

void AnnounceDhtProcess::DhtSendRPC(const DhtFindNodeEntry &nodeInfo, const unsigned int transactionID)
{
	const int bufLen = 1024;
	char rpcArgsBuf[bufLen];
	char buf[bufLen];

	// convert the token
	ArgumenterValueInfo& argBuf = announceArgumenterPtr->GetArgumenterValueInfo(a_token);
	char* b = (char*)argBuf.GetBufferPtr();
	int pos = snprintf(b, ArgumenterValueInfo::BUF_LEN, "%d:", int(nodeInfo.token.len));
	memcpy(b + pos, nodeInfo.token.b, nodeInfo.token.len);
	argBuf.SetNumBytesUsed(nodeInfo.token.len + pos);

	announceArgumenterPtr->enabled[a_token] = true;

	// build the bencoded query string
	SimpleBencoder sb(buf);
	char const* end = buf + sizeof(buf);

	sb.p += snprintf(sb.p, (end - sb.p), "d1:ad");

	int args_len = announceArgumenterPtr->BuildArgumentBytes((byte*)rpcArgsBuf, bufLen);
	sb.put_buf((byte*)rpcArgsBuf, args_len);

	sb.p += snprintf(sb.p, (end - sb.p), "e1:q13:announce_peer");
	impl->put_transaction_id(sb, Buffer((byte*)&transactionID, 4), end);
	impl->put_version(sb, end);
	sb.p += snprintf(sb.p, (end - sb.p), "1:y1:qe");

	// send the query
	impl->SendTo(nodeInfo.id, buf, sb.p - buf);
}

void AnnounceDhtProcess::ImplementationSpecificReplyProcess(void *userdata, const DhtPeerID &peer_id, DHTMessage &message, uint flags)
{
	// handle errors
	if(message.dhtMessageType != DHT_RESPONSE){
		impl->UpdateError(peer_id);
	}
}

void AnnounceDhtProcess::CompleteThisProcess()
{
	if (callbackPointers.processListener)
		callbackPointers.processListener->ProcessCallback();

	// Tell it that we're done
	if (callbackPointers.addnodesCallback) {
		byte bytes[20];
		DhtIDToBytes(bytes, target);
		callbackPointers.addnodesCallback(callbackPointers.callbackContext, bytes, NULL, 0);
	}

#if g_log_dht
	dht_log("AnnounceDhtProcess,complete_announce,id,%d,time,%d\n", target.id[0], get_milliseconds());
#endif
	DhtProcessBase::CompleteThisProcess();
}

//*****************************************************************************
//
// GetDhtProcess			get
//
//*****************************************************************************

GetDhtProcess::GetDhtProcess(DhtImpl* pDhtImpl, DhtProcessManager &dpm
	, const DhtID & target_2, int target_2_len, time_t startTime, const CallBackPointers &consumerCallbacks, int maxOutstanding, bool with_cas)
	: DhtLookupScheduler(pDhtImpl,dpm,target_2,target_2_len,startTime,consumerCallbacks,maxOutstanding), _with_cas(with_cas)
{
	
	char* buf = (char*)this->_id;
	memcpy(buf, pDhtImpl->_my_id_bytes, 20);


#if g_log_dht
	dht_log("GetDhtProcess,instantiated,id,%d,time,%d\n", target.id[0], get_milliseconds());
#endif

}

DhtProcessBase* GetDhtProcess::Create(DhtImpl* pDhtImpl, DhtProcessManager &dpm,
	const DhtID & target2, int target2_len,
	CallBackPointers &cbPointers, int flags, int maxOutstanding)
{
	GetDhtProcess* process = new GetDhtProcess(pDhtImpl, dpm, target2, target2_len, time(NULL), cbPointers, maxOutstanding, flags & IDht::with_cas);

	return process;
}

void GetDhtProcess::DhtSendRPC(const DhtFindNodeEntry &nodeInfo, const unsigned int transactionID)
{
	const int bufLen = 1024;
	char buf[bufLen];

	SimpleBencoder sb(buf);
	char const* end = buf + sizeof(buf);

	sb.p += snprintf(sb.p, (end - sb.p), "d1:ad");

	sb.p += snprintf(sb.p, (end - sb.p), "2:id20:");
	sb.put_buf((byte*)this->_id, 20);

	sb.p += snprintf(sb.p, (end - sb.p), "6:target20:");

	byte targetAsID[20];

	DhtIDToBytes(targetAsID, target);
	sb.put_buf(targetAsID, 20);

	sb.p += snprintf(sb.p, (end - sb.p), "e1:q3:get");
	impl->put_transaction_id(sb, Buffer((byte*)&transactionID, 4), end);
	impl->put_version(sb, end);
	sb.p += snprintf(sb.p, (end - sb.p), "1:y1:qe");
	
	impl->SendTo(nodeInfo.id, buf, sb.p - buf);
}

//*****************************************************************************
//
// PutDhtProcess			put
//
//*****************************************************************************

PutDhtProcess::PutDhtProcess(DhtImpl* pDhtImpl, DhtProcessManager &dpm, const byte * pkey, const byte * skey, time_t startTime, const CallBackPointers &consumerCallbacks, int flags)
	: DhtBroadcastScheduler(pDhtImpl,dpm,target,target_len,startTime,consumerCallbacks), _with_cas(flags & IDht::with_cas)
{

	signature.clear();
	char* buf = (char*)this->_id;
	memcpy(buf, pDhtImpl->_my_id_bytes, 20);

	buf = (char*)this->_pkey;
	memcpy(buf, pkey, 32);

	buf = (char*)this->_skey;
	memcpy(buf, skey, 64);

#if g_log_dht
	dht_log("PutDhtProcess,instantiated,id,%d,time,%d\n", target.id[0], get_milliseconds());
#endif
}

DhtProcessBase* PutDhtProcess::Create(DhtImpl* pDhtImpl, DhtProcessManager &dpm,
	const byte * pkey,
	const byte * skey,
	CallBackPointers &cbPointers, int flags)
{
	PutDhtProcess* process = new PutDhtProcess(pDhtImpl, dpm, pkey, skey, time(NULL), cbPointers, flags);

	return process;
}

void PutDhtProcess::Sign(std::vector<char> &signature, std::vector<char> v, byte * skey, int64_t seq) {
	unsigned char sig[64];
	char buf[1024];
	unsigned int index = 0;

	index += sprintf(buf, MUTABLE_PAYLOAD_FORMAT, seq);

	v.insert(v.begin(), buf, buf+index);	

	impl->_ed25519_sign_callback(sig, (unsigned char *)&v[0], v.size(), skey);

	signature.assign(sig, sig+64);
}

bool DhtImpl::Verify(byte const * signature, byte const * message, int message_length, byte *pkey, int64_t seq) {
	unsigned char buf[1024];
	int index = sprintf(reinterpret_cast<char*>(buf), MUTABLE_PAYLOAD_FORMAT, seq);
	memcpy(buf + index, message, message_length);
	return _ed25519_verify_callback(signature, buf, message_length + index, pkey);
}

void PutDhtProcess::DhtSendRPC(const DhtFindNodeEntry &nodeInfo, const unsigned int transactionID)
{

	int64_t seq = processManager.seq() + 1;
	if(signature.size() == 0){
		callbackPointers.putCallback(callbackPointers.callbackContext, processManager.get_data_blk(), seq);
		Sign(signature, processManager.get_data_blk(), _skey, seq);
	}
	
	const int bufLen = 1024;
	char buf[bufLen];

	SimpleBencoder sb(buf);
	char const* end = buf + sizeof(buf);

	sb.p += snprintf(sb.p, (end - sb.p), "d1:ad");

	if (!nodeInfo.cas.is_all_zero()) {
		sb.p += snprintf(sb.p, (end - sb.p), "3:cas20:");
		sb.put_buf(nodeInfo.cas.value, 20);
	}
	
	sb.p += snprintf(sb.p, (end - sb.p), "2:id20:");
	sb.put_buf((byte*)this->_id, 20);

	sb.p += snprintf(sb.p, (end - sb.p), "1:k32:");
	sb.put_buf((byte*)this->_pkey, 32);

	sb.p += snprintf(sb.p, (end - sb.p), "3:seqi");
	sb.p += snprintf(sb.p, (end - sb.p), "%" PRId64, seq);

	sb.p += snprintf(sb.p, (end - sb.p), "e3:sig64:");
	sb.put_buf((byte*)&signature[0], 64);

	sb.p += snprintf(sb.p, (end - sb.p), "5:token");
	sb.p += snprintf(sb.p, (end - sb.p), "%d:", int(nodeInfo.token.len));
	sb.put_buf((byte*)nodeInfo.token.b, int(nodeInfo.token.len));

	Buffer v;
	v.b = (byte*)processManager.get_data_blk(v.len);
	sb.p += snprintf(sb.p, (end - sb.p), "1:v");
	//sb.p += snprintf(sb.p, (end - sb.p), "%d:", int(v.len));
	sb.put_buf(v.b, v.len);

	sb.p += snprintf(sb.p, (end - sb.p), "e1:q3:put");

	impl->put_transaction_id(sb, Buffer((byte*)&transactionID, 4), end);
	
	impl->put_version(sb, end);
	
	sb.p += snprintf(sb.p, (end - sb.p), "1:y1:qe");
	// send the query
	impl->SendTo(nodeInfo.id, buf, sb.p - buf);
}

void PutDhtProcess::ImplementationSpecificReplyProcess(void *userdata, const DhtPeerID &peer_id, DHTMessage &message, uint flags)
{
	// handle errors
	if(message.dhtMessageType != DHT_RESPONSE){
		impl->UpdateError(peer_id);
	}
	if(message.dhtMessageType == DHT_ERROR) {
		if (message.error_code == LOWER_SEQ || message.error_code == CAS_MISMATCH) {
			Abort();
			DhtProcessBase* getProc = GetDhtProcess::Create(impl.get(), processManager, target, target_len, callbackPointers, _with_cas ? IDht::with_cas : 0);
			processManager.AddDhtProcess(getProc);
			DhtProcessBase* putProc = PutDhtProcess::Create(impl.get(), processManager,  _pkey, _skey, callbackPointers, _with_cas ? IDht::with_cas : 0);
			processManager.AddDhtProcess(putProc);
		}
	}
}

void PutDhtProcess::CompleteThisProcess()
{
	if (callbackPointers.processListener)
		callbackPointers.processListener->ProcessCallback();

	// Tell it that we're done
	if (callbackPointers.addnodesCallback) {
		byte bytes[20];
		DhtIDToBytes(bytes, target);
		callbackPointers.addnodesCallback(callbackPointers.callbackContext, bytes, NULL, 0);
	}
	signature.clear();

#if g_log_dht
	dht_log("PutDhtProcess,complete_announce,id,%d,time,%d\n", target.id[0], get_milliseconds());
#endif
	DhtProcessBase::CompleteThisProcess();
}

//*****************************************************************************
//
// ScrapeDhtProcess		get_peers with scrape
//
//*****************************************************************************

void ScrapeDhtProcess::ImplementationSpecificReplyProcess(void *userdata, const DhtPeerID &peer_id, DHTMessage &message, uint flags)
{
	Buffer seedsBF;
	Buffer downloadersBF;

	seedsBF.b = (byte*)message.replyDict->GetString("BFsd", &seedsBF.len);
	downloadersBF.b = (byte*)message.replyDict->GetString("BFpe", &downloadersBF.len);

	if(seedsBF.len == 256) {
		seeds->set_union(seedsBF.b);
	}
	if (downloadersBF.len == 256) {
		downloaders->set_union(downloadersBF.b);
	}

	// now do the parent class's reply process
	GetPeersDhtProcess::ImplementationSpecificReplyProcess(userdata, peer_id, message, flags);
}

void ScrapeDhtProcess::CompleteThisProcess()
{
	byte target_bytes[20];
	DhtIDToBytes(target_bytes, target);

	if(callbackPointers.scrapeCallback){
		callbackPointers.scrapeCallback(callbackPointers.callbackContext, target_bytes, downloaders->estimate_count(), seeds->estimate_count());
	}

	DhtProcessBase::CompleteThisProcess();
}

DhtProcessBase* ScrapeDhtProcess::Create(DhtImpl* pDhtImpl, DhtProcessManager &dpm,
	const DhtID &target2, int target2_len,
	CallBackPointers &cbPointers,
	int maxOutstanding)
{
	ScrapeDhtProcess* process = new ScrapeDhtProcess(pDhtImpl,dpm, target2, target2_len, time(NULL), cbPointers, maxOutstanding);
	return process;
}


//*****************************************************************************
//
// VoteDhtProcess			command = vote
//
//*****************************************************************************

void VoteDhtProcess::DhtSendRPC(const DhtFindNodeEntry &nodeInfo, const unsigned int transactionID)
{
	char buf[1024];
	byte target_bytes[20];

	DhtIDToBytes(target_bytes, target);

	SimpleBencoder sb(buf);
	char const* end = buf + sizeof(buf);

	// The find_node rpc
	sb.p += snprintf(sb.p, (end - sb.p), "d1:ad2:id20:");
	sb.put_buf(impl->_my_id_bytes, 20);
	sb.p += snprintf(sb.p, (end - sb.p), "6:target20:");
	sb.put_buf(target_bytes, 20);
	sb.p += snprintf(sb.p, (end - sb.p), "5:token%d:", int(nodeInfo.token.len));
	sb.put_buf(nodeInfo.token.b, nodeInfo.token.len);
	sb.p += snprintf(sb.p, (end - sb.p), "4:votei%de", voteValue);
	sb.p += snprintf(sb.p, (end - sb.p), "e1:q4:vote");
	impl->put_transaction_id(sb, Buffer((byte*)&transactionID, 4), end);
	impl->put_version(sb, end);
	sb.p += snprintf(sb.p, (end - sb.p), "1:y1:qe");

	impl->SendTo(nodeInfo.id, buf, sb.p - buf);
}

/**
 Factory for creating VoteDhtProcess objects
*/
DhtProcessBase* VoteDhtProcess::Create(DhtImpl* pDhtImpl, DhtProcessManager &dpm,
	const DhtID &target2, int target2_len,
	CallBackPointers &cbPointers, int voteValue)
{
	VoteDhtProcess* process = new VoteDhtProcess(pDhtImpl, dpm, target2, target2_len, time(NULL), cbPointers);
	process->SetVoteValue(voteValue);
	return process;
}

void VoteDhtProcess::ImplementationSpecificReplyProcess(void *userdata, const DhtPeerID &peer_id, DHTMessage &message, uint flags)
{
	int num_votes[5];
	BencodedList *votes = message.replyDict->GetList("v");
	if (votes) {
		for (int i = 0; i < 5; ++i) {
			if (i >= votes->GetCount()) {
				num_votes[i] = 0;
				continue;
			}
			num_votes[i] = votes->GetInt(i, 0);
		}
	} else {
		memset(num_votes, 0, sizeof(num_votes));
	}

	assert(callbackPointers.voteCallback);
	if (callbackPointers.voteCallback) {
		byte target_bytes[20];
		DhtIDToBytes(target_bytes, target);
		callbackPointers.voteCallback(callbackPointers.callbackContext, target_bytes, num_votes);
	}

	// now do the parent class's reply process
	DhtBroadcastScheduler::ImplementationSpecificReplyProcess(userdata, peer_id, message, flags);
}


//*****************************************************************************
//
// Argumenter
//
//*****************************************************************************
void ArgumenterValueInfo::SetValueBytes(const byte* valueBytesIn, int numBytesIn)
{
	if(numBytesIn > arrayLength){
		if((byte*)fixedLenBytes != valueBytes)  // delete the old buffer if it is not the statically allocated initial buffer
			delete[] valueBytes;
		valueBytes = new byte[numBytesIn]; // no make the new, larger buffer
		arrayLength = numBytesIn;
	}
	memcpy(valueBytes, valueBytesIn, numBytesIn);
	numBytesUsed = numBytesIn;
}

int Argumenter::BuildArgumentBytes(byte* buf, const int bufLen)
{
	int numBytesCopied = 0;

	for(int x=0; x<length; ++x){
		if(enabled[x]){
			assert((numBytesCopied + strlen(enumStrings[x]) + values[x].GetNumBytesUsed()) < bufLen);
			// copy the argument string
			memcpy(buf+numBytesCopied, enumStrings[x], enumStringLengths[x]);
			numBytesCopied += enumStringLengths[x];
			// copy the argument's value bytes
			memcpy(buf+numBytesCopied, values[x].GetBufferPtr(), values[x].GetNumBytesUsed());
			numBytesCopied += values[x].GetNumBytesUsed();
		}
	}
	return numBytesCopied;
}

Argumenter::Argumenter(int enumLength, const char** const enumStringsIn):length(enumLength), enumStrings(enumStringsIn)
{
	assert(length > 0);
	enumStringLengths = new int[length];
	enabled = new bool[length];
	values = new ArgumenterValueInfo[length];

	ClearAll();
	// pre-calculate the lengths of all of the argument name strings
	// defined in the consumers string array (such as "9:info_hash",
	// "5:token"...) so we know how many bytes to copy when building
	// the bencoded output string (and thus don't have to call
	// strlen all the time for something that is constant)
	for(int x=0; x<length; ++x){
		enumStringLengths[x] = strlen(enumStrings[x]);
	}
}

void Argumenter::ClearEnabled()
{
	for(int x=0; x<length; ++x)
		enabled[x] = false;
}

void Argumenter::ClearValues()
{
	for(int x=0; x<length; ++x){
		values[x].SetNumBytesUsed(0);
	}
}

void Argumenter::ClearAll()
{
	for(int x=0; x<length; ++x){
		enabled[x] = false;
		values[x].SetNumBytesUsed(0);
	}
}


//*****************************************************************************
//
// DhtPeer
//
//*****************************************************************************
/**
	NOTE:  The dht id MUST be set before this function can be meanignfully used!

	As an optimization to the lookup performance of the dht routing table, try to
	distribute the id's in a bucket evenly across the 8 slots available once the bucket
	becomes full and new id are to be added.  This corresponds to the 3 bits of the id
	following the bit prefix that is common to all nodes in the bucket.  These are the
	SubPrefixBits.  This function is general enough to work with any number of SubPrefixBits
	desired that make sense.  If the bucket span is less than the sub-prefix bit size, then
	the sub-prefix bit size is clamped to the bucket span size.
*/
void DhtPeer::ComputeSubPrefix(unsigned int bucketSpan, unsigned int numSubPrefixBits)
{
	assert(numSubPrefixBits <= 32); //can't be larger than the size of an int
	subPrefixPositionBit = 0;
	subPrefixInt = 0;

	if(bucketSpan < numSubPrefixBits)
		numSubPrefixBits = bucketSpan;

	for(int x=1; x<=numSubPrefixBits; ++x){
		subPrefixInt <<= 1;
		subPrefixInt |= id.GetIdBit(bucketSpan - x);
	}
	subPrefixPositionBit = 0x01 << subPrefixInt;
}


//*****************************************************************************
//
// DhtBucketList
//
//*****************************************************************************
void DhtBucketList::ClearSubPrefixInfo()
{
	subPrefixMask = 0;
	memset(subPrefixCounts, 0, sizeof(subPrefixCounts));
}

void DhtBucketList::ComputeSubPrefixInfo()
{
	ClearSubPrefixInfo();
	for (DhtPeer **peer = &first(); *peer; peer=&(*peer)->next)
		UpdateSubPrefixInfo(**peer);
}

/**
	There are two criteria for the Best Node in order of priority:
		1) The node sub-prefix matches the value provided in subPrefix
		2) The lowest rtt with least or no failures

	If the list is empty, NULL will be returned.
	If all you want is the node with the lowest rtt, provide a desiredSubPrefix value
	that does not exist, such as -1.
*/
DhtPeer* DhtBucketList::PopBestNode(int desiredSubPrefix)
{
	bool subPrefixMatchFound = false;
	DhtPeer *p;
	DhtPeer** candidate = &first();
	for (DhtPeer **peer = &first(); *peer; peer=&(*peer)->next) {
		p = *peer;
		if(p->GetSubprefixInt() == desiredSubPrefix){
			if(!subPrefixMatchFound){
				subPrefixMatchFound = true;
				candidate = peer;
			}
			else{
				if(((*candidate)->rtt > p->rtt)  || ((*candidate)->num_fail > p->num_fail)){
					candidate = peer;
				}
			}
		}
		else if(!subPrefixMatchFound){
			if (((*candidate)->rtt > p->rtt)  || ((*candidate)->num_fail > p->num_fail))
				candidate = peer;
		}
	}
	p = *candidate;
	if(p)
		unlinknext(candidate);
	return p;
}

//*****************************************************************************
//
// DhtBucket
//
//*****************************************************************************
/**
	TestForMatchingPrefix() returns TRUE if the prefix bits of 'id' matches
	the prefix bits of nodes that can be stored in the bucket.  If the node
	does not belong in the bucket, FALSE is returned.
*/
bool DhtBucket::TestForMatchingPrefix(const DhtID &id)
{
	if (span == 0)
		return false; // error condition..

	int workingSpan = 160 - span;
	int i = 0;
	while (workingSpan > 0) {
		uint mask = 0xFFFFFFFF;
		if (32 - workingSpan > 0) mask <<= (32 - workingSpan);
		if (((first.id[i]^id.id[i]) & mask) != 0)
			return false;
		workingSpan -= 32;
		i++;
	}
	return true;
}

/**
	Scans the indicated list and removes the entry with the matching dht id if it exists.
*/
bool DhtBucket::RemoveFromList(DhtImpl* pDhtImpl, const DhtID &id, BucketListType bucketType)
{
	DhtBucketList &bucketList = (bucketType == peer_list) ? peers : replacement_peers;

	for (DhtPeer **peer = &bucketList.first(); *peer; peer=&(*peer)->next) {
		DhtPeer *p = *peer;
		if (id != p->id.id) continue; // if this isn't the id we're looking for, skip the remainder of loop

		bucketList.unlinknext(peer);
		pDhtImpl->_dht_peer_allocator.Free(p);
		pDhtImpl->_dht_peers_count--;
		assert(pDhtImpl->_dht_peers_count >= 0);
		return true;
	}
	return false;
}

/**
	Searches through the designated node list for the candidate node's id.  If the id is in
	the list, the node information is updated.  If the candidate node's id is not found
	and the list is not full (less than the bucket size) the node is added.  In either
	of these cases, TRUE is returned.  If pout is proveded, it is set to the node that
	was updated/added.

	FALSE is returned if the bucket is full and the node is not in the list.  pout is
	not set to anything.

	While performing the search for the candidate node in the list, InsertOrUpdateNode()
	will generate the current sup-prefix information for the bucket.  It will also
	set the listContainesAnErroredNode flag if an errored node is encountered.

	InsertOrUpdateNode() should be invoked on a bucket before FindReplacementCandidate()
	is used on the bucket.
*/
bool DhtBucket::InsertOrUpdateNode(DhtImpl* pDhtImpl, DhtPeer const& candidateNode, BucketListType bucketType, DhtPeer** pout)
{
	DhtBucketList &bucketList = (bucketType == peer_list) ? peers : replacement_peers;

	uint n = 0;	// number of peers in bucket-list
	// for all peers in the bucket...
	bucketList.ClearSubPrefixInfo();
	bucketList.listContainesAnErroredNode = false;
	for (DhtPeer **peer = &bucketList.first(); *peer; peer=&(*peer)->next, ++n) {
		DhtPeer *p = *peer;
		bucketList.UpdateSubPrefixInfo(*p);
		if(p->num_fail)
			// This element is here for convienence Update() & InsertOrUpdateNode().
			// It only has a valid meaning immediatly after the consumer has set it.
			bucketList.listContainesAnErroredNode = true;

		// Check if the peer is already in the bucket
		if (candidateNode.id != p->id) continue;

		p->num_fail = 0;
		p->lastContactTime = candidateNode.lastContactTime;
		if (p->first_seen == 0) {
			p->first_seen = candidateNode.first_seen;
			p->rtt = candidateNode.rtt;
		}
		else {
			// sliding average. blend in the new RTT by one quarter
			if (candidateNode.rtt != INT_MAX)
				p->rtt = (p->rtt * 3 + candidateNode.rtt) >> 2;
		}
		if (pout) *pout = p;
		return true;
	}

	// if the bucket isn't full, just add this new node
	if (n < KADEMLIA_BUCKET_SIZE) {
		DhtPeer *peer = pDhtImpl->_dht_peer_allocator.Alloc();
		peer->id = candidateNode.id;
		peer->ComputeSubPrefix(span, KADEMLIA_BUCKET_SIZE_POWER);
		peer->num_fail = 0;
		peer->lastContactTime = candidateNode.lastContactTime;
		peer->first_seen = candidateNode.first_seen;
		peer->rtt = candidateNode.rtt;
		memset(&peer->client, 0, sizeof(peer->client));
		pDhtImpl->_dht_peers_count++;
		bucketList.enqueue(peer);

		if (pout) *pout = peer;
		return true;
	}

	// return false to indicate the bucket is full and does not contain the candidate node
	return false;
}

/**
	FindReplacementCandidate() should be called after InsertOrUpdateNode() if it is to be used.
	It assumes that the bucket it is working with is FULL and that subPrefix and peerMatrix
	information is current for the contents of the bucket (which InsertOrUpdateNode() computes
	as it processes what it should do with the node it is given).  It also assumes that the
	candidate node (id) is not in the bucket.

	The candidate object passed in, should have the rtt set and the sub-prefix computed.

	The algorithm will first check for nodes with errors to return as a replacement candidate.
	If there are no errored nodes it then checks if nodes with the same sub-prefix exists in
	the list.  If so, the longest rtt is used to identify the node with the matching sub-prefix
	that should be replaced with new info.

	If there are no nodes with the same sub-prefix in the list, then some of the other nodes
	in the list have duplicate sub-prefix bits.  Such a duplicative	nodes are scanned for the
	longest rtt and one is identified for being replaced.

	If a replacement node is identified, the pointer to the node is placed in pout and
	TRUE is returned

	If the new node is not suitable for replacing a current node, FALSE is returned and pout is
	not set.
*/
bool DhtBucket::FindReplacementCandidate(DhtImpl* pDhtImpl, DhtPeer const& candidate, BucketListType bucketType, DhtPeer** pout)
{
	assert(pout);
	DhtBucketList &bucketList = (bucketType == peer_list) ? peers : replacement_peers;

	DhtPeer* replaceCandidate = NULL;

	// if there is an errored node in the list, search list for an errored node to return
	if(bucketList.listContainesAnErroredNode){
		for (DhtPeer **peer = &bucketList.first(); *peer; peer=&(*peer)->next) {
			if((*peer)->num_fail){
				*pout = *peer;
				return true;
			}
		}
	}

	// if a node with the candidates sub-prefix already exists in the bucket
	if(bucketList.subPrefixMask & candidate.GetSubprefixPositionBit()){
		int row = candidate.GetSubprefixInt();
		int numNodesWithSubPrefix = bucketList.subPrefixCounts[row];
		assert(numNodesWithSubPrefix > 0);
		// identify the node with the highest rtt
		for(int x=0; x<numNodesWithSubPrefix; ++x){
			DhtPeer* p = bucketList.peerMatrix[row][x];
			if (replaceCandidate == NULL || p->rtt > replaceCandidate->rtt)
				replaceCandidate = p;
		}
		// if the rtt of the candidate node is not shorter than 1/2 the rtt of the node
		// identified for replacement, then it is not suitable to put in the list
		if(candidate.rtt > (replaceCandidate->rtt >> 1))
			return false;
	}
	else{
		// the sub-prefix is not represented in the bucket, but another one (or more) is
		// represented more than once (since the bucket is full).  Find the duplicate
		// with the highest rtt as the suitable node for replacement.
		for(int subPrefixIndex = 0; subPrefixIndex < KADEMLIA_BUCKET_SIZE; subPrefixIndex++){
			if(bucketList.subPrefixCounts[subPrefixIndex] > 1){
				for(int x=0; x<bucketList.subPrefixCounts[subPrefixIndex]; ++x){
					DhtPeer* p = bucketList.peerMatrix[subPrefixIndex][x];
					if (replaceCandidate == NULL || p->rtt > replaceCandidate->rtt)
						replaceCandidate = p;
				}
			}
		}
	}

	*pout = replaceCandidate;
	return true;
}

static char _temp_client[32];

const char* ClientID::str() const {
	char t[3];
	memcpy(t, client, 2);
	t[2] = 0;
	snprintf(_temp_client, sizeof(_temp_client), "%s:%d", t, ver);
	return _temp_client;
}

bool is_alpha(byte c) { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'); }

void ClientID::from_compact(byte *b, size_t len) {
	if (b && len >= 4 && is_alpha(b[0]) && is_alpha(b[1])) {
		ver = b[2] << 8 | b[3];
		memcpy(client, b, sizeof(client));
	}
}

ClientID & ClientID::operator =(const ClientID &c) {
	memcpy(this, &c, sizeof(c));
	return *this;
}

bool ClientID::operator ==(const ClientID &c) const {
	return memcmp(this, &c, sizeof(c)) == 0;
}

