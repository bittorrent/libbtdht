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
#include "get_microseconds.h"
#include "udp_utils.h"
#include "bloom_filter.h"
#include "endian_utils.h"
#include "ExternalIPCounter.h"
#include <string.h> // for strlen
#include <algorithm> // for std::min
#include <math.h>
#include <stdarg.h>
#include <limits>

#define lenof(x) (sizeof(x)/sizeof(x[0]))
const char MUTABLE_PAYLOAD_FORMAT[] = "3:seqi%" PRId64 "e1:v";

const int MESSAGE_TOO_BIG = 205;
const int INVALID_SIGNATURE = 206;
const int SALT_TOO_BIG = 207;
const int CAS_MISMATCH = 301;
const int LOWER_SEQ = 302;

bool DhtVerifyHardenedID(const SockAddr& addr, byte const* node_id, DhtSHACallback* sha);
void DhtCalculateHardenedID(const SockAddr& addr, byte *node_id);

int clamp(int v, int min, int max)
{
	if (v < min) return min;
	if (v > max) return max;
	return v;
}

void log_to_stderr(char const* str)
{
	fprintf(stderr, "DHT: %s\n", str);
}

static DhtLogCallback* g_logger = &log_to_stderr;

void set_log_callback(DhtLogCallback* log)
{
	g_logger = log;
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

	(*g_logger)(buf);

	va_end(args);
}

// TODO: factor this into btutils sockaddr
std::string print_sockaddr(SockAddr const& addr)
{
	char buf[256];
	if (addr.isv6()) {
		in6_addr a = addr.get_addr6();
		int offset = 0;
		buf[offset++] = '[';
		for (int i = 0; i < 16; ++i)
			offset += snprintf(buf + offset, sizeof(buf) - offset
				, ":%02x" + (i == 0), a.s6_addr[i]);
		snprintf(buf + offset, sizeof(buf) - offset, "]:%u", addr.get_port());
	} else {
		uint a = addr.get_addr4();
		snprintf(buf, sizeof(buf), "%u.%u.%u.%u:%u"
			, (a >> 24) & 0xff
			, (a >> 16) & 0xff
			, (a >> 8) & 0xff
			, a & 0xff
			, addr.get_port());
	}
	return buf;
}

#ifdef _MSC_VER
#define PRIu32 "u"
#endif

#ifdef _DEBUG_DHT_INSTRUMENT
#define instrument_log(direction, command, type, size, tid) \
		do_log("DHTI%c\t%" PRId64 "\t%s\t%c\t%lu\t%" PRIu32 "\n", direction, \
				get_milliseconds(), (command ? command : "unknown"), type, (size_t)size, tid)
#else
#define instrument_log(direction, command, type, size, tid)
#endif

#if defined(_DEBUG_DHT)

static void debug_log(char const* fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	char buf[1000];
	vsnprintf(buf, sizeof(buf), fmt, args);
	(*g_logger)(buf);
	va_end(args);
	// TODO: call callback or something
}

char *hexify(byte *b)
{
	char const static hex[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
	static char buff[2*DHT_ID_SIZE+1];
	for(int i=0; i!=DHT_ID_SIZE; i++) {
		buff[i*2] = hex[b[i]>>4];
		buff[i*2+1] = hex[b[i]&0xF];
	}
	buff[2*DHT_ID_SIZE] = 0;
	return buff;
}

char const* print_version(char c[2], int version)
{
	static char buf[100];
	if (c[0] == 0)
		snprintf(buf, sizeof(buf), "unknown");
	else
		snprintf(buf, sizeof(buf), "%c%c-%d", c[0], c[1], version);
	return buf;
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
	, DhtSaveCallback* save, DhtLoadCallback* load, ExternalIPCounter* eip)
{
	_ip_counter = eip;
	_add_node_callback = NULL;
	_save_callback = save;
	_load_callback = load;
	_packet_callback = NULL;
	_peers_tracked = 0;
	_dht_enabled = false;
	_dht_read_only = false;
	_closing = false;
	_udp_socket_mgr = NULL;
	_udp6_socket_mgr = NULL;
	_dht_busy = 0;

	_dht_bootstrap = not_bootstrapped;
	_dht_bootstrap_failed = 0;
	_bootstrap_attempts = 0;
	_allow_new_job = false;
	_refresh_buckets_counter = -1;
	_dht_peers_count = 0;

	// we just happen to know the DHT network is larger than this. If our routing
	// table isn't deep enough, just keep bootstrapping.
	_lowest_span = 150;

	_last_self_refresh = time(NULL);

	// ping a node every 6 seconds
	_ping_frequency = 6;
	_ping_batching = 1;
	_enable_quarantine = true;

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

	Initialize(udp_socket_mgr, udp6_socket_mgr);

	// initialize the put/get data stores
	_immutablePutStore.SetCurrentTime(time(NULL));
	_immutablePutStore.SetMaximumAge(7200); // 2 hours
	_immutablePutStore.SetMaximumSize(1000);

	_mutablePutStore.SetCurrentTime(time(NULL));
	_mutablePutStore.SetMaximumAge(7200); // 2 hours
	_mutablePutStore.SetMaximumSize(1000);

	// zero-out _dht_account
	memset(_dht_accounting, 0, sizeof(_dht_accounting));

	_ed25519_sign_callback = NULL;
	_ed25519_verify_callback = NULL;
	_sha_callback = NULL;

#ifdef _DEBUG_DHT
	debug_log("DhtImpl() [bootstrap=%d]", _dht_bootstrap);

	_bootstrap_log = fopen("dht-bootstrap.log", "w+");
	_lookup_log = fopen("dht-lookups.log", "w+");

#endif
}

DhtImpl::~DhtImpl()
{

#ifdef _DEBUG_DHT
	if (_lookup_log)
		fclose(_lookup_log);
	if (_bootstrap_log)
		fclose(_bootstrap_log);
#endif

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
	for (auto& peer: _peer_store) {
		free(peer.file_name);
	}
}

void DhtImpl::SetVersion(char const* client, int major, int minor)
{
	_dht_utversion[0] = client[0];
	_dht_utversion[1] = client[1];
	_dht_utversion[2] = major;
	_dht_utversion[3] = minor;
}

const unsigned char* DhtImpl::get_version() {
	return _dht_utversion;
}

/**
 * UDP handler
 */
bool DhtImpl::handleReadEvent(UDPSocketInterface *socket, byte *buffer
	, size_t len, const SockAddr& addr)
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
void DhtImpl::Initialize(UDPSocketInterface *udp_socket_mgr
	, UDPSocketInterface *udp6_socket_mgr )
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
	LoadState();

	// initialize _lastLeadingAddress
	if (_ip_counter) _ip_counter->GetIPv4(_lastLeadingAddress);
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
	if (rate < 1024 && rate != 0)	// rate of 0 means no rate limiting
		rate = 1024;

	_dht_rate = rate;
	_dht_probe_rate = 5;
	if (_dht_enabled != enabled) {
		_dht_enabled = enabled;
		_dht_bootstrap = not_bootstrapped;
		_closing = !enabled;
	}

#ifdef _DEBUG_DHT
	debug_log("Enable(enabled=%d, rate=%d) [bootstrap=%d]", enabled, rate, _dht_bootstrap);
#endif
}



/**
 * Check if DHT is enabled
 */
bool DhtImpl::IsEnabled()
{
	return _dht_enabled;
}

/**
 * Set/unset the node to read-only
 */
void DhtImpl::SetReadOnly(bool readOnly)
{
	_dht_read_only = readOnly;
}

void DhtImpl::SetPingFrequency(int seconds)
{
	assert(seconds > 0);
	_ping_frequency = seconds;
}

void DhtImpl::EnableQuarantine(bool e)
{
	_enable_quarantine = e;
}

void DhtImpl::SetPingBatching(int num_pings)
{
	assert(num_pings > 0);
	_ping_batching = num_pings;
}

/**
 * Make sure the buckets are refreshed next time Tick is called
 */
void DhtImpl::ForceRefresh()
{
	_refresh_buckets_counter = 0;
}

/**
 * Return true once bootstrap is complete every 4 seconds   // 4 seconds limits the amount of DHT traffic
 */
bool DhtImpl::CanAnnounce()
{
#ifdef _DEBUG_DHT
	debug_log("CanAnnounce() [bootstrap=%d] = %d", _dht_bootstrap
		, !(_dht_bootstrap != bootstrap_complete  || !_allow_new_job || _dht_peers_count < 32));
#endif

	if (_dht_bootstrap != bootstrap_complete  || !_allow_new_job || _dht_peers_count < 32)
		return false;
	return true;
}

/**
 * Set the ID of this DHT client
 */
void DhtImpl::SetId(byte new_id_bytes[DHT_ID_SIZE])
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
	byte id_bytes[DHT_ID_SIZE];

	if(_ip_counter && _ip_counter->GetIPv4(externIp)){
		DhtCalculateHardenedID(externIp, id_bytes);

#if defined(_DEBUG_DHT)
		debug_log("Generating a hardened node ID: \"%s\""
			, hexify(id_bytes));
#endif
	} else {
		uint32 *pTemp = (uint32 *) id_bytes;
		// Generate a random ID
		for(uint i=0; i<5; i++)
			*pTemp++ = rand();

#if defined(_DEBUG_DHT)
		debug_log("Generating a random node ID: \"%s\""
			, hexify(id_bytes));
#endif
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

bool ValidateEncoding( const void * data, uint len )
{
	BencodedDict dict;
	bool bReturn = false;
	if( BencEntity::Parse((const byte*) data, dict, ((const byte*) data ) + len)) {
		std::string b = dict.Serialize();
		bReturn = (memcmp(data, b.c_str(), len) == 0);
	}
	return bReturn;
}

#endif

bool DhtImpl::AccountAndSend(const DhtPeerID &peer, const void *data, int len,
		int packetSize) {
	Account(DHT_BW_IN_REQ, packetSize);

	if (len < 0) {
		do_log("dht blob exceeds maximum size.");
		return false;
	}
	Account(DHT_BW_OUT_REPL, len);
	SendTo(peer.addr, data, len);
	return true;
}

void DhtImpl::SendTo(SockAddr const& peer, const void *data, uint len)
{
	if (!_dht_enabled) return;

	assert(ValidateEncoding(data, len));
	Account(DHT_BW_OUT_TOTAL, len);

	if (_packet_callback) {
		_packet_callback(data, len, false);
	}

	_dht_quota -= len;

	//Need replace by the new WinRT udp socket implementation
	UDPSocketInterface *socketMgr = (peer.isv4())?_udp_socket_mgr:
		_udp6_socket_mgr;
	assert(socketMgr);
	socketMgr->Send(peer, (byte*)data, len);
}

void CopyBytesToDhtID(DhtID &id, const byte *b)
{
	assert(b);
#if BT_LITTLE_ENDIAN == 1
	for(uint i=0; i!=DHT_ID_SIZE; i++) {
		((byte*)&id)[i] = b[i^3]; // ids are a sequence of 5 uint32s, so this `hton`s
	}
#else
	memcpy((byte*)&id, b, DHT_ID_SIZE);
#endif
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
	byte abytes[DHT_ID_SIZE];
	byte bbytes[DHT_ID_SIZE];
	DhtIDToBytes(abytes, a);
	DhtIDToBytes(bbytes, b);
	return memcmp(abytes, bbytes, num);
}

void DhtIDToBytes(byte *b, const DhtID &id)
{
	for(uint i=0; i!=DHT_ID_SIZE; i++)
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

	do_log("Received: %u requests (%u B), %u replies (%u B), %u no quota (%u B), %u invalid (%u B)",
		 uint(acct[DHT_BW_IN_REQ].count),
		 uint(acct[DHT_BW_IN_REQ].size),
		 uint(acct[DHT_BW_IN_REPL].count),
		 uint(acct[DHT_BW_IN_REPL].size),
		 uint(acct[DHT_BW_IN_NO_QUOTA].count),
		 uint(acct[DHT_BW_IN_NO_QUOTA].size),
		 uint(acct[DHT_BW_IN_TOTAL].count-acct[DHT_BW_IN_REQ].count-acct[DHT_BW_IN_REPL].count),
		 uint(acct[DHT_BW_IN_TOTAL].size-acct[DHT_BW_IN_REQ].size-acct[DHT_BW_IN_REPL].size));

	do_log("Sent: %u requests (%u), %u replies (%u)",
		uint(acct[DHT_BW_OUT_TOTAL].count-acct[DHT_BW_OUT_REPL].count),
		uint(acct[DHT_BW_OUT_TOTAL].size-acct[DHT_BW_OUT_REPL].size),
		uint(acct[DHT_BW_OUT_REPL].count),
		uint(acct[DHT_BW_OUT_REPL].size));

#if defined(_DEBUG_DHT)
	char const* invalid_msg_names[] =
	{
		"DHT_INVALID_IPV6",
		"DHT_INVALID_PI_BAD_TID",
		"DHT_INVALID_PI_ERROR",
		"DHT_INVALID_PI_NO_DICT",
		"DHT_INVALID_PI_NO_TYPE",
		"DHT_INVALID_PI_Q_BAD_ARGUMENT",
		"DHT_INVALID_PI_Q_BAD_COMMAND",
		"DHT_INVALID_PI_R_BAD_REPLY",
		"DHT_INVALID_PI_UNKNOWN_TYPE",
		"DHT_INVALID_PQ_AP_BAD_INFO_HASH",
		"DHT_INVALID_PQ_BAD_ID_FIELD",
		"DHT_INVALID_PQ_BAD_PORT",
		"DHT_INVALID_PQ_BAD_TARGET_ID",
		"DHT_INVALID_PQ_BAD_WRITE_TOKEN",
		"DHT_INVALID_PQ_GP_BAD_INFO_HASH",
		"DHT_INVALID_PQ_INVALID_TOKEN",
		"DHT_INVALID_PQ_IPV6",
		"DHT_INVALID_PQ_BAD_PUT_NO_V",
		"DHT_INVALID_PQ_BAD_PUT_BAD_V_SIZE",
		"DHT_INVALID_PQ_BAD_PUT_SIGNATURE",
		"DHT_INVALID_PQ_BAD_PUT_CAS",
		"DHT_INVALID_PQ_BAD_PUT_KEY",
		"DHT_INVALID_PQ_BAD_PUT_SALT",
		"DHT_INVALID_PQ_BAD_GET_TARGET",
		"DHT_INVALID_PQ_UNKNOWN_COMMAND",
		"DHT_INVALID_PR_BAD_ID_FIELD",
		"DHT_INVALID_PR_BAD_TID_LENGTH",
		"DHT_INVALID_PR_IP_MISMATCH",
		"DHT_INVALID_PR_PEER_ID_MISMATCH",
		"DHT_INVALID_PR_UNKNOWN_TID",
	};
	for (int i = DHT_INVALID_BASE+1; i < DHT_INVALID_END; i++) {
		if (acct[i].count == 0) continue;
		do_log("%s: %u occurances (%u Bytes)"
			, invalid_msg_names[i - DHT_INVALID_IPV6], uint(acct[i].count), uint(acct[i].size));
	}
#endif
}

void DhtImpl::DumpBuckets()
{
	int total = 0;
	int total_cache = 0;
	int lowest_span = 160;
	do_log("Num buckets: %d. My DHT ID: %s", _buckets.size(), format_dht_id(_my_id));

	for(uint i=0; i<_buckets.size(); i++) {
		DhtBucket& bucket = *_buckets[i];
		if (bucket.span < lowest_span && bucket.peers.first() != NULL)
			lowest_span = bucket.span;

		int cache_nodes = 0;
		for (DhtPeer **peer = &bucket.replacement_peers.first(); *peer; peer=&(*peer)->next) {
			cache_nodes++;
			total_cache++;
		}
		int main_nodes = 0;
		int unpinged_nodes = 0;
		for (DhtPeer **peer = &bucket.peers.first(); *peer; peer=&(*peer)->next) {
			main_nodes++;
			total++;
			if ((*peer)->lastContactTime == 0) unpinged_nodes++;
		}

		char const* progress_bar = "########";

		char const* marker = "";
		if (bucket.TestForMatchingPrefix(_my_id)) marker = " <-- _my_id";

		do_log("Bucket %2d: %.8X nodes: [%-8s] replacements: [%-8s], "
			"span: %d, unpinged: [%-8s]%s", i
			, bucket.first.id[0], progress_bar + (8 - main_nodes)
			, progress_bar + (8 - cache_nodes), bucket.span
			, progress_bar + (8 - unpinged_nodes)
			, marker);

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
	do_log("Deepest bucket: %d [target: %d]", 160 - lowest_span, 160 - _lowest_span);
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
	_buckets.insert(_buckets.begin() + position, bucket);

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
#if g_log_dht
			assert(p->origin >= 0);
			assert(p->origin < sizeof(g_dht_peertype_count)/sizeof(g_dht_peertype_count[0]));
#endif
			new_bucket.replacement_peers.enqueue(p);
		} else {
			peer=&(*peer)->next;
		}
	}
}

DhtRequest *DhtImpl::LookupRequest(uint tid)
{
	for(DhtRequest *req = _requests.first(); req; req=req->next) {
#if g_log_dht
		assert(req->origin >= 0);
		assert(req->origin < sizeof(g_dht_peertype_count)/sizeof(g_dht_peertype_count[0]));
#endif
		if (req->tid == tid)
			return req;
	}
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

#if USE_HOLEPUNCH
// send a request to dst to ping punchee, in order for it to
// open a pinhole.
void DhtImpl::SendPunch(SockAddr const& dst, SockAddr const& punchee)
{
	unsigned char buf[120];
	smart_buffer sb(buf, sizeof(buf));

	assert(punchee.isv4());
	assert(dst.isv4());

	// see if we have this pair of nodes in the bloom filter
	// already. If we do, we've already sent a punch request recently,
	// and we should skip it this time.
	byte record[12];
	dst.compact(record, true);
	punchee.compact(record + 6, true);
	sha1_hash h = _sha_callback(record, 12);
	if (_recent_punch_requests.test(h)) {
#ifdef _DEBUG_DHT
		debug_log("SUPPRESSED PUNCH REQUEST TO: %s -> %s"
			, print_sockaddr(dst).c_str()
			, print_sockaddr(punchee).c_str());
#endif
		return;
	}

	_recent_punch_requests.add(h);

#ifdef _DEBUG_DHT
	debug_log("SEND PUNCH REQUEST TO: %s -> %s"
		, print_sockaddr(dst).c_str()
		, print_sockaddr(punchee).c_str());
#endif

	unsigned char target_ip[20];
	int len = punchee.compact(target_ip, true);
	assert(len == 6);
	sb("d1:ad2:id20:")(DHT_ID_SIZE, _my_id_bytes)
		("2:ip6:")(target_ip, 6)("e1:q5:punch");
	put_is_read_only(sb);
	sb("1:t4:....");
	put_version(sb);
	sb("1:y1:qe");
	assert(sb.length() >= 0);
	
	// punch commands have tid '....' which is never used, sicne there is no reply
	instrument_log('>', "punch", 'q', sb.length(), Read32((byte*)("....")));
	SendTo(dst, buf, sb.length());
}
#endif // USE_HOLEPUNCH

DhtRequest *DhtImpl::SendPing(const DhtPeerID &peer_id) {
	unsigned char buf[120];
	smart_buffer sb(buf, sizeof(buf));

	DhtRequest *req = AllocateRequest(peer_id);

#ifdef _DEBUG_DHT
	debug_log("SEND PING(%d): %s", req->tid
		, print_sockaddr(peer_id.addr).c_str());
#endif

	sb("d1:ad2:id20:")(DHT_ID_SIZE, _my_id_bytes)("e1:q4:ping");
	put_is_read_only(sb);
	put_transaction_id(sb, Buffer((byte*)&req->tid, 4));
	put_version(sb);
	sb("1:y1:qe");
	assert(sb.length() >= 0);
	
	if (sb.length() < 0) {
		do_log("SendPing blob exceeds maximum size.");
		return NULL;
	}
	instrument_log('>', "ping", 'q', sb.length(), req->tid);
	SendTo(peer_id.addr, buf, sb.length());
	return req;
}

// sends a single find-node request
DhtRequest *DhtImpl::SendFindNode(const DhtPeerID &peer_id) {
	unsigned char buf[1500];
	smart_buffer sb(buf, sizeof(buf));

	DhtID target;
	int buck = GetBucket(peer_id.id);

	// pick the target for the lookup. If we're in the bucket that can
	// split, use our ID as the target. We want to continuously try to find nodes
	// closer to us
	if (_buckets[buck]->TestForMatchingPrefix(_my_id)) {
		target = _my_id;
	} else {
		// pick an adjacent bucket, if it's empty
		if (buck + 1 < _buckets.size() && _buckets[buck + 1]->peers.first() == NULL)
			buck +=1;
		else if (buck - 1 >= 0 && _buckets[buck - 1]->peers.first() == NULL)
			buck -= 1;
		DhtBucket* bucket = _buckets[buck];

		// pick the bucket using a different round-robin counter,
		// to get nodes for empty buckets too
		GenRandomIDInBucket(target, bucket);
	}

	byte target_bytes[DHT_ID_SIZE];
	DhtIDToBytes(target_bytes, target);

	DhtRequest *req = AllocateRequest(peer_id);

#ifdef _DEBUG_DHT
	debug_log("SEND FIND_NODE ping (%d): %s", req->tid
		, print_sockaddr(peer_id.addr).c_str());
#endif

	sb("d1:ad2:id20:")(DHT_ID_SIZE, _my_id_bytes);
	sb("6:target20:")(DHT_ID_SIZE, target_bytes);
	sb("e1:q9:find_node");
	put_is_read_only(sb);
	put_transaction_id(sb, Buffer((byte*)&req->tid, 4));
	put_version(sb);
	sb("1:y1:qe");
	assert(sb.length() >= 0);
	
	if (sb.length() < 0) {
		do_log("SendFindNode blob exceeds maximum size.");
		return NULL;
	}

#ifdef _DEBUG_DHT
	if (_lookup_log)
		fprintf(_lookup_log, "[%u] [] []: FIND -> %s\n"
			, uint(get_milliseconds()), print_sockaddr(peer_id.addr).c_str());
#endif

	instrument_log('>', "find_node", 'q', sb.length(), req->tid);
	SendTo(peer_id.addr, buf, sb.length());
	return req;
}


/**
	Increase the error counter for a peer
*/
void DhtImpl::UpdateError(const DhtPeerID &id, bool force_remove)
{
	int bucket_id = GetBucket(id.id);
	if (bucket_id < 0) return;
	DhtBucket &bucket = *_buckets[bucket_id];

	for (DhtPeer **peer = &bucket.peers.first(); *peer; peer=&(*peer)->next) {

		DhtPeer *p = *peer;
		// Check if the peer is already in the bucket
		if (id != p->id) continue;

#ifdef _DEBUG_DHT
		debug_log("node %s (id: %s) failed"
			, print_sockaddr(p->id.addr).c_str()
			, format_dht_id(p->id.id));
#endif

		// rtt is set to INT_MAX until we receive the first response from this node
		if (++p->num_fail >= (p->rtt != INT_MAX ? FAIL_THRES : FAIL_THRES_NOCONTACT)
			|| !bucket.replacement_peers.empty()
			|| force_remove) {

			// We get here if the node should be deleted. Which happens if one of
			// the following criteria is satisfied:
			//   1. the fail-counter exceeds the limit
			//   2. there are nodes in the replacement cache ready
			//      to replace this node.
			//   3. we force removing it, typically because we received an ICMP
			//      error indicating the node is down.

#if g_log_dht
			assert((*peer)->origin >= 0);
			assert((*peer)->origin < sizeof(g_dht_peertype_count)/sizeof(g_dht_peertype_count[0]));
			g_dht_peertype_count[(*peer)->origin]--;
#endif
			// remove the node from its bucket and move one node from the
			// replacement cache
			RemoveTableIP(p->id.addr);
			bucket.peers.unlinknext(peer);
			if (!bucket.replacement_peers.empty()) {
				// move one from the replacement_peers instead.
				bucket.peers.enqueue(bucket.replacement_peers.PopBestNode(p->GetSubprefixInt()));
			}
			_dht_peer_allocator.Free(p);
			_dht_peers_count--;
			assert(_dht_peers_count >= 0);

#ifdef _DEBUG_DHT
			if (_dht_bootstrap == valid_response_received && _bootstrap_log) {
				fprintf(_bootstrap_log, "[%u] nodes: %u\n"
					, uint(get_milliseconds() - _bootstrap_start), _dht_peers_count);
			}
#endif
		}
		return; // nodes in the primary list and the reserve list should be mutually exclusive
	}

	// Also check if the peer is in the replacement cache already.
	for (DhtPeer **peer = &bucket.replacement_peers.first(); *peer; peer=&(*peer)->next) {
		DhtPeer *p = *peer;

		// Check if the peer is already in the bucket
		if (id != p->id) continue;

		if (++p->num_fail >= (p->rtt != INT_MAX ? FAIL_THRES : FAIL_THRES_NOCONTACT)
			|| force_remove) {
#if g_log_dht
			assert((*peer)->origin >= 0);
			assert((*peer)->origin < sizeof(g_dht_peertype_count)/sizeof(g_dht_peertype_count[0]));
			g_dht_peertype_count[(*peer)->origin]--;
#endif
			RemoveTableIP(p->id.addr);
			bucket.replacement_peers.unlinknext(peer);
			_dht_peer_allocator.Free(p);
			_dht_peers_count--;
			assert(_dht_peers_count >= 0);

#ifdef _DEBUG_DHT
			if (_dht_bootstrap == valid_response_received && _bootstrap_log) {
				fprintf(_bootstrap_log, "[%u] nodes: %u\n"
					, uint(get_milliseconds() - _bootstrap_start), _dht_peers_count);
			}
#endif
		}
		break;
	}
}


uint DhtImpl::CopyPeersFromBucket(uint bucket_id, DhtPeerID **list
	, uint numwant, int &wantfail, time_t min_age)
{
	DhtBucketList &bucket = _buckets[bucket_id]->peers;
	uint n = 0;
	time_t now = time(nullptr);
	for (DhtPeer *peer = bucket.first(); peer && n < numwant; peer=peer->next) {

		if (now - peer->first_seen < min_age) {
			continue;
		}

		// if lastContactTime is 0, it means we have never sent any query and seen
		// a response from this peer.
		if ((peer->lastContactTime != 0 && peer->num_fail == 0) || --wantfail >= 0) {

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
void FindNClosestToTarget( DhtPeerID *src[], uint srcCount, DhtPeerID *dest[]
	, uint destCount, const DhtID &target )
{
	// sort the list to find the closest peers.
	// Seems to only be used on lists of 30 or smaller
	std::vector<DhtPeerID*> sorted_list(src, src + srcCount);
	if (destCount > srcCount) destCount = srcCount;
	std::sort(sorted_list.begin(), sorted_list.end(), dht_node_comparator(target));
	for(int i = 0; i < destCount ; i++)
		dest[i] = sorted_list[i];
}

int DhtImpl::AssembleNodeList(const DhtID &target, DhtPeerID** ids
	, int numwant, bool bootstrap)
{
	// assemble a minimum of one bucket's worth or the requested count
	// whichever is lower
	int const minwant = (std::min)(8, numwant);

	// Find 8 good ones or bad ones (in case there are no good ones)
	int num = FindNodes(target, ids, minwant, minwant, 0);
	assert(num <= numwant);
	assert(num >= 0);
	// And 8 definitely good ones.
	num += FindNodes(target, ids + num, numwant - num, 0, 0);
	assert(num <= numwant);
	assert(num >= 0);
	// Only add the bootstrap servers if this is an explicit bootstrap or exponential
	// backoff is not in effect. This is important to avoid hammering the bootstrap servers
	// if the user's internet connection is broken such that it cannot receive responses.
	if (num < minwant && (bootstrap || _dht_bootstrap < bootstrap_error_received)) {
		if (_bootstrap_routers.size() > numwant - num) {
			num = numwant - _bootstrap_routers.size();
			assert(num <= numwant);
			assert(num >= 0);
			if (num < 0) num = 0;
		}

		// if we don't have enough nodes in our routing table, fill in with
		// bootstrap nodes.
		_temp_nodes.resize(numwant - num);

		int c = 0;
		for (std::vector<SockAddr>::iterator i = _bootstrap_routers.begin()
			, end(_bootstrap_routers.end()); i != end && num < numwant; ++i, ++c)
		{
			// just fake the id to match the target, so this is at the top
			// of the list
			_temp_nodes[c].id = target;
			// randomize the low 4 bytes to make the IDs be different. Later in
			// the lookup process we weed out duplicates, this prevents the
			// bootstrap nodes from beeing removed.
			_temp_nodes[c].id.id[4] = rand();
			_temp_nodes[c].addr = *i;
			ids[num] = &_temp_nodes[c];
			++num;
		}
		assert(num <= numwant);
		assert(num >= 0);
	}
	return num;
}

/**
 Find the numwant nodes closest to target
 Returns the number of nodes found.
*/
uint DhtImpl::FindNodes(const DhtID &target, DhtPeerID **list, uint numwant
	, int wantfail, time_t min_age)
{
	int bucket_id = GetBucket(target);
	if (bucket_id < 0) return 0;

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

//--------------------------------------------------------------------------------

// d( "a"= d("id" = <hash>, "target" = <hash>), "q"="find_node", "t" = 0, "y" = "q")
// d( "r" = d( "id" = <hash>, "nodes" = <208 byte string>), "t" = 1, "y" = "r")

int DhtImpl::BuildFindNodesPacket(smart_buffer &sb, DhtID &target_id, int size
	, SockAddr const& requestor, bool send_punches)
{
	DhtPeerID *list[KADEMLIA_K];
	uint n = FindNodes(target_id, list, sizeof(list)/sizeof(list[0]), 0
		, _enable_quarantine ? CROSBY_E : 0);

	// Send an array of peers.
	// Each peer is DHT_ID_SIZE byte id, 4 byte ip and 2 byte port, in big endian format.

	// don't write more nodes than what will fit in size
	// 11 bytes is the overhead of printing "5:nodesxxx:"
	// if we can't fit a single node, just skip it
	if (size < 11 + DHT_ID_SIZE + 4 + 2) return 0;
	n = (std::min)(n, uint(size - 11) / (DHT_ID_SIZE + 4 + 2));
	// never try to send more than 8 nodes
	// since 8 is the K constant in our kademlia implementation
	// i.e. bucket size
	if (n > 8) n = 8;

	// IP address, port and node-ID
	const int node_size = 4 + 2 + 20;

	sb("5:nodes%d:", n * node_size);
	for(uint i=0; i!=n; i++) {
		sb(list[i]->id)(list[i]->addr);
#if USE_HOLEPUNCH
		if (send_punches) SendPunch(list[i]->addr, requestor);
#endif
	}
	assert(sb.length() >= 0);
	return n;
}

// Get the storage container associated with a info_hash
std::vector<VoteContainer>::iterator DhtImpl::GetVoteStorageForID(DhtID const& key) {
	VoteContainer vc;
	vc.key = key;
	return lower_bound(_vote_store.begin(), _vote_store.end(), vc);
}

// Get the storage container associated with a info_hash
std::vector<StoredContainer>::iterator DhtImpl::GetStorageForID(const DhtID &info_hash)
{
	StoredContainer sc;
	sc.info_hash = info_hash;
	return lower_bound(_peer_store.begin(), _peer_store.end(), sc);
}

// Retrieve N random peers.
std::vector<StoredPeer> *DhtImpl::GetPeersFromStore(const DhtID &info_hash, str* file_name, uint n)
{
	std::vector<StoredContainer>::iterator it = GetStorageForID(info_hash);
	if (it == _peer_store.end())
		return NULL;

	if (it->info_hash != info_hash)
		return NULL;

	StoredContainer *sc = &(*it);

	if (sc->file_name && sc->file_name[0] != '\0') {
		*file_name = sc->file_name;
	}

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
void DhtImpl::AddVoteToStore(smart_buffer& sb, DhtID& target
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
	sb("1:vli%dei%dei%dei%dei%dee", vc->num_votes[0], vc->num_votes[1],
			vc->num_votes[2], vc->num_votes[3], vc->num_votes[4]);
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
	for(std::vector<StoredContainer>::iterator it = _peer_store.begin(); it != _peer_store.end();) {
		std::vector<StoredPeer> &sp = it->peers;
		for(uint j=0; j != sp.size();) {
			if (sp[j].time < expire_before) {
				sp[j] = sp[sp.size()-1];
				sp.resize(sp.size() - 1);
				_peers_tracked--;
			} else {
				++j;
			}
		}
		if (sp.size() == 0) {
			free(it->file_name);
			it = _peer_store.erase(it);
		} else {
			++it;
		}
	}

	for (std::vector<VoteContainer>::iterator it = _vote_store.begin(); it != _vote_store.end();) {
		// if nobody has voted for 2 hours, expire it!
		if (it->last_use + 2 * 60 * 60 > time(NULL)) {
			++it;
			continue;
		}

		it = _vote_store.erase(it);
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
	debug_log("Got ICMP error (rtt=%d ms) tid=%d"
		, get_milliseconds() - req->time, Read32(tid));
#endif

	UnlinkRequest(req);

	if (!strcmp(command, "ping")
		|| !strcmp(command, "get")
		|| !strcmp(command, "put")
		|| !strcmp(command, "find_node")
		|| !strcmp(command, "get_peers")
		|| !strcmp(command, "announce_peer")
		|| !strcmp(command, "vote")) {

		req->_pListener->Callback(req->peer, req, DhtProcessBase::dummyMessage
			, (DhtProcessFlags)ICMP_ERROR);
		delete req->_pListener;
	}

	// Cleanup
	delete req;
	return true;
}


void DhtImpl::AddIP(smart_buffer& sb, byte const* id, SockAddr const& addr)
{
	//verify the ip here...we need to notify them if they're using a
	//peer id that doesn't match with their external ip

	//	if (!DhtVerifyHardenedID(addr, id, _sha_callback)) {
	//We want to always notify nodes of their external IP and port, 
	//partly because it's a good idea to always know your external IP and port, 
	//but specifically for BT Chat we want to store our own IP port in an encrypted data blob, in a put request	
	if (addr.isv4()) {
		sb("2:ip6:")(addr);
	} else {
		sb("2:ip18:")(addr);
	}
}


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
		|| memcmp(TorrentSession::_dht_feed_items[index].info_hash.value, info_hash, DHT_ID_SIZE) != 0) {
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

void DhtImpl::put_transaction_id(smart_buffer& sb, Buffer tid) {
	sb("1:t%d:", int(tid.len))(tid);
}

void DhtImpl::put_version(smart_buffer& sb) {
	sb("1:v4:%c%c%c%c", _dht_utversion[0], _dht_utversion[1], _dht_utversion[2],
			_dht_utversion[3]);
}

void DhtImpl::put_is_read_only(smart_buffer& sb) {
	if (_dht_read_only)
		sb("2:roi1e");
}

bool DhtImpl::ProcessQueryAnnouncePeer(DHTMessage& message, DhtPeerID &peerID,
		int packetSize) {
	unsigned char buf[256];
	smart_buffer sb(buf, sizeof(buf));

	// read port
	if (message.portNum < 0 && !message.impliedPort) {
		Account(DHT_INVALID_PQ_BAD_PORT, packetSize);
		return false;
	}

	// read the info hash
	DhtID info_hash_id;
	if(!message.infoHash.b) {
		Account(DHT_INVALID_PQ_AP_BAD_INFO_HASH, packetSize);
		return false;
	}
	CopyBytesToDhtID(info_hash_id, message.infoHash.b);

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
		debug_log("ANNOUNCE_PEER: id='%s', info_hash='%s', token='%s', host='%A'", format_dht_id(peerID.id), temp, hexify(message.token.b), &peerID.addr); //TODO: valgrind fishiness
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
	sb("d");
	AddIP(sb, message.id, peerID.addr);
	sb("1:rd2:id20:")(DHT_ID_SIZE, _my_id_bytes)("e");
	put_transaction_id(sb, message.transactionID);
	put_version(sb);
	sb("1:y1:re");

	assert(sb.length() >= 0);
	instrument_log('>', "announce_peer", 'r', sb.length(), Read32(message.transactionID.b));
	return AccountAndSend(peerID, buf, sb.length(), packetSize);
}

bool DhtImpl::ProcessQueryGetPeers(DHTMessage &message, DhtPeerID &peerID,
		int packetSize) {
	unsigned char buf[8192];
	smart_buffer sb(buf, sizeof(buf));

	DhtID info_hash_id;
	sha1_hash ttoken;
	const int num_peers = 100;// maximum number of peers to return; much more than this won't fit in an MTU

	if (!message.infoHash.b) {
		Account(DHT_INVALID_PQ_GP_BAD_INFO_HASH, packetSize);
		return false;
	}
	CopyBytesToDhtID(info_hash_id, message.infoHash.b);

#if USE_DHTFEED
		if (s_core.collect_dht_feed) {
			add_to_dht_feed(message.infoHash.b, 0);
		}
#endif

	// Make sure the num_peers first peers are shuffled.
	DhtID null_id;
	memset(null_id.id, 0, sizeof(null_id.id));
	str file_name = NULL;

	// start the output info
	sb("d");
	AddIP(sb, message.id, peerID.addr);
	sb("1:rd");

	const std::vector<StoredPeer> *sc = GetPeersFromStore(info_hash_id
			, &file_name, num_peers);

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

		sb("4:BFpe256:")(256, downloaders.get_set());
		sb("4:BFsd256:")(256, seeds.get_set());
	}

	GenerateWriteToken(&ttoken, peerID);
	sb("2:id20:")(DHT_ID_SIZE, _my_id_bytes);

	if (message.filename.len) {
		int len = (message.filename.len>50) ? 50 : message.filename.len;
		// the max filename length of 50 here is really to be
		// extra conservative with the quite limited MTU space.
		// nodes and peers are much more useful than the filename
		// and should get the vast majority of it
		sb("1:n%d:%.*s", len, len, message.filename.b);
	}

	bool has_values = sc != NULL && !message.scrape;
	uint n = (std::min)((sc ? sc->size() : 0), size_t(num_peers));
	int size =
		(sb.length()) // written so far
		+ (has_values ? (10 + n * 8) : 0) // the values
		+ 30 // token
		+ 7 + message.transactionID.len + 18; // tail (t, v and y)

	const uint16 mtu = GetUDP_MTU(peerID.addr);
	assert(size <= mtu);

	BuildFindNodesPacket(sb, info_hash_id, mtu - size, peerID.addr);
	sb("5:token20:")(DHT_ID_SIZE, ttoken.value);

#if defined(_DEBUG_DHT)
	char const* temp = format_dht_id(info_hash_id);
	debug_log("GET_PEERS: id='%s', info_hash='%s', token='%s'",
			 format_dht_id(peerID.id), temp, hexify(ttoken.value));
#endif

	if (has_values) {
		int left = mtu - (sb.length() + 10);
		if (n > left / 8) n = left / 8;
		assert(sb.length() + 10 + 8 * n <= mtu);
		if (n > 0) {
			sb("6:valuesl");
			for(uint i=0; i!=n; i++) {
				sb("6:")(4, (*sc)[i].ip)(2, (*sc)[i].port);
			}
			sb("e");
		}
	}

	sb("e");

	put_transaction_id(sb, message.transactionID);
	put_version(sb);

	sb("1:y1:re");

	assert(sb.length() >= 0 && sb.length() <= mtu);

	instrument_log('>', "get_peers", 'r', sb.length(), Read32(message.transactionID.b));
	return AccountAndSend(peerID, buf, sb.length(), packetSize);
}

bool DhtImpl::ProcessQueryFindNode(DHTMessage &message, DhtPeerID &peerID,
		int packetSize) {
	DhtID target_id;
	if(!message.target.b) {
		Account(DHT_INVALID_PQ_BAD_TARGET_ID, packetSize);
		return false;
	}
	CopyBytesToDhtID(target_id, message.target.b);

	unsigned char buf[512];
	smart_buffer sb(buf, sizeof(buf));

	// Send my own ID
	sb("d");
	AddIP(sb, message.id, peerID.addr);
	
	sb("1:rd2:id20:")(DHT_ID_SIZE, _my_id_bytes);
	int size = sb.length() // written so far
		+ 7 + message.transactionID.len + 18; // tail (t, v and y)

	const uint16 mtu = GetUDP_MTU(peerID.addr);
	assert(size <= mtu);

#if defined(_DEBUG_DHT)
	uint n =
#endif
		BuildFindNodesPacket(sb, target_id, mtu - size, peerID.addr);

#if defined(_DEBUG_DHT)
	debug_log("FIND_NODE: %s. Found %d peers."
		, format_dht_id(target_id), n);
#endif

	sb("e");
	put_transaction_id(sb, message.transactionID);
	put_version(sb);
	sb("1:y1:re");

	assert(sb.length() >= 0 && sb.length() <= mtu);

	instrument_log('>', "find_node", 'r', sb.length(), Read32(message.transactionID.b));
	return AccountAndSend(peerID, buf, sb.length(), packetSize);
}

void DhtImpl::send_put_response(smart_buffer& sb, Buffer& transaction_id,
		int packetSize, const DhtPeerID &peerID) {
	sb("d1:rd2:id20:")(DHT_ID_SIZE, _my_id_bytes)("e");

	put_transaction_id(sb, transaction_id);
	put_version(sb);
	sb("1:y1:re");
	assert(sb.length() >= 0);

	instrument_log('>', "put", 'r', sb.length(), Read32(transaction_id.b));
	AccountAndSend(peerID, sb.begin(), sb.length(), packetSize);
}

void DhtImpl::send_put_response(smart_buffer& sb, Buffer& transaction_id,
		int packetSize, const DhtPeerID &peerID, unsigned int error_code,
		char const* error_message) {
	assert(error_message != NULL);
	sb("d1:eli%ue%u:%se", error_code, (unsigned int)strlen(error_message), error_message);
	sb("1:rd2:id20:")(DHT_ID_SIZE, _my_id_bytes)("e");

	put_transaction_id(sb, transaction_id);
	put_version(sb);
	sb("1:y1:ee");
	assert(sb.length() >= 0);

	instrument_log('>', "put", 'r', sb.length(), Read32(transaction_id.b));
	AccountAndSend(peerID, sb.begin(), sb.length(), packetSize);
}

bool DhtImpl::ProcessQueryPut(DHTMessage &message, DhtPeerID &peerID,
		int packetSize) {
	unsigned char buf[8192];
	smart_buffer sb(buf, sizeof(buf));

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
		send_put_response(sb, message.transactionID, packetSize, peerID,
				MESSAGE_TOO_BIG, "Message exceeds maximum size.");
		return true;
	}

	if(message.key.len && message.sequenceNum && message.signature.len)
	{ // mutable put

		if(message.key.len != DHT_KEY_SIZE || message.signature.len != DHT_SIG_SIZE) {
			Account(DHT_INVALID_PQ_BAD_PUT_KEY, packetSize);
			return true;
		}
		if (message.salt.len > DHT_MAX_SALT_SIZE || message.salt.len < 0)
		{
			Account(DHT_INVALID_PQ_BAD_PUT_SALT, packetSize);
			send_put_response(sb, message.transactionID, packetSize, peerID,
					SALT_TOO_BIG, "Salt too big.");
			return true;
		}
		if (!Verify(message.signature.b, message.vBuf.b, message.vBuf.len
				, message.salt.b, message.salt.len, message.key.b, message.sequenceNum)) {
			Account(DHT_INVALID_PQ_BAD_PUT_SIGNATURE, packetSize);
			send_put_response(sb, message.transactionID, packetSize, peerID,
					INVALID_SIGNATURE, "Invalid message signature.");
			return true;
		}

		// make a hash of the address for the DataStores to use to record usage of an item
		const sha1_hash addrHashPtr = _sha_callback((const byte*)peerID.addr.get_hash_key(), peerID.addr.get_hash_key_len());

		// at this point, the put request has been verified
		// store the data under a sha1 hash of the entire public key and optional salt
		DhtID targetDhtID = MutableTarget(message.key.b, message.salt.b, message.salt.len);
		PairContainerBase<MutableData>* containerPtr = NULL;
		if (_mutablePutStore.AddKeyToList(addrHashPtr, targetDhtID, &containerPtr, time(NULL)) == NEW_ITEM) {
			// this is new to the store, set the sequence num, copy the 'v' bytes, store the signature and key
			containerPtr->value.sequenceNum = message.sequenceNum;
			containerPtr->value.v.assign(message.vBuf.b, message.vBuf.b + message.vBuf.len);
			// store the signature
			memcpy(containerPtr->value.signature, message.signature.b, message.signature.len);
			// store the key
			memcpy(containerPtr->value.key, message.key.b, message.key.len);

			byte to_hash[1040]; // 1000 byte message + seq + formatting
			int written = snprintf(reinterpret_cast<char*>(to_hash), 1040,
				MUTABLE_PAYLOAD_FORMAT, message.sequenceNum);
			assert((written + message.vBuf.len) <= 1040);
			memcpy(to_hash + written, message.vBuf.b, message.vBuf.len);

			// update the time
			containerPtr->lastUse = time(NULL);
		} else {
			// check that the sequence num is larger (newer) than what is currently in
			// the store, and update 'v' bytes, sequence num, and signature
			// No need to update the key here, we already have it and it is not changing.
			if (message.sequenceNum >= containerPtr->value.sequenceNum) {

				if (message.cas != 0
					&& message.cas != containerPtr->value.sequenceNum) {

					Account(DHT_INVALID_PQ_BAD_PUT_CAS, packetSize);
					send_put_response(sb, message.transactionID, packetSize, peerID,
							CAS_MISMATCH, "Invalid CAS.");

					return true;
				} else {
					if (message.sequenceNum > containerPtr->value.sequenceNum) {
						// update the sequence number
						containerPtr->value.sequenceNum = message.sequenceNum;
						// update the value stored
						containerPtr->value.v.assign(message.vBuf.b, message.vBuf.b + message.vBuf.len);
						// update the signature
						memcpy(containerPtr->value.signature, message.signature.b, message.signature.len);
					}
					// update the last time accessed
					containerPtr->lastUse = time(NULL);
				}
			} else {
					send_put_response(sb, message.transactionID, packetSize, peerID,
							LOWER_SEQ, "Replacement sequence number is lower.");
					return true;
			}
		}
	} else {
		// immutable put
		// make a hash of the address for the DataStores to use to record usage of an item
		const sha1_hash addrHashPtr = _sha_callback((const byte*)peerID.addr.get_hash_key(), peerID.addr.get_hash_key_len());

		DhtID targetDhtID = _sha_callback((const byte*)message.vBuf.b, message.vBuf.len);
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
	send_put_response(sb, message.transactionID, packetSize, peerID);
	return true;
}

bool DhtImpl::ProcessQueryGet(DHTMessage &message, DhtPeerID &peerID,
		int packetSize) {
	unsigned char buf[8192];
	smart_buffer sb(buf, sizeof(buf));

	DhtID targetId;
	sha1_hash ttoken;
	Buffer valueToReturn;    // constructor initializes buffers to NULL & 0
	Buffer signatureToReturn;
	Buffer keyToReturn;
	DataStore<DhtID, MutableData>::pair_iterator mutableStoreIterator;
	int64 sequenceNum = 0;
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
	const sha1_hash hashPtr = _sha_callback((const byte*)peerID.addr.get_hash_key()
		, peerID.addr.get_hash_key_len());

	// look in the mutable table first
	mutableStoreIterator = _mutablePutStore.FindInList(targetId
		, time(NULL), hashPtr);

	if (mutableStoreIterator != _mutablePutStore.end()) {
		// we have found a match in the mutable table
		assert(mutableStoreIterator->first == targetId);
		sequenceNum = mutableStoreIterator->second.value.sequenceNum;
		if (message.sequenceNum == 0 || sequenceNum > message.sequenceNum) {
			// the sender either didn't specify a minimum sequence number or
			// ours is bigger than theirs
			valueToReturn.len = mutableStoreIterator->second.value.v.size();
			valueToReturn.b = &(mutableStoreIterator->second.value.v.front());
			signatureToReturn.len = sizeof(mutableStoreIterator->second.value.signature);
			signatureToReturn.b = (byte*)(mutableStoreIterator->second.value.signature);
			keyToReturn.len = sizeof(mutableStoreIterator->second.value.key);
			keyToReturn.b = mutableStoreIterator->second.value.key;
			mutableStoreIterator->second.lastUse = time(NULL);
		}
	} else if (message.key.len == 0) {
		// no key, look in the immutable table with the same target
		DataStore<DhtID, std::vector<byte> >::pair_iterator immutableStoreIterator;
		immutableStoreIterator = _immutablePutStore.FindInList(targetId, time(NULL), hashPtr);
		if (immutableStoreIterator != _immutablePutStore.end())
		{
			// we have a v value
			assert(immutableStoreIterator->first == targetId);
			valueToReturn.len = immutableStoreIterator->second.value.size();
			valueToReturn.b = &immutableStoreIterator->second.value[0];
			immutableStoreIterator->second.lastUse = time(NULL);
		}
	}

	const uint16 mtu = GetUDP_MTU(peerID.addr);
	int size = keyToReturn.len ? (5 + keyToReturn.len) : 0 // "4:key" + number of key bytes
		+ signatureToReturn.len ? 5 + signatureToReturn.len : 0 // "4:sig" + number of signature bytes
		+ valueToReturn.len ? 3 + valueToReturn.len : 0    // "1:v" + num bytes for value 'v'
		+ 30 // token
		+ 7 + message.transactionID.len + 18; // tail (t, v and y)
	assert(size <= mtu);

	// start the output info
	sb("d1:rd");
	sb("2:id20:")(DHT_ID_SIZE, _my_id_bytes);

	if (keyToReturn.len) {	// add a "key" field to the response, if there is one
		sb("1:k%d:", int(keyToReturn.len))(keyToReturn);
	}

	// the last argument specifies that we should use the holepunch feature
	// to improve the chances of the node performing the lookup being able
	// to reach the next level of nodes
	BuildFindNodesPacket(sb, targetId, mtu - size, peerID.addr, true);

	sb("3:seqi%" PRId64 "e", sequenceNum);

	if (signatureToReturn.len) {
		// add a "sig" field to the response, if there is one
		sb("3:sig%d:", int(signatureToReturn.len))(signatureToReturn);
	}

	GenerateWriteToken(&ttoken, peerID);
	sb("5:token20:")(DHT_ID_SIZE, ttoken.value);

	if (valueToReturn.len) {	// add a "v" field to the response, if there is one
		sb("1:v")(valueToReturn);
	}

	sb("e");
	put_transaction_id(sb, message.transactionID);
	put_version(sb);
	sb("1:y1:re");

	assert(sb.length() >= 0 && sb.length() <= mtu);

	instrument_log('>', "get", 'r', sb.length(), Read32(message.transactionID.b));
	return AccountAndSend(peerID, buf, sb.length(), packetSize);
}

bool DhtImpl::ProcessQueryVote(DHTMessage &message, DhtPeerID &peerID,
		int packetSize) {
	unsigned char buf[512];
	smart_buffer sb(buf, sizeof(buf));

	// read the target
	DhtID target_id;
	if(!message.target.b) {
		Account(DHT_INVALID_PQ_BAD_TARGET_ID, packetSize);
		return false;
	}
	CopyBytesToDhtID(target_id, message.target.b);

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
	sb("d");
	AddIP(sb, message.id, peerID.addr);
	sb("1:rd2:id20:")(DHT_ID_SIZE, _my_id_bytes);

	if (message.vote > 5) message.vote = 5;
	else if (message.vote < 0) message.vote = 0;

	AddVoteToStore(sb, target_id, peerID.addr, message.vote);

	sb("e");
	put_transaction_id(sb, message.transactionID);
	put_version(sb);
	sb("1:y1:re");

	assert(sb.length() >= 0 && sb.length() <= GetUDP_MTU(peerID.addr));

	// Send the reply to the peer.
	instrument_log('>', "vote", 'r', sb.length(), Read32(message.transactionID.b));
	return AccountAndSend(peerID, buf, sb.length(), packetSize);
}

bool DhtImpl::ProcessQueryPing(DHTMessage &message, DhtPeerID &peerID,
		int packetSize) {
	unsigned char buf[512];
	smart_buffer sb(buf, sizeof(buf));

#if defined(_DEBUG_DHT)
		debug_log("PING");
#endif

	sb("d");
	AddIP(sb, message.id, peerID.addr);

	sb("1:rd2:id20:")(DHT_ID_SIZE, _my_id_bytes)("e");

	put_transaction_id(sb, message.transactionID);
	put_version(sb);
	sb("1:y1:re");

	assert(sb.length() >= 0);

	instrument_log('>', "ping", 'r', sb.length(), Read32(message.transactionID.b));
	return AccountAndSend(peerID, sb.begin(), sb.length(), packetSize);
}

#if USE_HOLEPUNCH
// when we get a punch request, send a tiny message to the specified
// IP:port, in the hopes that our NAT will open up a pinhole to it
bool DhtImpl::ProcessQueryPunch(DHTMessage &message, DhtPeerID &peerID
	, int packetSize)
{
	if (!_dht_enabled) return false;

	SockAddr dst;
	bool ok = dst.from_compact(message.target_ip.b
		, message.target_ip.len);
	if (!ok) return false;
	if (!dst.isv4()) return false;

	byte record[6];
	dst.compact(record, true);
	sha1_hash h = _sha_callback(record, 6);
	if (_recent_punches.test(h)) {
#ifdef _DEBUG_DHT
		debug_log("SUPPRESSED PUNCH: %s"
			, print_sockaddr(dst).c_str());
#endif
		return true;
	}
	_recent_punches.add(h);

#if defined(_DEBUG_DHT)
	debug_log("PUNCHING %s", print_sockaddr(dst).c_str());
#endif

	unsigned char buf[5];
	smart_buffer sb(buf, sizeof(buf));

	sb("de");
	int len = sb.length();
	assert(len >= 0);

	assert(ValidateEncoding(buf, len));
	Account(DHT_BW_OUT_TOTAL, len);

	if (_packet_callback) {
		_packet_callback(buf, len, false);
	}

	_dht_quota -= len;

	UDPSocketInterface *socketMgr = (dst.isv4())
		? _udp_socket_mgr
		: _udp6_socket_mgr;

	assert(socketMgr);
	instrument_log('>', "punch", 'r', sb.length(), 0);
	socketMgr->Send(dst, buf, sb.length());
	return true;
}
#endif // USE_HOLEPUNCH

bool DhtImpl::ProcessQuery(DhtPeerID& peerID, DHTMessage &message, int packetSize) {

	if(!message.id) {
		Account(DHT_INVALID_PQ_BAD_ID_FIELD, packetSize);
		return false; // bad/missing ID field
	}

	// Out of DHT quota.. No space to send a reply.
	if (_dht_quota < 0 && _dht_rate) {
		// we don't really know it was valid, but otherwise it's marked as invalid
		Account(DHT_BW_IN_REQ, packetSize);
		Account(DHT_BW_IN_NO_QUOTA, packetSize);
		return false;
	}

	// Nodes that are read_only do not respond to queries, so we don't
	// want to add them to the buckets.  They also will not be pinged.
	if (!message.read_only) {
		DhtPeer *peer = Update(peerID, IDht::DHT_ORIGIN_INCOMING, false);
		// Update version
		if (peer != NULL) {
			peer->client.from_compact(message.version.b, message.version.len);
		}
	}

	switch(message.dhtCommand){
		case DHT_QUERY_PING: return ProcessQueryPing(message, peerID, packetSize);
		case DHT_QUERY_FIND_NODE: return ProcessQueryFindNode(message, peerID, packetSize);
		case DHT_QUERY_GET_PEERS: return ProcessQueryGetPeers(message, peerID, packetSize);
		case DHT_QUERY_ANNOUNCE_PEER: return ProcessQueryAnnouncePeer(message, peerID, packetSize);
		case DHT_QUERY_VOTE: return ProcessQueryVote(message, peerID, packetSize);
		case DHT_QUERY_PUT: return ProcessQueryPut(message, peerID, packetSize);
		case DHT_QUERY_GET: return ProcessQueryGet(message, peerID, packetSize);
#if USE_HOLEPUNCH
		case DHT_QUERY_PUNCH: return ProcessQueryPunch(message, peerID, packetSize);
#endif
		case DHT_QUERY_UNDEFINED: return false;
	}

	return true;
}

bool DhtImpl::ProcessResponse(DhtPeerID& peerID, DHTMessage &message, int pkt_size,
		DhtRequest *req) {

#if g_log_dht
	if (req) {
		assert(req->origin >= 0);
		assert(req->origin < sizeof(g_dht_peertype_count) / sizeof(g_dht_peertype_count[0]));
	}
#endif

	if (message.transactionID.len != 4) {
		Account(DHT_INVALID_PR_BAD_TID_LENGTH, pkt_size);
		return false;
	}

	if (!req) {
#if defined(_DEBUG_DHT)
		debug_log("Invalid transaction ID tid:%d", Read32(message.transactionID.b));
#endif
		Account(DHT_INVALID_PR_UNKNOWN_TID, pkt_size);
		return false;	// invalid transaction id?
	}
	// Verify that the id contained in the message matches with the peer id.
	if (message.dhtMessageType == DHT_RESPONSE) {
		if(!message.id) {
			Account(DHT_INVALID_PQ_BAD_ID_FIELD, pkt_size);
			return false; // bad/missing ID field
		}

//		When sending requests to bootstrap nodes (whose ID we don't know)
//		we fill in a somewhat arbitrary ID. That causes this test to fail.
//		This test doesn't seem terribly important anyway

//		if (req->has_id && !(req->peer.id == peerID.id)) {
//			Account(DHT_INVALID_PR_PEER_ID_MISMATCH, pkt_size);
//			return false;
//		}
	} else {
		// error messages do not have a peer id field, so have to infer from request
		peerID.id = req->peer.id;
	}

	// Verify that the source IP is correct.
	if (!req->peer.addr.ip_eq(peerID.addr)) {
		Account(DHT_INVALID_PR_IP_MISMATCH, pkt_size);
		return false;
	}

	Account(DHT_BW_IN_REPL, pkt_size);

	// It's possible that the peer uses a different port # for outgoing packets.
	// Report the port we sent the packet to.
	peerID.addr.set_port(req->peer.addr.get_port());

#if defined(_DEBUG_DHT)
	debug_log("Got reply (rtt=%d ms) tid=%d",
		int32(get_milliseconds() - req->time), Read32(message.transactionID.b));
#endif
#if g_log_dht
	dht_log("dlok replytime:%u\n", get_milliseconds() - req->time);
#endif

	UnlinkRequest(req);

	int rtt = (std::max)(int(get_milliseconds() - req->time), 1);

	// Update the internal tables with this peer's information
	// The contacted attribute is set because it replied to a query.
	DhtPeer *peer = Update(peerID, IDht::DHT_ORIGIN_UNKNOWN, true, rtt);

	// Update version field
	if (peer != NULL) {
		peer->client.from_compact(message.version.b, message.version.len);
	}

	if (message.external_ip.len == 6) {
		SockAddr myIp;
		myIp.set_addr4(*((uint32 *) message.external_ip.b));
		myIp.set_port(ReadBE16(message.external_ip.b+4));
		CountExternalIPReport(myIp, req->peer.addr);
	} else if (message.external_ip.len == 18) {
		SockAddr myIp;
		myIp.set_addr6(*((in6_addr *) message.external_ip.b));
		myIp.set_port(ReadBE16(message.external_ip.b+16));
		CountExternalIPReport(myIp, req->peer.addr);
	}

	// Call the completion callback
	req->_pListener->Callback(req->peer, req, message, (DhtProcessFlags)NORMAL_RESPONSE);
	delete req->_pListener;
	// Cleanup
	delete req;
	return true;
}

bool DhtImpl::ProcessError(DhtPeerID& peerID, DHTMessage &message, int pkt_size,
		DhtRequest *req) {
	// Handle an error for one of our requests.
#if defined(_DEBUG_DHT)
	if (message.error_message == NULL)
		debug_log("**** GOT ERROR (unknown error)");
	else
		debug_log("**** GOT ERROR (%d) '%s'", message.error_code, message.error_message);
#endif
	if (req != NULL) { // this may be a response to an existing request
		return ProcessResponse(peerID, message, pkt_size, req);
	}
	// otherwise we have no idea
	return true;
}

bool DhtImpl::InterpretMessage(DHTMessage &message, const SockAddr& addr, int pkt_size)
{
	// our transaction id length is 4, but we should be able to handle
	// most requests from the wild that have a different spec
	if (message.transactionID.len > 16) {
		Account(DHT_INVALID_PR_BAD_TID_LENGTH, pkt_size);
		return false;
	}

	if (!message.transactionID.b) {
		Account(DHT_INVALID_PI_BAD_TID, pkt_size);
		return false; // bad/missing tid
	}

	DhtPeerID peerID;
	peerID.addr = addr;
	if (message.id != NULL) {
		CopyBytesToDhtID(peerID.id, message.id);
	}

	switch(message.dhtMessageType)
	{
		case DHT_QUERY:
		{
			// if we are read-only, we don't process the query
			if (_dht_read_only)
				return true;

			// Handle a query from a peer
			if(message.dhtCommand == DHT_QUERY_UNDEFINED){
				Account(DHT_INVALID_PI_Q_BAD_COMMAND, pkt_size);
				return false; // bad/missing command.
			}

			if(!message.ValidArguments()){
				Account(DHT_INVALID_PI_Q_BAD_ARGUMENT, pkt_size);
				return false; // bad/missing argument.
			}
			return ProcessQuery(peerID, message, pkt_size);
		}
		case DHT_RESPONSE:
		{
			assert(message.replyDict);
			DhtRequest *req = LookupRequest(Read32(message.transactionID.b));
			return ProcessResponse(peerID, message, pkt_size, req);
		}
		case DHT_ERROR:
		{
			Account(DHT_INVALID_PI_ERROR, pkt_size);
			DhtRequest *req = LookupRequest(Read32(message.transactionID.b));
			return ProcessError(peerID, message, pkt_size, req);
		}
		default:
		{
			Account(DHT_INVALID_PI_NO_TYPE, pkt_size);
			return false;
		}
	}
	return false;
}

void DhtImpl::GenRandomIDInBucket(DhtID &target, DhtBucket *bucket)
{
	// since we start out with many top-level buckets, with the same
	// span. If there are more than two buckets with the same span as
	// the one specified, also pick a random bucket from those.
	int count = 0;
	for (int i = 0; i < _buckets.size(); ++i) {
		if (_buckets[i]->span == bucket->span) ++count;
	}

	if (count > 2) {
		// pick a random bucket with the same span as we specified
		int buck = rand() % count;
		for (int i = 0; i < _buckets.size(); ++i) {
			if (_buckets[i]->span != bucket->span) continue;

			if (buck > 0) {
				--buck;
				continue;
			}
			bucket = _buckets[i];
			break;
		}
	}

	target = bucket->first;
	uint span = bucket->span;
	uint i = 4;
	while (span > 32) {
		target.id[i] = rand();
		span -= 32;
		i -= 1;
	}
	assert(i >= 0 && i <= 4);
	assert(span <= 32);

	// shifting by the bitwidth or more is undefined behavior!
	// that's why we have to check for 32 here
	uint32 m = span == 32 ? 0 : 1 << span;
	target.id[i] = (target.id[i] & ~(m - 1)) | (rand() & (m - 1));
}

void DhtImpl::DoBootstrap()
{
	if (_closing) return;

	++_bootstrap_attempts;

#ifdef _DEBUG_DHT
	debug_log("start bootstrap");

	_bootstrap_start = get_milliseconds();
	if (_bootstrap_log) {
		fprintf(_bootstrap_log, "[0] start\n");
		fprintf(_bootstrap_log, "[%u] nodes: %u\n"
			, uint(get_milliseconds() - _bootstrap_start), _dht_peers_count);
	}
#endif
	DhtID target = _my_id;
	target.id[4] ^= 1;
	// Here, "this" is an IDhtProcessCallbackListener*, which leads
	// to DhtImpl::ProcessCallback(), necessary to complete bootstrapping

	// since we're bootstrapping, we want to find nodes as far away from us
	// as possible, to prolong the search path through the network and fill more
	// buckets with more nodes. Therefore, flip the first bit of the target.
	target.id[0] ^= 0x80000000;

	DhtPeerID *ids[32];
	int num = AssembleNodeList(target, ids, sizeof(ids)/sizeof(ids[0]), true);

	// and flip it back again
	target.id[0] ^= 0x80000000;

	DhtProcessManager *dpm = new DhtProcessManager(ids, num, target);

#if defined(_DEBUG_DHT)
//	debug_log("DoFindNodes: %s",format_dht_id(target));
//	for(uint i=0; i!=num; i++)
//		debug_log(" %A", &ids[i]->addr);
#endif

	CallBackPointers cbPtrs;

	// This is where we kick off the actual bootstrapping. We launch
	// Find Node on our own ID. keep in mind that if the routing
	// table is empty, we add the bootstrap nodes (see AssembleNodeList).

	cbPtrs.processListener = this;
	// get peers in those nodes
	DhtProcessBase* p = FindNodeDhtProcess::Create(this, *dpm, target, cbPtrs
		, KADEMLIA_LOOKUP_OUTSTANDING, 0);
#ifdef _DEBUG_DHT
	if (_lookup_log)
		fprintf(_lookup_log, "[%u] [%u] [%s]: START-BOOTSTRAP\n"
			, uint(get_milliseconds()), p->process_id(), p->name());
#endif
	dpm->AddDhtProcess(p);
	dpm->Start();

	_last_self_refresh = time(NULL);
}

void DhtImpl::DoFindNodes(DhtID &target
	, IDhtProcessCallbackListener *process_listener
	, int flags)
{
	int maxOutstanding = (flags & IDht::announce_non_aggressive)
		? KADEMLIA_LOOKUP_OUTSTANDING + KADEMLIA_LOOKUP_OUTSTANDING_DELTA
		: KADEMLIA_LOOKUP_OUTSTANDING;

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
	DhtProcessBase* p = FindNodeDhtProcess::Create(this, *dpm, target, cbPtrs
		, maxOutstanding, flags);
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
		DhtProcess* p = DoFindNodes(target, NULL, 0);
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

	DhtProcessBase* getPeersProc = GetPeersDhtProcess::Create(this, *dpm, target,
		cbPtrs, 0, maxOutstanding);
	DhtProcessBase* voteProc = VoteDhtProcess::Create(this, *dpm, target,
		cbPtrs, vote);
	// processes will be exercised in the order they are added
	dpm->AddDhtProcess(getPeersProc); // add get_peers first
	dpm->AddDhtProcess(voteProc); // add vote second
	dpm->Start();
}

void DhtImpl::DoScrape(const DhtID &target, DhtScrapeCallback *callb
	, void* ctx, int flags)
{
	int maxOutstanding = (flags & announce_non_aggressive)
		? KADEMLIA_LOOKUP_OUTSTANDING + KADEMLIA_LOOKUP_OUTSTANDING_DELTA
		: KADEMLIA_LOOKUP_OUTSTANDING;
	DhtPeerID *ids[32];
	int num = AssembleNodeList(target, ids, sizeof(ids)/sizeof(ids[0]));

	DhtProcessManager *dpm = new DhtProcessManager(ids, num, target);

	CallBackPointers cbPtrs;
	cbPtrs.scrapeCallback = callb;
	DhtProcessBase* p = ScrapeDhtProcess::Create(this, *dpm, target, cbPtrs
		, maxOutstanding, flags);

	dpm->AddDhtProcess(p);
	dpm->Start();
}

void DhtImpl::ResolveName(DhtID const& target, DhtHashFileNameCallback* callb
	, void *ctx, int flags)
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

	DhtProcessBase* getPeersProc = GetPeersDhtProcess::Create(this, *dpm, target, cbPtrs, flags, maxOutstanding);
	dpm->AddDhtProcess(getPeersProc);
	dpm->Start();
}

/**
	If performLessAgressiveSearch is false, a more agressive dht lookup will be performed with a greater number of outstanding
	dht queries allowed.  If true, the number of outstanding dht queries allowed is reduced by the specified 
	delta.  See KademliaConstants enum for actual values.
*/
void DhtImpl::DoAnnounce(const DhtID &target,
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
	cbPtrs.addnodesCallback = callb;
	cbPtrs.callbackContext = ctx;
	cbPtrs.portCallback = pcb;

	DhtProcessBase* getPeersProc = GetPeersDhtProcess::Create(this, *dpm, target
		, cbPtrs, flags, maxOutstanding);
	// processes will be exercised in the order they are added
	dpm->AddDhtProcess(getPeersProc); // add get_peers first

	if ((flags & announce_only_get) == 0) {
		DhtProcessBase* announceProc = AnnounceDhtProcess::Create(this, *dpm, target
			, cbPtrs, file_name, flags);
		dpm->AddDhtProcess(announceProc); // add announce second
	}

	dpm->Start();
}

int count_nodes(DhtBucketList& l)
{
	int ret = 0;
	for (DhtPeer **peer = &l.first(); *peer; peer=&(*peer)->next)
		++ret;
	return ret;
}

uint DhtImpl::PingStalestNode()
{
	if (_closing) return 0;

	// first we need to figure out which order the buckets are, from closest
	// to us from farthest away from us. The span is a proxy for this, larger
	// span means farther away.
	std::vector<int> bucket_order;
	bucket_order.resize(_buckets.size());
	for (int i = 0; i < _buckets.size(); ++i) bucket_order[i] = i;

	// bucket_order has the index of the buckets ordered by increasing span,
	// i.e. the smaller buckets first, the ones close to us.
	std::sort(bucket_order.begin(), bucket_order.end()
		, [&](int a, int b)
		{
			// whichever bucket our ID is in is actually the closest one.
			if (_buckets[a]->TestForMatchingPrefix(_my_id)) return true;
			if (_buckets[b]->TestForMatchingPrefix(_my_id)) return false;

			if (_buckets[a]->span < _buckets[b]->span) return true;
			if (_buckets[a]->span > _buckets[b]->span) return false;

			// an bucket with more nodes has lower priority
			// since we start with 32 buckets of equal span, it makes
			// sense to still rank them.
			return count_nodes(_buckets[a]->peers) < count_nodes(_buckets[b]->peers);
		});

	DhtPeer* oldest = NULL;
	for (int i = 0; i < bucket_order.size(); ++i) {
		DhtBucket &bucket = *_buckets[bucket_order[i]];
		for (DhtPeer *peer = bucket.peers.first(); peer != NULL; peer=peer->next) {

			if (!peer->lastContactTime) {
				oldest = peer;
				goto done;
			}
			if (oldest == NULL || peer->lastContactTime < oldest->lastContactTime) {
				oldest = peer;
			}
		}
	}
done:

	if (oldest == NULL) return 0;

	oldest->lastContactTime = time(NULL);
	DhtRequest *req = SendFindNode(oldest->id);
	req->_pListener = new DhtRequestListener<DhtImpl>(this
		, &DhtImpl::OnPingReply);
	return req->tid;
}

// Bootstrap complete.
void DhtImpl::ProcessCallback()
{
	// We need to make sure we do have more than 2 connected DHT nodes before finishing the bootstrapping.
	// That was due to the timeout error happened in the first DHT nodes lookup, which means we only
	// connected to the inital DHT routers but none of them replied in 4 seconds. If we failed to get enough
	// nodes in the first attempt, we will redo the bootstrapping again in 15 seconds.
	if (_dht_peers_count >= 8) {
		_dht_bootstrap = bootstrap_complete;
		_dht_bootstrap_failed = 0;
		_refresh_buckets_counter = 0; // start forced bucket refresh

#ifdef _DEBUG_DHT
		debug_log("DhtImpl::ProcessCallback() [ bootstrap done (%d)]", _dht_bootstrap);

		if (_bootstrap_log)
			fprintf(_bootstrap_log, "[%u] complete %u nodes\n\n\n"
				, uint(get_milliseconds() - _bootstrap_start), _dht_peers_count);
#endif

	} else {

		// bootstrapping failed. retry again soon.
		// 15s, 30s, 1m, 2m, 4m etc.
		// never wait more than 24 hours - 60 * 24 = 1440
		// so max for shift is 2 ^ 13 = 16384 or 1 << 14
		assert(_dht_bootstrap_failed >= 0 && _dht_bootstrap_failed <= 14);
		_dht_bootstrap_failed = (std::max)(0, _dht_bootstrap_failed);
		if (_dht_bootstrap_failed < 14) {
			_dht_bootstrap = 15 * (1 << _dht_bootstrap_failed);
			++_dht_bootstrap_failed;
		} else {
			// if we've failed too many times, try once every 24 hours.
			// this is the ceiling of our exponential back-off.
			_dht_bootstrap = 60 * 60 * 24;
		}

#ifdef _DEBUG_DHT
		debug_log("DhtImpl::ProcessCallback() [ bootstrap failed (%d)]", _dht_bootstrap);
		if (_bootstrap_log)
			fprintf(_bootstrap_log, "[%u] failed %u nodes\n\n\n"
				, uint(get_milliseconds() - _bootstrap_start), _dht_peers_count);
#endif
	}
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
void DhtImpl::OnAddNodeReply(void* &userdata, const DhtPeerID &peer_id
	, DhtRequest *req, DHTMessage &message, DhtProcessFlags flags)
{
	// if this is a reply on bhalf of a slow peer, do nothing
	if (flags == PROCESS_AS_SLOW)
		return;

	if (_add_node_callback && (flags & (NORMAL_RESPONSE | ANY_ERROR))) {
		_add_node_callback(userdata, message.dhtMessageType == DHT_RESPONSE, peer_id.addr);
	}

	OnPingReply(userdata, peer_id, req, message, flags);
}

void DhtImpl::OnPingReply(void* &userdata, const DhtPeerID &peer_id
	, DhtRequest *req, DHTMessage &message, DhtProcessFlags flags)
{
	// if this is a reply on behalf of a slow peer, do nothing
	if (flags == PROCESS_AS_SLOW) return;

	// This is a NICE ping reply - we are just refreshing the table.
	// We need to handle the error case here.
	if (message.dhtMessageType == DHT_UNDEFINED_MESSAGE
		|| message.dhtMessageType == DHT_ERROR
		|| (flags & ANY_ERROR)) {

		// Mark that the peer errored
		UpdateError(peer_id, flags & ICMP_ERROR);
		return;
	}

	// if we received nodes, let the routing table know about them
#ifdef _DEBUG_DHT
	int rtt = (std::max)(int(get_milliseconds() - req->time), 1);

	if (_lookup_log)
		fprintf(_lookup_log, "[%u] [] []: <- %s (rtt:%d ms)\n"
			, uint(get_milliseconds())
			, print_sockaddr(peer_id.addr).c_str(), rtt);
#endif

	Buffer nodes;
	nodes.b = (byte*)message.replyDict->GetString("nodes", &nodes.len);

	// IP address, port and node-ID
	const int node_size = 4 + 2 + 20;
	if (nodes.b && nodes.len % node_size == 0) {
		uint num_nodes = nodes.len / node_size;
		// Insert all peers into my internal list.
#if defined(_DEBUG_DHT_VERBOSE)
		debug_log("<-- adding %d new nodes", num_nodes);
#endif
		while (num_nodes != 0) {
			DhtPeerID peer;

			// Read into the peer struct
			CopyBytesToDhtID(peer.id, nodes.b);
			peer.addr.from_compact(nodes.b + DHT_ID_SIZE, 6);
			nodes.b += node_size;

			// Check if it's identical to myself?
			// Don't add myself to my internal list of peers.
			if (peer.id != _my_id && peer.addr.get_port() != 0) {

				// Update the internal tables with this peer's information
				// The contacted attribute is set to false because we haven't
				// actually confirmed that this node exists or works yet.
				Update(peer, IDht::DHT_ORIGIN_FROM_PEER, false);
			}
			num_nodes--;
		}
	}
}

void DhtImpl::AddNode(const SockAddr& addr, void* userdata, uint origin)
{
	assert(!addr.isv6());

	if (_closing) return;

	DhtPeerID peer_id;
	peer_id.addr = addr;
	// just make us look up nodes close to ourself, to continuously try to
	// get a deeper routing table.
	peer_id.id = _my_id;

	DhtRequest *req = SendFindNode(peer_id);
	req->has_id = false;
	req->_pListener = new DhtRequestListener<DhtImpl>(this
		, &DhtImpl::OnAddNodeReply, userdata);

#if g_log_dht
	assert(origin >= 0);
	assert(origin < sizeof(g_dht_peertype_count)/sizeof(g_dht_peertype_count[0]));
	req->origin = origin;
#endif
}

void DhtImpl::AddBootstrapNode(SockAddr const& addr)
{
	_bootstrap_routers.push_back(addr);

	for(int i = 0; i < _buckets.size(); i++) {
		DhtBucket& bucket = *_buckets[i];

		for (DhtPeer **peer = &bucket.peers.first(); *peer; peer=&(*peer)->next) {
			DhtPeer *p = *peer;

			if (addr != p->id.addr) continue;

#ifdef _DEBUG_DHT
			debug_log("found bootstrap node in routing table, purging");
#endif

			// remove the router from its bucket and move one node from the
			// replacement cache
			RemoveTableIP(p->id.addr);
			bucket.peers.unlinknext(peer);
			if (!bucket.replacement_peers.empty()) {
				// move one from the replacement_peers instead.
				bucket.peers.enqueue(bucket.replacement_peers.PopBestNode(p->GetSubprefixInt()));
			}
			_dht_peer_allocator.Free(p);
			_dht_peers_count--;
			assert(_dht_peers_count >= 0);

			// If at the end of the peers list, bail
			if (*peer == nullptr) {
				break;
			}
		}

		// Also check if the router is in the replacement cache already.
		for (DhtPeer **peer = &bucket.replacement_peers.first(); *peer; peer=&(*peer)->next) {
			DhtPeer *p = *peer;

			if (addr != p->id.addr) continue;

#ifdef _DEBUG_DHT
			debug_log("found bootstrap node in replacement queue, purging");
#endif
			RemoveTableIP(p->id.addr);
			bucket.replacement_peers.unlinknext(peer);
			_dht_peer_allocator.Free(p);
			_dht_peers_count--;
			assert(_dht_peers_count >= 0);


			// If at the end of the replacement peers list, bail
			if (*peer == nullptr) {
				break;
			}
		}
	}
}

void DhtImpl::Vote(void *ctx_ptr, const sha1_hash* info_hash, int vote, DhtVoteCallback* callb)
{
	assert(vote >= 0 && vote <= 5);

	byte buf[26];
	memcpy(buf, info_hash->value, DHT_ID_SIZE);
	memcpy(buf + DHT_ID_SIZE, "rating", 6);
	sha1_hash target = _sha_callback(buf, sizeof(buf));
	DoVote(target, vote, callb, ctx_ptr);
	_allow_new_job = false;
}

DhtID DhtImpl::MutableTarget(const byte* key, const byte* salt, int salt_length)
{
	assert(salt_length < DHT_MAX_SALT_SIZE && salt_length >= 0);

	byte targetBuf[DHT_KEY_SIZE + DHT_MAX_SALT_SIZE];
	memcpy(targetBuf, key, DHT_KEY_SIZE);
	memcpy(targetBuf + DHT_KEY_SIZE, salt, salt_length);
	return _sha_callback(targetBuf, DHT_KEY_SIZE + salt_length);
}

void DhtImpl::Put(const byte * pkey, const byte * skey
		, DhtPutCallback* put_callback
		, DhtPutCompletedCallback* put_completed_callback
		, DhtPutDataCallback* put_data_callback
		, void *ctx, int flags
		, int64 seq)
{
	int maxOutstanding = (flags & announce_non_aggressive)
		? KADEMLIA_LOOKUP_OUTSTANDING + KADEMLIA_LOOKUP_OUTSTANDING_DELTA
		: KADEMLIA_LOOKUP_OUTSTANDING;

	DhtID target = _sha_callback(pkey, DHT_KEY_SIZE);

	DhtPeerID *ids[32];
	int num = AssembleNodeList(target, ids, lenof(ids));

	if (num == 0) {
		put_completed_callback(ctx);
		return;
	}

	DhtProcessManager *dpm = new DhtProcessManager(ids, num, target);
	dpm->set_seq(seq);

	CallBackPointers callbacks;
	assert(put_callback);
	callbacks.putCallback = put_callback;
	callbacks.callbackContext = ctx;
	callbacks.putCompletedCallback = put_completed_callback;
	callbacks.putDataCallback = put_data_callback;

	DhtProcessBase* getProc = GetDhtProcess::Create(this, *dpm, target
		, callbacks, flags, maxOutstanding);
	// processes will be exercised in the order they are added
	dpm->AddDhtProcess(getProc); // add get_peers first

	// announce_only_get appears to be worthless because peers will get queried
	// and then nothing will happen with the result, as the callback only happens
	// below
	if ((flags & announce_only_get) == 0) {
	DhtProcessBase* putProc = PutDhtProcess::Create(this, *dpm, pkey, skey,
		callbacks, flags);
		dpm->AddDhtProcess(putProc); // add announce second
	}
	dpm->Start();
}

sha1_hash DhtImpl::ImmutablePut(const byte * data, size_t data_len
	, DhtPutCompletedCallback* put_completed_callback, void *ctx)
{
	std::vector<byte> tmp(data, data + data_len);
	char prefix[10];
	int len = snprintf(prefix, sizeof(prefix), "%d:", int(data_len));
	tmp.insert(tmp.begin(), prefix, prefix + len);
	sha1_hash h = _sha_callback(&tmp[0], tmp.size());

	DhtID target = h;
	DhtPeerID *ids[32];
	int num = AssembleNodeList(target, ids, lenof(ids));

	DhtProcessManager *dpm = new DhtProcessManager(ids, num, target);

	CallBackPointers callbacks;
	callbacks.putCompletedCallback = put_completed_callback;
	callbacks.callbackContext = ctx;

	DhtProcessBase* getProc = GetDhtProcess::Create(this, *dpm, target
		, callbacks, 0, KADEMLIA_LOOKUP_OUTSTANDING);
	dpm->AddDhtProcess(getProc);
	DhtProcessBase* putProc = ImmutablePutDhtProcess::Create(this, *dpm, data,
			data_len, callbacks);
	dpm->AddDhtProcess(putProc);
	dpm->Start();
	return h;
}

void DhtImpl::ImmutableGet(sha1_hash target, DhtGetCallback* cb
	, void* ctx)
{
	DhtID target_id = target;
	DhtPeerID *ids[32];
	int num = AssembleNodeList(target_id, ids, lenof(ids));

	DhtProcessManager *dpm = new DhtProcessManager(ids, num, target_id);

	CallBackPointers callbacks;
	callbacks.getCallback = cb;
	callbacks.callbackContext = ctx;

	DhtProcessBase* getProc = GetDhtProcess::Create(this, *dpm, target_id
		, callbacks, 0, KADEMLIA_LOOKUP_OUTSTANDING);
	dpm->AddDhtProcess(getProc);
	dpm->Start();
}

/**
 * The BT code calls this to announce itself to the DHT network.
 */
void DhtImpl::AnnounceInfoHash(
	const byte *info_hash,
	DhtAddNodesCallback *addnodes_callback,
	DhtPortCallback* pcb,
	cstr file_name,
	void *ctx,
	int flags)
{
	DhtID id;
	CopyBytesToDhtID(id, info_hash);
	DoAnnounce(id, addnodes_callback,
		pcb, file_name, ctx, flags);
	_allow_new_job = false;
}

void DhtImpl::SetRate(int bytes_per_second)
{
	_dht_rate = bytes_per_second;
}

int DhtImpl::CalculateLowestBucketSpan()
{
	int lowest_span = 160;
	for (int i = 0; i < _buckets.size(); i++) {
		DhtBucket &bucket = *_buckets[i];
		if (bucket.span < lowest_span && bucket.peers.first() != NULL)
			lowest_span = bucket.span;
	}

	return lowest_span;
}

/**
 * This is a tick function that should be called periodically.
 */
void DhtImpl::Tick()
{
	// TODO: make these members. and they could probably be collapsed to 1
	static int _5min_counter;
	static int _10min_counter;
	static int _4_sec_counter;

	_dht_probe_quota = _dht_probe_rate;

	// May accumulate up to 3 second of DHT bandwidth.
	// the quota is allowed to be negative since our requests
	// don't test against it, but still drains it
	_dht_quota = clamp(_dht_quota + _dht_rate, -_dht_rate, 3 * _dht_rate);

	// Expire 30 second old requests
	for(DhtRequest **reqp = &_requests.first(), *req; (req = *reqp) != NULL; ) {
		int delay = (int)(get_milliseconds() - req->time);

#if g_log_dht
		assert(req->origin >= 0);
		assert(req->origin < sizeof(g_dht_peertype_count)/sizeof(g_dht_peertype_count[0]));
#endif

		// Support time that goes backwards
		if (delay < 0) {
			req->time = get_milliseconds();
			reqp = &req->next;
			continue;
		}

		if ( delay >= 4000 ) {
			// 4 seconds passed with no reply.
			_requests.unlinknext(reqp);

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
		_immutablePutStore.UpdateUsage(time(NULL));
		_mutablePutStore.UpdateUsage(time(NULL));

#if USE_HOLEPUNCH
		_recent_punch_requests.clear();
		_recent_punches.clear();
#endif
	}

	if (_dht_bootstrap > valid_response_received) {
		// Boot-strapping.
		if (--_dht_bootstrap == valid_response_received) {

			DoBootstrap();
		}
	}

	if (--_refresh_buckets_counter < 0) {
		// refresh buckets every 6 (or so) seconds
		_refresh_buckets_counter = _ping_frequency * _ping_batching;
		for (int i = 0; i < _ping_batching; ++i) {
			PingStalestNode();
		}
	}

	// Save State to disk every 10 minutes if bootstrapping complete
	if (++_10min_counter == 60 * 10) {
		_10min_counter = 0;

		if (_dht_bootstrap == bootstrap_complete)
		{
			SaveState();
#ifdef _DEBUG_DHT
			debug_log("10 minute counter, saving DHT state to disk."
				, _dht_peers_count, _dht_bootstrap);
#endif
		}
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

		int lowest_span = CalculateLowestBucketSpan();

		if (lowest_span < _lowest_span) _lowest_span = lowest_span;

		time_t now = time(NULL);

		// if there's more than 3 levels to the deepest level we've seen
		// keep bootstrapping, but not too often. Back off gradually to
		// not keep hammering the bootstrap server when we can't get a foot hold
		// in the DHT anyway.
		// if we haven't reached the lowest span, the retries are:
		// 1, 2, 4, 8 etc. minutes
		// if we have fewer than 10 nodes, the retry intervals are:
		// 2, 4, 8, 16 etc. minutes
		if ((lowest_span > _lowest_span + 3
				&& now - _last_self_refresh > 60 * (1 << _bootstrap_attempts))
			|| (_dht_peers_count < 10
				&& now - _last_self_refresh > 2 * 60 * (1 << _bootstrap_attempts))) {

			// it's been 10 minutes since our last bootstrap attempt, issue
			// another one. If we haven't reached close enough to our routing
			// table depth, try every minute instead.
			DoBootstrap();
		}
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
	Enable(0,_dht_rate); // Stop Dht...this also enables the bootstrap process

	// this is called from GenerateID, which gets called when we initialize
	// the DHT. The problem of setting _dht_peer_count to zero is that
	// immediately following this, we receive handle the respons and consider
	// the bootstrap a failure (because we don't have any nodes)

	// store the nodes in a temporary vector while tearing down
	// and setting up the routing table again
	std::vector<DhtPeer*> temp;

	// clear the buckets
	for(int i = 0; i < _buckets.size(); i++) {
		for (DhtPeer **peer = &_buckets[i]->peers.first(); *peer;) {
			DhtPeer *p = *peer;

#if g_log_dht
			assert(p->origin >= 0);
			assert(p->origin < sizeof(g_dht_peertype_count)/sizeof(g_dht_peertype_count[0]));
#endif
			// unlinknext will make peer point the following entry
			// in the linked list, so there's no need to step forward
			// explicitly.
			_buckets[i]->peers.unlinknext(peer);
			p->next = NULL;
			temp.push_back(p);
		}
		for (DhtPeer **peer = &_buckets[i]->replacement_peers.first(); *peer;) {
			DhtPeer *p = *peer;

#if g_log_dht
			assert(p->origin >= 0);
			assert(p->origin < sizeof(g_dht_peertype_count)/sizeof(g_dht_peertype_count[0]));
#endif

			_buckets[i]->replacement_peers.unlinknext(peer);
			p->next = NULL;
			temp.push_back(p);
		}
		_dht_bucket_allocator.Free(_buckets[i]);
	}
	_buckets.clear();
	_refresh_buckets_counter = 0;
	_dht_peers_count = 0;
	_ip4s.clear();

#ifdef _DEBUG_DHT
	if (_dht_bootstrap == valid_response_received && _bootstrap_log) {
		fprintf(_bootstrap_log, "[%u] nodes: %u\n"
			, uint(get_milliseconds() - _bootstrap_start), _dht_peers_count);
	}
#endif

	// Initialize the buckets
	for (int i = 0; i < 32; ++i) {
		DhtBucket *bucket = CreateBucket(i);
		bucket->span = 155;
		memset(&bucket->first, 0, sizeof(bucket->first));
		// map the [0, 32) range onto the top of
		// the first word in the ID
		bucket->first.id[0] = uint(i) << (32 - 5);
	}

	for (std::vector<DhtPeer*>::iterator i = temp.begin(), end(temp.end());
		i != end; ++i) {
		DhtPeer* p = *i;

#if g_log_dht
		assert(p->origin >= 0);
		assert(p->origin < sizeof(g_dht_peertype_count)/sizeof(g_dht_peertype_count[0]));
#endif

		Update(p->id
#if g_log_dht
			, p->origin
#else
			, 0
#endif
			, p->rtt != INT_MAX, p->rtt);

		_dht_peer_allocator.Free(p);
	}

	// Need to do this twice so prev_token becomes random too
	RandomizeWriteToken();
	RandomizeWriteToken();
	_dht_enabled = old_g_dht_enabled;
	_closing = !_dht_enabled;
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
	static char a[] = "d1:ad2:id20:";
	static char b[] = "e1:q4:ping1:t4:";
	static char c[] = "1:v4:";
	static char d[] = "1:y1:qe";

	if (memcmp(buf, a, sizeof(a)-1))
		return false;
	if (memcmp(buf+32, b, sizeof(b)-1))
		return false;
	if (memcmp(buf+51, c, sizeof(c)-1))
		return false;
	if (memcmp(buf+60, d, sizeof(d)-1))
		return false;

	if (_dht_read_only)
		return true;

	DHTMessage message;

	// process the packet using the dynamic parts
	// set only the minimum of elements needed by ProcessQuery
	message.transactionID.b = buf+47;
	message.transactionID.len = 4;

	message.version.b = buf+56;
	message.version.len = 4;

	message.dhtCommand = DHT_QUERY_PING;
	message.id = buf+12;

	DhtPeerID peerID;
	peerID.addr = addr;
	CopyBytesToDhtID(peerID.id, message.id);
	return ProcessQuery(peerID, message, pkt_size);
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

#if defined(_DEBUG_DHT_INSTRUMENT)
	if (message.type && message.transactionID.b && message.transactionID.len >= sizeof(uint32)) {
		instrument_log('<', message.command, message.type[0], len, Read32(message.transactionID.b));
	}
#endif

#if defined(_DEBUG_DHT)
	if (message.version.len == 4) {
		debug_log(" [%d.%d.%d.%d:%u] client version: %c%c %u"
			, addr._sin6[12]
			, addr._sin6[13]
			, addr._sin6[14]
			, addr._sin6[15]
			, addr.get_port()
			, message.version.b[0]
			, message.version.b[1]
			, (int(message.version.b[2]) << 8) | message.version.b[3]
			);
	} else {
		debug_log(" [%d.%d.%d.%d:%u] client version: unknown"
			, addr._sin6[12]
			, addr._sin6[13]
			, addr._sin6[14]
			, addr._sin6[15]
			, addr.get_port()
			);
	}
#endif
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
	BencEntityMem beMemId(_my_id_bytes, DHT_ID_SIZE);
	dict->Insert("id", beMemId);

	if (_ip_counter) {
		byte buf[256];
		// we found a potential external IP for us. Place
			// one vote for this IP, just to seed it with something

		SockAddr addr;
		_ip_counter->GetIPv4(addr);
		size_t iplen = addr.compact(buf, false);
		BencEntityMem beMemIP(buf, iplen);
		dict->Insert("ip", beMemIP);
	}

	std::vector<PackedDhtPeer> peer_list(0);

	for (int i = 0; i < _buckets.size(); i++) {
		DhtBucket &bucket = *_buckets[i];
		if (bucket.span < _lowest_span) _lowest_span = bucket.span;
		for (DhtPeer *peer = bucket.peers.first(); peer; peer=peer->next) {
			if (peer->num_fail == 0 && peer->id.addr.isv4()) {
				PackedDhtPeer tmp;
				DhtIDToBytes(tmp.id, peer->id.id);
				peer->id.addr.compact(tmp.ip, true);
				peer_list.push_back(tmp);
			}
		}
	}

	BencEntityMem beM;
	if (peer_list.empty()) beM.SetMemOwn(NULL, 0);
	else beM.SetMemOwn(&peer_list[0], peer_list.size() * sizeof(PackedDhtPeer));
	dict->Insert("nodes", beM);

	// CHECK: time(NULL) can be int64....
	dict->InsertInt("age", (int)time(NULL));

	// don't save the lowest span we loaded, save the lowest span we've seen
	// this session.
	int lowest_span = CalculateLowestBucketSpan();

	// save the lowest table depth 
	dict->InsertInt("table_depth", (int)160 - lowest_span);

	std::string b = base.Serialize();
	_save_callback((const byte*)b.c_str(), b.size());
}

void DhtImpl::LoadState()
{
	if (_load_callback == NULL) return;
	BencEntity base;

	_load_callback(&base);

#if defined(_DEBUG_DHT)
	int num_loaded = 0;
#endif

	BencodedDict *dict = base.AsDict(&base);
	if (dict) {

		_lowest_span = 160 - dict->GetInt("table_depth", 160 - _lowest_span);

		// Load the ID
		byte* id = (byte*)dict->GetString("id", DHT_ID_SIZE);
		if (id) {
			CopyBytesToDhtID(_my_id, id);
			DhtIDToBytes(_my_id_bytes, _my_id);
		}

		size_t ip_len = 0;
		byte* ip = (byte*)dict->GetString("ip", &ip_len);

		if (ip && _ip_counter) {
			// we found a potential external IP for us. Place
			// one vote for this IP, just to seed it with something
			SockAddr addr;
			if (addr.from_compact(ip, ip_len)) {
				_ip_counter->CountIP(addr);
				
#if defined(_DEBUG_DHT)
				SockAddr tmp;
				_ip_counter->GetIPv4(tmp);
				debug_log("Loaded possible external IP \"%s\""
					, print_sockaddr(addr).c_str());
#endif
			}
		}

		if ((uint)(time(NULL) - dict->GetInt("age", 0)) < 24 * 60 * 60) {
			// Load nodes...
			size_t nodes_len;
			byte *nodes = (byte*)dict->GetString("nodes", &nodes_len);
			if (nodes && nodes_len % sizeof(PackedDhtPeer) == 0) {
				while (nodes_len >= sizeof(PackedDhtPeer)) {
					// Read into the peer struct
					DhtPeerID peer;
					CopyBytesToDhtID(peer.id, nodes);
					peer.addr.from_compact(nodes + DHT_ID_SIZE, 6);
					nodes += sizeof(PackedDhtPeer);
					nodes_len -= sizeof(PackedDhtPeer);
					Update(peer, IDht::DHT_ORIGIN_UNKNOWN, false);
#if defined(_DEBUG_DHT)
					++num_loaded;
#endif
				}
			}
		}
	}

#if defined(_DEBUG_DHT)
	debug_log("Loaded %d nodes and ID \"%s\" from disk"
		, num_loaded, hexify(_my_id_bytes));
#endif
}

int DhtImpl::GetNumPutItems()
{
	return _immutablePutStore.pair_list.size();
}

// TODO: The external IP reports from non-DHT sources don't
// pass through here.  They are counted, but they just won't
// pass through here
void DhtImpl::CountExternalIPReport(const SockAddr& addr, const SockAddr& voter )
{
	if (_ip_counter == NULL) return;

	SockAddr tempWinner;
	_ip_counter->CountIP(addr, voter);

	if (_ip_counter->GetIPv4(tempWinner) && !tempWinner.ip_eq(_lastLeadingAddress)) {

#if defined(_DEBUG_DHT)
		debug_log("External IP changed from: \"%s\" to \"%s\""
			, print_sockaddr(_lastLeadingAddress).c_str()
			, print_sockaddr(tempWinner).c_str());
#endif
		_lastLeadingAddress = tempWinner;

		GenerateId();
		Restart();
	}
}

bool DhtImpl::IsBootstrap(const SockAddr& addr)
{
	for (auto const& router : _bootstrap_routers)
		if (addr.ip_eq(router))
			return true;
	return false;
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

#if g_log_dht
	assert(origin >= 0);
	assert(origin < sizeof(g_dht_peertype_count)/sizeof(g_dht_peertype_count[0]));
#endif

	if (id.addr.get_port() == 0)
		return NULL;

	// never add ourself to the routing table
	if (id.id == _my_id) {
		return NULL;
	}

	// Don't allow bootstrap servers into the rounting table
	if (IsBootstrap(id.addr))
		return NULL;

	DhtPeer* existing = NULL;
	// TODO: IPv6
	if (_ip4s.count(id.addr.get_addr4()))
	{
		int b = 0;
		DhtBucket::BucketListType list;
		for (; b < _buckets.size(); b++)
		{
			existing = _buckets[b]->FindNode(id.addr, list);
			if (existing) break;
		}

		// we didn't find an existing node
		// this means we have an existing entry with the same ip but different port
		// ignore the new node
		if (!existing)
		{
			return NULL;
		}
		// this is the same node, continue on to update the entry
		else if (existing->id.id == id.id)
		{ }
		// someone claiming the same endpoint has a different id
		// but we haven't confirmed it, this may just be spoofing
		// so ignore it
		else if (!seen)
		{
			return NULL;
		}
		// the same endpoint is claiming a different id
		// this is suspicious so remove the node form the routing table
		else
		{
			RemoveTableIP(id.addr);
			bool removed = _buckets[b]->RemoveFromList(this, existing->id.id, list);
			assert(removed);
			return NULL;
		}
	}

	int bucket_id = GetBucket(id.id);

	// this will detect the -1 case
	if (bucket_id < 0) {
		return NULL;
	}

	DhtBucket &bucket = *_buckets[bucket_id];

#if defined(_DEBUG_DHT)
//	debug_log("Update: %s.", format_dht_id(id.id));
#endif

	assert(bucket.TestForMatchingPrefix(id.id));

	DhtPeer* returnNode = NULL;

	time_t now = time(NULL);

	DhtPeer candidateNode;
	candidateNode.id = id;
	candidateNode.rtt = rtt;
	candidateNode.num_fail = 0;
	candidateNode.first_seen = now;
	candidateNode.lastContactTime = seen ? now : 0;
#if g_log_dht
	candidateNode.origin = origin;
#endif

	{
		DhtPeer* existingNode = bucket.FindNode(id.id);
		// if the node is trying to claim the same id with a different IP, reject it
		if (existingNode && existingNode->id.addr != id.addr)
			return NULL;
	}

	// try putting the node in the active node list (or updating it if it's already there)
	bool added = bucket.InsertOrUpdateNode(this, candidateNode, DhtBucket::peer_list, &returnNode);

	// the node was already in or added to the main bucket
	if (returnNode) {
		if (added)
		{
			// if the candidate node is in the replacement list, remove it (to
			// prevent it from possibly being in both lists simultainously)
			if (bucket.RemoveFromList(this, candidateNode.id.id, DhtBucket::replacement_list))
			{
				RemoveTableIP(candidateNode.id.addr);
			}
			else
			{
				assert(!existing);
			}

			AddTableIP(id.addr);
		}
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
	bool replacementAvailable = bucket.FindReplacementCandidate(this
		, candidateNode, DhtBucket::peer_list, &returnNode);

	// did we find a candidate to replace?
	if (replacementAvailable) {

		// if the candidate node is in the replacement list, remove it (to
		// prevent it from possibly being in both lists simultainously)
		if (bucket.RemoveFromList(this, candidateNode.id.id, DhtBucket::replacement_list))
		{
			RemoveTableIP(candidateNode.id.addr);
		}
		else
		{
			assert(!existing);
		}

		// a replacement candidate has been identified in the active peers list.

		// If the candidate for replacement in the active peer list is errored,
		// just replace it
		if (returnNode->num_fail) {
			// replace the node with the candidate
			RemoveTableIP(returnNode->id.addr);
			AddTableIP(candidateNode.id.addr);
			(*returnNode).CopyAllButNext(candidateNode);
			return returnNode;
		}

		// The replacement candidate isn't errored, see if there is a place
		// for it in the reserve list.
		DhtPeer* replaceNode = NULL;
		added = bucket.InsertOrUpdateNode(this, *returnNode, DhtBucket::replacement_list, &replaceNode);
		if (replaceNode) {
			// assert that the node wasn't on both lists
			assert(added);
			// the peer list node is now in the replacement list, put the new
			// node in the peer list
			AddTableIP(candidateNode.id.addr);
			(*returnNode).CopyAllButNext(candidateNode); // replace the node with the candidate
		} else {
			// the replacement candidate was not added directly to the replace list (full), see
			// if there is a sub-prefix or rtt that should be replaced
			replacementAvailable = bucket.FindReplacementCandidate(this, *returnNode, DhtBucket::replacement_list, &replaceNode);
			if (replacementAvailable) {
				RemoveTableIP(replaceNode->id.addr);
				replaceNode->CopyAllButNext(*returnNode);
			}
			else
			{
				RemoveTableIP(returnNode->id.addr);
			}
			AddTableIP(candidateNode.id.addr);
			(*returnNode).CopyAllButNext(candidateNode); // replace the node with the candidate
		}
	} else {
		// no suitable replacement node was identified in the active peers list,
		// see if the candidate node belongs in the replacement list
		added = bucket.InsertOrUpdateNode(this, candidateNode, DhtBucket::replacement_list, &returnNode);
		if(!added){
			if (!returnNode)
			{
				// The candidate node was not added to the bucket; see if a node in the replacement bucket
				// can be replaced with the candidate node to either improve the sub-prefix distribution
				// or significantly improve the rtt of the reserve.
				replacementAvailable = bucket.FindReplacementCandidate(this, candidateNode, DhtBucket::replacement_list, &returnNode);
				if (replacementAvailable) {
					RemoveTableIP(returnNode->id.addr);
					AddTableIP(candidateNode.id.addr);
					(*returnNode).CopyAllButNext(candidateNode); // replace the node with the candidate
					return returnNode;
				} else {
					return NULL; // the candidate node is being discarded
				}
			}
		}
		else
		{
			AddTableIP(returnNode->id.addr);
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
		if (r == 0 || ep->id.addr.ip_eq(id.addr))
			return; // duplicate ids or ip address
		if (r > 0)
			break; // cur pos > id?
	}

	for (int ip = i+1; ip < numNodes; ip++) {
		if (nodes[ip].id.addr.ip_eq(id.addr))
			return; // duplicate ip address
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
	ep->cas = 0;
	memset(ep->client, 0, sizeof(ep->client));
	ep->version = 0;
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

void DhtLookupNodeList::set_data_blk(byte * v, int v_len, SockAddr src)
{
	data_blk.assign(v, v + v_len);
	src_ip = src;
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

void DhtProcessManager::Start()
{
	_currentProcessNumber = 0;
	if (_dhtProcesses.size() > 0)
		_dhtProcesses[0]->Start();
}

void DhtProcessManager::Abort()
{
	_currentProcessNumber = _dhtProcesses.size();
}

void DhtProcessManager::Next()
{
	_currentProcessNumber++;  // increment to the next process
	if (_currentProcessNumber < _dhtProcesses.size())
		_dhtProcesses[_currentProcessNumber]->Start();
	else
		delete this; // all processes have completed; terminate the manager
}

//*****************************************************************************
//
// DhtProcessBase
//
//*****************************************************************************
DHTMessage DhtProcessBase::dummyMessage;

#ifdef _DEBUG_DHT
unsigned int DhtProcessBase::process_id() const
{
	return uintptr_t(this) + start_time;
}
#endif

void DhtProcessBase::Abort()
{
	aborted = true;
	processManager.Abort();
}

void DhtProcessBase::CompleteThisProcess()
{
#ifdef _DEBUG_DHT
	if (impl->_lookup_log)
		fprintf(impl->_lookup_log, "[%u] [%u] [%s]: COMPLETE\n"
			, uint(get_milliseconds()), process_id(), name());
#endif

#if defined(_DEBUG_DHT_VERBOSE)
	debug_log("[%u] COMPLETED total=%d", process_id()
		, processManager.size());
	for (int i = 0; i < processManager.size(); ++i) {
		debug_log("[%u] [%d] queried=%s\t filtered=%d version=%s", process_id(), i
			, _queried_str[processManager[i].queried], Filter(processManager[i])
			, print_version(processManager[i].client, processManager[i].version));
	}
#endif

	// let the process manager know that this phase of the dht process is complete
	// and to start the next phase of the process (or terminate if all phases are
	// complete).
	processManager.Next();
}

void DhtProcessBase::Start()
{
	Schedule();
}

DhtProcessBase::DhtProcessBase(DhtImpl *pImpl, DhtProcessManager &dpm
	, const DhtID &target2, time_t startTime
	, const CallBackPointers &consumerCallbacks)
	: callbackPointers(consumerCallbacks)
	, target(target2)
	, impl(pImpl)
	, start_time(startTime)
	, aborted(false)
	, processManager(dpm)
{
	// let the DHT know there is an active process
	impl->_dht_busy++;
};

DhtProcessBase::~DhtProcessBase()
{
	impl->_dht_busy--;
}
 
//*****************************************************************************
//
// DhtLookupScheduler
//
//*****************************************************************************

DhtLookupScheduler::DhtLookupScheduler(DhtImpl* pDhtImpl
	, DhtProcessManager &dpm, const DhtID &target2
	, time_t startTime, const CallBackPointers &consumerCallbacks
	, int maxOutstanding, int fl, int targets)
	: DhtProcessBase(pDhtImpl, dpm, target2
		, startTime, consumerCallbacks)
	, num_targets(targets)
	, maxOutstandingLookupQueries(maxOutstanding)
	, numNonSlowRequestsOutstanding(0)
	, totalOutstandingRequests(0)
	, flags(fl)
{
	assert(maxOutstandingLookupQueries > 0);
#if g_log_dht
	dht_log("DhtLookupScheduler,instantiated,id,%d,time,%d\n", target.id[0]
		, get_microseconds());
#endif
}

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
	// Don't let processes run for too long while closing
	// assumption is the application doesn't want to linger too long after
	// receiving the quit command
	// Don't call Abort() so that the next process will get a chance to run
	// this is important for allowing a Put to execute after a long running Get
	if (impl->Closing() && time(NULL) - start_time >= 15) {
		aborted = true;

#if defined(_DEBUG_DHT_VERBOSE)
		debug_log("[%u] Process ran for too long, aborting", process_id());
#endif
	}

	if (aborted) {
		if (totalOutstandingRequests == 0){
			CompleteThisProcess();
		}
		return;
	}

	int numOutstandingRequestsToClosestNodes = 0;
	int K = num_targets;
	int nodeIndex=0;

	bool aggressive = (flags & IDht::announce_non_aggressive) == 0;

	// so long as the index is still within the size of the nodes array and so
	// long as we have not queried KADEMLIA_K (8) non-errored nodes (as a
	// terminating condition) if the first 4 (default value) good nodes in the
	// list do not yet have queries out to them - continue making queries if the
	// number of uncompromised outstanding queries is less than max outstanding
	// allowed - continue making queries
	while (nodeIndex < processManager.size()
		&& nodeIndex < K
		&& ((aggressive && numOutstandingRequestsToClosestNodes < maxOutstandingLookupQueries)
			|| numNonSlowRequestsOutstanding < maxOutstandingLookupQueries
			)
		) {

		if (aborted) {
			if (totalOutstandingRequests == 0){
				CompleteThisProcess();
			}
			return;
		}

		switch (processManager[nodeIndex].queried){
			case QUERIED_NO: {
				if (aborted) break;
				IssueQuery(nodeIndex);
				// NOTE: break is intentionally omitted here
			}
			case QUERIED_YES:

			// if a node is marked as slow, a query to the next unqueried node has
			// already been sent in its place.
			case QUERIED_SLOW: {
				numOutstandingRequestsToClosestNodes++;
				break;
			}
			case QUERIED_ERROR: {
				// if a node has errored, advance how far down the list we are
				// allowed to travel
				++K;
				break;
			}
			case QUERIED_REPLIED:{

				// if this node is filtered, look further for more nodes
				if (Filter(processManager[nodeIndex])) ++K;
				break;
			}
			default: {
				// an illegal status was set to a node
				assert(false);
			}
		}
		++nodeIndex;
	}

#if defined(_DEBUG_DHT_VERBOSE)
	debug_log("[%u] SCHEDULE total=%d outstanding=%d K=%d", process_id()
		, processManager.size(), totalOutstandingRequests, K);

	for (int i = 0; i < processManager.size(); ++i) {
		if (i == nodeIndex) {
			debug_log(" ---- DhtProcess end ----");
		}

		debug_log("[%u] [%d] queried=%s\t filtered=%d\t version=%s", process_id(), i
			, _queried_str[processManager[i].queried], Filter(processManager[i])
			, print_version(processManager[i].client, processManager[i].version));
	}
#endif

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
	if (aborted) return;

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

void DhtLookupScheduler::OnReply(void*& userdata, const DhtPeerID &peer_id
	, DhtRequest *req, DHTMessage &message, DhtProcessFlags flags)
{
#if g_log_dht
	assert(req->origin >= 0);
	assert(req->origin < sizeof(g_dht_peertype_count)/sizeof(g_dht_peertype_count[0]));
#endif

	// if we are processing a reply to a non-slow peer then decrease the count of
	// non-slow outstanding requests
	if(!req->slow_peer){
		--numNonSlowRequestsOutstanding;
	}
	// If a "slow" problem, mark the node as slow and see if another query can be issued.
	if (flags & PROCESS_AS_SLOW){
		--numNonSlowRequestsOutstanding;
#if defined(_DEBUG_DHT_VERBOSE)
		debug_log("[%u] *** 1ST-TIMEOUT tid=%d", process_id(), req->tid);
#endif
#ifdef _DEBUG_DHT
		if (impl->_lookup_log)
			fprintf(impl->_lookup_log, "[%u] [%u] [%s]: 1ST-TIMEOUT %s\n"
				, uint(get_milliseconds()), process_id(), name(), print_sockaddr(peer_id.addr).c_str());
#endif
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
		impl->UpdateError(peer_id, flags & ICMP_ERROR);

#if defined(_DEBUG_DHT_VERBOSE)
		debug_log("[%u] *** TIMEOUT tid=%d", process_id(), req->tid);
#endif
#ifdef _DEBUG_DHT
		if (impl->_lookup_log)
			fprintf(impl->_lookup_log, "[%u] [%u] [%s]: TIMEOUT %s\n"
				, uint(get_milliseconds()), process_id(), name(), print_sockaddr(peer_id.addr).c_str());
#endif
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

#ifdef _DEBUG_DHT
	int rtt = (std::max)(int(get_milliseconds() - req->time), 1);

	if (impl->_lookup_log)
		fprintf(impl->_lookup_log, "[%u] [%u] [%s]: <- %s (rtt:%d ms)\n"
			, uint(get_milliseconds()), process_id(), name()
			, print_sockaddr(peer_id.addr).c_str(), rtt);
#endif

	ImplementationSpecificReplyProcess(userdata, peer_id, message, flags);

	// mark this node replied and schedule more queries
	DhtFindNodeEntry *dfnh = processManager.FindQueriedPeer(peer_id);
	if (dfnh) { 
		if (message.dhtMessageType == DHT_ERROR) {
			dfnh->queried = QUERIED_ERROR;
		} else {
			dfnh->queried = QUERIED_REPLIED;
		}

		// if the node included its software version, remember that in the node
		// table
		if (message.version.b && message.version.len == 4) {
			memcpy(dfnh->client, message.version.b, 2);
			dfnh->version = (int(message.version.b[2]) << 8) | message.version.b[3];
		}
	}
	Schedule();
}

DhtFindNodeEntry* DhtLookupScheduler::ProcessMetadataAndPeer(
	const DhtPeerID &peer_id, DHTMessage &message, uint flags)
{
	DhtFindNodeEntry *dfnh = NULL;
	bool errored = false;

	// extract the nodes from the reply
	if(flags & NORMAL_RESPONSE)
	{
		// extract the possible reply arguments
		Buffer nodes;
		Buffer info_hash;
		std::vector<Buffer> values;

		BencodedList* valuesList = NULL;
		if (message.replyDict) {
			nodes.b = (byte*)message.replyDict->GetString("nodes", &nodes.len);
			info_hash.b = (byte*)message.replyDict->GetString("info_hash", &info_hash.len);
			valuesList = message.replyDict->GetList("values");
		} else {
			nodes.b = NULL;
			info_hash.b = NULL;
		}

		if (valuesList) {
			for(uint i=0; i!=valuesList->GetCount(); i++) {
				Buffer b;
				b.b = (byte*)valuesList->GetString(i, &b.len);
				if (!b.b)
					continue;
				values.push_back(b);
			}
		}

		// if there is a filename callback, see if a filename is in the reply
		if (callbackPointers.filenameCallback && message.replyDict) {
			Buffer filename;
			filename.b = (byte*)message.replyDict->GetString("n", &filename.len);
			if (filename.b && filename.len) {
				byte target_bytes[DHT_ID_SIZE];
				DhtIDToBytes(target_bytes, target);
				callbackPointers.filenameCallback(callbackPointers.callbackContext
					, target_bytes, filename.b);
			}
		}

		if(values.size()){
			byte bytes[DHT_ID_SIZE];
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

		// IP address, port and node-ID
		const int node_size = 4 + 2 + 20;
		if (nodes.b && nodes.len % node_size == 0) {
			uint num_nodes = nodes.len / node_size;
			// Insert all peers into my internal list.
#if defined(_DEBUG_DHT_VERBOSE)
			debug_log("[%u] <-- adding %d new nodes", process_id(), num_nodes);
#endif
			while (num_nodes != 0) {
				DhtPeerID peer;

				// Read into the peer struct
				CopyBytesToDhtID(peer.id, nodes.b);
				peer.addr.from_compact(nodes.b + DHT_ID_SIZE, 6);
				nodes.b += node_size;

				// Check if it's identical to myself?
				// Don't add myself to my internal list of peers.
				if (!(peer.id == impl->_my_id)
					&& peer.addr.get_port() != 0
					&& !impl->IsBootstrap(peer.addr)) {

					impl->Update(peer, IDht::DHT_ORIGIN_FROM_PEER, false);

					// Insert into my list...
					processManager.InsertPeer(peer, target);
				}
				num_nodes--;
			}
		} else if (values.empty()) {
			// we didn't get any nodes nor any values
			errored = true;
		}
	}

	dfnh = processManager.FindQueriedPeer(peer_id);
	if(errored || (flags & ANY_ERROR)){
		// mark peer as errored
		if (dfnh) dfnh->queried = QUERIED_ERROR;
		impl->UpdateError(peer_id, flags & ICMP_ERROR);
	}
	else if (dfnh) {
		// mark that the peer replied.
		dfnh->queried = QUERIED_REPLIED;
		// When getting peers, remember the write-token.
		// This is needed to be able to announce to the peers.
		// it's also required to cast votes
		Buffer token;
		if (message.replyDict) {
			token.b = (byte*)message.replyDict->GetString("token", &token.len);
		} else {
			token.b = NULL;
		}

		if (token.b && token.len <= 20) {
			dfnh->token.len = token.len;
			assert(dfnh->token.b == NULL);
			dfnh->token.b = (byte*)malloc(token.len);
			memcpy(dfnh->token.b, token.b, token.len);
		}

		// capture client version
		if (message.version.b && message.version.len == 4) {
			memcpy(dfnh->client, message.version.b, 2);
			dfnh->version = (int(message.version.b[2]) << 8) | message.version.b[3];
		}
		return dfnh;
	}
	return NULL;
}

void DhtLookupScheduler::ImplementationSpecificReplyProcess(void *userdata
	, const DhtPeerID &peer_id, DHTMessage &message, uint flags)
{
	ProcessMetadataAndPeer(peer_id, message, flags);
}

void GetDhtProcess::ImplementationSpecificReplyProcess(void *userdata
	, const DhtPeerID &peer_id, DHTMessage &message, uint flags)
{
	DhtFindNodeEntry *dfnh = ProcessMetadataAndPeer(peer_id, message, flags);
	if (dfnh == NULL) return;

	// We are looking for the response message with the maximum seq number.
	if (message.sequenceNum >= processManager.seq()
		&& message.signature.len > 0
		&& message.vBuf.len > 0
		&& message.key.len > 0
		&& impl->Verify(message.signature.b, message.vBuf.b, message.vBuf.len
			, NULL, 0, message.key.b, message.sequenceNum)) {
		// The maximum seq and the vBuf are saved by the
		// processManager and will be used in creating Put messages.
		processManager.set_data_blk(message.vBuf.b, message.vBuf.len, peer_id.addr);
		processManager.set_seq(message.sequenceNum);

#ifdef _DEBUG_DHT
		if (impl->_lookup_log)
			fprintf(impl->_lookup_log, "[%u] [%u] [%s]: BLOB (seq: %" PRId64 ")\n"
				, uint(get_milliseconds()), process_id(), name(), message.sequenceNum);
#endif

		if (callbackPointers.putDataCallback) {
			std::vector<char> blk((char*)message.vBuf.b
				, (char*)message.vBuf.b + message.vBuf.len);

			if (callbackPointers.putDataCallback(callbackPointers.callbackContext
				, blk, message.sequenceNum, peer_id.addr) != 0) {
				Abort();
			}
		}
	}

	if (callbackPointers.getCallback && message.vBuf.len > 0) {

		// This is an immutable get, without a put associated with it.
		// if we got a data response, there's no need to continue, every
		// response is guaranteed to be identical, so just abort

		// make sure the response actually matches what we were looking for
		DhtID result_hash_id = impl->_sha_callback(message.vBuf.b, message.vBuf.len);
		if (result_hash_id == target) {

			std::vector<char> blk((char*)message.vBuf.b
				, (char*)message.vBuf.b + message.vBuf.len);

			callbackPointers.getCallback(callbackPointers.callbackContext, blk);

			// avoid having the callback called twice
			callbackPointers.getCallback = NULL;
			Abort();
		}
	}

	if (_with_cas) {
		// record the sequence number to echo it back when writing.
		// this allows us to do race-free writes
		dfnh->cas = message.sequenceNum;
	}

#if defined(_DEBUG_DHT_VERBOSE)
	debug_log("[%u] <-- GET tid=%d", process_id(), Read32(message.transactionID.b));
#endif
}

//*****************************************************************************
//
// DhtBroadcastScheduler
//
//*****************************************************************************
void DhtBroadcastScheduler::Schedule()
{
	if (aborted) {
		if (outstanding == 0){
			CompleteThisProcess();
		}
		return;
	}

	// Send rpc's up to a maximum of KADEMLIA_K_ANNOUNCE (usually 8).
	// Do not allow more than KADEMLIA_BROADCAST_OUTSTANDING (usually 4) to be
	// in flight an any given time.  Do not track "slow peers".  Once a peer times
	// out, then issue another rpc.
	int numReplies = 0, index = 0;
	while(index < processManager.size()
		&& outstanding < KADEMLIA_BROADCAST_OUTSTANDING
		&& (outstanding + numReplies) < num_targets)
	{
		switch(processManager[index].queried){
			case QUERIED_NO:
			{
				DhtFindNodeEntry& nodeInfo = processManager[index];
				if (!aborted && !Filter(nodeInfo)) {
					nodeInfo.queried = QUERIED_YES;
					DhtRequest *req = impl->AllocateRequest(nodeInfo.id);
					DhtSendRPC(nodeInfo, req->tid);
					req->_pListener = new DhtRequestListener<DhtProcessBase>(this
						, &DhtProcessBase::OnReply);
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

#if defined(_DEBUG_DHT_VERBOSE)
	debug_log("[%u] SCHEDULE total=%d outstanding=%d replied=%d", process_id()
		, processManager.size(), outstanding, numReplies);
	for (int i = 0; i < processManager.size(); ++i) {
		if (i == index) {
			debug_log("  ---- DhtProcess end ----");
		}
		debug_log("[%u] [%d] queried=%s\t filtered=%d\t version=%s", process_id(), i
			, _queried_str[processManager[i].queried], Filter(processManager[i])
			, print_version(processManager[i].client, processManager[i].version));
	}
#endif

	// No outstanding requests. Means we're finished.
	if (outstanding == 0)
		CompleteThisProcess();
}

/**
Let slow peers continue until they either respond or timeout.
*/
void DhtBroadcastScheduler::OnReply(void*& userdata, const DhtPeerID &peer_id
	, DhtRequest *req, DHTMessage &message, DhtProcessFlags flags)
{
#if g_log_dht
	assert(req->origin >= 0);
	assert(req->origin < sizeof(g_dht_peertype_count)/sizeof(g_dht_peertype_count[0]));
#endif

	if(flags & NORMAL_RESPONSE){
		// a normal response, let the derived class handle it
		if (!aborted) {
			ImplementationSpecificReplyProcess(userdata, peer_id, message, flags);
		}

		DhtFindNodeEntry *dfnh = processManager.FindQueriedPeer(peer_id);
		if (dfnh) {
			dfnh->queried = QUERIED_REPLIED;

			// if the node included its software version, remember that in the node
			// table
			if (message.version.b && message.version.len == 4) {
				memcpy(dfnh->client, message.version.b, 2);
				dfnh->version = (int(message.version.b[2]) << 8) | message.version.b[3];
			}
		}
		outstanding--;
		Schedule();
	}
	else if(flags & ANY_ERROR){  // if ICMP or timeout error
		DhtFindNodeEntry *dfnh = processManager.FindQueriedPeer(peer_id);
		if (dfnh) dfnh->queried = QUERIED_ERROR;
		impl->UpdateError(peer_id, flags & ICMP_ERROR);
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

FindNodeDhtProcess::FindNodeDhtProcess(DhtImpl* pDhtImpl
	, DhtProcessManager &dpm, const DhtID &target2
	, time_t startTime
	, const CallBackPointers &consumerCallbacks, int maxOutstanding
	, int flags)
	: DhtLookupScheduler(pDhtImpl,dpm,target2,startTime
		, consumerCallbacks,maxOutstanding, flags)
{
	DhtIDToBytes(target_bytes, target);
#if g_log_dht
	dht_log("FindNodeDhtProcess,instantiated,id,%d,time,%d\n", target.id[0], get_microseconds());
#endif
}

void FindNodeDhtProcess::DhtSendRPC(const DhtFindNodeEntry &nodeInfo
	, const unsigned int transactionID)
{
	unsigned char buf[1500];
	smart_buffer sb(buf, sizeof(buf));

	// The find_node rpc
	sb("d1:ad2:id20:")(DHT_ID_SIZE, impl->_my_id_bytes);
	sb("6:target20:")(DHT_ID_SIZE, target_bytes);
	sb("e1:q9:find_node");
	impl->put_is_read_only(sb);
	impl->put_transaction_id(sb, Buffer((byte*)&transactionID, 4));
	impl->put_version(sb);
	sb("1:y1:qe");

	assert(sb.length() >= 0);
	if (sb.length() < 0) {
		do_log("DhtSendRPC blob exceeds maximum size.");
		return;
	}

#ifdef _DEBUG_DHT
	if (impl->_lookup_log)
		fprintf(impl->_lookup_log, "[%u] [%u] [%s]: FIND -> %s\n"
			, uint(get_milliseconds()), process_id(), name(), print_sockaddr(nodeInfo.id.addr).c_str());
#endif

	instrument_log('>', "find_node", 'q', sb.length(), transactionID);
	impl->SendTo(nodeInfo.id.addr, buf, sb.length());
}

/**
 Factory for creating FindNodeDhtProcess objects
*/
DhtProcessBase* FindNodeDhtProcess::Create(DhtImpl* pDhtImpl
	, DhtProcessManager &dpm
	, const DhtID &target2
	, CallBackPointers &cbPointers
	, int maxOutstanding
	, int flags)
{
	FindNodeDhtProcess* process = new FindNodeDhtProcess(pDhtImpl, dpm, target2
		, time(NULL), cbPointers, maxOutstanding, flags);
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
	"9:info_hash",
	"4:name",
	"6:noseedi1e", // no need to set the corresponding value, it is encodede here
	"4:port",
	"6:scrapei1e", // no need to set the corresponding value, it is encodede here
	"5:token",
	"4:vote"
};

void GetPeersDhtProcess::CompleteThisProcess()
{
#if g_log_dht
	dht_log("GetPeersDhtProcess,completed,id,%d,time,%d\n", target.id[0], get_microseconds());
#endif

#if defined(_DEBUG_DHT_VERBOSE)
	debug_log("[%u] PRE-COMPACT total=%d", process_id()
		, processManager.size());
	for (int i = 0; i < processManager.size(); ++i) {
		debug_log("[%u] [%d] queried=%s\t filtered=%d version=%s", process_id(), i
			, _queried_str[processManager[i].queried], Filter(processManager[i])
			, print_version(processManager[i].client, processManager[i].version));
	}
#endif

	processManager.CompactList();

#if defined(_DEBUG_DHT_VERBOSE)
	debug_log("[%u] COMPACT total=%d", process_id()
		, processManager.size());
	for (int i = 0; i < processManager.size(); ++i) {
		debug_log("[%u] [%d] queried=%s\t filtered=%d\t version=%s", process_id(), i
			, _queried_str[processManager[i].queried], Filter(processManager[i])
			, print_version(processManager[i].client, processManager[i].version));
	}
#endif

	DhtProcessBase::CompleteThisProcess();
}

GetPeersDhtProcess::~GetPeersDhtProcess()
{
	delete gpArgumenterPtr;
}

GetPeersDhtProcess::GetPeersDhtProcess(DhtImpl* pDhtImpl, DhtProcessManager &dpm
	, const DhtID &target2, time_t startTime
	, const CallBackPointers &consumerCallbacks, int maxOutstanding, int flags)
	: DhtLookupScheduler(pDhtImpl, dpm, target2, startTime
		, consumerCallbacks,maxOutstanding,flags)
{
	byte infoHashBytes[DHT_ID_SIZE];

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
	memcpy(buf + 3, pDhtImpl->_my_id_bytes, DHT_ID_SIZE);
	argBuf1.SetNumBytesUsed(DHT_ID_SIZE + 3);
	gpArgumenterPtr->enabled[a_id] = true;

	DhtIDToBytes(infoHashBytes, target);
	ArgumenterValueInfo& argBuf2 = gpArgumenterPtr->GetArgumenterValueInfo(a_info_hash);
	buf = (char*)argBuf2.GetBufferPtr();
	snprintf(buf, ArgumenterValueInfo::BUF_LEN, "20:");
	memcpy(buf + 3, infoHashBytes, DHT_ID_SIZE);
	argBuf2.SetNumBytesUsed(DHT_ID_SIZE + 3);
	gpArgumenterPtr->enabled[a_info_hash] = true;

#if g_log_dht
	dht_log("GetPeersDhtProcess,instantiated,id,%d,time,%d\n", target.id[0], get_milliseconds());
#endif
}

DhtProcessBase* GetPeersDhtProcess::Create(DhtImpl* pDhtImpl, DhtProcessManager &dpm
	, const DhtID &target2
	, CallBackPointers &cbPointers
	, int flags
	, int maxOutstanding)
{
	GetPeersDhtProcess* process = new GetPeersDhtProcess(pDhtImpl, dpm, target2
		, time(NULL), cbPointers, maxOutstanding, flags);

	// If flags & announce_seed is true, then we want to include noseed in the rpc arguments.
	// If seed is false, then noseed should also be false (just not included in the
	// rpc argument list)
	// This can coordinate with an announce with seed=1
	process->gpArgumenterPtr->enabled[a_noseed] = flags & IDht::announce_seed;

	return process;
}

void GetPeersDhtProcess::DhtSendRPC(const DhtFindNodeEntry &nodeInfo
	, const unsigned int transactionID)
{
	static const int bufLen = 1500;
	char rpcArgsBuf[bufLen];
	unsigned char buf[bufLen];

	smart_buffer sb(buf, bufLen);

	sb("d1:ad");

	int args_len = gpArgumenterPtr->BuildArgumentBytes((byte*)rpcArgsBuf, bufLen);
	sb(args_len, (byte*)rpcArgsBuf);

	sb("e1:q9:get_peers");
	impl->put_is_read_only(sb);
	impl->put_transaction_id(sb, Buffer((byte*)&transactionID, 4));
	impl->put_version(sb);
	sb("1:y1:qe");

	assert(sb.length() >= 0);
	if (sb.length() < 0) {
		do_log("DhtSendRPC blob exceeds maximum size");
		return;
	}

#ifdef _DEBUG_DHT
	if (impl->_lookup_log)
		fprintf(impl->_lookup_log, "[%u] [%u] [%s]: GET-PEERS -> %s\n"
			, uint(get_milliseconds()), process_id(), name(), print_sockaddr(nodeInfo.id.addr).c_str());
#endif

	instrument_log('>', "get_peers", 'q', sb.length(), transactionID);
	impl->SendTo(nodeInfo.id.addr, buf, sb.length());
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

AnnounceDhtProcess::AnnounceDhtProcess(DhtImpl* pDhtImpl, DhtProcessManager &dpm
	, const DhtID &target2, time_t startTime, const CallBackPointers &consumerCallbacks)
	: DhtBroadcastScheduler(pDhtImpl,dpm,target2,startTime,consumerCallbacks)
{
	byte infoHashBytes[DHT_ID_SIZE];

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
	memcpy(buf + 3, pDhtImpl->_my_id_bytes, DHT_ID_SIZE);
	argBuf1.SetNumBytesUsed(DHT_ID_SIZE + 3);
	announceArgumenterPtr->enabled[a_id] = true;

	DhtIDToBytes(infoHashBytes, target);
	ArgumenterValueInfo& argBuf2 = announceArgumenterPtr->GetArgumenterValueInfo(a_info_hash);
	buf = (char*)argBuf2.GetBufferPtr();
	snprintf(buf, ArgumenterValueInfo::BUF_LEN, "20:");
	memcpy(buf + 3, infoHashBytes, DHT_ID_SIZE);
	argBuf2.SetNumBytesUsed(DHT_ID_SIZE + 3);
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

void AnnounceDhtProcess::Start()
{
#if g_log_dht
	dht_log("AnnounceDhtProcess,start_announce,id,%d,time,%d\n", target.id[0], get_microseconds());
#endif
	processManager.SetAllQueriedStatus(QUERIED_NO);
	DhtProcessBase::Start();
}

AnnounceDhtProcess::~AnnounceDhtProcess()
{
	delete announceArgumenterPtr;
}

DhtProcessBase* AnnounceDhtProcess::Create(DhtImpl* pDhtImpl, DhtProcessManager &dpm,
	const DhtID &target2,
	CallBackPointers &cbPointers,
	cstr file_name, int flags)
{
	AnnounceDhtProcess* process = new AnnounceDhtProcess(pDhtImpl, dpm, target2, time(NULL), cbPointers);

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

void AnnounceDhtProcess::DhtSendRPC(const DhtFindNodeEntry &nodeInfo
	, const unsigned int transactionID)
{
	static const int bufLen = 1500;
	char rpcArgsBuf[bufLen];
	unsigned char buf[bufLen];

	// convert the token
	ArgumenterValueInfo& argBuf = announceArgumenterPtr->GetArgumenterValueInfo(a_token);
	char* b = (char*)argBuf.GetBufferPtr();
	int pos = snprintf(b, ArgumenterValueInfo::BUF_LEN, "%d:", int(nodeInfo.token.len));
	memcpy(b + pos, nodeInfo.token.b, nodeInfo.token.len);
	argBuf.SetNumBytesUsed(nodeInfo.token.len + pos);

	announceArgumenterPtr->enabled[a_token] = true;

	// build the bencoded query string
	smart_buffer sb(buf, bufLen);

	sb("d1:ad");

	int args_len = announceArgumenterPtr->BuildArgumentBytes((byte*)rpcArgsBuf, bufLen);
	sb(args_len, (byte*)rpcArgsBuf);
	sb("e1:q13:announce_peer");
	impl->put_is_read_only(sb);
	impl->put_transaction_id(sb, Buffer((byte*)&transactionID, 4));
	impl->put_version(sb);
	sb("1:y1:qe");

	assert(sb.length() >= 0);
	if (sb.length() < 0) {
		do_log("DhtSendRPC blob exceeds maximum size.");
		return;
	}

#ifdef _DEBUG_DHT
	if (impl->_lookup_log)
		fprintf(impl->_lookup_log, "[%u] [%u] [%s]: ANNOUNCE -> %s\n"
			, uint(get_milliseconds()), process_id(), name(), print_sockaddr(nodeInfo.id.addr).c_str());
#endif

	instrument_log('>', "announce_peer", 'q', sb.length(), transactionID);
	impl->SendTo(nodeInfo.id.addr, buf, sb.length());
}

void AnnounceDhtProcess::ImplementationSpecificReplyProcess(void *userdata, const DhtPeerID &peer_id, DHTMessage &message, uint flags)
{
	// handle errors
	if(message.dhtMessageType != DHT_RESPONSE){
		impl->UpdateError(peer_id, flags & ICMP_ERROR);
	}
}

void AnnounceDhtProcess::CompleteThisProcess()
{
	if (callbackPointers.processListener)
		callbackPointers.processListener->ProcessCallback();

	// Tell it that we're done
	if (callbackPointers.addnodesCallback) {
		byte bytes[DHT_ID_SIZE];
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
	, const DhtID & target_2, time_t startTime
	, const CallBackPointers &consumerCallbacks, int maxOutstanding
	, int flags)
	: DhtLookupScheduler(pDhtImpl, dpm, target_2, startTime
		, consumerCallbacks, maxOutstanding, flags, 12) // <-- find 12 nodes, not 8!
	, _with_cas(flags & IDht::with_cas)
	, retries(0)
{
	
	char* buf = (char*)this->_id;
	memcpy(buf, pDhtImpl->_my_id_bytes, DHT_ID_SIZE);

#if defined(_DEBUG_DHT_VERBOSE)
	debug_log("[%u] NEW GET process", process_id());
	debug_log("[%u] maxOutstandingLookupQueries=%d", process_id()
		, maxOutstandingLookupQueries);
#endif

#if g_log_dht
	dht_log("GetDhtProcess,instantiated,id,%d,time,%d\n", target.id[0], get_milliseconds());
#endif

}

DhtProcessBase* GetDhtProcess::Create(DhtImpl* pDhtImpl, DhtProcessManager &dpm,
	const DhtID & target2,
	CallBackPointers &cbPointers, int flags, int maxOutstanding)
{
	GetDhtProcess* process = new GetDhtProcess(pDhtImpl, dpm, target2
		, time(NULL), cbPointers, maxOutstanding, flags);

	return process;
}

// returns false if the node doesn't support Put and Get
bool no_put_support(DhtFindNodeEntry const& e)
{
	// uTorrent builds older than 31395 do not support the DHT put/get feature
	if (memcmp(e.client, "UT", 2) == 0 && e.version < 31395) {
		return true;
	}

	// libtorrent versions less than 1.0 do not support the DHT put/get feature
	if (memcmp(e.client, "LT", 2) == 0 && e.version < 0x100) {
		return true;
	}

	// let everything else through
	return false;
}

bool GetDhtProcess::Filter(DhtFindNodeEntry const& e)
{
	return no_put_support(e) || e.token.b == NULL;
}

void GetDhtProcess::DhtSendRPC(const DhtFindNodeEntry &nodeInfo
	, const unsigned int transactionID)
{
	static const int bufLen = 1500;
	unsigned char buf[bufLen];
	smart_buffer sb(buf, bufLen);

	sb("d1:ad2:id20:")(DHT_ID_SIZE, (byte*)this->_id);

	if (processManager.seq() > 0)
		sb("3:seqi%" PRId64 "e", processManager.seq());

	byte targetAsID[DHT_ID_SIZE];

	DhtIDToBytes(targetAsID, target);
	sb("6:target20:")(DHT_ID_SIZE, targetAsID);
	sb("e1:q3:get");
	impl->put_is_read_only(sb);
	impl->put_transaction_id(sb, Buffer((byte*)&transactionID, 4));
	impl->put_version(sb);
	sb("1:y1:qe");
	
	assert(sb.length() >= 0);

	if (sb.length() < 0) {
		do_log("DhtSendRPC blob exceeds maximum size.");
		return;
	}

#ifdef _DEBUG_DHT
	if (impl->_lookup_log)
		fprintf(impl->_lookup_log, "[%u] [%u] [%s]: GET -> %s\n"
			, uint(get_milliseconds()), process_id(), name(), print_sockaddr(nodeInfo.id.addr).c_str());
#endif

#if defined(_DEBUG_DHT_VERBOSE)
	debug_log("[%u] --> GET %s tid=%d", process_id()
		, hexify(targetAsID), transactionID);
#endif
	instrument_log('>', "get", 'q', sb.length(), transactionID);
	impl->SendTo(nodeInfo.id.addr, buf, sb.length());
}

void GetDhtProcess::CompleteThisProcess()
{
#if g_log_dht
	dht_log("GetDhtProcess,completed,id,%d,time,%d\n", target.id[0], get_microseconds());
#endif

#if defined(_DEBUG_DHT_VERBOSE)
	debug_log("[%u] PRE-COMPACT total=%d", process_id()
		, processManager.size());
	for (int i = 0; i < processManager.size(); ++i) {
		debug_log("[%u] [%d] queried=%s\t filtered=%d\t version=%s", process_id(), i
			, _queried_str[processManager[i].queried], Filter(processManager[i])
			, print_version(processManager[i].client, processManager[i].version));
	}
#endif

	processManager.CompactList();

#if defined(_DEBUG_DHT_VERBOSE)
	debug_log("[%u] COMPACT total=%d", process_id()
		, processManager.size());
	for (int i = 0; i < processManager.size(); ++i) {
		debug_log("[%u] [%d] queried=%s\t filtered=%d version=%s", process_id(), i
			, _queried_str[processManager[i].queried], Filter(processManager[i])
			, print_version(processManager[i].client, processManager[i].version));
	}
#endif

	if (processManager.size() < 8 && !aborted && retries++ < 2) {
		// we got less than a bucket's worth of replies
		// we obviously didn't get a good set of peers to query, so try again
#if defined(_DEBUG_DHT_VERBOSE)
		debug_log("[%u] Restarting process", process_id());
#endif
		for (int i = 0; i < processManager.size(); ++i) {
			// CompactList resets the queried state to QUERIED_NO, since we're
			// going to restart we need to set the state back to REPLIED
			// so we don't query the nodes again
			// The reason we don't just do the restart before compacting the list
			// is because we want to allow for retrying failed nodes. The hope is
			// that truely dead nodes will get removed from the routing table by
			// the time we do the second restart.
			processManager[i].queried = QUERIED_REPLIED;
		}
		DhtPeerID *ids[32];
		int num = impl->AssembleNodeList(target, ids, lenof(ids));
		processManager.SetNodeIds(ids, num, target);
		Schedule();
		return;
	}

	if (callbackPointers.getCallback) {
		callbackPointers.getCallback(callbackPointers.callbackContext
			, std::vector<char>());

		// never call this twice
		callbackPointers.getCallback = NULL;
	}

	DhtProcessBase::CompleteThisProcess();
}


//*****************************************************************************
//
// PutDhtProcess			put
//
//*****************************************************************************

PutDhtProcess::PutDhtProcess(DhtImpl* pDhtImpl, DhtProcessManager &dpm
	, const byte * pkey, const byte * skey, time_t startTime
	, const CallBackPointers &consumerCallbacks, int flags)
	: DhtBroadcastScheduler(pDhtImpl, dpm, target
		, startTime, consumerCallbacks, 12) // <- put to 12 nodes instead of 8!
	, getProc(NULL)
	, _with_cas(flags & IDht::with_cas)
	, _put_callback_called(false)
{
	signature.clear();
	char* buf = (char*)this->_id;
	memcpy(buf, pDhtImpl->_my_id_bytes, DHT_ID_SIZE);

	buf = (char*)this->_pkey;
	memcpy(buf, pkey, DHT_KEY_SIZE);

	buf = (char*)this->_skey;
	memcpy(buf, skey, 64);

#if defined(_DEBUG_DHT_VERBOSE)
	debug_log("[%u] NEW PUT process", process_id());
#endif

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

void PutDhtProcess::Start()
{
#if g_log_dht
	dht_log("PutDhtProcess,start_announce,id,%d,time,%d\n", target.id[0], get_microseconds());
#endif
	processManager.SetAllQueriedStatus(QUERIED_NO);
	DhtProcessBase::Start();
}
 
PutDhtProcess::~PutDhtProcess()
{
}

bool PutDhtProcess::Filter(DhtFindNodeEntry const& e)
{
	return no_put_support(e) || e.token.b == NULL;
}

void PutDhtProcess::Sign(std::vector<char> &signature, std::vector<char> v, byte * skey, int64 seq) {
	unsigned char sig[DHT_SIG_SIZE];
	char buf[1024];
	unsigned int index = 0;

	index += sprintf(buf, MUTABLE_PAYLOAD_FORMAT, seq);

	v.insert(v.begin(), buf, buf+index);

	assert(impl->_ed25519_sign_callback);
	impl->_ed25519_sign_callback(sig, (unsigned char *)&v[0], v.size(), skey);

	signature.assign(sig, sig+DHT_SIG_SIZE);
}

//*****************************************************************************
//
// ImmutablePutDhtProcess			immutable put
//
//*****************************************************************************
ImmutablePutDhtProcess::ImmutablePutDhtProcess(DhtImpl* pDhtImpl
	, DhtProcessManager &dpm
	, byte const* data
	, size_t data_len
	, time_t startTime
	, const CallBackPointers &consumerCallbacks)
	: DhtBroadcastScheduler(pDhtImpl, dpm, target
		, startTime, consumerCallbacks, 12)
{
	char* buf = (char*)this->_id;
	memcpy(buf, pDhtImpl->_my_id_bytes, DHT_ID_SIZE);
	_data.assign(data, data + data_len);

#if defined(_DEBUG_DHT_VERBOSE)
	debug_log("[%u] NEW IPUT process", process_id());
#endif

#if g_log_dht
	dht_log("ImmutablePutDhtProcess,instantiated,id,%d,time,%d\n", target.id[0],
			get_milliseconds());
#endif
}

DhtProcessBase* ImmutablePutDhtProcess::Create(DhtImpl* pDhtImpl,
		DhtProcessManager &dpm, byte const* data, size_t data_len,
		CallBackPointers &cbPointers)
{
	return new ImmutablePutDhtProcess(pDhtImpl, dpm, data, data_len, time(NULL),
			cbPointers);
}

void ImmutablePutDhtProcess::Start()
{
#if g_log_dht
	dht_log("ImmutablePutDhtProcess,start_announce,id,%d,time,%d\n",
			target.id[0], get_microseconds());
#endif
	processManager.SetAllQueriedStatus(QUERIED_NO);
	DhtProcessBase::Start();
}
 
ImmutablePutDhtProcess::~ImmutablePutDhtProcess()
{
}

bool ImmutablePutDhtProcess::Filter(DhtFindNodeEntry const& e)
{
	return no_put_support(e) || e.token.b == NULL;
}

bool DhtImpl::Verify(byte const * signature, byte const * message, int message_length
	, byte const * salt, int salt_length, byte *pkey, int64 seq)
{
	char buf[1500];

	int index = 0;
	if (salt_length > 0)
	{
		index += snprintf(buf + index, sizeof(buf) - index, "4:salt%d:", salt_length);
		memcpy(buf + index, salt, salt_length);
		index += salt_length;
	}

	index += snprintf(buf + index, sizeof(buf) - index, MUTABLE_PAYLOAD_FORMAT, seq);
	if (index + message_length >= sizeof(buf)) {
		return false;
	}
	memcpy(buf + index, message, message_length);
	assert(_ed25519_verify_callback);
	return _ed25519_verify_callback(signature, (unsigned char*)buf, message_length + index, pkey);
}

void PutDhtProcess::DhtSendRPC(const DhtFindNodeEntry &nodeInfo
	, const unsigned int transactionID)
{
	int64 seq = processManager.seq();
	// note that blk is returned by reference
	// we want a copy that the put callback can modify
	std::vector<char>& blk = processManager.get_data_blk();
	assert(callbackPointers.putCallback);

	if (callbackPointers.putCallback != NULL
		&& !_put_callback_called
		&& (signature.empty() || blk.empty())) {

		if (callbackPointers.putCallback(callbackPointers.callbackContext
			, blk, seq, processManager.data_blk_source()) != 0) {
			Abort();
			return;
		}

		// only call the callback once
		_put_callback_called = true;

		// the callback may have updated the sequence number
		processManager.set_seq(seq);

		// the buffer has to be greater than zero. The empty string must be
		// represented by "0:"
		assert(blk.size() > 0);
		assert(blk.size() <= 1024);
	}

	// the callback must return either an empty buffer, or
	// a valid bencoded structure
	if (blk.empty()) {
		char empty_string[] = "0:";
		blk.insert(blk.begin(), empty_string, empty_string + 2);
	}

	if (signature.empty()) {
		Sign(signature, blk, _skey, seq);
		assert(signature.size() > 0);

#ifdef _DEBUG_DHT
		assert(impl->Verify((unsigned char*)&signature[0], (unsigned char*)&blk[0]
			, blk.size(), NULL, 0, _pkey, seq));
#endif
	}

	// the buffer has to be greater than zero. The empty string must be
	// represented by "0:"
	assert(blk.size() > 0);
	assert(signature.size() > 0);

	static const int buf_len = 1500;
	unsigned char buf[buf_len];
	smart_buffer sb(reinterpret_cast<unsigned char*>(buf), buf_len);
	sb("d1:ad");

	if (_with_cas) {
		sb("3:casi%" PRId64 "e", nodeInfo.cas);
	}
	sb("2:id20:")(DHT_ID_SIZE, (byte const*)this->_id);
	sb("1:k32:")(DHT_KEY_SIZE, (byte*)this->_pkey);
	sb("3:seqi%" PRId64 "e", seq);
	sb("3:sig64:")(DHT_SIG_SIZE, (byte const*)&signature[0]);
	sb("5:token")("%d:", int(nodeInfo.token.len));
	sb(nodeInfo.token.len, (byte const*)nodeInfo.token.b);
	sb("1:v")(blk.size(), (byte const*)&blk[0]);
	sb("e1:q3:put");
	impl->put_is_read_only(sb);
	sb("1:t4:")(4, (byte const*)&transactionID);
	byte const* dht_utversion = impl->get_version();
	sb("1:v4:")(4, dht_utversion);
	sb("1:y1:qe");
	int64 len = sb.length();

	// send the query
	if (len < 0) {
		do_log("DHT put blob exceeds %i byte maximum size! blk size: %lu", buf_len,
				blk.size());
		return;
	}

#ifdef _DEBUG_DHT
	if (impl->_lookup_log)
		fprintf(impl->_lookup_log, "[%u] [%u] [%s]: PUT -> %s\n"
			, uint(get_milliseconds()), process_id(), name(), print_sockaddr(nodeInfo.id.addr).c_str());
#endif

#if defined(_DEBUG_DHT_VERBOSE)
	debug_log("[%u] --> PUT %s tid=%d", process_id()
		, hexify(this->_id), transactionID);
#endif
	instrument_log('>', "put", 'q', sb.length(), transactionID);
	impl->SendTo(nodeInfo.id.addr, buf, len);
}

void PutDhtProcess::ImplementationSpecificReplyProcess(void *userdata
	, const DhtPeerID &peer_id, DHTMessage &message, uint flags)
{
	// handle errors
	if (message.dhtMessageType != DHT_RESPONSE){
		impl->UpdateError(peer_id, flags & ICMP_ERROR);
	}
	if (message.dhtMessageType == DHT_ERROR
		&& (message.error_code == LOWER_SEQ
			|| message.error_code == CAS_MISMATCH)) {
		if (!aborted) {
			// don't issue the put twice
			impl->Put(_pkey, _skey
				, callbackPointers.putCallback
				, callbackPointers.putCompletedCallback
				, callbackPointers.putDataCallback
				, callbackPointers.callbackContext
				, _with_cas ? IDht::with_cas : 0, processManager.seq());
		}
		Abort();

		// don't call the completion callback twice. Since we just
		// passed it into a new Put process, it will be called when
		// it completes
		callbackPointers.putCompletedCallback = NULL;
	}

#if defined(_DEBUG_DHT_VERBOSE)
	debug_log("[%u] <-- PUT tid=%d", process_id(), Read32(message.transactionID.b));
#endif
}

void PutDhtProcess::CompleteThisProcess()
{
	if (callbackPointers.processListener)
		callbackPointers.processListener->ProcessCallback();

	// Tell it that we're done
	if (callbackPointers.addnodesCallback) {
		byte bytes[DHT_ID_SIZE];
		DhtIDToBytes(bytes, target);
		callbackPointers.addnodesCallback(callbackPointers.callbackContext, bytes, NULL, 0);
	}
	signature.clear();

#if g_log_dht
	dht_log("PutDhtProcess,completed,id,%d,time,%d\n", target.id[0]
		, get_milliseconds());
#endif

	if (callbackPointers.putCompletedCallback) {
		callbackPointers.putCompletedCallback(callbackPointers.callbackContext);

		// never call this twice
		callbackPointers.putCompletedCallback = NULL;
	}

	DhtProcessBase::CompleteThisProcess();
}

//*****************************************************************************
//
// ImmutablePutDhtProcess		immutable put
//
//*****************************************************************************

void ImmutablePutDhtProcess::ImplementationSpecificReplyProcess(void *userdata, const DhtPeerID &peer_id, DHTMessage &message, uint flags) {
	if (message.dhtMessageType != DHT_RESPONSE) {
		impl->UpdateError(peer_id, flags & ICMP_ERROR);
	}

#if defined(_DEBUG_DHT_VERBOSE)
	debug_log("[%u] <-- PUT tid=%d", process_id(), Read32(message.transactionID.b));
#endif
}

void ImmutablePutDhtProcess::DhtSendRPC(const DhtFindNodeEntry &nodeInfo
	, const unsigned int transactionID)
{
	static const int buf_len = 1500;
	unsigned char buf[buf_len];
	smart_buffer sb(reinterpret_cast<unsigned char*>(buf), buf_len);

	sb("d1:ad");
	sb("2:id20:")(DHT_ID_SIZE, (byte*)this->_id);
	sb("5:token%d:", int(nodeInfo.token.len));
	sb(nodeInfo.token.len, (byte const*)nodeInfo.token.b);
	sb("1:v%d:", int(_data.size()))(_data.size(), (byte const*)&_data[0]);
	sb("e1:q3:put");
	impl->put_is_read_only(sb);
	sb("1:t4:")(4, (byte const*)&transactionID);
	byte const* dht_utversion = impl->get_version();
	sb("1:v4:")(4, dht_utversion);
	sb("1:y1:qe");
	int64 len = sb.length();
	
	// send the query
	if (len < 0) {
		do_log("DHT put blob exceeds %i byte maximum size! blk size: %lu", buf_len,
				_data.size());
		return;
	}

#ifdef _DEBUG_DHT
	if (impl->_lookup_log)
		fprintf(impl->_lookup_log, "[%u] [%u] [%s]: IPUT -> %s\n"
			, uint(get_milliseconds()), process_id(), name(), print_sockaddr(nodeInfo.id.addr).c_str());
#endif

#if defined(_DEBUG_DHT_VERBOSE)
	debug_log("[%u] --> IPUT %s tid=%d", process_id()
		, hexify(this->_id), transactionID);
#endif
	instrument_log('>', "iput", 'q', sb.length(), transactionID);
	impl->SendTo(nodeInfo.id.addr, buf, len);
}

void ImmutablePutDhtProcess::CompleteThisProcess() {
	// why would this ever be set for a non-FindNodes process?
	assert(callbackPointers.processListener == nullptr);
	assert(callbackPointers.addnodesCallback == nullptr);

#if g_log_dht
	dht_log("ImmutablePutDhtProcess,completed,id,%d,time,%d\n", target.id[0]
		, get_milliseconds());
#endif

	if (callbackPointers.putCompletedCallback)
		callbackPointers.putCompletedCallback(callbackPointers.callbackContext);

	// never call this twice
	callbackPointers.putCompletedCallback = NULL;

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
		seeds.set_union(seedsBF.b);
	}
	if (downloadersBF.len == 256) {
		downloaders.set_union(downloadersBF.b);
	}

	// now do the parent class's reply process
	GetPeersDhtProcess::ImplementationSpecificReplyProcess(userdata, peer_id, message, flags);
}

ScrapeDhtProcess::ScrapeDhtProcess(DhtImpl* pDhtImpl, DhtProcessManager &dpm
	, const DhtID &target2, time_t startTime
	, const CallBackPointers &consumerCallbacks, int maxOutstanding, int flags)
	: GetPeersDhtProcess(pDhtImpl, dpm, target2, startTime
		, consumerCallbacks, maxOutstanding, flags)
	, seeds(2048, 2)
	, downloaders(2048, 2)
{
	gpArgumenterPtr->enabled[a_scrape] = true;
}

ScrapeDhtProcess::~ScrapeDhtProcess() {}

void ScrapeDhtProcess::CompleteThisProcess()
{
	byte target_bytes[DHT_ID_SIZE];
	DhtIDToBytes(target_bytes, target);

	if(callbackPointers.scrapeCallback){
		callbackPointers.scrapeCallback(callbackPointers.callbackContext
			, target_bytes, downloaders.estimate_count(), seeds.estimate_count());
	}

	DhtProcessBase::CompleteThisProcess();
}

DhtProcessBase* ScrapeDhtProcess::Create(DhtImpl* pDhtImpl, DhtProcessManager &dpm
	, const DhtID &target2
	, CallBackPointers &cbPointers
	, int maxOutstanding
	, int flags)
{
	ScrapeDhtProcess* process = new ScrapeDhtProcess(pDhtImpl,dpm, target2
		, time(NULL), cbPointers, maxOutstanding, flags);
	return process;
}


//*****************************************************************************
//
// VoteDhtProcess			command = vote
//
//*****************************************************************************

void VoteDhtProcess::DhtSendRPC(const DhtFindNodeEntry &nodeInfo
	, const unsigned int transactionID)
{
	unsigned char buf[1500];
	byte target_bytes[DHT_ID_SIZE];

	DhtIDToBytes(target_bytes, target);

	smart_buffer sb(buf, sizeof(buf));

	// The vote rpc
	sb("d1:ad2:id20:")(DHT_ID_SIZE, impl->_my_id_bytes);
	sb("6:target20:")(DHT_ID_SIZE, target_bytes);
	sb("5:token%d:", int(nodeInfo.token.len))(nodeInfo.token);
	sb("4:votei%de", voteValue)("e1:q4:vote");
	impl->put_is_read_only(sb);
	impl->put_transaction_id(sb, Buffer((byte*)&transactionID, 4));
	impl->put_version(sb);
	sb("1:y1:qe");

	assert(sb.length() >= 0);
	if (sb.length() < 0) {
		do_log("DhSendRPC blob exceeds maximum size");
		return;
	}

#ifdef _DEBUG_DHT
	if (impl->_lookup_log)
		fprintf(impl->_lookup_log, "[%u] [%u] [%s]: VOTE -> %s\n"
			, uint(get_milliseconds()), process_id(), name(), print_sockaddr(nodeInfo.id.addr).c_str());
#endif

	instrument_log('>', "vote", 'q', sb.length(), transactionID);
	impl->SendTo(nodeInfo.id.addr, buf, sb.length());
}

VoteDhtProcess::VoteDhtProcess(DhtImpl* pDhtImpl, DhtProcessManager &dpm
	, const DhtID &target2, time_t startTime
	, const CallBackPointers &consumerCallbacks)
	: DhtBroadcastScheduler(pDhtImpl,dpm,target2,startTime,consumerCallbacks)
	, voteValue(0)
{
}

void VoteDhtProcess::SetVoteValue(int value)
{
	assert(value >= 0 && value <= 5);
	voteValue = value;
}

void VoteDhtProcess::Start()
{
	processManager.SetAllQueriedStatus(QUERIED_NO);
	DhtProcessBase::Start();
}

/**
 Factory for creating VoteDhtProcess objects
*/
DhtProcessBase* VoteDhtProcess::Create(DhtImpl* pDhtImpl, DhtProcessManager &dpm,
	const DhtID &target2,
	CallBackPointers &cbPointers, int voteValue)
{
	VoteDhtProcess* process = new VoteDhtProcess(pDhtImpl, dpm, target2, time(NULL), cbPointers);
	process->SetVoteValue(voteValue);
	return process;
}

void VoteDhtProcess::ImplementationSpecificReplyProcess(void *userdata
	, const DhtPeerID &peer_id, DHTMessage &message, uint flags)
{
	int num_votes[5];
	BencodedList *votes = NULL;
	if (message.replyDict != NULL)
		votes = message.replyDict->GetList("v");

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
		byte target_bytes[DHT_ID_SIZE];
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
		if (p->GetSubprefixInt() == desiredSubPrefix) {
			if (!subPrefixMatchFound) {
				subPrefixMatchFound = true;
				candidate = peer;
			} else {
				if (((*candidate)->rtt > p->rtt)  || ((*candidate)->num_fail > p->num_fail)){
					candidate = peer;
				}
			}
		} else if (!subPrefixMatchFound) {
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
bool DhtBucket::TestForMatchingPrefix(const DhtID &id) const
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

#ifdef _DEBUG_DHT
		if (pDhtImpl->_dht_bootstrap == DhtImpl::valid_response_received && pDhtImpl->_bootstrap_log) {
			fprintf(pDhtImpl->_bootstrap_log, "[%u] nodes: %u\n"
				, uint(get_milliseconds() - pDhtImpl->_bootstrap_start)
				, pDhtImpl->_dht_peers_count);
		}
#endif
		return true;
	}
	return false;
}

DhtPeer* DhtBucket::FindNode(SockAddr const& addr, BucketListType& list)
{
	for (DhtPeer **peer = &peers.first(); *peer; peer=&(*peer)->next) {
		DhtPeer *p = *peer;
		if (p->id.addr == addr)
		{
			list = peer_list;
			return p;
		}
	}

	for (DhtPeer **peer = &replacement_peers.first(); *peer; peer=&(*peer)->next) {
		DhtPeer *p = *peer;
		if (p->id.addr == addr)
		{
			list = replacement_list;
			return p;
		}
	}

	return NULL;
}

DhtPeer* DhtBucket::FindNode(const DhtID& id)
{
	for (DhtPeer **peer = &peers.first(); *peer; peer=&(*peer)->next) {
		DhtPeer *p = *peer;
		if (p->id.id == id)
		{
			return p;
		}
	}

	for (DhtPeer **peer = &replacement_peers.first(); *peer; peer=&(*peer)->next) {
		DhtPeer *p = *peer;
		if (p->id.id == id)
		{
			return p;
		}
	}

	return NULL;
}

/**
	Searches through the designated node list for the candidate node's id.  If the id is in
	the list, the node information is updated.  If the candidate node's id is not found
	and the list is not full (less than the bucket size) the node is added and TRUE is
	returned.  If pout is proveded, it is set to the node that
	was updated/added.

	FALSE is returned if the bucket is full and the node is not in the list.  pout is
	not set to anything.

	While performing the search for the candidate node in the list, InsertOrUpdateNode()
	will generate the current sup-prefix information for the bucket.  It will also
	set the listContainesAnErroredNode flag if an errored node is encountered.

	InsertOrUpdateNode() should be invoked on a bucket before FindReplacementCandidate()
	is used on the bucket.
*/
bool DhtBucket::InsertOrUpdateNode(DhtImpl* pDhtImpl, DhtPeer const& candidateNode
	, BucketListType bucketType, DhtPeer** pout)
{
	DhtBucketList &bucketList = (bucketType == peer_list) ? peers : replacement_peers;

#if g_log_dht
	assert(candidateNode.origin >= 0);
	assert(candidateNode.origin < sizeof(g_dht_peertype_count)/sizeof(g_dht_peertype_count[0]));
#endif

	uint n = 0;	// number of peers in bucket-list
	// for all peers in the bucket...
	bucketList.ClearSubPrefixInfo();
	bucketList.listContainesAnErroredNode = false;
	for (DhtPeer **peer = &bucketList.first(); *peer; peer=&(*peer)->next, ++n) {
		DhtPeer *p = *peer;
		bucketList.UpdateSubPrefixInfo(*p);
		if (p->num_fail) {
			// This element is here for convienence Update() & InsertOrUpdateNode().
			// It only has a valid meaning immediatly after the consumer has set it.
			bucketList.listContainesAnErroredNode = true;
		}

		// Check if the peer is already in the bucket
		if (candidateNode.id != p->id) continue;

#if g_log_dht
		assert(p->origin >= 0);
		assert(p->origin < sizeof(g_dht_peertype_count)/sizeof(g_dht_peertype_count[0]));
#endif
		p->num_fail = 0;
		if (candidateNode.lastContactTime > p->lastContactTime)
			p->lastContactTime = candidateNode.lastContactTime;

		if (p->first_seen == 0)
			p->first_seen = candidateNode.first_seen;

		if (p->rtt == INT_MAX)
			p->rtt = candidateNode.rtt;
		else if (candidateNode.rtt != INT_MAX) {
			// sliding average. blend in the new RTT by one quarter
				p->rtt = (p->rtt * 3 + candidateNode.rtt) / 4;
		}
		if (pout) *pout = p;
		return false;
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
#if g_log_dht
		peer->origin = candidateNode.origin;
#endif
		memset(&peer->client, 0, sizeof(peer->client));
		pDhtImpl->_dht_peers_count++;
		bucketList.enqueue(peer);

#ifdef _DEBUG_DHT
		if (pDhtImpl->_dht_bootstrap == DhtImpl::valid_response_received && pDhtImpl->_bootstrap_log) {
			fprintf(pDhtImpl->_bootstrap_log, "[%u] nodes: %u\n"
				, uint(get_milliseconds() - pDhtImpl->_bootstrap_start)
				, pDhtImpl->_dht_peers_count);
		}
#endif

#if defined(_DEBUG_DHT)
		debug_log("Routing table num_nodes=%d", pDhtImpl->_dht_peers_count);
#endif
		if (pout) *pout = peer;
		return true;
	}

	if (pout) *pout = NULL;
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
bool DhtBucket::FindReplacementCandidate(DhtImpl* pDhtImpl
	, DhtPeer const& candidate, BucketListType bucketType
	, DhtPeer** pout)
{
	assert(pout);
	DhtBucketList &bucketList = (bucketType == peer_list) ? peers : replacement_peers;

	DhtPeer* replaceCandidate = NULL;

	// if there is an errored node in the list, search list for an errored node to return
	if (bucketList.listContainesAnErroredNode) {
		for (DhtPeer **peer = &bucketList.first(); *peer; peer=&(*peer)->next) {
			if ((*peer)->num_fail) {
				*pout = *peer;
				return true;
			}
		}
	}

	// if a node with the candidates sub-prefix already exists in the bucket
	if (bucketList.subPrefixMask & candidate.GetSubprefixPositionBit()) {
		int row = candidate.GetSubprefixInt();
		int numNodesWithSubPrefix = bucketList.subPrefixCounts[row];
		assert(numNodesWithSubPrefix > 0);
		// identify the node with the highest rtt
		for (int x=0; x<numNodesWithSubPrefix; ++x) {
			DhtPeer* p = bucketList.peerMatrix[row][x];
			if (replaceCandidate == NULL || p->rtt > replaceCandidate->rtt)
				replaceCandidate = p;
		}
		// if the rtt of the candidate node is not shorter than 1/2 the rtt of the node
		// identified for replacement, then it is not suitable to put in the list
		if (replaceCandidate && candidate.rtt > (replaceCandidate->rtt >> 1))
			return false;
	} else {
		// the sub-prefix is not represented in the bucket, but another one (or more) is
		// represented more than once (since the bucket is full).  Find the duplicate
		// with the highest rtt as the suitable node for replacement.
		for (int subPrefixIndex = 0; subPrefixIndex < KADEMLIA_BUCKET_SIZE; subPrefixIndex++) {
			if (bucketList.subPrefixCounts[subPrefixIndex] > 1) {
				for (int x=0; x<bucketList.subPrefixCounts[subPrefixIndex]; ++x) {
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

