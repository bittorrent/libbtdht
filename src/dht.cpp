/**
 * @ingroup dht
 */

#include "DhtImpl.h"
#include "sockaddr.h"

IDht* create_dht(UDPSocketInterface *udp_socket_mgr, UDPSocketInterface *udp6_socket_mgr
	, DhtSaveCallback* save, DhtLoadCallback* load)
{
	return new DhtImpl(udp_socket_mgr, udp6_socket_mgr, save, load);
}

IDht::~IDht() {}

// See http://www.rasterbar.com/products/libtorrent/dht_sec.html
sha1_hash generate_node_id_prefix(const SockAddr& addr, int random, DhtSHACallback* sha)
{
	uint8 octets[9];
	int size;
	if (addr.isv6()) {
		// our external IPv6 address (network byte order)
		memcpy(octets, (uint const*)&addr._sin6d, 8);
		// If IPV6
		// 00000000 00000001 00000011 00000111 00001111 00011111 00111111 01111111
		const static uint8 mask[] = { 0x00, 0x01, 0x03, 0x07, 0x0f, 0x1f, 0x3f, 0x7f };
		for (int i = 0; i < 8; ++i) octets[i] &= mask[i];
		size = 8;
	} else {
		// our external IPv4 address (network byte order)
		memcpy(octets, (uint const*)&addr._sin4, 4);
		// If IPV4
		// 00000001 00000011 00001111 00111111
		const static uint8 mask[] = { 0x01, 0x07, 0x1f, 0x7f };
		for (int i = 0; i < 4; ++i) octets[i] &= mask[i];
		size = 4;
	}
	octets[size++] = random & 0x7;

	return sha((const byte*)octets, size);
}

// See http://www.rasterbar.com/products/libtorrent/dht_sec.html
bool DhtVerifyHardenedID(const SockAddr& addr, byte const* node_id, DhtSHACallback* sha)
{
	if (is_ip_local(addr)) return true;

	uint seed = node_id[19];
	sha1_hash digest = generate_node_id_prefix(addr, seed, sha);

	if (memcmp(digest.value, node_id, 4) != 0)
		return false; // failed verification
	else
		return true; // verification passed
}

// See http://www.rasterbar.com/products/libtorrent/dht_sec.html
void DhtCalculateHardenedID(const SockAddr& addr, byte *node_id, DhtSHACallback* sha)
{
	uint seed = rand() & 0xff;
	sha1_hash digest = generate_node_id_prefix(addr, seed, sha);

	for (int i = 0; i < 4; i++)
		node_id[i] = digest.value[i];
	for (int i = 4; i < 19; i++)
		node_id[i] = rand();
	node_id[19] = seed;
}


