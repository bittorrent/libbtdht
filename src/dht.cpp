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

/**
 * @ingroup dht
 */

#include "DhtImpl.h"
#include "sockaddr.h"
#include "utypes.h"

extern uint32 crc32c(const unsigned char* buf, uint32 len=4);

smart_ptr<IDht> create_dht(UDPSocketInterface *udp_socket_mgr, UDPSocketInterface *udp6_socket_mgr
	, DhtSaveCallback* save, DhtLoadCallback* load, ExternalIPCounter* eip)
{
	return smart_ptr<IDht>(new DhtImpl(udp_socket_mgr, udp6_socket_mgr, save, load, eip));
}

IDht::~IDht() {}

// See http://www.rasterbar.com/products/libtorrent/dht_sec.html
uint32 generate_node_id_prefix(const SockAddr& addr, int random)
{
	uint8 octets[8];
	uint32 size;
	if (addr.isv6()) {
		// our external IPv6 address (network byte order)
		memcpy(octets, (uint const*)&addr._sin6d, 8);
		// If IPV6
		const static uint8 mask[] = { 0x01, 0x03, 0x07, 0x0f, 0x1f, 0x3f, 0x7f, 0xff };
		for (int i = 0; i < 8; ++i) octets[i] &= mask[i];
		size = 8;
	} else {
		// our external IPv4 address (network byte order)
		memcpy(octets, (uint const*)&addr._sin4, 4);
		// If IPV4
		// 00000011 00001111 00111111 11111111
		const static uint8 mask[] = { 0x03, 0x0f, 0x3f, 0xff };
		for (int i = 0; i < 4; ++i) octets[i] &= mask[i];
		size = 4;
	}
	octets[0] |= (random<<5) & 0xff;

	return crc32c((const unsigned char*)octets, size);
}

// See http://www.rasterbar.com/products/libtorrent/dht_sec.html
bool DhtVerifyHardenedID(const SockAddr& addr, byte const* node_id)
{
	if (is_ip_local(addr)) return true;
	uint seed = node_id[19];
	uint32 crc32_hash = generate_node_id_prefix(addr, seed);
//compare the first 21 bits only, so keep bits 17 to 21 only.
	byte from_hash = static_cast<byte>((crc32_hash >> 8) & 0xff);
	byte from_node = node_id[2] ;
	return node_id[0] == static_cast<byte>((crc32_hash >> 24) & 0xff) &&
		node_id[1] == static_cast<byte>((crc32_hash >> 16) & 0xff) &&
		(from_hash & 0xf8) == (from_node & 0xf8);
}

// See http://www.rasterbar.com/products/libtorrent/dht_sec.html
void DhtCalculateHardenedID(const SockAddr& addr, byte *node_id)
{
	uint seed = rand() & 0xff;
	uint32 crc32_hash = generate_node_id_prefix(addr, seed);
	node_id[0] = static_cast<byte>((crc32_hash >> 24) & 0xff);
	node_id[1] = static_cast<byte>((crc32_hash >> 16) & 0xff);
	node_id[2] = static_cast<byte>((crc32_hash >> 8) & 0xff);
	//need to change all bits except the first 5, xor randomizes the rest of the bits
	node_id[2] ^= static_cast<byte>(rand() & 0x7);
	for (int i = 3; i < 19; i++)
		node_id[i] = static_cast<byte>(rand() & 0xff);
	node_id[19] = static_cast<byte>(seed);
}


