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

#ifndef __UDPUNITTESTSOCKET_H__
#define __UDPUNITTESTSOCKET_H__

#include "vector"
#include "string"

#include "udp_utils.h"
#include "utypes.h"

/// The UnitTestUDPSocket class is intended to just capture bytes (particularly bencoded strings) being
/// sent out for unit testing purposes.
class UnitTestUDPSocket : public UDPSocketInterface
{
private:
	std::vector<std::vector<byte> > _packets;
	SockAddr _bind_addr;

public:
	UnitTestUDPSocket(){Reset();}
	virtual ~UnitTestUDPSocket(){}
	virtual void Send(const SockAddr& dest, const byte *p, size_t len, uint32 flags = 0);
	virtual void Send(const SockAddr& dest, cstr host, const byte *p, size_t len, uint32 flags = 0) { Send(dest, p, len, flags); };
	virtual const SockAddr &GetBindAddr( void ) const {return _bind_addr;}
	std::string GetSentDataAsString(int i = -1);
	std::vector<byte> GetSentByteVector(int i = -1);
	void Reset() {_packets.clear(); }
	virtual void event(DWORD events) {}
	virtual DWORD get_event_mask() const {return 0;}
	void SetBindAddr(SockAddr &bindAddr){_bind_addr = bindAddr;}
	void popPacket();

	int numPackets() const { return _packets.size(); }

};

#endif // __UDPUNITTESTSOCKET_H__
