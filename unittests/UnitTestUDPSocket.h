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
	std::vector<byte> _dataBytes;
	SockAddr _bind_addr;

public:
	UnitTestUDPSocket(){Reset();}
	virtual ~UnitTestUDPSocket(){}
	virtual void Send(const SockAddr& dest, const byte *p, size_t len, uint32 flags = 0);
	virtual void Send(const SockAddr& dest, cstr host, const byte *p, size_t len, uint32 flags = 0) { Send(dest, p, len, flags); };
	virtual const SockAddr &GetBindAddr( void ) const {return _bind_addr;}
	std::string GetSentDataAsString();
	std::vector<byte>& GetSentByteVector(){return _dataBytes;}
	void Reset(){_dataBytes.clear();}
	virtual void event(DWORD events){}
	virtual DWORD get_event_mask() const {return 0;}
	void SetBindAddr(SockAddr &bindAddr){_bind_addr = bindAddr;}

	// use Length() and [] to iterate through the bytes in a loop
	unsigned int Length(){return _dataBytes.size();}
	byte& operator[](int index){return _dataBytes[index];}
};

#endif // __UDPUNITTESTSOCKET_H__
