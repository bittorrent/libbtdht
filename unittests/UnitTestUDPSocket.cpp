// these undef's needed for the google test framework
#undef _M_CEE_PURE
#undef new

#include "UnitTestUDPSocket.h"

// all this Send does is grab the bytes to be sent and put them into the vector
void UnitTestUDPSocket::Send(const SockAddr& dummyDest, const byte *p, size_t len, uint32 flags /* = 0 */)
{
	for(size_t x=0; x<len; ++x)
	{
		_dataBytes.push_back(p[x]);
	}
}

std::string UnitTestUDPSocket::GetSentDataAsString()
{
	std::string ReturnString;
	ReturnString.clear();

	for(unsigned int x=0; x < _dataBytes.size(); ++x)
	{
		ReturnString.push_back(_dataBytes[x]);
	}

	return ReturnString;
}
