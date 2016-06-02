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

// these undef's needed for the google test framework
#undef _M_CEE_PURE
#undef new

#include "UnitTestUDPSocket.h"

// all this Send does is grab the bytes to be sent and put them into the vector
void UnitTestUDPSocket::Send(const SockAddr& dummyDest, const byte *p, size_t len, uint32 flags /* = 0 */)
{
	_packets.push_back(std::vector<byte>(p, p + len));
}

// this pops the packets in reverse order of being sent
std::string UnitTestUDPSocket::GetSentDataAsString(int i)
{
	if (_packets.empty()) return std::string();

	if (i < 0) {
		std::string ret;
		for (int i = 0; i < _packets.size(); ++i)
			ret.insert(ret.end(), _packets[i].begin(), _packets[i].end());
		return ret;
	}
	assert(i < _packets.size());
	std::string ret(_packets[i].begin(), _packets[i].end());

#ifdef _DEBUG_DHT
	printf("\x1b[33mread packet (str) [%d]: \"", i);
	for (int i = 0; i < ret.size(); ++i)
		printf("%c", ret[i]);
	printf("\"\x1b[0m\n");
#endif

	return ret;
}

std::vector<byte> UnitTestUDPSocket::GetSentByteVector(int i)
{
	std::vector<byte> ret;
	if (_packets.empty()) return ret;

	if (i < 0) {
		std::vector<byte> ret;
		for (int i = 0; i < _packets.size(); ++i)
			ret.insert(ret.end(), _packets[i].begin(), _packets[i].end());
		return ret;
	}
	assert(i < _packets.size());
	ret = _packets[i];

#ifdef _DEBUG_DHT
	printf("\x1b[33mread packet (vec) [%d]: ", i);
	for (int i = 0; i < ret.size(); ++i)
		printf("%c", ret[i]);
	printf("\x1b[0m\n");
#endif

	return ret;
}

void UnitTestUDPSocket::popPacket()
{
	assert(!_packets.empty());
	_packets.erase(_packets.end()-1);
}

