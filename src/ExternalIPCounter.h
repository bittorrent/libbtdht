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

#ifndef __EXTERNAL_IP_COUNTER_H__
#define __EXTERNAL_IP_COUNTER_H__

// A voting heat ends after the max number of votes have
// been counted or the heat duration (in seconds) expires,
// whichever comes last
#define EXTERNAL_IP_HEAT_DURATION	600	// 10 minutes
#define EXTERNAL_IP_HEAT_MAX_VOTES	50

#include <map>
#include "sockaddr.h"
#include "bloom_filter.h"

// allows the dht client to define what SHA-1 implementation to use
typedef sha1_hash SHACallback(byte const* buf, int len);

struct ip_change_observer {
	virtual ~ip_change_observer() {}
	virtual void on_ip_change(SockAddr const & new_ip) = 0;
};

class ExternalIPCounter
{
public:
	ExternalIPCounter(SHACallback* sha);
	void set_ip_change_observer(ip_change_observer * ip_observer){_ip_change_observer = ip_observer;}
	void CountIP( const SockAddr& addr, const SockAddr& voter, int weight = 1);
	void CountIP( const SockAddr& addr, int weight = 1 );
	bool GetIP( SockAddr& addr ) const;
	bool GetIPv4( SockAddr& addr ) const;
	bool GetIPv6( SockAddr& addr ) const;

	void SetHeatStarted(time_t t) { _HeatStarted = t; }

	void NetworkChanged();

	void Reset();

private:
	void Rotate();
	bool IsExpired() const;

	typedef std::map<SockAddr, int> candidate_map;

	candidate_map _map;
	candidate_map::const_iterator _winnerV4;
	candidate_map::const_iterator _winnerV6;
	bloom_filter _voterFilter;
	time_t _HeatStarted;
	int _TotalVotes;

	SockAddr _last_winner4;
	SockAddr _last_winner6;
	int _last_votes4;
	int _last_votes6;
	ip_change_observer * _ip_change_observer;
	SHACallback* _sha_callback;
};


#endif //__EXTERNAL_IP_COUNTER_H__
