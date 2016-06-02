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

#include "ExternalIPCounter.h"
#include "sockaddr.h" // for SockAddr, is_ip_local

#include <utility> // for std::make_pair
#include <time.h>

ExternalIPCounter::ExternalIPCounter(SHACallback* sha)
	: _winnerV4(_map.end()), _winnerV6(_map.end()), _HeatStarted(0)
	, _TotalVotes(0)
	, _last_votes4(0)
	, _last_votes6(0)
	, _ip_change_observer(NULL)
	, _sha_callback(sha)
{}

void ExternalIPCounter::Rotate()
{
	if (!IsExpired()) return;

	if (_winnerV4 != _map.end()) {
		byte ip_winner[4];
		byte last_winner[4];
		_winnerV4->first.compact(ip_winner, false);
		_last_winner4.compact(last_winner, false);
		// don't invoke the observer if last_votes is zero, that means this is the first
		// IP we've seen
		if(_last_votes4 && memcmp(ip_winner, last_winner, 4) && _ip_change_observer){
			_ip_change_observer->on_ip_change(_winnerV4->first);
		}
		_last_winner4 = _winnerV4->first;
		_last_votes4 = _winnerV4->second;
	}
	if (_winnerV6 != _map.end()) {
		byte ip_winner[16];
		byte last_winner[16];
		_winnerV6->first.compact(ip_winner, false);
		_last_winner6.compact(last_winner, false);
		if(_last_votes6 && memcmp(ip_winner, last_winner, 16) && _ip_change_observer){
			_ip_change_observer->on_ip_change(_winnerV6->first);
		}
		_last_winner6 = _winnerV6->first;
		_last_votes6 = _winnerV6->second;
	}

	_map.clear();
	_winnerV6 = _map.end();
	_winnerV4 = _map.end();
	_HeatStarted = time(NULL);
	_TotalVotes = 0;
	_voterFilter.clear();
}

void ExternalIPCounter::NetworkChanged()
{
	// Force a rotation after the next vote
	_TotalVotes = EXTERNAL_IP_HEAT_MAX_VOTES;
	// Our IP likely changed so give minimal weight to previous votes
	for (auto& m : _map)
		m.second = 1;
	// peers who already voted may have legitmatly changed their vote
	// so don't filter them
	_voterFilter.clear();
}

void ExternalIPCounter::Reset()
{
       _TotalVotes = 0;
       _last_votes4 = _last_votes6 = 0;
       _map.clear();
       _winnerV6 = _map.end();
       _winnerV4 = _map.end();
       _HeatStarted = time(NULL);
       _voterFilter.clear();
       memset(&_last_winner4, 0, sizeof(SockAddr));
       memset(&_last_winner6, 0, sizeof(SockAddr));
}

void ExternalIPCounter::CountIP( const SockAddr& addr, int weight ) {
	// ignore anyone who claims our external IP is
	// INADDR_ANY or on a local network
	if(addr.is_addr_any() || is_ip_local(addr))
		return;

	// timestamp the first time we get a vote
	if(! _HeatStarted)
		_HeatStarted = time(NULL);

	// attempt to insert this vote
	std::pair<candidate_map::iterator, bool> inserted = _map.insert(std::make_pair(addr, weight));

	// if the new IP wasn't inserted, it's already in there
	// increase the vote counter
	if (!inserted.second)
		inserted.first->second += weight;

	// if the IP vout count exceeds the current leader, replace it
	if(addr.isv4() && (_winnerV4 == _map.end() || inserted.first->second > _winnerV4->second))
		_winnerV4 = inserted.first;
	if(addr.isv6() && (_winnerV6 == _map.end() || inserted.first->second > _winnerV6->second))
		_winnerV6 = inserted.first;
	_TotalVotes += weight;

	Rotate();
}

void ExternalIPCounter::CountIP( const SockAddr& addr, const SockAddr& voter, int weight ) {
	// Don't let local peers vote on our IP address

	if (is_ip_local(voter))
		return;

	// Accept an empty voter address.
	if ( ! voter.is_addr_any() ) {
		// TODO: we should support IPv6 voters as well
		// If voter is in bloom filter, return
		uint32 vaddr = voter.get_addr4();
		sha1_hash key = _sha_callback((const byte*)&vaddr, 4);

		if (_voterFilter.test(key))
			return;
		_voterFilter.add(key);
	}
	CountIP(addr, weight);
}

bool ExternalIPCounter::GetIP(SockAddr &addr) const {

	if (_last_votes4 >= _last_votes6 && _last_votes4 > 0) {
		addr = _last_winner4;
		return true;
	} else if (_last_votes6 > _last_votes4 && _last_votes6 > 0) {
		addr = _last_winner6;
		return true;
	}

	if (_winnerV4 != _map.end()) {
		if(_winnerV6 != _map.end() && _winnerV6->second > _winnerV4->second) {
			addr = _winnerV6->first;
		} else {
			addr = _winnerV4->first;
		}
		return true;
	}
	if (_winnerV6 != _map.end()) {
		addr = _winnerV6->first;
		return true;
	}
	return false;
}

bool ExternalIPCounter::GetIPv4(SockAddr &addr) const {
	if (!_last_winner4.is_addr_any()) {
		addr = _last_winner4;
		return true;
	}

	if(_winnerV4 != _map.end()) {
		addr = _winnerV4->first;
		return true;
	}
	return false;
}

bool ExternalIPCounter::GetIPv6(SockAddr &addr) const {
	if (!_last_winner6.is_addr_any()) {
		addr = _last_winner6;
		return true;
	}

	if(_winnerV6 != _map.end()) {
		addr = _winnerV6->first;
		return true;
	}
	return false;
}

// both thresholds must be crossed (time and count)
bool ExternalIPCounter::IsExpired() const {
	if(!_HeatStarted) return false;
	if(_TotalVotes > EXTERNAL_IP_HEAT_MAX_VOTES ||
		(_HeatStarted + EXTERNAL_IP_HEAT_DURATION) < time(NULL))
		return true;
	return false;

}

