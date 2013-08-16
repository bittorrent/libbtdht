#include "ExternalIPCounter.h"
#include "sockaddr.h" // for SockAddr, is_ip_local

#include <utility> // for std::make_pair
#include <time.h>

ExternalIPCounter::ExternalIPCounter(SHACallback* sha)
	: _winnerV4(_map.end()), _winnerV6(_map.end()), _HeatStarted(0)
	, _TotalVotes(0), _sha_callback(sha)
	, _last_votes4(0), _last_votes6(0)
{}

void ExternalIPCounter::Rotate()
{
	if (!IsExpired()) return;

	if (_winnerV4 != _map.end()) {
		_last_winner4 = _winnerV4->first;
		_last_votes4 = _winnerV4->second;
	}
	if (_winnerV6 != _map.end()) {
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

void ExternalIPCounter::CountIP( const SockAddr& addr ) {

	// ignore anyone who claims our external IP is
	// INADDR_ANY or on a local network
	if(addr.is_addr_any() || is_ip_local(addr))
		return;

	// timestamp the first time we get a vote
	if(! _HeatStarted)
		_HeatStarted = time(NULL);

	Rotate();

	// attempt to insert this vote
	std::pair<candidate_map::iterator, bool> inserted = _map.insert(std::make_pair(addr, 1));

	// if the new IP wasn't inserted, it's already in there
	// increase the vote counter
	if (!inserted.second)
		inserted.first->second++;

	// if the IP vout count exceeds the current leader, replace it
	if(addr.isv4() && (_winnerV4 == _map.end() || inserted.first->second > _winnerV4->second))
		_winnerV4 = inserted.first;
	if(addr.isv6() && (_winnerV6 == _map.end() || inserted.first->second > _winnerV6->second))
		_winnerV6 = inserted.first;
	_TotalVotes++;
}

void ExternalIPCounter::CountIP( const SockAddr& addr, const SockAddr& voter ) {
	// Don't let local peers vote on our IP address
	if (is_ip_local(voter))
		return;

	Rotate();

	// Accept an empty voter address.
	if ( ! voter.is_addr_any() ) {
		// TODO: we should support IPv6 voters as well
		// If voter is in bloom filter, return
		uint32 addr = voter.get_addr4();
		sha1_hash key = _sha_callback((const byte*)&addr, 4);

		if (_voterFilter.test(key))
			return;
		_voterFilter.add(key);
	}
	CountIP(addr);
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
	if((_HeatStarted + EXTERNAL_IP_HEAT_DURATION) > time(NULL)) return false;
	return (_TotalVotes > EXTERNAL_IP_HEAT_MAX_VOTES)?true:false;
}

