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

#ifndef __DHT_IMPL_H__
#define __DHT_IMPL_H__

#include "dht.h"
#include <climits>
#include <assert.h> // for assert
#include <time.h> // for time_t
#include <string.h> // for memcmp
#include <vector>
#include <map>
#include <set>
#include <string>
#include <array>
#include <algorithm> // for min_element
#include <stdarg.h> // for va_start etc.

#include "smart_ptr.h" // for smart_ptr
#include "blockallocator.h"
#include "Buffer.h"
#include "DHTMessage.h"
#include "utypes.h"
#include "bloom_filter.h"
#include "tailqueue.h"
#include "get_microseconds.h"

#if defined(_DEBUG_DHT_VERBOSE) && !defined _DEBUG_DHT
#define _DEBUG_DHT
#endif

// for logging dht activity
#if g_log_dht

void dht_log(char const* fmt, ...);

#else // g_log_dht

inline void dht_log(char const* fmt, ...) {}

#endif // g_log_dht

class BencEntity;
class DhtImpl;
class DhtID;

void CopyBytesToDhtID(DhtID &id, const byte *b);

//--------------------------------------------------------------------------------
//
// Types used by DhtImpl
//
//--------------------------------------------------------------------------------

class DhtID
{
public:
	DhtID(){ memset(id, 0, sizeof(id));}
	DhtID(sha1_hash const& hash)
	{
		CopyBytesToDhtID(*this, hash.value);
	}

	uint32 id[DHT_ID_WORDCOUNT];

	unsigned int GetBit(unsigned int index);

	DhtID& operator=(sha1_hash const& lhs)
	{
		CopyBytesToDhtID(*this, lhs.value);
		return *this;
	}

	bool operator <(const DhtID &n) const {
		for(uint i=0; i<DHT_ID_WORDCOUNT; i++) {
			if (id[i] > n.id[i]) return false;
			if (id[i] < n.id[i]) return true;
		}
		return false;
	}

	bool operator ==(const DhtID &n) const {
		return memcmp(id, n.id, DHT_ID_SIZE) == 0;
	}

	bool operator !=(const DhtID &n) const {
		return memcmp(id, n.id, DHT_ID_SIZE) != 0;
	}
};

const char *format_dht_id(const DhtID &id);

/**
 Returns the bit at bitIndex.  id[0] contains the upper most bits and
 id[4] containes the lowest bits in the 160 bit string
*/
inline unsigned int DhtID::GetBit(unsigned int bitIndex)
{
	assert(bitIndex < 160);
	// divide by 32 and invert
	unsigned int wordIndex = (DHT_ID_WORDCOUNT-1) - (bitIndex >> DHT_ID_WORDCOUNT);
	return (id[wordIndex] >> (bitIndex & 0x1f)) & 0x00000001;
}

int CompareDhtIDToTarget(const DhtID &a, const DhtID &b, const DhtID &target);
int CompareDhtID(const DhtID &a, const DhtID &b);
int CompareDhtIDBytes(const DhtID &a, const DhtID &b, int num);
void DhtIDToBytes(byte *b, const DhtID &id);

struct StoredPeer {
	byte ip[4];
	byte port[2];
	bool seed:1;
	time_t time;
};

class DhtPeerID
{
public:
	DhtID id;
	SockAddr addr;

	unsigned int GetIdBit(unsigned int index);

	bool operator ==(const DhtPeerID &p) const {
		return addr == p.addr && (p.id == id);
	}

	bool operator !=(const DhtPeerID &p) const {
		return addr != p.addr || (p.id != id);
	}
};

inline unsigned int DhtPeerID::GetIdBit(unsigned int index)
{
	return id.GetBit(index);
}


struct DHTPackedPeer {
	byte ip[4];
	byte port[2];
};


struct ClientID {
	char client[2];
	uint16 ver;

	const char* str() const;
	void from_compact(byte *b, size_t len);
	ClientID & operator =(const ClientID &c);
	bool operator ==(const ClientID &c) const;
};

// Note: Operator = is called due to MoveUpLast
const int MAX_FILE_NAME_LENGTH = 128;
struct StoredContainer {
	StoredContainer() : file_name(NULL) {}
	~StoredContainer() {}
	DhtID info_hash;
	std::vector<StoredPeer> peers;
	char* file_name;

	bool operator <(const StoredContainer& sc) const {
		return info_hash < sc.info_hash;
	}
};

struct VoteContainer {
	VoteContainer(): last_use(time(NULL)) { memset(num_votes, 0, sizeof(num_votes)); }
	DhtID key;
	bloom_filter votes[5];
	int num_votes[5];
	time_t last_use;

	bool operator <(const VoteContainer& sc) const {
		return key < sc.key;
	}
};

// TODO: this should live in its own header
class smart_buffer {
	unsigned char* buffer;
	unsigned char* start;
	unsigned char* end;

public:
	smart_buffer(unsigned char* buffer, int64 len) :
		buffer(buffer), start(buffer), end(buffer + len) {}
	smart_buffer& operator() (char const* fmt, ...) {

		assert(buffer < end);
		if (buffer >= end) return *this;

		va_list list;
		va_start(list, fmt);
		int64 written = vsnprintf(reinterpret_cast<char*>(buffer), end - buffer,
				fmt, list);
		// if we fuck up formatting, vsnprintf will return a negative value
		assert(written >= 0);
		if (written >= 0) {
			buffer += written;
		} else {
			buffer = end;
		}
		va_end(list);
		return *this;
	}

	// It's critical that this overload is distinct from the format string
	// overload. Otherwise they are too similar and error prone
	smart_buffer& operator() (size_t len, unsigned char const* value) {
		assert(buffer + len < end);
		if (buffer + len >= end) return *this;

		memcpy(buffer, value, len);
		buffer += len;
		return *this;
	}
	smart_buffer& operator() (DhtID const& value) {
		assert(buffer < end);
		if (buffer >= end) return *this;

		assert(buffer + DHT_ID_SIZE <= end);
		if (buffer + DHT_ID_SIZE > end) return *this;

		DhtIDToBytes(buffer, value);
		buffer += DHT_ID_SIZE;
		return *this;
	}
	smart_buffer& operator() (SockAddr const& value) {
		int value_size = value.isv4() ? 6 : 18;
		assert(buffer < end);
		if (buffer >= end) return *this;

		assert(buffer + value_size <= end);
		if (buffer + value_size > end) return *this;

		value.compact(buffer, true);

		buffer += value_size;
		return *this;
	}
	smart_buffer& operator() (Buffer const& value) {
		return (*this)(value.len, value.b);
	}
	template <size_t N>
	smart_buffer& operator() (std::array<char, N> const& value) {
		return (*this)(N, (byte const*)value.data());
	}
	template <size_t N>
	smart_buffer& operator() (std::array<unsigned char, N> const& value) {
		return (*this)(N, (byte const*)value.data());
	}
	smart_buffer& operator() (std::string const& value) {
		return (*this)(value.size(), (byte const*)&value[0]);
	}

	unsigned char const * begin() const {
		return start;
	}
	int64 length() const { return buffer < end ? buffer - start : -1; }
	int get_pos() const { return buffer - start; }
	void restore_pos(int pos)
	{
		assert(pos >= 0);
		assert(pos < length());
		buffer = start + pos;
	}
};

/*******************************************************************************

 PairContainerBase

*****************************************************************************/
template<typename DataType>
class PairContainerBase
{
private:
	bloom_filter _bf;
	unsigned int previousBfCount;

public:
	DataType value;
	time_t lastUse;

	bool operator==(PairContainerBase const& lhs) const
	{ return value == lhs.value; }

	PairContainerBase();
	PairContainerBase(DataType const& valueIn, time_t time=0);
	virtual ~PairContainerBase(){}
	void UpdateUsage(const sha1_hash &idHash, time_t currentTime);
	void CycleUsage();
	unsigned int GetUsageMeasure() const;
};

template<typename DataType>
inline PairContainerBase<DataType>::PairContainerBase()
	: previousBfCount(0)
	, lastUse(0)
{}

template<typename DataType>
inline PairContainerBase<DataType>::PairContainerBase(DataType const& valueIn, time_t time)
	: value(valueIn)
	, previousBfCount(0)
	, lastUse(time)
{}

/**
 A bloom filter (_bf) is associated with the data for the purpose of determining
 the interest users have in the data.  This bloom filter is updated with a hash
 each time UpdateUsage() is invoked on the element.  Also, the last update time
 is recorded (as provided by the consumer).

 Related member funcitons:  GetUsageMeasure(), CycleUsage()
*/
template<typename DataType>
inline void PairContainerBase<DataType>::UpdateUsage(const sha1_hash &idHash, time_t currentTime)
{
	_bf.add(idHash);
	lastUse = currentTime;
}

/**
 One level of bloom filter history is maintained for a data item.  Invoking this member
 function records the estimated count provided by the bloom filter in its current
 state.  The bloom filter is then cleared to start recording fresh id hashes as
 UpdateUsage() is invoked.

 Related member funcitons:  UpdateUsage(), GetUsageMeasure()
*/
template<typename DataType>
void PairContainerBase<DataType>::CycleUsage()
{
	previousBfCount = (unsigned int)_bf.estimate_count();
	_bf.clear();
}

/**
 If there is a history (if previousBfCount is not 0) then a measure that is
 a blend of the current count and the historical count is returned.  If there
 is no history, then the current count is returned

 Related member funcitons:  UpdateUsage(), CycleUsage()
*/
template<typename DataType>
unsigned int PairContainerBase<DataType>::GetUsageMeasure() const
{
	return (previousBfCount) ? previousBfCount + ((unsigned int)_bf.estimate_count() >> 1) : (unsigned int)_bf.estimate_count();
}


// *****************************************************************************
enum ItemStatus
{	NEW_ITEM,
	PREEXISTING_ITEM
};
// *****************************************************************************
/**

 DataStore

 This is a generic key value list.  Keys are inserted in order and retrieved
 using a binary search.

 This object also provides two approaches to removing items from the list that
 work in conjunction with information stored with each item by PairContainerBase
 class:

 1) EliminateTimeouts() to remove items that are unused beyond a time limit
 2) DoEvict() to remove items that are least used when the list is full

 EliminateTimeouts() is given the current time and scans the entire list for items
 that are older than the maximum age allowed.  Those items are erased from the list.
 This is primarily intended to be used by the UpdateUsage() member function.

 EvictLeastUsed() uses the bloom filter history of items to determine their popularity.
 Items with higher estimated counts are retained.  A single item with the lowest
 estimated count is eliminated.

 UpdateUsage() is intended to be invoked periodically with the current time.  It will
 invoke EliminateTimeouts() to remove items that have not been accessed within the
 timeout period (stored in _maximumAge).  It will also cycle the bloom filters
 of the data items if the _updateInterval has been met or exceded.  This member
 function should probably be called from the dht's Tick() function.

 See also: PairContainerBase::UpdateUsage(), PairContainerBase::CycleUsage(), and
 PairContainerBase::GetUsageMeasure()

*/
template<typename KeyType, typename DataType>
class DataStore
{
private:
	unsigned int _maximumAge; // in seconds
	unsigned int _maxSize;

	unsigned int _updateInterval;
	time_t _lastUpdateTime;

public:
	DataStore(unsigned int maximumAge = 7200, const time_t currentTime = 0, unsigned int maxSize = 1000);

	std::map<KeyType, PairContainerBase<DataType> > pair_list;
	typedef typename std::map<KeyType, PairContainerBase<DataType> >::iterator pair_iterator;
	pair_iterator end() { return pair_list.end(); }

	pair_iterator FindInList(const KeyType &key, const time_t currentTime, const sha1_hash &idHash);

	ItemStatus AddPairToList(const sha1_hash &idHash, const KeyType &keyIn, const DataType &valueIn
		, PairContainerBase<DataType>** containerOut, const time_t currentTime = 0);
	ItemStatus AddKeyToList(const sha1_hash &idHash, const KeyType &keyIn
		, PairContainerBase<DataType>** containerOut, const time_t currentTime = 0);

	int EvictLeastUsed();
	void UpdateUsage(time_t currentTime);
	int EliminateTimeouts(time_t currentTime);
	int RemoveItem(const KeyType &keyToRemove);

	void SetCurrentTime(const time_t currentTime){_lastUpdateTime = currentTime;}
	void SetMaximumAge(const unsigned int maximumAge){_maximumAge = maximumAge; _updateInterval = maximumAge >> 1;}
	unsigned int GetMaximumAge(){return _maximumAge;}
	void SetMaximumSize(unsigned int maxSize){_maxSize = maxSize;}
	unsigned int GetMaximumSize(){return _maxSize;}
};

template<typename KeyType, typename DataType>
DataStore<KeyType, DataType>::DataStore(unsigned int maximumAge, const time_t currentTime, unsigned int maxSize)
{
	_maximumAge = maximumAge;
	_updateInterval = maximumAge >> 1; // set the update interval to be half of the maximum age
	_lastUpdateTime = currentTime;
	_maxSize = maxSize;
}

template <typename K, typename T>
bool compare_usage(std::pair<K, PairContainerBase<T> > const& lhs, std::pair<K, PairContainerBase<T> > const& rhs)
{
	return lhs.second.GetUsageMeasure() < rhs.second.GetUsageMeasure();
};

/** 
 Determine an item with the lowest measure of interest and remove it.  Interest is
 measured by the number of different hashId's (typically a hash of the IP address)
 that have requested the item as estimated by a bloom filter.

 EvictLeastUsed will only search the list to determine an evictee if the list is full
 (at maxSize).  Otherwise there are still space available for new items to be added
 and there is no need to perform the search.  Unused items should be removed
 by using EliminateTimeouts() member function.

Note:  See the note concerning std::vector::erase() described for EliminateTimeouts().
*/
template<typename KeyType, typename DataType>
int DataStore<KeyType, DataType>::EvictLeastUsed()
{
	// nothing to do (the list is either empty or less than full)
	if (pair_list.size() < _maxSize || pair_list.empty())
		return 0;

	pair_iterator i = std::min_element(pair_list.begin(), pair_list.end(), &compare_usage<KeyType, DataType>);

	pair_list.erase(i);
	return 1;
}

/**
 UpdateUsage() is intended to be invoked periodically with the current time.  It will
 invoke EliminateTimeouts() to remove items that have not been accessed within the
 timeout period (stored in _maximumAge).  It will also cycle the bloom filters
 of the data items if the _updateInterval has been met or exceded.  This member
 function should probably be called from the dht's Tick() function.
*/
template<typename KeyType, typename DataType>
void DataStore<KeyType, DataType>::UpdateUsage(time_t currentTime)
{
	// get rid of items that are older than max age allows
	EliminateTimeouts(currentTime);

	// cycle the usage remaining items
	if ((currentTime - _lastUpdateTime) > _updateInterval){
		_lastUpdateTime = currentTime;
		for (pair_iterator i = pair_list.begin(); i != pair_list.end(); ++i) {
			i->second.CycleUsage();
		}
	}
}

/**
 Remove any items with an age greater than the maximum age allowed.

 Note:
 The std::vector class implimentation of erase() has an optimization that makes it
 unsuitable to use (if erasing a single item, it just moves the item at the end
 of the std::vector list to the position of the item being erased - thus corrupting
 the order of the list (i.e. the largest element at the end of the list is moved
 to a position not at the end of the list)).  So, a single pass solution is
 implemented here.
*/
template<typename KeyType, typename DataType>
int DataStore<KeyType, DataType>::EliminateTimeouts(time_t currentTime)
{
	int n = 0;

	for (pair_iterator i = pair_list.begin(); i != pair_list.end();)
	{
		if (currentTime - i->second.lastUse <= _maximumAge)
		{
			++i;
			continue;
		}
		pair_list.erase(i++);
		++n;
	}

	return n;
}

/**
 Removes the item with the key value of keyToRemove from the list.
*/
template<typename KeyType, typename DataType>
int DataStore<KeyType, DataType>::RemoveItem(const KeyType &keyToRemove)
{
	if (pair_list.empty())
		return 0; // empty list; nothing to do

	// look for the item with the key
	pair_iterator i = pair_list.find(keyToRemove);
	if (i == pair_list.end()) return 0;
	pair_list.erase(i);
	return 1;
}

/**
Retrieve an iterator to the entry for key.
If key is not found, the end() iterator is returned.
*/
template<typename KeyType, typename DataType>
inline typename DataStore<KeyType, DataType>::pair_iterator DataStore<KeyType, DataType>::FindInList(
	const KeyType &key, const time_t currentTime, const sha1_hash &idHash)
{
	pair_iterator ret = pair_list.find(key);
	if(ret != pair_list.end())
		ret->second.UpdateUsage(idHash, currentTime);

	return ret;
}

/**
Add a key and value pair to the list.  If the key is already in the list, a pointer to
that pair is placed in the containerOut argument and no data is copied.  Otherwise,
a new entry is inserted, the key and value assigned/copied to it, and the pointer
to that entry is placed in the containerOut argument.

@return ItemStatus
  NEW_ITEM if a new entry is created and added to the store
  PREEXISTING_ITEM if the entry was found in the store
*/

template<typename KeyType, typename DataType>
ItemStatus DataStore<KeyType, DataType>::AddPairToList(const sha1_hash &idHash, const KeyType &keyIn
	, const DataType &valueIn, PairContainerBase<DataType>** containerOut, time_t currentTime)
{
	ItemStatus returnStatus;

	pair_iterator i = pair_list.find(keyIn);
	PairContainerBase<DataType>* found = NULL;

	// do we have this key in the list, if so return a pointer to the entry
	if (i != pair_list.end()) {
		found = &i->second;
		returnStatus = PREEXISTING_ITEM;
	} else {
		// the key is not in the list, put a container there
		// if the list is full, evict something first
		if (pair_list.size() >= _maxSize)
			EvictLeastUsed();

		std::pair<pair_iterator, bool> ret = pair_list.insert(std::make_pair(keyIn, PairContainerBase<DataType>()));
		i = ret.first;
		i->second.value = valueIn;
		found = &i->second;
		returnStatus = NEW_ITEM;
	}

	*containerOut = found;

	// update the time
	found->UpdateUsage(idHash, currentTime);
	return returnStatus;
}
/**

Adds a default constructed value under the specified key to the list.
If the key is already in the list, a pointer to
that pair is placed in the containerOut argument and no data is copied.

value element is not assigned.  If the key was
found in the list, then PREEXISTING_ITEM is returned.  If a new container was added,
NEW_ITEM is returned.  In either case, a pointer to the container with the key is
assigned to the containerOut argument.
*/
template<typename KeyType, typename DataType>
ItemStatus DataStore<KeyType, DataType>::AddKeyToList(const sha1_hash &idHash
	, const KeyType &keyIn
	, PairContainerBase<DataType>** containerOut
	, const time_t currentTime)
{
	ItemStatus returnStatus;
	PairContainerBase<DataType>* found = NULL;

	pair_iterator i = pair_list.find(keyIn);

	// do we have this key in the list, if so return a pointer to the entry
	if (i != pair_list.end()) {
		found = &i->second;
		returnStatus = PREEXISTING_ITEM;
	} else {
		// the key is not in the list, put a container there
		// if the list is full, evict something first
		if (pair_list.size() >= _maxSize)
			EvictLeastUsed();

		std::pair<pair_iterator, bool> ret = pair_list.insert(std::make_pair(keyIn, PairContainerBase<DataType>()));
		i = ret.first;
		found = &i->second;
		returnStatus = NEW_ITEM;
	}

	*containerOut = found;

	// update the time
	found->UpdateUsage(idHash, currentTime);

	return returnStatus;
}

// *****************************************************************************
/**
MutableData

This simple struct collects the information from a mutable put rpc.

*/
// *****************************************************************************
struct MutableData
{
	int64 sequenceNum;
	// ed25519 signatire
	byte signature[64];
	// ed25519 key
	byte key[32];
	std::vector<byte> v;
};


// stores information for a peer
class DhtPeer
{
private:
	int subPrefixInt;
	int subPrefixPositionBit;

public:
	// node ID and address
	DhtPeerID id;

	// Number of failed RPCs
	byte num_fail;

	// time of last contact with this peer
	// lastContactTime may be 0, in case we have not contacted this node yet
	time_t lastContactTime;

	// round trip time of this node. This is
	// a sliding average. Every time we hear from this
	// node we update our understanding of its RTT.
	// this is used to prioritize nodes with low RTT,
	// to speed up lookups
	// if this is INT_MAX, it means we don't know its RTT yet
	int rtt;

	// the time we've first seen this node. This can be
	// used for a "quarantine", where we don't forward this
	// node to others until we trust it more, i.e. have talked
	// to it again some time after the first time we saw it.
	// first_seen may be 0, in case we have not contacted this node yet
	time_t first_seen;

	ClientID client;
	DhtPeer *next;

	void ComputeSubPrefix(unsigned int bucketSpan, unsigned int numSubPrefixBits);
	int GetSubprefixInt() const {return subPrefixInt;}
	int GetSubprefixPositionBit() const {return subPrefixPositionBit;}
	void CopyAllButNext(const DhtPeer &src);

#if g_log_dht
	uint origin;
#endif

	DhtPeer()
		: subPrefixInt(0)
		, subPrefixPositionBit(0)
		, num_fail(0)
		, lastContactTime(0)
		, rtt(INT_MAX)
		, first_seen(0)
		, next(NULL)
#if g_log_dht
		, origin(0)
#endif
	{}
};

/**
	Performs a memberwise copy from replaceNode to nodeToReplace.  NOTE:  the 'next' member
	pointer is NOT copied.  This allows the function to work directly with elements in
	the linked lists of the bucket without corrupting the list chain.
*/
inline void DhtPeer::CopyAllButNext(const DhtPeer &src)
{
	subPrefixInt = src.subPrefixInt;
	subPrefixPositionBit = src.subPrefixPositionBit;
	id = src.id;
	num_fail = src.num_fail;
	lastContactTime = src.lastContactTime;
	rtt = src.rtt;
	first_seen = src.first_seen;
	client = src.client;
#if g_log_dht
	origin = src.origin;
#endif
}


enum DhtProcessFlags
{
	EMPTY           = 0x00,
	NORMAL_RESPONSE = 0x01,
	PROCESS_AS_SLOW = 0x02,
	ICMP_ERROR      = 0x04,
	TIMEOUT_ERROR   = 0x08,
	ANY_ERROR       = ICMP_ERROR | TIMEOUT_ERROR
};

struct DhtRequest;

/**
 This is used by DhtProcessBase type callbacks stored in the DhtImpl's request table and
 tied to a transaction ID

 Typically used with OnReply()
*/

// TODO: this is most likely a redundant interface. look for ways to remove it
// to simplify the code. This goes for DhtRequestListener also
class IDhtRequestListener
{
public:
	virtual ~IDhtRequestListener(){}
	virtual void Callback(const DhtPeerID &peer_id, DhtRequest *req, DHTMessage &message, DhtProcessFlags flags) = 0;
};

/**
This is all so that different classes can register for the same callbacks
from DhtRequest.
*/
template <typename T> class DhtRequestListener : public IDhtRequestListener
{
public:
	typedef void (T::*ReplyCallback)(void*& userdata, const DhtPeerID &peer_id, DhtRequest *req, DHTMessage &message, DhtProcessFlags flags);

	DhtRequestListener(T * listener, ReplyCallback callback):_pListener(listener), _pCallback(callback), _userdata(NULL){}
	DhtRequestListener(T * listener, ReplyCallback callback, void *userdata):_pListener(listener), _pCallback(callback), _userdata(userdata){}

	virtual void Callback(const DhtPeerID &peer_id, DhtRequest *req, DHTMessage &message, DhtProcessFlags flags)
	{
		(_pListener->* _pCallback)(_userdata, peer_id, req, message, flags);
	}
protected:

	T *_pListener;
	ReplyCallback _pCallback;
	void *_userdata;
};

enum KademliaConstants
{
	// the default number of nodes to find in searches (for
	// PUTs, we need to find at least as many nodes as we're
	// PUTting to).
	KADEMLIA_K = 8,

	// the default number of nodes to announce and put to
	KADEMLIA_K_ANNOUNCE = 8,

	// MUST be a power of 2 for routing table optimization; see
	// KADEMLIA_BUCKET_SIZE_POWER
	KADEMLIA_BUCKET_SIZE = 8,

	// MUST stay coordinated with KADEMLIA_BUCKET_SIZE
	KADEMLIA_BUCKET_SIZE_POWER = 3,

	// The sum of these two items should always be greater than 0.

	// initial dht searches should allow more outstanding lookups
	KADEMLIA_LOOKUP_OUTSTANDING = 4, 

	// How much to reduce the number of outstanding lookup requests allowed for
	// less agressive dht searches once some connectivity threshold is reached.
	KADEMLIA_LOOKUP_OUTSTANDING_DELTA = -2,

	// the number of outstanding announce_peer / put requests to have at a time
	KADEMLIA_BROADCAST_OUTSTANDING = 4,
};

struct DhtRequest {
	uint tid; // Request identifier

	IDhtRequestListener *_pListener;

	DhtPeerID peer;
	bool has_id;
	bool slow_peer;

	// Requests form a linked list
	DhtRequest *next;

	// timestamp when we sent this request.
	// This is specified in the GetTickCount64() space
	uint64 time;

#if g_log_dht
	uint origin;
#endif
};


class DhtBucketList : public TailQueueX<DhtPeer, offsetof(DhtPeer,next)>
{
public:
	// used to determine if a sub prefix position is not yet represented by an id
	// when evaluating whether to add a new node in Update() & InsertOrUpdateNode()
	unsigned int subPrefixMask;
	unsigned char subPrefixCounts[KADEMLIA_BUCKET_SIZE];
	DhtPeer* peerMatrix[KADEMLIA_BUCKET_SIZE][KADEMLIA_BUCKET_SIZE];

	// This element is here for convienence Update() & InsertOrUpdateNode().
	// It only has a valid meaning immediatly after the consumer has set it.
	bool listContainesAnErroredNode;

	DhtBucketList():subPrefixMask(0){}
	void ClearSubPrefixInfo();
	void UpdateSubPrefixInfo(DhtPeer &node);
	void ComputeSubPrefixInfo();
	DhtPeer* PopBestNode(int subPrefix);
};

inline void DhtBucketList::UpdateSubPrefixInfo(DhtPeer &node)
{
	assert(node.GetSubprefixInt() < KADEMLIA_BUCKET_SIZE);
	assert(node.GetSubprefixInt() >= 0);

	subPrefixMask |= node.GetSubprefixPositionBit();
	peerMatrix[node.GetSubprefixInt()][subPrefixCounts[node.GetSubprefixInt()]] = &node;
	subPrefixCounts[node.GetSubprefixInt()]++;
}


class DhtBucket
{
public:
	enum BucketListType
	{
		peer_list,
		replacement_list
	};
	// this is the start of the range this bucket
	// covers, in the ID space. This together with
	// span indicates the start and end of the
	// space this bucket covers.
	DhtID first;

	// "size" of bucket. This is the length of the
	// ID space this bucket covers, expressed in the
	// number of bits, i.e. 2^span
	uint span;

	// these are the peers in this bucket
	DhtBucketList peers, replacement_peers;

	DhtPeer* FindNode(SockAddr const& addr, BucketListType& list);
	DhtPeer* FindNode(const DhtID& id);
	bool InsertOrUpdateNode(DhtImpl* pDhtImpl, DhtPeer const& node, BucketListType bucketType, DhtPeer** pout);
	bool FindReplacementCandidate(DhtImpl* pDhtImpl, DhtPeer const& candidate, BucketListType bucketType, DhtPeer** pout);
	bool TestForMatchingPrefix(const DhtID &id) const;
	bool RemoveFromList(DhtImpl* pDhtImpl, const DhtID &id, BucketListType bucketType);
};

//--------------------------------------------------------------------------------
//
// DhtImpl
//
//--------------------------------------------------------------------------------

#define FAIL_THRES_NOCONTACT 2 // no contact?, lower thres...
#define FAIL_THRES 10

#define CROSBY_E (2*60) // age in second a peer must be before we include them in find nodes

enum QueriedStatus
{
	QUERIED_NO = 0,
	QUERIED_YES = 1,
	QUERIED_REPLIED = 2,
	QUERIED_ERROR = 3,
	QUERIED_SLOW = 4,
};

static const char * const _queried_str[] = {
	"QUERIED_NO",
	"QUERIED_YES",
	"QUERIED_REPLIED",
	"QUERIED_ERROR",
	"QUERIED_SLOW",
};

struct DhtFindNodeEntry {
	DhtPeerID id;
	byte queried;
	Buffer token;

	// sequence number the data we got back from this node had. Or 0 if
	// we did not receive data from this node. This is used to implement
	// atomic writes. Once we have modified the blob we found on the DHT
	// and are writing it back, we echo this sequence number back to make
	// sure nonody else has writtent to it since we read it.
	int64 cas;

	// the two letter client version from the DHT messages
	char client[2];

	// the 16 bit version number from the DHT messages
	uint version;
};

struct DhtGetNodeResult {
	DhtPeerID id;
	DhtID token;
};

/**
 This is used for GUI/Client/Consumer level callbacks
*/
class IDhtProcessCallbackListener
{
public:
	virtual void ProcessCallback() = 0;
	virtual ~IDhtProcessCallbackListener() {}
};

//*****************************************************************************
//
// CallBackPointers			A class to collect the various consumer level callbacks
//
//*****************************************************************************
/**
*/
class CallBackPointers
{
	public:
		CallBackPointers();

		void* callbackContext;
		IDhtProcessCallbackListener* processListener;
		DhtAddNodesCallback* addnodesCallback;
		DhtScrapeCallback* scrapeCallback;
		DhtVoteCallback* voteCallback;
		DhtHashFileNameCallback* filenameCallback;
		DhtPortCallback* portCallback;
		DhtPutCallback* putCallback;
		DhtPutCompletedCallback* putCompletedCallback;
		DhtPutDataCallback* putDataCallback;
		DhtGetCallback* getCallback;
};

inline CallBackPointers::CallBackPointers()
	: callbackContext(NULL)
	, processListener(NULL)
	, addnodesCallback(NULL)
	, scrapeCallback(NULL)
	, voteCallback(NULL)
	, filenameCallback(NULL)
	, portCallback(NULL)
	, putCallback(NULL)
	, putCompletedCallback(NULL)
	, putDataCallback(NULL)
	, getCallback(NULL)
{}

//*****************************************************************************
//
// DhtLookupNodeList	A class to collect the nodes found during a dht lookup
//
//*****************************************************************************
/**
Holds the dht nodes found during a dht lookup process (such as find_nodes or get_peers)
*/
class DhtLookupNodeList
{
	private:
		unsigned int numNodes;	// Number of entries in node table
		DhtFindNodeEntry nodes[KADEMLIA_K*8];		// Table of closest nodes
		static void FreeNodeEntry(DhtFindNodeEntry &ent) { if (ent.token.b) free(ent.token.b); }

	protected:
		int64 seq_max;
		std::vector<char> data_blk;
		SockAddr src_ip;

	public:
		DhtLookupNodeList();
		DhtLookupNodeList(DhtPeerID** ids, unsigned int numId, const DhtID &target);
		virtual ~DhtLookupNodeList();
		DhtFindNodeEntry* FindQueriedPeer(const DhtPeerID &id);
		virtual void InsertPeer(const DhtPeerID &id, const DhtID &target);
		int size() { return numNodes; }
		DhtFindNodeEntry& operator[](const unsigned int index);
		void SetQueriedStatus(unsigned int index, QueriedStatus status);
		void SetAllQueriedStatus(QueriedStatus status);
		void SetNodeIds(DhtPeerID** ids, unsigned int numId, const DhtID &target);
		void CompactList();
		int64 seq() { return seq_max; }
		void set_seq(int64 sq) {seq_max = sq;}
		void set_data_blk(byte * v, int v_len, SockAddr src);
		std::vector<char> &get_data_blk() { return data_blk; }
		char * get_data_blk(size_t & len) { len = data_blk.size(); return &data_blk[0]; }	
		SockAddr data_blk_source() const { return src_ip; }
};

inline DhtLookupNodeList::DhtLookupNodeList():numNodes(0), seq_max(0)
{
	memset(nodes, 0, sizeof(nodes));
}

/**
Initializes the node list with the provided list of nodes.
*/
inline DhtLookupNodeList::DhtLookupNodeList(DhtPeerID** ids, unsigned int numId
	, const DhtID &target):numNodes(0), seq_max(0)
{
	memset(nodes, 0, sizeof(nodes));
	SetNodeIds(ids, numId, target);
}

inline DhtFindNodeEntry& DhtLookupNodeList::operator[](const unsigned int index)
{
	assert(index < numNodes);
	return nodes[index];
}
/**
Set the status of the node at the specified index to the specified status.
*/
inline void DhtLookupNodeList::SetQueriedStatus(unsigned int index, QueriedStatus status)
{
	assert(index < numNodes);
	nodes[index].queried = status;
}


//*****************************************************************************
//
// DhtProcessManager  (initial definition)
//
//*****************************************************************************
class DhtProcessBase;

/**
	This class is implements self terminating objects that perform simple management
	of dht process objects based on DhtProcessBase.  The two classes work in
	conjunction with each other.  It is a DhtLookupNodeList object and should
	generally be initialized with a list of nodes (or at least one node).  If the
	node list is empty, the dht processes will have nothing to do.

	Dht process objects are added in the order they are to be exercised. All process
	objects being added to a process manager should be provided the reference to the
	same DhtProcessManager object.  When all process objects have been added, the
	Start() member function should be invoked to kick-off the whole series of dht
	processes that have been assembled.  Start() will invoke the first dht process
	object in the list.  When that object is finished, it must call the Next() member
	function of the process manager.  The process manager will then invoke the
	Start() member function of the next dht process object in the list.

	If Next() is called, and there are no more process objects to start, the
	process manager will delete the dht process objects that were added and then
	delete itself.
*/
class DhtProcessManager : public DhtLookupNodeList
{
	private:
		std::vector<DhtProcessBase*> _dhtProcesses;
		unsigned int _currentProcessNumber;

	public:
		DhtProcessManager():_currentProcessNumber(0){}
		DhtProcessManager(DhtPeerID** ids, unsigned int numId, const DhtID &target)
			: DhtLookupNodeList(ids,numId,target)
			, _currentProcessNumber(0)
		{}
		~DhtProcessManager();
		unsigned int AddDhtProcess(DhtProcessBase *process);

		void Start();
		void Next();
		void Abort();
};

inline unsigned int DhtProcessManager::AddDhtProcess(DhtProcessBase *process)
{
	_dhtProcesses.push_back(process);
	return _dhtProcesses.size();
}


//*****************************************************************************
//
// DhtProcessBase		A base class for all DHT Processes
//
//*****************************************************************************
/**
	The is the base class for dht processes.  Through inheritance, the various
	DhtProcessStates can be implemented.  All related dht processes will share a
	reference to the same DhtProcessManager object which will contain the list
	of nodes the processes to work with and which will manage the invocation
	of successive processes (such as "get_peers" dht lookup type process followed
	by an "announce_peer" broadcast type process).

	Generally each derived dht process class will implement a Create function
	to allocate and prepare the object for its task.  Also, it will generally be the
	responsibility of the DhtProcessManager object to delete the dht process
	object once the task is complete.

	To execute the process described above, DhtProcessBase follows the following
	sequence:

		Start -> Schedule --//--> CompleteThisProcess
					/\
					||
				 OnReply

	*Start* represents the entry point for the consumer.  It is also a hook where
	the developer of the object can set any initial states and do any other
	initialization not handled in the constructor (such as resetting the list of
	nodes to that may have been developed by a previously executed object to a
	"not queried" state).  Start will initiate the first Schedule cycle.  Derived
	classes may either invoke DhtProcessBase::Start() or call the Schedule
	function themselves.

	*Schedule* performs the work of issuing DHT requests and maintaining the
	bookkeeping for the outstanding requests.  It may also limit the number of
	outstanding requests for the process that are in flight at any one time.

	Schedule may be entered many times over during the course of the process.
	When Schedule can no longer issue DHT requests, either because the flight
	deck if full or the queue to be issued is empty, Schedule exits and the
	object goes dormant.  The Schedule segment is reactivated by the OnReply()
	method.  OnReply is invoked either by an incoming reply to a previously issued
	request or a timeout operation on an outstanding request.  Once Schedule
	determines that all of the outstanding requests are complete and there are
	no more requests to issue, it should invoke CompleteThisProcess().  Schedule is
	a pure virtual member function.  However, two scheduling objects have been
	defined to provide the dht lookup and broadcast modes of functionality.
	(See DhtLookupScheduler and DhtBroadcastScheduler)

	*OnReply* is the callback entry point for processing incoming replys to
	requests and timeout operations (such as for "slow peers" or non-responders).
	After handling the outstanding request bookkeeping, OnReply invokes the
	user defined ImplementationSpecificReplyProcess() function.  This gives the
	object designer a hook to perform some custom task that relates to the
	DHT process being implemented.  Once this is complete, OnReply invokes
	the Schedule function to issue another dht query or terminate the process.

	*CompleteThisProcess* is the last chance for the object to do any cleanup
	before exiting.  For example, a "get_peers" process can compact the node
	table (in the manager) to contain only good nodes that replied for any
	subsequent process to use.  The DhtProcessBase version invokes the manager
	classes Next() function to indicate that this process is finished and the next
	process may be started.

	An additional virtual functions that must be implemented is:

		DhtSendRPC() - This outputs the bencoded dht query string to the socket.
*/
class DhtProcessBase
{
	private:
		DhtProcessBase(DhtProcessManager& dpm);

	protected:
		CallBackPointers callbackPointers;
		DhtID target;
		smart_ptr<DhtImpl> impl;
		time_t start_time;
		bool aborted;
		DhtProcessManager &processManager;

		virtual void DhtSendRPC(const DhtFindNodeEntry &nodeInfo
			, const unsigned int transactionID) = 0;
		virtual void Schedule() = 0;
		virtual void CompleteThisProcess();

		void Abort();

	public:

#ifdef _DEBUG_DHT
		unsigned int process_id() const;
		virtual char const* name() const = 0;
#endif

		static DHTMessage dummyMessage;

		DhtProcessBase(DhtImpl *pImpl, DhtProcessManager &dpm
			, const DhtID &target2, time_t startTime
			, const CallBackPointers &consumerCallbacks);
		virtual ~DhtProcessBase();
		virtual void Start();
		virtual void OnReply(void*& userdata, const DhtPeerID &peer_id
			, DhtRequest *req, DHTMessage &message, DhtProcessFlags flags) = 0;
		virtual void ImplementationSpecificReplyProcess(void *userdata
			, const DhtPeerID &peer_id, DHTMessage &message, uint flags) {}

		// return true if we should not send an RPC to this node. This is
		// used to not send put messages to nodes we know don't support it
		// For lookups this has slightly different semantics. For a lookup
		// it means whether or not it will be filtered in a store operation
		// (i.e. put or announce_peer). nodes that will be filtered
		// don't count when we try to get a response from K nodes,
		// to try to get more responses if nodes are filtered
		// The behavior is implemented in the two Schedule() functions
		virtual bool Filter(DhtFindNodeEntry const& e) { return false; }
};

//*****************************************************************************
//
// DhtLookupScheduler
//
//*****************************************************************************
/**
	This scheduler is optimized for use with "find_nodes" and "get_peers".  It
	will issue dht requests up to a maximum of KADEMLIA_LOOKUP_OUTSTANDING = 4
	out standing requests at a time by default or a different maximum if specified
	in the constructor. As more nodes are added to the node list,
	additional requests will be made.  If a node with an outstanding request
	to it is designated as "slow" an additional request to another node will
	be issued (if available).
*/
class DhtLookupScheduler : public DhtProcessBase
{
	private:
		DhtLookupScheduler(DhtProcessManager &dpm, int flags);

	protected:
		// the number of closest nodes to find
		int num_targets;
		int maxOutstandingLookupQueries;

		int numNonSlowRequestsOutstanding;
		int totalOutstandingRequests;

		int flags;

		virtual void Schedule();
		virtual void ImplementationSpecificReplyProcess(void *userdata
			, const DhtPeerID &peer_id, DHTMessage &message, uint flags);
		DhtFindNodeEntry* ProcessMetadataAndPeer(const DhtPeerID &peer_id
			, DHTMessage &message, uint flags);
		void IssueOneAdditionalQuery();
		void IssueQuery(int nodeIndex);

	public:
		virtual void OnReply(void*& userdata, const DhtPeerID &peer_id
			, DhtRequest *req, DHTMessage &message, DhtProcessFlags flags);

		DhtLookupScheduler(DhtImpl* pDhtImpl, DhtProcessManager &dpm
			, const DhtID &target2, time_t startTime
			, const CallBackPointers &consumerCallbacks
			, int maxOutstanding
			, int flags
			, int targets = KADEMLIA_K);

#ifdef _DEBUG_DHT
		virtual char const* name() const { return "Lookup"; }
#endif
};

//*****************************************************************************
//
// DhtBroadcastScheduler
//
//*****************************************************************************
/**
	This mode runs through the list of peers once, issuing the RPC.
*/
class DhtBroadcastScheduler : public DhtProcessBase
{
	private:
		DhtBroadcastScheduler(DhtProcessManager &dpm);

	protected:
		// the number of nodes to announce/put to
		int num_targets;

		// the number of outstanding announces/puts to keep at any given time
		int outstanding;

		virtual void Schedule();

	public:
		void OnReply(void*& userdata, const DhtPeerID &peer_id, DhtRequest *req
			, DHTMessage &message, DhtProcessFlags flags);

		DhtBroadcastScheduler(DhtImpl* pDhtImpl, DhtProcessManager &dpm
			, const DhtID &target2, time_t startTime
			, const CallBackPointers &consumerCallbacks
			, int targets = KADEMLIA_K_ANNOUNCE)
			: DhtProcessBase(pDhtImpl, dpm, target2, startTime
			, consumerCallbacks), num_targets(targets), outstanding(0)
			{}

#ifdef _DEBUG_DHT
		virtual char const* name() const { return "Broadcast"; }
#endif
};


//*****************************************************************************
//
// FindNodeDhtProcess		find_node
//
//*****************************************************************************
class FindNodeDhtProcess : public DhtLookupScheduler //public DhtProcessBase
{
	protected:

		byte target_bytes[DHT_ID_SIZE]; // used to store the bytes of the target DhtID

		virtual void DhtSendRPC(const DhtFindNodeEntry &nodeInfo, const unsigned int transactionID);
		virtual void CompleteThisProcess();

	public:

		FindNodeDhtProcess(DhtImpl* pDhtImpl, DhtProcessManager &dpm, const DhtID &target2
			, time_t startTime, const CallBackPointers &consumerCallbacks
			, int maxOutstanding, int flags);

		static DhtProcessBase* Create(DhtImpl* pImpl, DhtProcessManager &dpm
			, const DhtID &target2
			, CallBackPointers &cbPointers
			, int maxOutstanding
			, int flags);

#ifdef _DEBUG_DHT
		virtual char const* name() const { return "FindNode"; }
#endif
};


//*****************************************************************************
//
// Argumenter
//
//*****************************************************************************
/**
	This class collects the bytes of the value of a dht query argument (such as
	the bytes of an info_hash).  It keeps track of the number of bytes so than
	memcpy can be used when assembling the bencoded argument string in the
	Argumenter class.

	It statically allocates a buffer of 32 bytes.  However,
	if a larger buffer is needed, using the SetValueBytes() method will automatically
	allocate a buffer sized to numBytes before copying the data.

	If the consumer wants to write directly to the buffer, GetBufferPtr() will return
	a pointer to the byte array.  The consumer is then responsible for not writing
	beyond the buffer length and must also set the number of useful bytes in the
	array using SetNumUsefulBytes().
*/

// TODO: remove this class along with Argumenter. There is no need for the
// members to be dynamically allocated
class ArgumenterValueInfo
{
	public:
		enum ArgumenterBufferLength {BUF_LEN = 32};

	private:
		byte fixedLenBytes[BUF_LEN];
		byte* valueBytes;

		// the number of bytes of value in the array (not necessarily the lenth of the byte array)
		// If the consumer writes directly to the buffer, the consumer is responsible for
		// maintaining the count of useful bytes in the array
		int numBytesUsed;
		int arrayLength; // the actual number of bytes in the buffer array

	public:
		ArgumenterValueInfo():valueBytes((byte*)fixedLenBytes),numBytesUsed(0),arrayLength(BUF_LEN){}
		~ArgumenterValueInfo();
		void SetValueBytes(const byte* valueBytes, int numBytes);
		void SetNumBytesUsed(int num);
		byte* GetBufferPtr();  // The consumer may use this to write directly to the buffer
		int GetNumBytesUsed();
		int GetArrayLength();
};

inline ArgumenterValueInfo::~ArgumenterValueInfo()
{
	if((byte*)fixedLenBytes != valueBytes)
		delete[] valueBytes;
}

inline byte* ArgumenterValueInfo::GetBufferPtr()
{
	return valueBytes;
}

inline void ArgumenterValueInfo::SetNumBytesUsed(int num)
{
	assert(((byte*)fixedLenBytes == valueBytes)?(num >=0 && num <= arrayLength):true);
	numBytesUsed = num;
}

inline int ArgumenterValueInfo::GetNumBytesUsed()
{
	return numBytesUsed;
}

inline int ArgumenterValueInfo::GetArrayLength()
{
	return arrayLength;
}


/**
	Used to uniformly generate argument list strings for dht queries that
	have many optional components.

	Classes using the Argumenter must make their own enum of options
	and accompaning static array of option strings (accessed via enumStrings).
	Enable an option to be included in the bencoded string by setting the
	enabled[ enum-name-as-the-index ] to be true.
*/
class Argumenter
{
	private:
		int length;
		const char** const enumStrings; // consumer must provide this array of strings
		int* enumStringLengths;

	public:
		bool* enabled;
		ArgumenterValueInfo* values;

		Argumenter(int enumLength, const char** const enumStringsIn);
		~Argumenter();
		void ClearEnabled();
		void ClearValues();
		void ClearAll();
		int BuildArgumentBytes(byte* buf, const int bufLen);
		void SetValueBytes(int index, const byte* valueBytes, int numBytes);
		ArgumenterValueInfo& GetArgumenterValueInfo(int index);
};

inline Argumenter::~Argumenter()
{
	delete[] enumStringLengths;
	delete[] enabled;
	delete[] values;
}

inline void Argumenter::SetValueBytes(int index, const byte* valueBytes, int numBytes)
{
	assert(index >= 0 && index < length);
	values[index].SetValueBytes(valueBytes, numBytes);
	enabled[index] = true;
}

inline ArgumenterValueInfo& Argumenter::GetArgumenterValueInfo(int index)
{
	assert(index >= 0 && index < length);
	return values[index];
}


//*****************************************************************************
//
// GetPeersDhtProcess		get_peers
//
//*****************************************************************************
class GetPeersDhtProcess : public DhtLookupScheduler
{
	protected:
		// IMPORTANT:
		//    1) The first element in the enum must start at 0
		//    2) The elements of the enum must be alphebetical (for dht rpc protocol)
		//    3) The last element in the enum must be "ARGUMENTER_SIZE"
		//    4) Be sure to keep the accompaning static string list coordinated with this enum
		enum GetPeersRPC_Arguments
		{
			a_id = 0,
			a_info_hash,
			a_name,
			a_noseed,
			a_port,
			a_scrape,
			a_token,
			a_vote,
			ARGUMENTER_SIZE  // This must be here.  This must be called ARGUMENTER_SIZE
		};
		static const char * const ArgsNamesStr[]; // strings that correspond to the GetPeersRPC_Arguments enum
		Argumenter* gpArgumenterPtr;

		virtual void DhtSendRPC(const DhtFindNodeEntry &nodeInfo, const unsigned int transactionID);
		virtual void CompleteThisProcess();

	public:

		GetPeersDhtProcess(DhtImpl *pDhtImpl, DhtProcessManager &dpm, const DhtID &target2
			, time_t startTime, const CallBackPointers &consumerCallbacks
			, int maxOutstanding, int flags);
		~GetPeersDhtProcess();
		static DhtProcessBase* Create(DhtImpl* pImpl, DhtProcessManager &dpm,
			const DhtID &target2,
			CallBackPointers &cbPointers,
			int flags = 0,
			int maxOutstanding = KADEMLIA_LOOKUP_OUTSTANDING);

#ifdef _DEBUG_DHT
		virtual char const* name() const { return "GetPeers"; }
#endif
};

//*****************************************************************************
//
// AnnounceDhtProcess		announce
//
//*****************************************************************************
class AnnounceDhtProcess : public DhtBroadcastScheduler
{
	protected:
		// IMPORTANT:
		//    1) The first element in the enum must start at 0
		//    2) The elements of the enum must be alphebetical (for dht rpc protocol)
		//    3) The last element in the enum must be "ARGUMENTER_SIZE"
		//    4) Be sure to keep the accompaning static string list coordinated with this enum
		enum AnnounceRPC_Arguments
		{
			a_id = 0,
			a_implied_port,
			a_info_hash,
			a_name,
			a_port,
			a_seed,
			a_token,
			ARGUMENTER_SIZE  // This must be here.  This must be called ARGUMENTER_SIZE
		};
		static const char * const ArgsNamesStr[];
		Argumenter* announceArgumenterPtr;

		virtual void ImplementationSpecificReplyProcess(void *userdata, const DhtPeerID &peer_id, DHTMessage &message, uint flags);
		virtual void DhtSendRPC(const DhtFindNodeEntry &nodeInfo, const unsigned int transactionID);
		virtual void CompleteThisProcess();

	public:
		AnnounceDhtProcess(DhtImpl* pDhtImpl, DhtProcessManager &dpm, const DhtID &target2
			, time_t startTime, const CallBackPointers &consumerCallbacks);
		~AnnounceDhtProcess();
		virtual void Start();

		static DhtProcessBase* Create(DhtImpl* pDhtImpl, DhtProcessManager &dpm,
			const DhtID &target2,
			CallBackPointers &cbPointers,
			cstr file_name,
			int flags);

#ifdef _DEBUG_DHT
		virtual char const* name() const { return "Announce"; }
#endif
};

//*****************************************************************************
//
// GetDhtProcess		get
//
//*****************************************************************************
class GetDhtProcess : public DhtLookupScheduler
{
	protected:
		bool _with_cas;
		// Keep a count of the number of times the process has been restarted to
		// avoid a potential infinite loop
		byte retries;
		virtual void DhtSendRPC(const DhtFindNodeEntry &nodeInfo, const unsigned int transactionID);
		virtual void ImplementationSpecificReplyProcess(void *userdata, const DhtPeerID &peer_id, DHTMessage &message, uint flags);
		virtual void CompleteThisProcess();

	public:

		byte _id[DHT_ID_SIZE];

		GetDhtProcess(DhtImpl *pDhtImpl, DhtProcessManager &dpm, const DhtID& target2
			, time_t startTime, const CallBackPointers &consumerCallbacks
			, int maxOutstanding, int flags);

		virtual bool Filter(DhtFindNodeEntry const& e);

		static DhtProcessBase* Create(DhtImpl* pImpl, DhtProcessManager &dpm,
			const DhtID &target2,
			CallBackPointers &cbPointers,
			int flags = 0,
			int maxOutstanding = KADEMLIA_LOOKUP_OUTSTANDING);

#ifdef _DEBUG_DHT
		virtual char const* name() const { return "Get"; }
#endif
};

//*****************************************************************************
//
// PutDhtProcess		put
//
//*****************************************************************************
class PutDhtProcess : public DhtBroadcastScheduler
{
	protected:
		virtual void ImplementationSpecificReplyProcess(void *userdata, const DhtPeerID &peer_id, DHTMessage &message, uint flags);
		virtual void DhtSendRPC(const DhtFindNodeEntry &nodeInfo, const unsigned int transactionID);
		virtual void CompleteThisProcess();
		std::vector<char> signature;
		GetDhtProcess* getProc;

		virtual bool Filter(DhtFindNodeEntry const& e);

	public:

		byte _id[DHT_ID_SIZE];
		byte _pkey[32];
		byte _skey[64];

		PutDhtProcess(DhtImpl* pDhtImpl, DhtProcessManager &dpm, const byte * pkey, const byte * skey, time_t startTime, const CallBackPointers &consumerCallbacks, int flags);
		~PutDhtProcess();
		virtual void Start();

		void Sign(std::vector<char> & signature, std::vector<char> v, byte * skey, int64 seq);
		
		static DhtProcessBase* Create(DhtImpl* pDhtImpl, DhtProcessManager &dpm,
			const byte * pkey,
			const byte * skey,
			CallBackPointers &cbPointers,
			int flags);

#ifdef _DEBUG_DHT
		virtual char const* name() const { return "Put"; }
#endif
	protected:
		bool _with_cas;
		// records whether we've called the callback or not. We just want to
		// call it once!
		bool _put_callback_called;
};

class ImmutablePutDhtProcess : public DhtBroadcastScheduler
{
	protected:
		virtual void ImplementationSpecificReplyProcess(void *userdata, const DhtPeerID &peer_id, DHTMessage &message, uint flags);
		virtual void DhtSendRPC(const DhtFindNodeEntry &nodeInfo, const unsigned int transactionID);
		virtual void CompleteThisProcess();

		virtual bool Filter(DhtFindNodeEntry const& e);

	public:

		byte _id[DHT_ID_SIZE];
		std::vector<byte> _data;

		ImmutablePutDhtProcess(DhtImpl* pDhtImpl, DhtProcessManager &dpm,
				const byte * data, size_t data_len, time_t startTime,
				const CallBackPointers &consumerCallbacks);
		~ImmutablePutDhtProcess();
		virtual void Start();

		static DhtProcessBase* Create(DhtImpl* pDhtImpl, DhtProcessManager &dpm,
			byte const * data, size_t len, CallBackPointers &cbPointers);

#ifdef _DEBUG_DHT
		virtual char const* name() const { return "ImmutablePut"; }
#endif
};

//*****************************************************************************
//
// ScrapeDhtProcess		get_peers with scrape
//
//*****************************************************************************
class ScrapeDhtProcess : public GetPeersDhtProcess
{
	private:
		// used to aggregate responses from scrapes
		bloom_filter seeds;
		bloom_filter downloaders;

	protected:
		virtual void ImplementationSpecificReplyProcess(void *userdata, const DhtPeerID &peer_id, DHTMessage &message, uint flags);
		virtual void CompleteThisProcess();

	public:
		ScrapeDhtProcess(DhtImpl* pDhtImpl, DhtProcessManager &dpm
			, const DhtID &target2, time_t startTime
			, const CallBackPointers &consumerCallbacks, int maxOutstanding
			, int flags);
		virtual ~ScrapeDhtProcess();

		static DhtProcessBase* Create(DhtImpl* pDhtImpl, DhtProcessManager &dpm
			, const DhtID &target2
			, CallBackPointers &cbPointers
			, int maxOutstanding
			, int flags);

#ifdef _DEBUG_DHT
		virtual char const* name() const { return "Scrape"; }
#endif
};

//*****************************************************************************
//
// VoteDhtProcess		command = vote
//
//*****************************************************************************
class VoteDhtProcess : public DhtBroadcastScheduler
{
private:
	int voteValue;

protected:
	virtual void ImplementationSpecificReplyProcess(void *userdata, const DhtPeerID &peer_id, DHTMessage &message, uint flags);
	virtual void DhtSendRPC(const DhtFindNodeEntry &nodeInfo, const unsigned int transactionID);

public:

	VoteDhtProcess(DhtImpl* pDhtImpl, DhtProcessManager &dpm, const DhtID &target2, time_t startTime, const CallBackPointers &consumerCallbacks);
	virtual ~VoteDhtProcess(){}
	void SetVoteValue(int value);
	virtual void Start();

	static DhtProcessBase* Create(DhtImpl* pImpl, DhtProcessManager &dpm
		, const DhtID &target2
		, CallBackPointers &cbPointers, int voteValue);

#ifdef _DEBUG_DHT
		virtual char const* name() const { return "Vote"; }
#endif
};

#if !STABLE_VERSION || defined _DEBUG || defined BRANDED_MAC
	bool ValidateEncoding( const void * data, uint len );
#endif

//--------------------------------------------------------------------------------

/**
 * DhtImpl
 *
 */
class DhtImpl : public IDht, public IDhtProcessCallbackListener
{
public:
	DhtImpl(UDPSocketInterface *_udp_socket_mgr, UDPSocketInterface *_udp6_socket_mgr
		, DhtSaveCallback* save = NULL
		, DhtLoadCallback* load = NULL
		, ExternalIPCounter* eip = NULL);
	~DhtImpl();
	REFBASE;

#ifdef _DEBUG_DHT
	FILE* _lookup_log;

	FILE* _bootstrap_log;
	// timestamp of when we started bootstrap
	uint _bootstrap_start;
#endif
#ifdef _DEBUG_DHT_INSTRUMENT
	FILE* _instrument_log;
#endif

private:
	void Initialize(UDPSocketInterface *_udp_socket_mgr, UDPSocketInterface *_udp6_socket_mgr );
public:

	// UDPSocketManagerObserver
	bool handleReadEvent(UDPSocketInterface *socket, byte *buffer, size_t len, const SockAddr& addr);
	bool handleICMP(UDPSocketInterface *socket, byte *buffer, size_t len, const SockAddr& addr);

	void Close() { _closing = true; }
	bool Closing() { return _closing; }
	void Shutdown();
	void Tick();
	void Enable(bool enabled, int rate);
	bool IsEnabled();
	void ForceRefresh();
	// do not respond to queries - for mobile nodes with data constraints
	void SetReadOnly(bool readOnly);
	void SetPingFrequency(int seconds);
	void SetPingBatching(int num_pings);
	void EnableQuarantine(bool e);

	bool CanAnnounce();

	void Vote(void *ctx, const sha1_hash* info_hash, int vote, DhtVoteCallback* callb);

	void SetId(byte new_id_bytes[DHT_ID_SIZE]);

	// get the target id of a mutable item
	DhtID MutableTarget(const byte* key, const byte* salt, int salt_length);

	void Put(const byte * pkey, const byte* skey, DhtPutCallback * put_callback
		, DhtPutCompletedCallback* put_completed_callback
		, DhtPutDataCallback* put_data_callback
		, void *ctx, int flags = 0
		, int64 seq = 0);

	sha1_hash ImmutablePut(const byte * data, size_t data_len,
			DhtPutCompletedCallback* put_completed_callback, void *ctx);

	void ImmutableGet(sha1_hash target, DhtGetCallback* cb
		, void* ctx = nullptr);

	void AnnounceInfoHash(const byte *info_hash,
		DhtAddNodesCallback *addnodes_callback, DhtPortCallback* pcb, cstr file_name,
		void *ctx, int flags);

	void SetRate(int bytes_per_second);
	void SetVersion(char const* client, int major, int minor);
	void SetExternalIPCounter(ExternalIPCounter* ip);
	void SetAddNodeResponseCallback(DhtAddNodeResponseCallback* cb);
	void SetSHACallback(DhtSHACallback* cb);
	void SetEd25519VerifyCallback(Ed25519VerifyCallback* cb);
	void SetEd25519SignCallback(Ed25519SignCallback* cb);
	void SetPacketCallback(DhtPacketCallback* cb);

	void AddNode(const SockAddr& addr, void* userdata, uint origin);
	void AddBootstrapNode(SockAddr const& addr);

	void DumpBuckets();
	void DumpTracked();

	int CalculateLowestBucketSpan();

	int GetProbeQuota();
	bool CanAddNode();
	int GetNumPeers();
	bool IsBusy();
	int GetBootstrapState();
	int GetRate();
	int GetQuota();
	int GetProbeRate();
	int GetNumPeersTracked();
	int GetNumPutItems();
	void CountExternalIPReport( const SockAddr& addr, const SockAddr& voter );

	bool IsBootstrap(const SockAddr& addr);


	//--------------------------------------------------------------------------------


#ifdef DHT_SEARCH_TEST
#define NUM_SEARCHES 10000
	static bool search_running = false;
#endif

	DhtID _my_id;
	byte _my_id_bytes[DHT_ID_SIZE];
	byte _dht_utversion[4];
	DhtAddNodeResponseCallback* _add_node_callback;
	DhtSaveCallback* _save_callback;
	DhtLoadCallback* _load_callback;
	DhtPacketCallback* _packet_callback;
	DhtSHACallback* _sha_callback;
	Ed25519VerifyCallback* _ed25519_verify_callback;
	Ed25519SignCallback* _ed25519_sign_callback;
	ExternalIPCounter* _ip_counter;

	// the buckets in the routing table. These buckets are ordered by their
	// absolute location in the node ID space, _not_ by the distance from
	// our node ID. Any bucket can be split, but we only split the ones
	// our ID falls into. This is the general structure of an example routing
	// table:

	//        ID space
	// |---------------------------------------------------*---------------------------|
	// 0                                                   |                         2^160
	// |------------------- 0 -----------------|           |
	// ^                                                   |       |--------- 4 -------|
	// |  span=159                             |--- 1 ---| |
	// first                                   ^           |  |-3--|
	//                                         |         |-2--|
	//                                         first       |
	//                                                     |
	//                                                     _my_id
	// the numbers are the index in _buckets
	// 0: span=159
	// 1: span=157
	// 2: span=156
	// 3: span=156
	// 4: span=158

	// in order to implement the optimization of having a larger routing table, especially
	// larger buckets that are far away from us. This is described in this paper:
	//    http://people.kth.se/~rauljc/p2p11/jimenez2011subsecond.pdf
	// instead of increasing the bucket sizes of buckets with span 156+, we initialize
	// the routing table to contain 32 buckets, evenly distributed. That has a very similar
	// effect, since half of the space will fit 128 nodes.

	// TODO: we should probably factor out the routing table into its own class and unit test it
	// TODO: why is this an array of pointers instead of an array of objects?
	// DhtBucket is fairly light weight
	std::vector<DhtBucket*> _buckets; // DHT buckets

	// set of all addresses in the routing table
	// used to enforce only one entry per IP
	std::set<uint32> _ip4s;

	//static MAKE_BLOCK_ALLOCATOR(_dht_bucket_allocator, DhtBucket, 50);
	//static MAKE_BLOCK_ALLOCATOR(_dht_peer_allocator, DhtPeer, 100);

	BlockAllocatorX<DhtBucket> _dht_bucket_allocator;
	BlockAllocatorX<DhtPeer> _dht_peer_allocator;


	TailQueue(DhtRequest,next) _requests;
	std::vector<StoredContainer> _peer_store;

	DataStore<DhtID, std::vector<byte> > _immutablePutStore;
	DataStore<DhtID, MutableData> _mutablePutStore;

	// stores votes for keys
	std::vector<VoteContainer> _vote_store;

#if USE_HOLEPUNCH
	// recent punch requests we've sent. Don't send duplicates within
	// short periods of time. This bloom filter is cleared every 5 minutes
	// or so
	bloom_filter _recent_punch_requests;

	// recent punches we've sent (this is the small packet meant to open the
	// pinhole, sent in response to a punch request).
	bloom_filter _recent_punches;
#endif

#define MAX_PEERS (4*1000*1000)
	int _peers_tracked;
	time_t _last_self_refresh;
	// this is different than _dht_bootstrap_failed. This counts the number of
	// times we've tried to bootstrap. It's not reset just because the bootstrap
	// server responds. This is used to gradually back-off our aggressiveness
	// of trying to bootstrap, to eventually give up.
	int _bootstrap_attempts;

	uint32 _cur_token[2];
	uint32 _prev_token[2];
	int _dht_bootstrap; // Possible states in enum below

	// a counter used to compute the back-off time for bootstrap re-tries
	// it's reset when we get a response from the bootstrap server.
	int _dht_bootstrap_failed;
	int _dht_busy;
	bool _allow_new_job;
	bool _dht_enabled;
	bool _dht_read_only;
	bool _closing; // app is closing, don't initiate bootstrap

	int _dht_peers_count;
	int _refresh_buckets_counter;	// Number of seconds since the last bucket was operated upon
	int _dht_quota;
	int _dht_rate;
	int _dht_probe_quota;
	int _dht_probe_rate;

	// the smallest bucket span we've seen in the table, ever. This is a target
	// for bootstrapping. Until we reach this depth, we'll keep trying to
	// bootstrap.
	int _lowest_span;

	// Possible states for _dht_bootstrap
	enum {
		bootstrap_complete = -2, 	// -2: bootstrap find_nodes complete
		bootstrap_ping_replied,		// -1: bootstrap ping has replied
		valid_response_received,		//  0: a vaild bootstrapping
									// response from dht routers has been received
		not_bootstrapped,			//  1: dht not bootstrapped (initial state)
		bootstrap_error_received	// >1: an error was received, _dht_bootstrap set with a large number of seconds for a count-down
	};

	enum {
		DHT_BW_IN_REQ = 0,	// incoming requests
		DHT_BW_IN_REPL,		// incoming replies
		DHT_BW_IN_TOTAL,	// incoming erroneous data
		DHT_BW_IN_KNOWN,	// incoming quick-parsed
		DHT_BW_IN_NO_QUOTA,	// no quota to reply
		DHT_BW_IN_TIMEOUT = 4,	// outgoing requests which failed

		DHT_BW_OUT_TOTAL,	// outgoing request (i request)
		DHT_BW_OUT_REPL,	// outgoing reply (i reply)

		DHT_INVALID_BASE,
		DHT_INVALID_IPV6,
		DHT_INVALID_PI_BAD_TID,
		DHT_INVALID_PI_ERROR,
		DHT_INVALID_PI_NO_DICT,
		DHT_INVALID_PI_NO_TYPE,
		DHT_INVALID_PI_Q_BAD_ARGUMENT,
		DHT_INVALID_PI_Q_BAD_COMMAND,
		DHT_INVALID_PI_R_BAD_REPLY,
		DHT_INVALID_PI_UNKNOWN_TYPE,
		DHT_INVALID_PQ_AP_BAD_INFO_HASH,
		DHT_INVALID_PQ_BAD_ID_FIELD,
		DHT_INVALID_PQ_BAD_PORT,
		DHT_INVALID_PQ_BAD_TARGET_ID,
		DHT_INVALID_PQ_BAD_WRITE_TOKEN,
		DHT_INVALID_PQ_GP_BAD_INFO_HASH,
		DHT_INVALID_PQ_INVALID_TOKEN,
		DHT_INVALID_PQ_IPV6,
		DHT_INVALID_PQ_BAD_PUT_NO_V,
		DHT_INVALID_PQ_BAD_PUT_BAD_V_SIZE,
		DHT_INVALID_PQ_BAD_PUT_SIGNATURE,
		DHT_INVALID_PQ_BAD_PUT_CAS,
		DHT_INVALID_PQ_BAD_PUT_KEY,
		DHT_INVALID_PQ_BAD_PUT_SALT,
		DHT_INVALID_PQ_BAD_GET_TARGET,
		DHT_INVALID_PQ_UNKNOWN_COMMAND,
		DHT_INVALID_PR_BAD_ID_FIELD,
		DHT_INVALID_PR_BAD_TID_LENGTH,
		DHT_INVALID_PR_IP_MISMATCH,
		DHT_INVALID_PR_PEER_ID_MISMATCH,
		DHT_INVALID_PR_UNKNOWN_TID,
		DHT_INVALID_END,

		DHT_NUM_ACCOUNTING
	};

	struct DhtAccounting {
		uint64 size;
		uint64 count;
	};

	DhtAccounting _dht_accounting[DHT_NUM_ACCOUNTING];

	UDPSocketInterface *_udp_socket_mgr;
	UDPSocketInterface *_udp6_socket_mgr;
	SockAddr _lastLeadingAddress;	// For tracking external voting of our ip
	std::vector<SockAddr> _bootstrap_routers;

	// this is used temporarily when assembling the node list. If we need to
	// add bootstrap routers to the list, they need to be allocated somewhere
	// temporarily. This is where we put them.
	std::vector<DhtPeerID> _temp_nodes;

	// the number of seconds in between each pings to nodes in the
	// routing table
	int _ping_frequency;

	// when refreshing the routing table, ping this many nodes at a time, when
	// waking up. (if this is > 1, the interval between waking up to ping is
	// also multiplied by _ping_batching)
	int _ping_batching;

	// when false, don't require nodes to be old enough before handing them
	// out to requestors
	bool _enable_quarantine;

	void Account(int slot, int size);

	void DumpAccountingInfo();
	bool Verify(byte const * signature, byte const * message, int message_length
		, byte const * salt, int salt_length, byte *pkey, int64 seq);

	//--------------------------------------------------------------------------------


	bool AccountAndSend(const DhtPeerID &peer, const void *data, int len,
			int packetSize);
	void SendTo(SockAddr const& peer, const void *data, uint len);

	// determine which bucket an id belongs to
	int GetBucket(const DhtID &id);

	DhtBucket *CreateBucket(uint position);
	void SplitBucket(uint bucket_id);
	int NumBuckets() const;

	DhtRequest *LookupRequest(uint tid);
	void UnlinkRequest(DhtRequest *to_delete);
	DhtRequest *AllocateRequest(const DhtPeerID &peer_id);

	DhtRequest *SendPing(const DhtPeerID &peer_id);
	DhtRequest *SendFindNode(const DhtPeerID &peer_id);

	void SendPunch(SockAddr const& dst, SockAddr const& punchee);

	void AddTableIP(SockAddr const& addr)
	{
		uint32 addr4 = addr.get_addr4();
		bool inserted = _ip4s.insert(addr4).second;
		assert(inserted);
	}

	void RemoveTableIP(SockAddr const& addr)
	{
		uint32 addr4 = addr.get_addr4();
		assert(_ip4s.count(addr4) == 1);
		_ip4s.erase(addr4);
	}

	// Update the internal DHT tables with an id.
	DhtPeer *Update(const DhtPeerID &id, uint origin, bool seen = false, int rtt = INT_MAX);

	// Increase the error counter for a peer
	void UpdateError(const DhtPeerID &id, bool force_remove = false);
	
	uint CopyPeersFromBucket(uint bucket_id, DhtPeerID **list, uint numwant, int &wantfail, time_t min_age);

	// Find the numwant nodes closest to target
	// Returns the number of nodes found.
	uint FindNodes(const DhtID &target, DhtPeerID **list, uint numwant, int wantfail, time_t min_age);

	// uses FindNodes to assemble a list of nodes
	int AssembleNodeList(const DhtID &target, DhtPeerID** ids, int numwant, bool bootstrap = false);

#ifdef _DEBUG_MEM_LEAK
	int clean_up_dht_request();
#endif

	int BuildFindNodesPacket(smart_buffer &sb, DhtID &target_id, int size
		, SockAddr const& requestor, bool send_punches = false);

	// Get the storage container associated with a info_hash
	std::vector<VoteContainer>::iterator GetVoteStorageForID(DhtID const& key);

	// Get the storage container associated with a info_hash
	std::vector<StoredContainer>::iterator GetStorageForID(const DhtID &info_hash);

	// Retrieve N random peers.
	std::vector<StoredPeer> *GetPeersFromStore(const DhtID &info_hash, str* file_name, uint n);

	void hash_ip(SockAddr const& ip, sha1_hash& h);

	// add a vote to the vote store for 'target'. Fill in a vote
	// response into sb.
	void AddVoteToStore(smart_buffer& sb, DhtID& target
		, SockAddr const& addr, int vote);

	void AddPeerToStore(const DhtID &info_hash, cstr file_name, const SockAddr& addr, bool seed);

	void ExpirePeersFromStore(time_t expire_before);

	void GenerateWriteToken(sha1_hash *token, const DhtPeerID &peer_id);
	bool ValidateWriteToken(const DhtPeerID &peer_id, const byte *token);
	void RandomizeWriteToken();

	enum {
		PACKET_PING,
		PACKET_FIND_NODE,
		PACKET_GET_PEERS,
		PACKET_ANNOUNCE_PEER,
		PACKET_VOTE
	};

	bool ParseIncomingICMP(BencEntity &benc, const SockAddr& addr);

	bool IsCompatibleIPPeerIDPair(const SockAddr& addr, byte const* id);
	bool IsCompatibleIPPeerIDPair(const SockAddr& addr, DhtID const& id);

	void AddIP(smart_buffer& sb, byte const* id, SockAddr const& addr);

#if USE_DHTFEED
	void dht_name_resolved(const byte *info_hash, const byte *file_name);
	static void dht_name_resolved_static(void *ctx, const byte *info_hash, const byte *file_name);
	void dht_on_scrape(const byte *info_hash, int downloaders, int seeds);
	static void dht_on_scrape_static(void *ctx, const byte *info_hash, int downloaders, int seeds);
	void add_to_dht_feed(byte const* info_hash, char const* file_name);
	static void add_to_dht_feed_static(void *ctx, byte const* info_hash, char const* file_name);
#endif

	void put_transaction_id(smart_buffer& sb, Buffer tid);
	void put_version(smart_buffer& sb);
	void put_is_read_only(smart_buffer& sb);
	const unsigned char* get_version();
private:
	void send_put_response(smart_buffer& sb, Buffer& transaction_id,
			int packetSize, const DhtPeerID &peerID);
	void send_put_response(smart_buffer& sb, Buffer& transaction_id,
			int packetSize, const DhtPeerID &peerID, unsigned int error_code,
			char const* error_message);

public:
	bool ProcessQueryPing(DHTMessage &message, DhtPeerID &peerID, int packetSize);
	bool ProcessQueryFindNode(DHTMessage &message, DhtPeerID &peerID,
			int packetSize);
	bool ProcessQueryGetPeers(DHTMessage &message, DhtPeerID &peerID,
			int packetSize);
	bool ProcessQueryAnnouncePeer(DHTMessage &message, DhtPeerID &peerID,
			int packetSize);
	bool ProcessQueryVote(DHTMessage &message, DhtPeerID &peerID, int packetSize);
	bool ProcessQueryPut(DHTMessage &message, DhtPeerID &peerID, int packetSize);
	bool ProcessQueryGet(DHTMessage &message, DhtPeerID &peerID, int packetSize);

	bool ProcessQuery(DhtPeerID& peerID, DHTMessage &message, int packetSize);
	bool ProcessResponse(DhtPeerID& peerID, DHTMessage &message, int pkt_size,
			DhtRequest *req);
	bool ProcessError(DhtPeerID& peerID, DHTMessage &message, int pkt_size,
			DhtRequest *req);
	bool ProcessQueryPunch(DHTMessage &message, DhtPeerID &peerID
		, int packetSize);


	bool InterpretMessage(DHTMessage &message, const SockAddr& addr, int pkt_size);

	void GenRandomIDInBucket(DhtID &target, DhtBucket* bucket);
	uint PingStalestNode();

	void DoFindNodes(DhtID &target
		, IDhtProcessCallbackListener *process_callback
		, int flags = 0);

	void DoBootstrap();

#ifdef DHT_SEARCH_TEST
	void RunSearches();
#endif

	void DoVote(const DhtID &target, int vote, DhtVoteCallback* callb, void *ctx, int flags = 0);

	void DoScrape(const DhtID &target, DhtScrapeCallback *callb, void *ctx, int flags = 0);

	void ResolveName(DhtID const& target, DhtHashFileNameCallback* callb, void *ctx, int flags = 0);

	void DoAnnounce(const DhtID &target,
		DhtAddNodesCallback *callb,
		DhtPortCallback *pcb,
		cstr file_name,
		void *ctx,
		int flags);

	uint PingStalestInBucket(uint buck);

	// Implement IDhtProcessCallback::ProcessCallback(), for bootstrap callback
	void ProcessCallback();

	// the response from a node passed to AddNode()
	void OnAddNodeReply(void*& userdata, const DhtPeerID &peer_id
		, DhtRequest *req, DHTMessage &message, DhtProcessFlags flags);

	// the respons from a NICE ping (part of bucket maintanence)
	void OnPingReply(void*& userdata, const DhtPeerID &peer_id
		, DhtRequest *req, DHTMessage &message, DhtProcessFlags flags);

	static void AddNodeCallback(void *userdata, void *data2, int error
		, cstr hostname, const SockAddr& ip, uint32 time);

	void SetId(DhtID id);

	void Restart();
	void GenerateId();

	bool ParseKnownPackets(const SockAddr& addr, byte *buf, int pkt_size);
	bool ProcessIncoming(byte *buffer, size_t len, const SockAddr& addr);


	// Save all non-failed peers.
	// Save my peer id.
	// Don't save announced stuff.

	struct PackedDhtPeer {
		byte id[DHT_ID_SIZE];
		byte ip[4];
		byte port[2];
	};

	void SaveState();
	void LoadState();
};

void LoadDHTFeed();

#endif //__DHT_IMPL_H__
