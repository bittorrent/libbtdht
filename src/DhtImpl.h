#ifndef __DHT_IMPL_H__
#define __DHT_IMPL_H__

#include "dht.h"
#include <climits>
#include <assert.h> // for assert
#include <time.h> // for time_t
#include <string.h> // for memcmp
#include <vector>
#include <map>
#include <algorithm> // for min_element

#include "smart_ptr.h" // for smart_ptr
#include "blockallocator.h"
#include "Buffer.h"
#include "DHTMessage.h"
#include "utypes.h"
#include "bloom_filter.h"
#include "tailqueue.h"

// for logging dht activity
#if g_log_dht

void dht_log(char const* fmt, ...);

#else // g_log_dht

inline void dht_log(char const* fmt, ...) {}

#endif // g_log_dht

class BencEntity;
class DhtImpl;

//--------------------------------------------------------------------------------
//
// Types used by DhtImpl
//
//--------------------------------------------------------------------------------

class DhtID
{
public:
	DhtID(){ memset(id, 0, sizeof(id));}
	uint32 id[5];

	unsigned int GetBit(unsigned int index);

	bool operator <(const DhtID &n) const {
		for(uint i=0; i<5; i++) {
			if (id[i] > n.id[i]) return false;
			if (id[i] < n.id[i]) return true;
		}
		return false;
	}

	bool operator ==(const DhtID &n) const {
		return memcmp(id, n.id, 20) == 0;
	}

	bool operator !=(const DhtID &n) const {
		return memcmp(id, n.id, 20) != 0;
	}
};

/**
 Returns the bit at bitIndex.  id[0] contains the upper most bits and
 id[4] containes the lowest bits in the 160 bit string
*/
inline unsigned int DhtID::GetBit(unsigned int bitIndex)
{
	assert(bitIndex < 160);
	register unsigned int wordIndex = 4-(bitIndex >> 5);  // divide by 32 and invert
	return (id[wordIndex] >> (bitIndex & 0x1f)) & 0x00000001;
}

bool CopyBytesToDhtID(DhtID &id, const byte *b);
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
{
	previousBfCount = 0;
}

template<typename DataType>
inline PairContainerBase<DataType>::PairContainerBase(DataType const& valueIn, time_t time)
	: value(valueIn)
	, lastUse(time)
{
	previousBfCount = 0;
}

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
	long sequenceNum;
	byte rsaSignature[256];  // rsa signatures are either 128 or 256 bytes
	unsigned int rsaSignatureLen;
	std::vector<byte> rsaKey;
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
	time_t lastContactTime;

	// round trip time of this node. This is
	// a sliding average. Every time we hear from this
	// not we update our understanding of its RTT.
	// this is used to prioritize nodes with low RTT,
	// to speed up lookups
	// if this is INT_MAX, it means we don't know its RTT yet
	int rtt;

	// the time we've first seen this node. This can be
	// used for a "quarantine", where we don't forward this
	// node to others until we trust it more, i.e. have talked
	// to it again some time after the first time we saw it.
	time_t first_seen;

	ClientID client;
	DhtPeer *next;

	void ComputeSubPrefix(unsigned int bucketSpan, unsigned int numSubPrefixBits);
	int GetSubprefixInt() const {return subPrefixInt;}
	int GetSubprefixPositionBit() const {return subPrefixPositionBit;}
	void CopyAllButNext(const DhtPeer &src);

#if g_log_dht
	uint origin;
	DhtPeer() { origin = 0; }
#endif
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
 This is used by DhtProcess type callbacks stored in the DhtImpl's request table and
 tied to a transaction ID

 Typically used with OnReply()
*/
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
	typedef void (T::*ReplyCallback)(void *userdata, const DhtPeerID &peer_id, DhtRequest *req, DHTMessage &message, DhtProcessFlags flags);

	DhtRequestListener(T * listener, ReplyCallback callback):_pListener(listener), _pCallback(callback), _userdata(NULL){}
	DhtRequestListener(T * listener, ReplyCallback callback, void *userdata):_pListener(listener), _pCallback(callback), _userdata(userdata){}

	virtual void Callback(const DhtPeerID &peer_id, DhtRequest *req, DHTMessage &message, DhtProcessFlags flags){
		(_pListener->* _pCallback)(_userdata, peer_id, req, message, flags);
	}
protected:

	T *_pListener;
	ReplyCallback _pCallback;
	void *_userdata;
};

enum KademliaConstants
{
	KADEMLIA_K = 8,
	KADEMLIA_K_ANNOUNCE = 8,
	KADEMLIA_BUCKET_SIZE = 8, // MUST be a power of 2 for routing table optimization; see KADEMLIA_BUCKET_SIZE_POWER
	KADEMLIA_BUCKET_SIZE_POWER = 3, // MUST stay coordinated with KADEMLIA_BUCKET_SIZE

	// The sum of these two items should always be greater than 0.
	KADEMLIA_LOOKUP_OUTSTANDING = 4,  // initial dht searches should allow more outstanding lookups
	KADEMLIA_LOOKUP_OUTSTANDING_DELTA = -2, // How much to reduce the number of outstanding lookup requests allowed for
											// less agressive dht searches once some connectivity threshold is reached.
	KADEMLIA_BROADCAST_OUTSTANDING = 3,
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
	time_t last_active;

	bool InsertOrUpdateNode(DhtImpl* pDhtImpl, DhtPeer const& node, BucketListType bucketType, DhtPeer** pout);
	bool FindReplacementCandidate(DhtImpl* pDhtImpl, DhtPeer const& candidate, BucketListType bucketType, DhtPeer** pout);
	bool TestForMatchingPrefix(const DhtID &id);
	bool RemoveFromList(DhtImpl* pDhtImpl, const DhtID &id, BucketListType bucketType);
};

//--------------------------------------------------------------------------------
//
// DhtImpl
//
//--------------------------------------------------------------------------------

#define FAIL_THRES_NOCONTACT 1 // no contact?, lower thres...
#define FAIL_THRES_BAD_NOCONTACT 1 // no contact ever? delete quickly..

#define FAIL_THRES 2
#define FAIL_THRES_BAD 5 // really bad, force delete even if buckets are empty..

#define CROSBY_E (2*60) // age in second a peer must be before we include them in find nodes


struct SimpleBencoder {
	char *p;
	SimpleBencoder(char *a) { p=a; }
	void Out(cstr s);
	void put_buf(byte const* buf, int len);
};

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
		IDhtProcessCallbackListener *processListener;
		DhtPartialHashCompletedCallback *partialCallback;
		DhtAddNodesCallback *addnodesCallback;
		DhtScrapeCallback *scrapeCallback;
		DhtVoteCallback *voteCallback;
		DhtHashFileNameCallback *filenameCallback;
		DhtPortCallback *portCallback;
};

inline CallBackPointers::CallBackPointers():callbackContext(NULL),
	processListener(NULL),
	partialCallback(NULL),
	addnodesCallback(NULL),
	scrapeCallback(NULL),
	voteCallback(NULL),
	filenameCallback(NULL),
	portCallback(NULL)
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
		DhtFindNodeEntry nodes[KADEMLIA_K*4];		// Table of closest nodes
		static void FreeNodeEntry(DhtFindNodeEntry &ent) { if (ent.token.b) free(ent.token.b); }

	public:
		DhtLookupNodeList();
		DhtLookupNodeList(DhtPeerID** ids, unsigned int numId, const DhtID &target);
		virtual ~DhtLookupNodeList();
		DhtFindNodeEntry* FindQueriedPeer(const DhtPeerID &id);
		virtual void InsertPeer(const DhtPeerID &id, const DhtID &target);
		int size(){return numNodes;}
		DhtFindNodeEntry& operator[](const unsigned int index);
		void SetQueriedStatus(unsigned int index, QueriedStatus status);
		void SetAllQueriedStatus(QueriedStatus status);
		void SetNodeIds(DhtPeerID** ids, unsigned int numId, const DhtID &target);
		void CompactList();
};

inline DhtLookupNodeList::DhtLookupNodeList():numNodes(0)
{
	memset(nodes, 0, sizeof(nodes));
}

/**
Initializes the node list with the provided list of nodes.
*/
inline DhtLookupNodeList::DhtLookupNodeList(DhtPeerID** ids, unsigned int numId, const DhtID &target):numNodes(0)
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
		DhtProcessManager(DhtPeerID** ids, unsigned int numId, const DhtID &target):DhtLookupNodeList(ids,numId,target){}
		~DhtProcessManager();
		unsigned int AddDhtProcess(DhtProcessBase *process);
		void Start();
		void Next();
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
	protected:
		CallBackPointers callbackPointers;
		DhtID target;
		int target_len;
		smart_ptr<DhtImpl> impl;
		time_t start_time;
		DhtProcessManager &processManager;

		DhtProcessBase(DhtProcessManager &dpm):processManager(dpm){assert(false);} // this constructor should never be used.

		virtual void DhtSendRPC(const DhtFindNodeEntry &nodeInfo, const unsigned int transactionID) = 0;
		virtual void Schedule() = 0;
		virtual void CompleteThisProcess();

	public:
		static DHTMessage dummyMessage;

		DhtProcessBase(DhtImpl *pImpl, DhtProcessManager &dpm, const DhtID &target2, int target2_len, time_t startTime, const CallBackPointers &consumerCallbacks);
		virtual ~DhtProcessBase();
		virtual void Start();
		virtual void OnReply(void *userdata, const DhtPeerID &peer_id, DhtRequest *req, DHTMessage &message, DhtProcessFlags flags) = 0;
		virtual void ImplementationSpecificReplyProcess(void *userdata, const DhtPeerID &peer_id, DHTMessage &message, uint flags){}
};

inline void DhtProcessBase::Start()
{
	Schedule();
}

inline void DhtProcessBase::CompleteThisProcess()
{
	// let the process manager know that this phase of the dht process is complete
	// and to start the next phase of the process (or terminate if all phases are
	// complete).
	processManager.Next();
}


//*****************************************************************************
//
// DhtProcessManager  (additional definitions)
//
//*****************************************************************************
inline void DhtProcessManager::Start()
{
	_currentProcessNumber = 0;
	if(_dhtProcesses.size() > 0)
		_dhtProcesses[0]->Start();
}

inline void DhtProcessManager::Next()
{
	_currentProcessNumber++;  // increment to the next process
	if(_currentProcessNumber < _dhtProcesses.size())
		_dhtProcesses[_currentProcessNumber]->Start();
	else
		delete this; // all processes have completed; terminate the manager
}


//*****************************************************************************
//
// DhtLookupScheduler
//
//*****************************************************************************
/**
	This scheduler is optimized for use with "find_nodes" and "get_peers".  It
	will issue dht requests up to a maximum of KADEMLIA_LOOKUP_OUTSTANDING = 4
	out standing requests at a time by default or a different maximum if specified
	in the constructor or set using SetMaxOutstandingLookupQueries().
	after construction. As more nodes are added to the node list,
	additional requests will be made.  If a node with an outstanding request
	to it is designated as "slow" an additional request to another node will
	be issued (if available).
*/
class DhtLookupScheduler : public DhtProcessBase
{
	private:
		int maxOutstandingLookupQueries;

	protected:
		int numNonSlowRequestsOutstanding;
		int totalOutstandingRequests;

		DhtLookupScheduler(DhtProcessManager &dpm):DhtProcessBase(dpm){assert(false);}
		virtual void Schedule();
		virtual void ImplementationSpecificReplyProcess(void *userdata, const DhtPeerID &peer_id, DHTMessage &message, uint flags);
		void IssueOneAdditionalQuery();
		void IssueQuery(int nodeIndex);

	public:
		virtual void OnReply(void *userdata, const DhtPeerID &peer_id, DhtRequest *req, DHTMessage &message, DhtProcessFlags flags);
		DhtLookupScheduler(DhtImpl* pDhtImpl, DhtProcessManager &dpm, const DhtID &target2, int target2_len, time_t startTime, const CallBackPointers &consumerCallbacks, int maxOutstanding);
		void SetMaxOutstandingLookupQueries(int maxOutstanding);
};

inline DhtLookupScheduler::DhtLookupScheduler(DhtImpl* pDhtImpl, DhtProcessManager &dpm, const DhtID &target2, int target2_len, time_t startTime, const CallBackPointers &consumerCallbacks, int maxOutstanding)
	:DhtProcessBase(pDhtImpl,dpm,target2,target2_len,startTime,consumerCallbacks),
		maxOutstandingLookupQueries(maxOutstanding),numNonSlowRequestsOutstanding(0),totalOutstandingRequests(0)
{
	assert(maxOutstandingLookupQueries > 0);
#if g_log_dht
	dht_log("DhtLookupScheduler,instantiated,id,%d,time,%d\n", target.id[0], get_microseconds());
#endif
}

inline void DhtLookupScheduler::SetMaxOutstandingLookupQueries(int maxOutstanding)
{
	maxOutstandingLookupQueries = maxOutstanding;
	assert(maxOutstandingLookupQueries > 0);
}

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
	protected:
		int outstanding;

		DhtBroadcastScheduler(DhtProcessManager &dpm):DhtProcessBase(dpm),outstanding(0){assert(false);}
		virtual void Schedule();

	public:
		void OnReply(void *userdata, const DhtPeerID &peer_id, DhtRequest *req, DHTMessage &message, DhtProcessFlags flags);
		DhtBroadcastScheduler(DhtImpl* pDhtImpl, DhtProcessManager &dpm, const DhtID &target2
			, int target2_len, time_t startTime, const CallBackPointers &consumerCallbacks)
			:DhtProcessBase(pDhtImpl,dpm,target2,target2_len,startTime,consumerCallbacks),outstanding(0){}
};


//*****************************************************************************
//
// FindNodeDhtProcess		find_node
//
//*****************************************************************************
class FindNodeDhtProcess : public DhtLookupScheduler //public DhtProcessBase
{
	protected:
		byte target_bytes[20]; // used to store the bytes of the target DhtID

		virtual void DhtSendRPC(const DhtFindNodeEntry &nodeInfo, const unsigned int transactionID);
		virtual void CompleteThisProcess();

	public:

		FindNodeDhtProcess(DhtImpl* pDhtImpl, DhtProcessManager &dpm, const DhtID &target2
			, int target2_len, time_t startTime, const CallBackPointers &consumerCallbacks
			, int maxOutstanding = KADEMLIA_LOOKUP_OUTSTANDING);

		static DhtProcessBase* Create(DhtImpl* pImpl, DhtProcessManager &dpm,
			const DhtID &target2, int target2_len,
			CallBackPointers &cbPointers,
			int maxOutstanding = KADEMLIA_LOOKUP_OUTSTANDING);
};

inline FindNodeDhtProcess::FindNodeDhtProcess(DhtImpl* pDhtImpl, DhtProcessManager &dpm, const DhtID &target2
	, int target2_len, time_t startTime, const CallBackPointers &consumerCallbacks, int maxOutstanding)
	: DhtLookupScheduler(pDhtImpl,dpm,target2,target2_len,startTime,consumerCallbacks,maxOutstanding)
{
	DhtIDToBytes(target_bytes, target);
#if g_log_dht
	dht_log("FindNodeDhtProcess,instantiated,id,%d,time,%d\n", target.id[0], get_microseconds());
#endif
}


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
			a_ifhpfxl, // info hash prefix length (for info hashes less than 20 bytes)
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
			, int target2_len, time_t startTime, const CallBackPointers &consumerCallbacks
			, int maxOutstanding = KADEMLIA_LOOKUP_OUTSTANDING);
		~GetPeersDhtProcess();
		static DhtProcessBase* Create(DhtImpl* pImpl, DhtProcessManager &dpm,
			const DhtID &target2, int target2_len,
			CallBackPointers &cbPointers,
			bool seed = false,
			int maxOutstanding = KADEMLIA_LOOKUP_OUTSTANDING);
};

inline void GetPeersDhtProcess::CompleteThisProcess()
{
#if g_log_dht
	dht_log("GetPeersDhtProcess,completed,id,%d,time,%d\n", target.id[0], get_microseconds());
#endif
	processManager.CompactList();
	DhtProcessBase::CompleteThisProcess();
}

inline GetPeersDhtProcess::~GetPeersDhtProcess()
{
	delete gpArgumenterPtr;
}


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
			, int target2_len, time_t startTime, const CallBackPointers &consumerCallbacks);
		~AnnounceDhtProcess();
		virtual void Start();

		static DhtProcessBase* Create(DhtImpl* pDhtImpl, DhtProcessManager &dpm,
			const DhtID &target2, int target2_len,
			CallBackPointers &cbPointers,
			cstr file_name,
			bool seed);
};

inline void AnnounceDhtProcess::Start()
{
#if g_log_dht
	dht_log("AnnounceDhtProcess,start_announce,id,%d,time,%d\n", target.id[0], get_microseconds());
#endif
	processManager.SetAllQueriedStatus(QUERIED_NO);
	DhtProcessBase::Start();
}

inline AnnounceDhtProcess::~AnnounceDhtProcess()
{
	delete announceArgumenterPtr;
}


//*****************************************************************************
//
// ScrapeDhtProcess		get_peers with scrape
//
//*****************************************************************************
class ScrapeDhtProcess : public GetPeersDhtProcess
{
	private:
		// used to aggregate responses from scrapes
		bloom_filter* seeds;
		bloom_filter* downloaders;

	protected:
		virtual void ImplementationSpecificReplyProcess(void *userdata, const DhtPeerID &peer_id, DHTMessage &message, uint flags);
		virtual void CompleteThisProcess();

	public:
		ScrapeDhtProcess(DhtImpl* pDhtImpl, DhtProcessManager &dpm, const DhtID &target2, int target2_len, time_t startTime, const CallBackPointers &consumerCallbacks, int maxOutstanding);
		virtual ~ScrapeDhtProcess();

		static DhtProcessBase* Create(DhtImpl* pDhtImpl, DhtProcessManager &dpm,
			const DhtID &target2, int target2_len,
			CallBackPointers &cbPointers,
			int maxOutstanding);
};

inline ScrapeDhtProcess::ScrapeDhtProcess(DhtImpl* pDhtImpl, DhtProcessManager &dpm
	, const DhtID &target2, int target2_len, time_t startTime, const CallBackPointers &consumerCallbacks, int maxOutstanding)
	: GetPeersDhtProcess(pDhtImpl,dpm,target2,target2_len,startTime,consumerCallbacks,maxOutstanding)
{
	gpArgumenterPtr->enabled[a_scrape] = true;
	seeds = new bloom_filter(2048, 2);
	downloaders = new bloom_filter(2048, 2);
}

inline ScrapeDhtProcess::~ScrapeDhtProcess()
{
	delete seeds;
	delete downloaders;
}


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

		VoteDhtProcess(DhtImpl* pDhtImpl, DhtProcessManager &dpm, const DhtID &target2, int target2_len, time_t startTime, const CallBackPointers &consumerCallbacks);
		virtual ~VoteDhtProcess(){}
		void SetVoteValue(int value);
		virtual void Start();

		static DhtProcessBase* Create(DhtImpl* pImpl, DhtProcessManager &dpm,
								const DhtID &target2, int target2_len,
								CallBackPointers &cbPointers, int voteValue);
};

inline VoteDhtProcess::VoteDhtProcess(DhtImpl* pDhtImpl, DhtProcessManager &dpm, const DhtID &target2, int target2_len, time_t startTime, const CallBackPointers &consumerCallbacks)
											: DhtBroadcastScheduler(pDhtImpl,dpm,target2,target2_len,startTime,consumerCallbacks)
{
}

inline void VoteDhtProcess::SetVoteValue(int value)
{
	assert(value >= 0 && value <= 5);
	voteValue = value;
}

inline void VoteDhtProcess::Start()
{
	processManager.SetAllQueriedStatus(QUERIED_NO);
	DhtProcessBase::Start();
}


//--------------------------------------------------------------------------------

/**
 * DhtImpl
 *
 */
class DhtImpl : public IDht, public IDhtProcessCallbackListener
{
public:
	DhtImpl(UDPSocketInterface *_udp_socket_mgr, UDPSocketInterface *_udp6_socket_mgr
		, DhtSaveCallback* save, DhtLoadCallback* load);
	~DhtImpl();
	REFBASE;

private:
	void Initialize(UDPSocketInterface *_udp_socket_mgr, UDPSocketInterface *_udp6_socket_mgr );
public:

	// UDPSocketManagerObserver
	bool handleReadEvent(UDPSocketInterface *socket, byte *buffer, size_t len, const SockAddr& addr);
	bool handleICMP(UDPSocketInterface *socket, byte *buffer, size_t len, const SockAddr& addr);

	void Shutdown();
	void Tick();
	void Enable(bool enabled, int rate);
	bool IsEnabled();

	bool CanAnnounce();

	void Vote(void *ctx, const sha1_hash* info_hash, int vote, DhtVoteCallback* callb);

	void SetId(byte new_id_bytes[20]);
	void AnnounceInfoHash(
		const byte *info_hash,
		int info_hash_len,
		DhtPartialHashCompletedCallback *partial_callback,
		DhtAddNodesCallback *addnodes_callback,
		DhtPortCallback* pcb,
		cstr file_name,
		bool seed,
		void *ctx,
		bool performLessAgressiveSearch);

	void SetRate(int bytes_per_second);
	void SetVersion(char const* client, int major, int minor);
	void SetExternalIPCounter(ExternalIPCounter* ip);
	void SetAddNodeResponseCallback(DhtAddNodeResponseCallback* cb);
	void SetSHACallback(DhtSHACallback* cb);
	void SetPacketCallback(DhtPacketCallback* cb);

	void AddNode(const SockAddr& addr, void* userdata, uint origin);
	void AddBootstrapNode(SockAddr const& addr);

	void DumpBuckets();
	void DumpTracked();


	int GetProbeQuota();
	bool CanAddNode();
	int GetNumPeers();
	bool IsBusy();
	int GetBootstrapState();
	int GetRate();
	int GetQuota();
	int GetNumOutstandingAddNodes();
	int GetProbeRate();
	int GetNumPeersTracked();
	int GetNumPutItems();
	void CountExternalIPReport( const SockAddr& addr, const SockAddr& voter );


	//--------------------------------------------------------------------------------


#ifdef DHT_SEARCH_TEST
#define NUM_SEARCHES 10000
	static bool search_running = false;
#endif

#ifdef _DEBUG_MEM_LEAK
	std::vector<DhtProcess*> _dhtprocesses;
	int _dhtprocesses_init;

	void AddDhtProcess(DhtProcess *p);
	void RemoveDhtProcess(DhtProcess *p);
	int FreeRequests();
#endif


	DhtID _my_id;
	byte _my_id_bytes[20];
	byte _dht_utversion[4];
	DhtAddNodeResponseCallback* _add_node_callback;
	DhtSaveCallback* _save_callback;
	DhtLoadCallback* _load_callback;
	DhtPacketCallback* _packet_callback;
	DhtSHACallback* _sha_callback;
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
	std::vector<DhtBucket*> _buckets; // DHT buckets

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

#define MAX_PEERS (4*1000*1000)
	int _peers_tracked;

	uint32 _cur_token[2];
	uint32 _prev_token[2];
	int _dht_bootstrap; // -1: bootstrap ping has replied
						// -2: bootstrap find_nodes process has completed
						// 1:  dht not bootstrapped (initial condition)
						// >1: an error was received, _dth_bootstrap set with a large number of seconds for a count-down
	int _dht_bootstrap_failed; // a counter used to compute the back-off time for bootstrap re-tries
	int _dht_busy;
	bool _allow_new_job;
	bool _dht_enabled;

	int _refresh_bucket;		// Which bucket are we currently refreshing? -1 if disabled
	bool _refresh_bucket_force;	// Force bucket refresh, generally at start/restart
	int _dht_peers_count;
	int _outstanding_add_node;
	int _refresh_buckets_counter;	// Number of seconds since the last bucket was operated upon
	int _dht_quota;
	int _dht_rate;
	int _dht_probe_quota;
	int _dht_probe_rate;

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
		DHT_INVALID_PQ_BAD_PUT_KEY,
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

	void Account(int slot, int size);

	void DumpAccountingInfo();


#if !STABLE_VERSION || defined _DEBUG || defined BRANDED_MAC
	bool ValidateEncoding( const void * data, uint len );
#endif


	//--------------------------------------------------------------------------------


	void SendTo(const DhtPeerID &peer, const void *data, uint len);

	// determine which bucket an id belongs to
	int GetBucket(const DhtID &id);

	DhtBucket *CreateBucket(uint position);
	void SplitBucket(uint bucket_id);
	int NumBuckets() const;

	DhtRequest *LookupRequest(uint tid);
	void UnlinkRequest(DhtRequest *to_delete);
	DhtRequest *AllocateRequest(const DhtPeerID &peer_id);

	DhtRequest *SendPing(const DhtPeerID &peer_id);

	// Update the internal DHT tables with an id.
	DhtPeer *Update(const DhtPeerID &id, uint origin, bool seen = false, int rtt = INT_MAX);

	// Increase the error counter for a peer
	void UpdateError(const DhtPeerID &id);
	
	uint CopyPeersFromBucket(uint bucket_id, DhtPeerID **list, uint numwant, int &wantfail, time_t min_age);

	// Find the numwant nodes closest to target
	// Returns the number of nodes found.
	uint FindNodes(const DhtID &target, DhtPeerID **list, uint numwant, int wantfail, time_t min_age);

	// uses FindNodes to assemble a list of nodes
	int AssembleNodeList(const DhtID &target, DhtPeerID** ids, int numwant);


#ifdef _DEBUG_MEM_LEAK
	int clean_up_dht_request();
#endif

	int BuildFindNodesPacket(SimpleBencoder &sb, DhtID &target_id, int size);


	//ONLY FOR USE WITH InfoHashLessThan and GetStorageForID
	static int InfoHashCmp(const DhtID &id1, const DhtID &id2, int len);

	// Get the storage container associated with a info_hash
	std::vector<VoteContainer>::iterator GetVoteStorageForID(DhtID const& key);

	// Get the storage container associated with a info_hash
	std::vector<StoredContainer>::iterator GetStorageForID(const DhtID &info_hash, int len=20);

	// Retrieve N random peers.
	std::vector<StoredPeer> *GetPeersFromStore(const DhtID &info_hash, int info_hash_len, /*output param*/DhtID *correct_info_hash, str* file_name, uint n);

	void hash_ip(SockAddr const& ip, sha1_hash& h);

	// add a vote to the vote store for 'target'. Fill in a vote
	// response into sb.
	void AddVoteToStore(SimpleBencoder& sb, DhtID& target
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

	char *hexify(byte *b);

	bool ParseIncomingICMP(BencEntity &benc, const SockAddr& addr);

	bool IsCompatibleIPPeerIDPair(const SockAddr& addr, byte const* id);
	bool IsCompatibleIPPeerIDPair(const SockAddr& addr, DhtID const& id);

	void AddIP(SimpleBencoder& sb, byte const* id, SockAddr const& addr);

#if USE_DHTFEED
	void dht_name_resolved(const byte *info_hash, const byte *file_name);
	static void dht_name_resolved_static(void *ctx, const byte *info_hash, const byte *file_name);
	void dht_on_scrape(const byte *info_hash, int downloaders, int seeds);
	static void dht_on_scrape_static(void *ctx, const byte *info_hash, int downloaders, int seeds);
	void add_to_dht_feed(byte const* info_hash, char const* file_name);
	static void add_to_dht_feed_static(void *ctx, byte const* info_hash, char const* file_name);
#endif

	void put_transaction_id(SimpleBencoder& sb, Buffer tid, char const* end);
	void put_version(SimpleBencoder& sb, char const* end);

	bool ProcessQueryPing(const SockAddr &addr, DHTMessage &message, DhtPeerID &peerID, int packetSize);
	bool ProcessQueryFindNode(const SockAddr &addr, DHTMessage &message, DhtPeerID &peerID, int packetSize);
	bool ProcessQueryGetPeers(const SockAddr &addr, DHTMessage &message, DhtPeerID &peerID, int packetSize);
	bool ProcessQueryAnnouncePeer(const SockAddr &addr, DHTMessage &message, DhtPeerID &peerID, int packetSize);
	bool ProcessQueryVote(const SockAddr &addr, DHTMessage &message, DhtPeerID &peerID, int packetSize);
	bool ProcessQueryPut(const SockAddr &addr, DHTMessage &message, DhtPeerID &peerID, int packetSize);
	bool ProcessQueryGet(const SockAddr &addr, DHTMessage &message, DhtPeerID &peerID, int packetSize);

	bool ProcessQuery(const SockAddr& addr, DHTMessage &message, int packetSize);

	bool ProcessResponse(const SockAddr& addr, DHTMessage &message, int pkt_size);

	bool ProcessError(cstr e);

	bool InterpretMessage(DHTMessage &message, const SockAddr& addr, int pkt_size);

	void GenRandomIDInBucket(DhtID &target, DhtBucket &bucket);
	void GetStalestPeerInBucket(DhtPeer **ppeerFound, DhtBucket &bucket);

	void DoFindNodes(DhtID &target, int target_len, IDhtProcessCallbackListener *process_callback = NULL, bool performLessAgressiveSearch = true);

#ifdef DHT_SEARCH_TEST
	void RunSearches();
#endif

	void DoVote(const DhtID &target, int vote, DhtVoteCallback* callb, void *ctx, bool performLessAgressiveSearch = true);

	void DoScrape(const DhtID &target, DhtScrapeCallback *callb, void *ctx, bool performLessAgressiveSearch = true);

	void ResolveName(DhtID const& target, DhtHashFileNameCallback* callb, void *ctx, bool performLessAgressiveSearch = true);

	void DoAnnounce(const DhtID &target,
		int target_len,
		DhtPartialHashCompletedCallback *pcallb,
		DhtAddNodesCallback *callb,
		DhtPortCallback *pcb,
		cstr file_name,
		bool seed,
		void *ctx,
		bool performLessAgressiveSearch = true);

	void RefreshBucket(uint buck);
	uint PingStalestInBucket(uint buck);

	// Implement IDhtProcessCallback::ProcessCallback(), for bootstrap callback
	void ProcessCallback();

	void OnBootStrapPingReply(void *userdata, const DhtPeerID &peer_id, DhtRequest *req, DHTMessage &message, DhtProcessFlags flags);

	static void AddNodeCallback(void *userdata, void *data2, int error, cstr hostname, const SockAddr& ip, uint32 time);

	void SetId(DhtID id);

	void Restart();
	void GenerateId();

	bool ParseKnownPackets(const SockAddr& addr, byte *buf, int pkt_size);
	bool ProcessIncoming(byte *buffer, size_t len, const SockAddr& addr);


	// Save all non-failed peers.
	// Save my peer id.
	// Don't save announced stuff.

	struct PackedDhtPeer {
		byte id[20];
		byte ip[4];
		byte port[2];
	};

	void SaveState();
	void LoadState();

};

void LoadDHTFeed();

//*****************************************************************************
//
// DhtProcessBase  (members that needed to be defined after DhtImpl definition
//
//*****************************************************************************
inline DhtProcessBase::DhtProcessBase(DhtImpl *pImpl, DhtProcessManager &dpm, const DhtID &target2, int target2_len, time_t startTime, const CallBackPointers &consumerCallbacks):
	callbackPointers(consumerCallbacks),
	target(target2),
	target_len(target2_len),
	impl(pImpl),
	start_time(startTime),
	processManager(dpm)
{
	// let the DHT know there is an active process
	impl->_dht_busy++;
};

inline DhtProcessBase::~DhtProcessBase()
{
	impl->_dht_busy--;
}


#endif //__DHT_IMPL_H__
