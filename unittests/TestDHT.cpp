/*
Test the classes in:	dht.h
						DhtImpl.h
*/


// if defined, the testcase requiring user input will be enabled

//#include "StdAfx.h"
#undef _M_CEE_PURE
#undef new

#include <fstream>
#include <arpa/inet.h>

#include <boost/uuid/sha1.hpp>
using namespace boost::uuids::detail;

#include "gtest/gtest.h"
#include "gmock/gmock.h"

#include "utypes.h"
#include "endian_utils.h"
#include "dht.h"
#include "DhtImpl.h"
#include "bencoding.h"
#include "sha1_hash.h"
#include "UnitTestUDPSocket.h"

#ifdef ENABLE_SRP
#include "tommath.h"
#include "tomcrypt.h"
#endif

// Factor used in speed tests (use 1000 for meaningful results)
const unsigned int speedTestFactor = 10;

// constant values to use in the dht under test
const std::string DHTID_BYTES("AAAABBBBCCCCDDDDEEEE"); // the dht ID should be 20 bytes (characters) long.
// the next three sAddr* constants must remain coordinated with each other
const SockAddr    sAddr('zzzz', ('x' << 8) + 'x'); // ip = zzzz and socket = xx
const std::string sAddr_AddressAsString("zzzz"); // **** keep coordinated with sAddr above
const std::string sAddr_PortAsString("xx"); // **** keep coordinated with sAddr above
const int keyBufferSize = 2048;


// defined in DhtImpl.cpp
bool DhtVerifyHardenedID(const SockAddr& addr, byte const* node_id, DhtSHACallback* sha);
void DhtCalculateHardenedID(const SockAddr& addr, byte *node_id, DhtSHACallback* sha);

// defined in dht.cpp
sha1_hash generate_node_id_prefix(const SockAddr& addr, int random, DhtSHACallback* sha);

// utility objects

sha1_hash sha1_callback(const byte* buf, int len)
{
	sha1 hash;
	unsigned int digest[5];
	hash.process_bytes(buf, len);
	hash.get_digest(digest);
	for(unsigned short i = 0; i < 5; i++) {
		digest[i] = htonl(digest[i]);
	}
	sha1_hash ret(reinterpret_cast<byte*>(digest));
	return ret;
}

void fillTestDataBytes(std::vector<byte> &result, const Buffer &token, const std::string &one, const std::string &two) {
	char itoa_string[50];
	snprintf(itoa_string, 50, "%u", static_cast<unsigned int>(token.len));

	result.insert(result.end(), one.c_str(), one.c_str() + one.length());
	result.insert(result.end(), itoa_string, itoa_string + strlen(itoa_string));
	result.push_back(':');
	result.insert(result.end(), token.b, token.b + token.len);
	result.insert(result.end(), two.c_str(), two.c_str() + two.length());
}


/**
use this class for testing the mutable put and get rpc's
*/
class MutableComponents
{
public:
	std::string valueData;
	std::vector<byte> key;
	std::vector<byte> signature;

	bool operator==(MutableComponents &right);
};

/** all components must match for a true result */
bool MutableComponents::operator==(MutableComponents &right)
{
	if(valueData != right.valueData) return false;
	if(key != right.key) return false;
	if(signature != right.signature) return false;
	return true;
}


// utility functions

unsigned int CountSetBits(Buffer &data)
{
	unsigned int count = 0;
	for(unsigned int x=0; x<data.len; ++x)
	{
		if(data.b[x] & 0x01) ++count;
		if(data.b[x] & 0x02) ++count;
		if(data.b[x] & 0x04) ++count;
		if(data.b[x] & 0x08) ++count;
		if(data.b[x] & 0x10) ++count;
		if(data.b[x] & 0x20) ++count;
		if(data.b[x] & 0x40) ++count;
		if(data.b[x] & 0x80) ++count;
	}
	return count;
}

void SetDHT_my_id_Bytes(smart_ptr<DhtImpl> &dhtObj)
{
	dhtObj->SetId((byte*)DHTID_BYTES.c_str());
}

void BencStartDictionary(std::vector<byte> &bencString)
{
	bencString.push_back('d');
}

void BencEndDictionary(std::vector<byte> &bencString)
{
	bencString.push_back('e');
}

void BencStartList(std::vector<byte> &bencString)
{
	bencString.push_back('l');
}

void BencEndList(std::vector<byte> &bencString)
{
	bencString.push_back('e');
}

// take a string and bencode it into a list of bytes
void BencAddString(std::vector<byte> &bencString, const std::string &str)
{
	char stringSize[50];
	snprintf(stringSize, 50, "%u", static_cast<unsigned int>(str.size()));
	bencString.insert(bencString.end(), stringSize, stringSize + strlen(stringSize));
	bencString.push_back(':');
	bencString.insert(bencString.end(), str.c_str(), str.c_str() + str.size());
}

void BencAddInt(std::vector<byte> &bencString, const int value)
{
	char intChars[50];
	snprintf(intChars, 50, "%u", static_cast<unsigned int>(value));
	bencString.push_back('i');
	bencString.insert(bencString.end(), intChars, intChars + strlen(intChars));
	bencString.push_back('e');
}

void BencAddNameValuePair(std::vector<byte> &bencString, const std::string &name, const std::string &value)
{
	BencAddString(bencString, name);
	BencAddString(bencString, value);
}

void BencAddNameValuePair(std::vector<byte> &bencString, const char* name, const char* value)
{
	BencAddString(bencString, std::string(name));
	BencAddString(bencString, std::string(value));
}

void BencAddNameValuePair(std::vector<byte> &bencString, const char* name, const Buffer &value)
{
	BencAddString(bencString, std::string(name));

	char itoa_string[50];
	snprintf(itoa_string, 50, "%u", static_cast<unsigned int>(value.len));
	bencString.insert(bencString.end(), itoa_string, itoa_string + strlen(itoa_string));
	bencString.push_back(':');
	bencString.insert(bencString.end(), value.b, value.b + value.len);
}

void BencAddNameValuePair(std::vector<byte> &bencString, const std::string &name, const int value)
{
	BencAddString(bencString, name);
	BencAddInt(bencString, value);
}

void BencAddNameValuePair(std::vector<byte> &bencString, const char *name, const int value)
{
	BencAddString(bencString, std::string(name));
	BencAddInt(bencString, value);
}

void BencAddNameValuePair(std::vector<byte> &bencString, const std::string &name, const std::vector<byte> &value)
{
	BencAddNameValuePair(bencString, name.c_str(), Buffer(const_cast<unsigned char*>(&value.front()), value.size()));
}

void BencAddNameAndBencodedEntity(std::vector<byte> &bencString, const std::string &name, const std::vector<byte> &value)
{
	BencAddString(bencString, name);
	bencString.insert(bencString.end(), &value.front(), &value.front() + value.size());
}

void BencAddNameAndBencodedEntity(std::vector<byte> &bencString, const std::string &name, const std::string &value)
{
	BencAddNameAndBencodedEntity(bencString, name, std::vector<byte>(&value.front(), &value.front() + value.size()));
	/*BencAddString(bencString, name);
	AddBytes(bencString, value.c_str(), value.size());*/
}

void BencAddNameAndBencodedDictionary(std::vector<byte> &bencString, const std::string &name, const std::vector<byte> &value)
{
	BencAddNameAndBencodedEntity(bencString, name, value);
}

std::vector<byte> MakeRandomByteString(unsigned int numBytesLong)
{
	std::vector<byte> key;
	for(unsigned int x=0; x<numBytesLong; ++x){
		key.push_back(rand()%74 + 48); // make something in the alphanumeric range
	}
	return key;
}

std::vector<byte> MakeRandomKey20()
{
	return MakeRandomByteString(20);
}

bool GetToken(smart_ptr<DhtImpl> &dht, const std::string &idToUse, std::vector<byte> &tokenBytes, UnitTestUDPSocket &socket4)
{
	BencodedDict bDictGetPeer;
	SockAddr sAddr(0x7a7a7a7a,0x7878); // ip = zzzz and socket = xx
	Buffer token;

	if(idToUse.size() != 20) return false;

	// use this to get a token
	std::string bEncodedGetPeers = "d1:ad2:id20:" + idToUse + "9:info_hash20:mnopqrstuvwxyz123456e1:q9:get_peers1:t2:aa1:y1:qe";

	// do the get_peers to obtain a token
	socket4.Reset();
	dht->ProcessIncoming((byte*)bEncodedGetPeers.c_str(), bEncodedGetPeers.size(), sAddr);

	// get the bencoded string out of the socket
	std::string bencMessageGetPeerResponse = socket4.GetSentDataAsString();
	BencEntity bEntityGetPeer;

	// verify the bencoded string that went out the socket
	BencEntity::Parse((const byte *)bencMessageGetPeerResponse.c_str(), bEntityGetPeer, (const byte *)(bencMessageGetPeerResponse.c_str() + bencMessageGetPeerResponse.length()));

	// get the response dictionary for our get_peers query
	BencodedDict *dictForPeer = BencodedDict::AsDict(&bEntityGetPeer);
	EXPECT_TRUE(dictForPeer);
	if (!dictForPeer) {
		return false;
	}

	// now look into the response data
	BencodedDict *replyGetPeer = dictForPeer->GetDict("r");
	if (!replyGetPeer) {
		return false;
	}

	// Finally! Now get the token to use
	token.b = (byte*)replyGetPeer->GetString("token", &token.len);
	if(token.len == 0){
		return false;
	}

	// put the bytes into the consumer's vector
	tokenBytes.clear();
	for(unsigned int x=0; x<token.len; ++x)
	{
		tokenBytes.push_back(token.b[x]);
	}

	// cleanup the dht for the consumer
	dht->Tick();
	socket4.Reset();
	return true;
}

bool GetToken(smart_ptr<DhtImpl> &dht, std::vector<byte> &tokenBytes, UnitTestUDPSocket &socket4)
{
	return GetToken(dht, std::string("abcdefghij0101010101"), tokenBytes, socket4);
}

bool AnnouncePeer(smart_ptr<DhtImpl> &dht, const std::string &id, const std::vector<byte> &infoHash, const int port, const std::string &name, UnitTestUDPSocket &socket4)
{
	SockAddr sAddr(0x7a7a7a7a,0x7878); // ip = zzzz and socket = xx
	std::vector<byte>	messageBytes;
	std::vector<byte>	argumentBytes;

	// get a token
	std::vector<byte> token;
	if(!GetToken(dht, token, socket4) || token.size()==0)
	{	return false;
	}

	// build a message
	BencStartDictionary(argumentBytes);
	{
		BencAddNameValuePair(argumentBytes,"id",id);
		BencAddNameValuePair(argumentBytes,"info_hash",infoHash);
		BencAddNameValuePair(argumentBytes,"port",port);
		BencAddNameValuePair(argumentBytes,"name",name);
		BencAddNameValuePair(argumentBytes,"token",token);
	}
	BencEndDictionary(argumentBytes);

	BencStartDictionary(messageBytes);
	{
		BencAddNameAndBencodedDictionary(messageBytes,"a",argumentBytes);
		BencAddNameValuePair(messageBytes,"q","announce_peer");
		BencAddNameValuePair(messageBytes,"t","zz");
		BencAddNameValuePair(messageBytes,"y","q");
	}
	BencEndDictionary(messageBytes);

	// Send the announce_peer query
	dht->ProcessIncoming((byte*)&messageBytes.front(), messageBytes.size(), sAddr);

	// get the bencoded string out of the socket
	std::string bencMessage = socket4.GetSentDataAsString();
	BencEntity bEntity;

	// verify the bencoded string that went out the socket
	BencEntity::Parse((const byte *)bencMessage.c_str(), bEntity, (const byte *)(bencMessage.c_str() + bencMessage.length()));

	// did we get a valid dictionary
	BencodedDict *dict = BencodedDict::AsDict(&bEntity);
	if (!dict) {
		return false;
	}

	// is there a type and is it "r" for response
	cstr type = dict->GetString("y", 1);
	if (!type) {
		return false;
	}

	// check the transaction ID:  length=2, value = "zz"
	Buffer tid;
	tid.b = (byte*)dict->GetString("t", &tid.len);
	if (!tid.b || tid.len > 16 || strcmp((const char *)tid.b,"zz")) {
		return false;
	}

	// did we get an ip back
	Buffer ip;
	ip.b = (byte*)dict->GetString("ip", &ip.len);
	if(!ip.b){
		return false;
	}

	// now look into the response data
	BencodedDict *reply = dict->GetDict("r");
	if (!reply) {
		return false;
	}

	// did we get an id back
	byte *returnID = (byte*)reply->GetString("id", 20);
	if(!returnID){
		return false;
	}


	// cleanup the dht for the consumer
	dht->Tick();
	socket4.Reset();
	return true;
}

// vStr should be a correctly formatted character string of bencoded information (dictionary, list, string, int).
// This performs an IMMUTABLE PUT only.
bool PutBencString(smart_ptr<DhtImpl> &dhtTestObj, const std::string &id, const std::string &vStr, UnitTestUDPSocket &socket4)
{
	std::vector<byte>	messageBytes;
	std::vector<byte>	argumentBytes;

	BencodedDict bDictGetPeer;

	// get a token to use
	std::vector<byte> token;
	socket4.Reset();
	if(!GetToken(dhtTestObj, id, token, socket4)){
		return false;
	}

	BencStartDictionary(argumentBytes);
	{
		BencAddNameValuePair(argumentBytes,"id",id);
		BencAddNameValuePair(argumentBytes,"token",token);
		BencAddNameAndBencodedEntity(argumentBytes,"v", vStr);
	}
	BencEndDictionary(argumentBytes);

	BencStartDictionary(messageBytes);
	{
		BencAddNameAndBencodedDictionary(messageBytes,"a",argumentBytes);
		BencAddNameValuePair(messageBytes,"q","put");
		BencAddNameValuePair(messageBytes,"t","aa");
		BencAddNameValuePair(messageBytes,"y","q");
	}
	BencEndDictionary(messageBytes);

	// parse and send the message constructed above
	socket4.Reset();
	dhtTestObj->ProcessIncoming((byte*)&messageBytes.front(), messageBytes.size(), sAddr);

	// get the bencoded string out of the socket
	std::string bencMessage = socket4.GetSentDataAsString();
	BencEntity bEntity;

	// verify the bencoded string that went out the socket
	BencEntity::Parse((const byte *)bencMessage.c_str(), bEntity, (const byte *)(bencMessage.c_str() + bencMessage.length()));

	// did we get a valid dictionary
	BencodedDict *dict = BencodedDict::AsDict(&bEntity);
	if (!dict) {
		return false;
	}

	// now look into the response data
	BencodedDict *reply = dict->GetDict("r");
	if (!reply) {
		return false;
	}

	// cleanup the dht for the consumer
	dhtTestObj->Tick();
	socket4.Reset();
	return true;
}

#if 0
#if ENABLE_SRP
bool MakeRsaKey(rsa_key &keyOut, std::vector<byte> &exportedPublicKey)
{
	unsigned long publicKeyLen = keyBufferSize;
	unsigned char publicKeyBytes[keyBufferSize];

	// register tomcrypt algorithms
	register_prng(&rc4_desc);
	register_cipher(&aes_desc);
	register_hash(&sha1_desc);
	// use libtommath
	ltc_mp = ltm_desc;

	// generate the key
	prng_state prngState;
	rng_make_prng(512, find_prng("rc4"), &prngState, NULL);
	int prng_idx = find_prng("rc4");
	if(rsa_make_key(&prngState, prng_idx, 256, 65537, &keyOut) != CRYPT_OK ){
		return false;
	}

	// export the public key
	exportedPublicKey.clear();
	if(der_encode_sequence_multi(publicKeyBytes, &publicKeyLen,
		LTC_ASN1_INTEGER, 1UL,  keyOut.N,
		LTC_ASN1_INTEGER, 1UL,  keyOut.e,
		LTC_ASN1_EOL,     0UL,  NULL) != CRYPT_OK){
			return false;
	}
	for(unsigned int x=0; x<publicKeyLen; ++x)
		exportedPublicKey.push_back(publicKeyBytes[x]);

	return true;
}
#endif

#if ENABLE_SRP
// vStr should be a correctly formatted character string of bencoded information (dictionary, list, string, int).
// This performs MUTABLE PUT only.
bool MutablePutBencString(smart_ptr<DhtImpl> &dhtTestObj, const std::string &id, const std::string &vStr, int sequenceNum, rsa_key &key, UnitTestUDPSocket &socket4, std::vector<byte> &signatureOut)
{
	std::vector<byte>	messageBytes;
	std::vector<byte>	argumentBytes;
	BencodedDict bDictGetPeer;
	unsigned long publicKeyLen = keyBufferSize;
	unsigned char publicKeyBytes[keyBufferSize];
	Buffer publicKeyBuf; // just point this to PublicKeyBytes
	Buffer signatureBuf; // just point this to signatureBytes

	// get a token to use
	std::vector<byte> token;
	if(!GetToken(dhtTestObj, id, token, socket4)){
		return false;
	}

	unsigned long signatureLen = keyBufferSize;
	unsigned char signatureBytes[keyBufferSize];
	byte sha1Digest[SHA1_DIGESTSIZE];
	int err;

	// The string below must be the bencoding of what is put into the argumentBytes
	// for the sequence number and the 'v' element
	std::string sequenceToHash("3:seqi");
	sequenceToHash += toString(sequenceNum);
	sequenceToHash += "e1:v";
	sequenceToHash += vStr;
	SHA1::Hash((void*)sequenceToHash.c_str(), sequenceToHash.size(), (byte*)sha1Digest);
	prng_state prngState;
	rng_make_prng(512, find_prng("rc4"), &prngState, NULL);
	err = rsa_sign_hash((unsigned char*)sha1Digest, 20,
		                (unsigned char*)signatureBytes, &signatureLen,
						&prngState, 0,
						0, 0,
						&key);
	if(err != CRYPT_OK)
		return false;
	signatureBuf.b = (byte*)signatureBytes;
	signatureBuf.len = signatureLen;

	// export the public key
	err = der_encode_sequence_multi(publicKeyBytes, &publicKeyLen,
		LTC_ASN1_INTEGER, 1UL,  key.N,
		LTC_ASN1_INTEGER, 1UL,  key.e,
		LTC_ASN1_EOL,     0UL,  NULL);
	publicKeyBuf.b = (byte*)publicKeyBytes;
	publicKeyBuf.len = publicKeyLen;

	// assemble the benc string
	BencStartDictionary(argumentBytes);
	{
		BencAddNameValuePair(argumentBytes,"id",id);
		BencAddNameValuePair(argumentBytes,"k", publicKeyBuf);
		BencAddNameValuePair(argumentBytes,"seq",sequenceNum);
		BencAddNameValuePair(argumentBytes,"sig",signatureBuf);
		BencAddNameValuePair(argumentBytes,"token",token);
		BencAddNameAndBencodedEntity(argumentBytes,"v",vStr);
	}
	BencEndDictionary(argumentBytes);

	BencStartDictionary(messageBytes);
	{
		BencAddNameAndBencodedDictionary(messageBytes,"a",argumentBytes);
		BencAddNameValuePair(messageBytes,"q","put");
		BencAddNameValuePair(messageBytes,"t","aa");
		BencAddNameValuePair(messageBytes,"y","q");
	}
	BencEndDictionary(messageBytes);

	// parse and send the message constructed above
	dhtTestObj->ProcessIncoming((byte*)&messageBytes.front(), messageBytes.size(), sAddr);

	// get the bencoded string out of the socket
	std::string bencMessage = socket4.GetSentDataAsString();
	BencEntity bEntity;

	// verify the bencoded string that went out the socket
	BencEntity::Parse((const byte *)bencMessage.c_str(), bEntity, (const byte *)(bencMessage.c_str() + bencMessage.length()));

	// did we get a valid dictionary
	BencodedDict *dict = BencodedDict::AsDict(&bEntity);
	if (!dict) {
		return false;
	}

	// set the signature to return to the consumer
	signatureOut.clear();
	for(int x=0; x<signatureLen; ++x){
		signatureOut.push_back(signatureBytes[x]);
	}

	// cleanup the dht for the consumer
	dhtTestObj->Tick();
	socket4.Reset();
	return true;
}
#endif

#if ENABLE_SRP
bool MutablePutBencString(smart_ptr<DhtImpl> &dhtTestObj, const std::string &id, const std::string &vStr, int sequenceNum, rsa_key &key, UnitTestUDPSocket &socket4)
{
	std::vector<byte> dummy;
	return MutablePutBencString(dhtTestObj, id, vStr, sequenceNum, key, socket4, dummy);
}
#endif

#if ENABLE_SRP
std::string MutableGetString(smart_ptr<DhtImpl> &dhtTestObj, std::vector<byte> &keyIn, UnitTestUDPSocket &socket4)
{
	std::vector<byte> messageBytes;
	std::vector<byte> argumentBytes;
	std::string returnStr;

	BencodedDict bDictGetPeer;

	// divide the exported public key into the first 20 bytes for the target and the remainder for the 'k' overflow
	if(keyIn.size() <=21){ // key is too small
		return returnStr;
	}
	Buffer first20;
	Buffer remainder;
	first20.b = (byte*)&keyIn[0];
	first20.len = 20;
	remainder.b = (byte*)&keyIn[20];
	remainder.len = keyIn.size() - 20;

	BencStartDictionary(argumentBytes);
	{
		BencAddNameValuePair(argumentBytes,"id","abcdefghij0123456789");
		BencAddNameValuePair(argumentBytes,"k",remainder);
		BencAddNameValuePair(argumentBytes,"target",first20);
	}
	BencEndDictionary(argumentBytes);

	BencStartDictionary(messageBytes);
	{
		BencAddNameAndBencodedDictionary(messageBytes,"a",argumentBytes);
		BencAddNameValuePair(messageBytes,"q","get");
		BencAddNameValuePair(messageBytes,"t","aa");
		BencAddNameValuePair(messageBytes,"y","q");
	}
	BencEndDictionary(messageBytes);

	// parse and send the message constructed above
	socket4.Reset();
	dhtTestObj->ProcessIncoming((byte*)&messageBytes.front(), messageBytes.size(), sAddr);

	// get the bencoded string out of the socket
	std::string bencMessage = socket4.GetSentDataAsString();

	// verify the bencoded string that went out the socket
	BencEntity bEntity;
	BencEntity::Parse((const byte *)bencMessage.c_str(), bEntity, (const byte *)(bencMessage.c_str() + bencMessage.length()));

	// did we get a valid dictionary
	BencodedDict* dict = BencodedDict::AsDict(&bEntity);
	if (!dict) {
		return returnStr;
	}

	// is there a type and is it "r" for response
	cstr type = dict->GetString("y", 1);
	if (!type) {
		return returnStr;
	}

	// now look into the response data
	BencodedDict* reply = dict->GetDict("r");
	if (!reply) {
		return returnStr;
	}

	BencEntity* vElement;
	Buffer vBuf;
	vElement = reply->Get("v");
	if(vElement){
		vBuf.b = SerializeBencEntity(vElement, &vBuf.len);
	}
	else{
		vBuf.b = NULL;
		vBuf.len = 0;
	}

	returnStr.clear();
	for(unsigned int x=0; x<vBuf.len; ++x){
		returnStr += vBuf.b[x];
	}

	// cleanup the dht for the consumer
	dhtTestObj->Tick();
	socket4.Reset();

	return returnStr;
}
#endif
#endif

/**
If useShaHashOfKeyForTarget is true (AND keyInIsAlreadyShaHashed is false), then the
hash of the key will be placed in the 'target' of the *get* rpc and the 'key' element
will be filled with the entire key.

If keyInIsAlreadyShaHashed is true then useShaHashOfKeyForTarget is ignored and the
20 bytes in keyIn are used directly as the 'target' and the 'key' element is not
included in the *get* rpc.  This form of *get* may be either mutable or immutable.

NOTE: This Mode is Deprecated
If useShaHashOfKeyForTarget and keyInIsAlreadyShaHashed are both false, then keyIn
is divided so the its first 20 bytes are placed in the 'target' element and the
remaining bytes are placed in the 'key' element of the *get* rpc for a difinitively
mutable get invocation.
*/
MutableComponents GetComponents(smart_ptr<DhtImpl> &dhtTestObj, std::vector<byte> &keyIn, UnitTestUDPSocket &socket4, bool useShaHashOfKeyForTarget = false, bool keyInIsAlreadyShaHashed = false)
{
	Buffer targetBytes; // constructor initializes Buffer to 0, NULL
	Buffer keyBytes;
	std::vector<byte> messageBytes;
	std::vector<byte> argumentBytes;
	MutableComponents returnData;

	BencodedDict bDictGetPeer;

	if(keyInIsAlreadyShaHashed){
		targetBytes.b = &keyIn.front();
		targetBytes.len = keyIn.size();
	}
	else{
		if(useShaHashOfKeyForTarget){
			sha1_hash hash = sha1_callback(&keyIn.front(), keyIn.size());
			targetBytes.b = hash.value;
			targetBytes.len = 20;
			keyBytes.b = &keyIn.front();
			keyBytes.len = keyIn.size();
		}
		// this mode has been deprecated
		//else{
		//	// divide the exported public key into the first 20 bytes for the target and the remainder for the 'k' overflow
		//	if(keyIn.size() <=21){ // key is too small
		//		return returnData;
		//	}
		//	first20.b = (byte*)&keyIn[0];
		//	first20.len = 20;
		//	remainder.b = (byte*)&keyIn[20];
		//	remainder.len = keyIn.size() - 20;
		//}
	}

	BencStartDictionary(argumentBytes);
	{
		BencAddNameValuePair(argumentBytes,"id","abcdefghij0123456789");
		if(keyBytes.len != 0){
			BencAddNameValuePair(argumentBytes,"k",keyBytes);
		}
		BencAddNameValuePair(argumentBytes,"target",targetBytes);
	}
	BencEndDictionary(argumentBytes);

	BencStartDictionary(messageBytes);
	{
		BencAddNameAndBencodedDictionary(messageBytes,"a",argumentBytes);
		BencAddNameValuePair(messageBytes,"q","get");
		BencAddNameValuePair(messageBytes,"t","aa");
		BencAddNameValuePair(messageBytes,"y","q");
	}
	BencEndDictionary(messageBytes);

	// parse and send the message constructed above
	socket4.Reset();
	dhtTestObj->ProcessIncoming((byte*)&messageBytes.front(), messageBytes.size(), sAddr);

	// get the bencoded string out of the socket
	std::string bencMessage = socket4.GetSentDataAsString();

	// verify the bencoded string that went out the socket
	BencEntity bEntity;
	BencEntity::Parse((const byte *)bencMessage.c_str(), bEntity, (const byte *)(bencMessage.c_str() + bencMessage.length()));

	// did we get a valid dictionary
	BencodedDict* dict = BencodedDict::AsDict(&bEntity);
	if (!dict) {
		return returnData;
	}

	// is there a type and is it "r" for response
	cstr type = dict->GetString("y", 1);
	if (!type || type[0]!='r') {
		return returnData;
	}

	// now look into the response data
	BencodedDict* reply = dict->GetDict("r");
	if (!reply) {
		return returnData;
	}

	// get the bytes for the 'v' data
	BencEntity* vElement;
	Buffer vBuf;
	vElement = reply->Get("v");
	if(vElement){
		vBuf.b = SerializeBencEntity(vElement, &vBuf.len);
	}
	returnData.valueData.clear();
	for(int x=0; x<vBuf.len; ++x){
		returnData.valueData += vBuf.b[x];
	}

	// return the key info
	free(vBuf.b);
	vBuf.len = 0;
	vBuf.b = (byte*)reply->GetString("key", &vBuf.len);
	returnData.key.clear();
	for(int x=0; x<vBuf.len; ++x){
		returnData.key.push_back(vBuf.b[x]);
	}

	// return the signature info
	vBuf.len = 0;
	vBuf.b = (byte*)reply->GetString("sig", &vBuf.len);
	returnData.signature.clear();
	for(int x=0; x<vBuf.len; ++x){
		returnData.signature.push_back(vBuf.b[x]);
	}

	// cleanup the dht for the consumer
	dhtTestObj->Tick();
	socket4.Reset();

	return returnData;
}


// ***************************************************************************************
// DhtID class tests
// ***************************************************************************************
TEST(DhtID_Tests, Init)
{
	DhtID	TestID;
	uint	Sum = 0;

	for(uint x=0; x<5; ++x)
	{
		Sum += TestID.id[x];
	}
	EXPECT_TRUE(Sum == 0);
}


// test equality returns true on two identical non-zero objects
TEST(DhtID_Tests, EqualityOfEqualObjects)
{
	DhtID aDHT;
	DhtID bDHT;

	aDHT.id[0] = bDHT.id[0] = 0x80000000;
	aDHT.id[1] = bDHT.id[1] = 0x0;
	aDHT.id[2] = bDHT.id[2] = 0x0;
	aDHT.id[3] = bDHT.id[3] = 0x0;
	aDHT.id[4] = bDHT.id[4] = 0x00000001;

	EXPECT_TRUE(aDHT == bDHT);
}

// test that equality returns false for operator= on two non-equal objects
TEST(DhtID_Tests, InequalityOfUnequalObjects)
{
	DhtID aDHT;
	DhtID bDHT;

	aDHT.id[0] = bDHT.id[0] = 0x80000000;
	aDHT.id[1] = bDHT.id[1] = 0x0;
	aDHT.id[2] = bDHT.id[2] = 0x0;
	aDHT.id[3] = bDHT.id[3] = 0x0;
	aDHT.id[4] = 0x0;
	bDHT.id[4] = 0x00000001;

	EXPECT_FALSE(aDHT == bDHT);
}

// test less-than operator returns false on equal objects
TEST(DhtID_Tests, LessThanFalseForEqualObjects)
{
	DhtID aDHT;
	DhtID bDHT;

	aDHT.id[0] = bDHT.id[0] = 0x800f0040;
	aDHT.id[1] = bDHT.id[1] = 0x80f00040;
	aDHT.id[2] = bDHT.id[2] = 0x030f005a;
	aDHT.id[3] = bDHT.id[3] = 0xe00f0040;
	aDHT.id[4] = bDHT.id[4] = 0x00c00001;
	EXPECT_FALSE(aDHT < bDHT);
}

// test less-than operator returns true when a < b
TEST(DhtID_Tests, LessThanTrueForA_LT_B)
{
	DhtID aDHT;
	DhtID bDHT;

	aDHT.id[0] = bDHT.id[0] = 0x80000000;
	aDHT.id[1] = bDHT.id[1] = 0x0;
	aDHT.id[2] = bDHT.id[2] = 0x0;
	aDHT.id[3] = bDHT.id[3] = 0x0;
	aDHT.id[4] = 0x0;
	bDHT.id[4] = 0x00000001;
	EXPECT_TRUE(aDHT < bDHT);
}

// test less-than operator returns false when a > b
TEST(DhtID_Tests, LessThanFalseForA_GT_B)
{
	DhtID aDHT;
	DhtID bDHT;

	aDHT.id[0] = bDHT.id[0] = 0x80000000;
	aDHT.id[1] = bDHT.id[1] = 0x0;
	aDHT.id[2] = bDHT.id[2] = 0x0;
	aDHT.id[3] = bDHT.id[3] = 0x0;
	aDHT.id[4] = 0x00000001;
	bDHT.id[4] = 0x0;
	EXPECT_FALSE(aDHT < bDHT);
}

// test for not-equal is true for a difference in the high order byte
TEST(DhtID_Tests, HighOrderByteNotEqual)
{
	DhtID aDHT;
	DhtID bDHT;

	aDHT.id[0] = 0x80000000;
	bDHT.id[0] = 0x40000000;
	aDHT.id[1] = bDHT.id[1] = 0x0;
	aDHT.id[2] = bDHT.id[2] = 0x0;
	aDHT.id[3] = bDHT.id[3] = 0x0;
	aDHT.id[4] = bDHT.id[4] = 0x00000001;
	EXPECT_TRUE(aDHT != bDHT);
}

// test for not-equal is true for a difference in the low order byte
TEST(DhtID_Tests, LowOrderByteNotEqual)
{
	DhtID aDHT;
	DhtID bDHT;

	aDHT.id[0] = bDHT.id[0] = 0x80000000;
	aDHT.id[1] = bDHT.id[1] = 0x0;
	aDHT.id[2] = bDHT.id[2] = 0x0;
	aDHT.id[3] = bDHT.id[3] = 0x0;
	aDHT.id[4] = 0x0;
	bDHT.id[4] = 0x00000001;
	EXPECT_TRUE(aDHT != bDHT);
}

// test for not-equal is false for equal objects
TEST(DhtID_Tests, NotEqualFalseForEqualObjects)
{
	DhtID aDHT;
	DhtID bDHT;

	aDHT.id[0] = bDHT.id[0] = 0x80000000;
	aDHT.id[1] = bDHT.id[1] = 0x0;
	aDHT.id[2] = bDHT.id[2] = 0x0;
	aDHT.id[3] = bDHT.id[3] = 0x0;
	aDHT.id[4] = bDHT.id[4] = 0x00000001;
	EXPECT_FALSE(aDHT != bDHT);
}

// ***************************************************************************************
// Secure DHTID test
// ***************************************************************************************

TEST(TestSecureDHTID, SecureDHTIDTest)
{
#ifdef WIN32
	// XXX: ouch. akelly in r20567 made me do this.
	extern DWORD _tls_index;
	extern bool _tls_set;
	_tls_index = TlsAlloc();
	EXPECT_TRUE(_tls_index != TLS_OUT_OF_INDEXES);
	_tls_set = true;
#endif

	byte Id_1[20], Id_2[20];
	SockAddr addr_1 = SockAddr::parse_addr("4.3.2.1");
	SockAddr addr_2 = SockAddr::parse_addr("[2001:420:80:1::5]");

	for( int i = 0;  i <5;  i++) {
		DhtCalculateHardenedID(addr_1, Id_1, sha1_callback);
		DhtCalculateHardenedID(addr_2, Id_2, sha1_callback);
		EXPECT_TRUE(DhtVerifyHardenedID(addr_1, Id_1, sha1_callback));
		EXPECT_TRUE(DhtVerifyHardenedID(addr_2, Id_2, sha1_callback));
		EXPECT_TRUE(!DhtVerifyHardenedID(addr_2, Id_1, sha1_callback));
		EXPECT_TRUE(!DhtVerifyHardenedID(addr_1, Id_2, sha1_callback));
		addr_1._sin4++;
		addr_2._sin4++;
	}

	char const* ips[] =
	{
		"124.31.75.21",
		"21.75.31.124",
		"65.23.51.170",
		"84.124.73.14",
		"43.213.53.83"
	};

	uint8 seeds[] = { 1, 86, 22, 65, 90 };

	uint8 prefixes[][4] =
	{
		{ 0xf7, 0x66, 0xf9, 0xf5 },
		{ 0x7e, 0xe0, 0x47, 0x79 },
		{ 0x76, 0xa6, 0x26, 0xff },
		{ 0xbe, 0xb4, 0xe6, 0x19 },
		{ 0xac, 0xe5, 0x61, 0x3a },
	};

	for (int i = 0; i < 5; ++i) {
		SockAddr addr = SockAddr::parse_addr(ips[i]);
		sha1_hash id = generate_node_id_prefix(addr, seeds[i], sha1_callback);
		for (int j = 0; j < 4; ++j) {
			EXPECT_EQ(prefixes[i][j], id[j]);
		}
	}
}

#if 0 //TODO
extern CRITICAL_SECTION g_csTickWrapping;

void InitDHTTestEnvironment()
{
#ifdef WIN32
	InitializeCriticalSection(&g_csTickWrapping);
	// XXX: ouch. akelly in r20567 made me do this.
	extern DWORD _tls_index;
	extern bool _tls_set;
	_tls_index = TlsAlloc();
	EXPECT_TRUE(_tls_index != TLS_OUT_OF_INDEXES);
	_tls_set = true;
#endif // WIN32
	Network_Initialize_CriticalSection();
	UpdateGlobalCurTime();
	Log_Init();
	g_net_testmode = true;
	seedMT(time(NULL));
#if ENABLE_SRP
	BTInitializeCriticalSection(&g_prng_mutex, "prng");
#endif // ENABLE_SRP

	{
		BtScopedLock _l;
		TorrentSession::_g_channel = new BandwidthChannel;
		TorrentSession::_g_channel->AddRef();
		TorrentSession::_g_channel->Insert();

		TorrentSession::_disk_congestion_channel = new BandwidthChannel;
		TorrentSession::_disk_congestion_channel->AddRef();
		TorrentSession::_disk_congestion_channel->Insert();

		TorrentSession::_tcp_channel = new BandwidthChannel;
		TorrentSession::_tcp_channel->AddRef();
		TorrentSession::_tcp_channel->Insert();

		// make dummy dht.dat.* files
		tstring path = ComputeStoragePath();
		if(path[path.size()-1] == '\\')
			path[path.size()-1] = '\0';
		tstrcpy(_storage_path, path.c_str());
		tstring dhtDat = MakeStorageFilename(_T("\\dht.dat"));
		tstring dhtDatNew = MakeStorageFilename(_T("\\dht.dat.new"));
		tstring dhtDatOld = MakeStorageFilename(_T("\\dht.dat.old"));

		std::fstream file;
		file.open(to_ansi(dhtDat.c_str()), std::ios_base::out);
		file << "text" << std::endl;
		file.close();

		std::fstream fileNew;
		fileNew.open(to_ansi(dhtDatNew.c_str()), std::ios_base::out);
		fileNew << "text" << std::endl;
		fileNew.close();

		std::fstream fileOld;
		fileOld.open(to_ansi(dhtDatOld.c_str()), std::ios_base::out);
		fileOld << "text" << std::endl;
		fileOld.close();
	}

	// start network thread before installer so that
	// we can use our own http downloader for toolbars
	// and installer graphics (and collect network
	// performance stats)
	Network_Initialize();

	// register tomcrypt algorithms
	register_prng(&rc4_desc);
	register_cipher(&aes_desc);
	register_hash(&sha1_desc);
	// use libtommath
	ltc_mp = ltm_desc;
}
#endif

// ***************************************************************************************
// DataStore class tests
// ***************************************************************************************

TEST(TestDataStore, TestDataStore_AddPairToList)
{
	SockAddr addr;
	DataStore<DhtID, int> ds;
	DataStore<DhtID, int>::pair_iterator it;
	PairContainerBase<int>* containerPtr;

	DhtID key1, key2, key3, key4;
	key1.id[0] = 1;
	key2.id[0] = 2;
	key3.id[0] = 3;
	key4.id[0] = 4;

	// make a hash of the address for the DataStores to use to record usage of an item
	sha1_hash hash = sha1_callback(reinterpret_cast<const byte*>(addr.get_hash_key()), addr.get_hash_key_len());
	time_t g_cur_time = time(NULL);

	// look for a key when no keys have been added
	it = ds.FindInList(key1, g_cur_time, hash);
	ASSERT_TRUE(it == ds.end()) << "A end iterator should have been returned from an attempt to find something in an empty list.";

	// add keys in reverse order and check that they are inserted in ascending order
	ds.AddPairToList(hash, key3,33,&containerPtr);
	ds.AddPairToList(hash, key2,22,&containerPtr);
	ds.AddPairToList(hash, key1,11,&containerPtr);
	ASSERT_EQ(3,ds.pair_list.size()); // there should now be 3 peers total

	std::pair<const DhtID, PairContainerBase<int> > compare[] = {
		std::pair<const DhtID, PairContainerBase<int> >(key1, 11),
		std::pair<const DhtID, PairContainerBase<int> >(key2, 22),
		std::pair<const DhtID, PairContainerBase<int> >(key3, 33),
	};

	EXPECT_TRUE(std::equal(ds.pair_list.begin(), ds.pair_list.end(), compare));

	// add the same key and see that the list size doesn't change
	ds.AddPairToList(hash, key3,33,&containerPtr);
	ds.AddPairToList(hash, key3,33,&containerPtr);
	ASSERT_EQ(3,ds.pair_list.size()); // there should now be 5 peers total

	// test the find for a key in the list
	it = ds.FindInList(key3, g_cur_time, hash);
	EXPECT_TRUE(it->second.value == 33);
	it = ds.FindInList(key2, g_cur_time, hash);
	EXPECT_TRUE(it->second.value == 22);
	it = ds.FindInList(key1, g_cur_time, hash);
	EXPECT_TRUE(it->second.value == 11);

	// test the find for a key that is NOT in the list
	it = ds.FindInList(key4, g_cur_time, hash);
	EXPECT_TRUE(it == ds.end());
}

TEST(TestDataStore, TestDataStore_AddKeyToList)
{
	SockAddr addr;
	DataStore<DhtID, int> ds;
	DataStore<DhtID, int>::pair_iterator it;
	PairContainerBase<int>* containerPtr;

	DhtID key1, key2, key3, key4;
	key1.id[0] = 1;
	key2.id[0] = 2;
	key3.id[0] = 3;
	key4.id[0] = 4;

	// make a hash of the address for the DataStores to use to record usage of an item
	sha1_hash hash = sha1_callback(reinterpret_cast<const byte*>(addr.get_hash_key()), addr.get_hash_key_len());
	time_t g_cur_time = time(NULL);

	// look for a key when no keys have been added
	it = ds.FindInList(key1, g_cur_time, hash);
	ASSERT_TRUE(it == ds.end());

	// add keys in reverse order and check that they are inserted in ascending order
	ds.AddKeyToList(hash, key3,&containerPtr);
	containerPtr->value=33;
	ds.AddKeyToList(hash, key2,&containerPtr);
	containerPtr->value=22;
	ds.AddKeyToList(hash, key1,&containerPtr);
	containerPtr->value=11;
	ASSERT_EQ(3,ds.pair_list.size()); // there should now be 3 peers total

	std::pair<const DhtID, PairContainerBase<int> > compare[] = {
		std::pair<const DhtID, PairContainerBase<int> >(key1, 11),
		std::pair<const DhtID, PairContainerBase<int> >(key2, 22),
		std::pair<const DhtID, PairContainerBase<int> >(key3, 33),
	};

	EXPECT_TRUE(std::equal(ds.pair_list.begin(), ds.pair_list.end(), compare));

	// add the same key and see that the list size doesn't change
	ds.AddKeyToList(hash, key3,&containerPtr);
	ds.AddKeyToList(hash, key3,&containerPtr);
	ASSERT_EQ(3,ds.pair_list.size()); // there should now be 5 peers total

	// test the find for a key in the list
	it = ds.FindInList(key3, g_cur_time, hash);
	EXPECT_TRUE(it->second.value == 33);
	it = ds.FindInList(key2, g_cur_time, hash);
	EXPECT_TRUE(it->second.value == 22);
	it = ds.FindInList(key1, g_cur_time, hash);
	EXPECT_TRUE(it->second.value == 11);

	// test the find for a key that is NOT in the list
	it = ds.FindInList(key4, g_cur_time, hash);
	EXPECT_TRUE(it == ds.end());
}


TEST(TestDataStore, TestDataStore_FindInList)
{
	SockAddr addr;
	DataStore<DhtID, int> ds;
	DataStore<DhtID, int>::pair_iterator it;
	PairContainerBase<int>* containerPtr;

	DhtID key1, key2, key3, key4;
	key1.id[0] = 1;
	key2.id[0] = 2;
	key3.id[0] = 3;
	key4.id[0] = 4;

	// make a hash of the address for the DataStores to use to record usage of an item
	sha1_hash hash = sha1_callback(reinterpret_cast<const byte*>(addr.get_hash_key()), addr.get_hash_key_len());
	time_t g_cur_time = time(NULL);

	// look for a key when no keys have been added
	it = ds.FindInList(key1, g_cur_time, hash);
	ASSERT_TRUE(it == ds.end()) << "An end iterator should have been returned from an attempt to find something in an empty list.";

	// add keys in reverse order and check that they are inserted in ascending order
	ds.AddPairToList(hash, key4, 44, &containerPtr);
	ds.AddPairToList(hash, key2, 22, &containerPtr);
	ds.AddPairToList(hash, key1, 11, &containerPtr);

	// look for a key that is not in the list
	it = ds.FindInList(key3, g_cur_time, hash);
	ASSERT_TRUE(it == ds.end()) << "An end iterator should have been returned from an attempt to find something not in the list.";
}


TEST(TestDataStore, TestDataStore_EliminateTimeouts)
{
	SockAddr addr;
	DataStore<DhtID, int> ds(7200);
	PairContainerBase<int>* containerPtr;
	int numEliminated;

	DhtID key1, key2, key3, key4;
	key1.id[0] = 1;
	key2.id[0] = 2;
	key3.id[0] = 3;
	key4.id[0] = 4;

	// make a hash of the address for the DataStores to use to record usage of an item
	sha1_hash hash = sha1_callback(reinterpret_cast<const byte*>(addr.get_hash_key()), addr.get_hash_key_len());

	// test elimination when list is empty
	try
	{
		numEliminated = ds.EliminateTimeouts(8000); // use a time greater than the max time provided to the constructor
	}
	catch(...)
	{
		FAIL() << "An exception was thrown when eliminating from an empty list.";
	}
	EXPECT_EQ(0,numEliminated) << "The list was empty, there shouldn't be any eliminations";
	EXPECT_EQ(0,ds.pair_list.size());

	// add 4 items (with default time of 0) and eliminate all 4 items
	ds.AddPairToList(hash, key1,11,&containerPtr,0);
	ds.AddPairToList(hash, key2,22,&containerPtr,0);
	ds.AddPairToList(hash, key3,33,&containerPtr,0);
	ds.AddPairToList(hash, key4,44,&containerPtr,0);
	try
	{
		numEliminated = ds.EliminateTimeouts(8000); // use a time greater than the max time provided to the constructor
	}
	catch(...)
	{
		FAIL() << "An exception was thrown when eliminating everything in the list.";
	}
	EXPECT_EQ(4,numEliminated) << "4 items should have been eliminated from the list";
	EXPECT_EQ(0,ds.pair_list.size());

	// add 4 items with none old enough to eliminate
	ds.AddPairToList(hash, key1,11,&containerPtr,7000);
	ds.AddPairToList(hash, key2,22,&containerPtr,7000);
	ds.AddPairToList(hash, key3,33,&containerPtr,7000);
	ds.AddPairToList(hash, key4,44,&containerPtr,7000);
	try
	{
		numEliminated = ds.EliminateTimeouts(8000); // use a time greater than the max time provided to the constructor
	}
	catch(...)
	{
		FAIL() << "An exception was thrown when eliminating nothing list.";
	}
	EXPECT_EQ(0,numEliminated) << "no items should have been eliminated from the list";
	EXPECT_EQ(4,ds.pair_list.size());
/*	EXPECT_TRUE(ds.pair_list[0].key == key1);
	EXPECT_TRUE(ds.pair_list[1].key == key2);
	EXPECT_TRUE(ds.pair_list[2].key == key3);
	EXPECT_TRUE(ds.pair_list[3].key == key4);
*/
	// add 4 items with one old enough to eliminate
	ds.AddPairToList(hash, key1,11,&containerPtr,0);
	ds.AddPairToList(hash, key2,22,&containerPtr,7000);
	ds.AddPairToList(hash, key3,33,&containerPtr,7000);
	ds.AddPairToList(hash, key4,44,&containerPtr,7000);
	try
	{
		numEliminated = ds.EliminateTimeouts(8000); // use a time greater than the max time provided to the constructor
	}
	catch(...)
	{
		FAIL() << "An exception was thrown when eliminating from the beginning of the list.";
	}
	EXPECT_EQ(1,numEliminated) << "only 1 item should have been eliminated from the list";
	EXPECT_EQ(3,ds.pair_list.size());
/*	EXPECT_TRUE(ds.pair_list[0].key == key2);
	EXPECT_TRUE(ds.pair_list[1].key == key3);
	EXPECT_TRUE(ds.pair_list[2].key == key4);
*/
	// repeat above but from the other end
	ds.AddPairToList(hash, key1,11,&containerPtr,7000);
	ds.AddPairToList(hash, key2,22,&containerPtr,7000);
	ds.AddPairToList(hash, key3,33,&containerPtr,7000);
	ds.AddPairToList(hash, key4,44,&containerPtr,0);
	try
	{
		numEliminated = ds.EliminateTimeouts(8000); // use a time greater than the max time provided to the constructor
	}
	catch(...)
	{
		FAIL() << "An exception was thrown when eliminating from the end of the list.";
	}
	EXPECT_EQ(1,numEliminated) << "only 1 item should have been eliminated from the list";
	EXPECT_EQ(3,ds.pair_list.size());
/*	EXPECT_TRUE(ds.pair_list[0].key == key1);
	EXPECT_TRUE(ds.pair_list[1].key == key2);
	EXPECT_TRUE(ds.pair_list[2].key == key3);
*/
	// set up to eliminate from the middle
	ds.AddPairToList(hash, key1,11,&containerPtr,7000);
	ds.AddPairToList(hash, key2,22,&containerPtr,0);
	ds.AddPairToList(hash, key3,33,&containerPtr,0);
	ds.AddPairToList(hash, key4,44,&containerPtr,7000);
	try
	{
		numEliminated = ds.EliminateTimeouts(8000); // use a time greater than the max time provided to the constructor
	}
	catch(...)
	{
		FAIL() << "An exception was thrown when eliminating from the middle of the list.";
	}
	EXPECT_EQ(2,numEliminated) << "only 2 items should have been eliminated from the list";
	EXPECT_EQ(2,ds.pair_list.size());
//	EXPECT_TRUE(ds.pair_list[0].key == key1);
//	EXPECT_TRUE(ds.pair_list[1].key == key4);
}

TEST(TestDataStore, TestDataStore_RemoveItem)
{
	SockAddr addr;
	DataStore<DhtID, int> ds(7200);
	PairContainerBase<int>* containerPtr;
	int numEliminated;

	DhtID key1, key2, key3, key4, key5;
	key1.id[0] = 1;
	key2.id[0] = 2;
	key3.id[0] = 3;
	key4.id[0] = 4;
	key5.id[0] = 5;

	// make a hash of the address for the DataStores to use to record usage of an item
	sha1_hash hash = sha1_callback(reinterpret_cast<const byte*>(addr.get_hash_key()), addr.get_hash_key_len());

	// test removing from an empty list
	try
	{
		numEliminated = ds.RemoveItem(key2);
	}
	catch(...)
	{
		FAIL() << "An exception was thrown when eliminating from an empty list.";
	}
	EXPECT_EQ(0,numEliminated) << "The list was empty, there shouldn't be any eliminations";
	EXPECT_EQ(0,ds.pair_list.size());

	// add 4 items try to remove something not there
	ds.AddPairToList(hash, key1,11,&containerPtr,0);
	ds.AddPairToList(hash, key2,22,&containerPtr,0);
	ds.AddPairToList(hash, key3,33,&containerPtr,0);
	ds.AddPairToList(hash, key5,55,&containerPtr,0);
	try
	{
		numEliminated = ds.RemoveItem(key4);
	}
	catch(...)
	{
		FAIL() << "An exception was thrown when eliminating from an empty list.";
	}
	EXPECT_EQ(0,numEliminated) << "The item to be removed was not in the list, nothing should have been removed";
	EXPECT_EQ(4,ds.pair_list.size());

	// remove from the beginning of the list
	try
	{
		numEliminated = ds.RemoveItem(key1);
	}
	catch(...)
	{
		FAIL() << "An exception was thrown when eliminating from an empty list.";
	}
	EXPECT_EQ(1,numEliminated) << "A single item should have been removed";
	EXPECT_EQ(3,ds.pair_list.size());

	// remove from the end of the list
	try
	{
		numEliminated = ds.RemoveItem(key5);
	}
	catch(...)
	{
		FAIL() << "An exception was thrown when eliminating from an empty list.";
	}
	EXPECT_EQ(1,numEliminated) << "A single item should have been removed";
	EXPECT_EQ(2,ds.pair_list.size());
}

TEST(TestDataStore, TestDataStore_EvictLeastUsed)
{
	DataStore<DhtID, int> ds(500, 0, 4); // max age, current time, max size
	DataStore<DhtID, int>::pair_iterator it;
	PairContainerBase<int>* containerPtr;
	int numEliminated;

	SockAddr addr1, addr2, addr3, addr4;
	addr1.set_addr4(0xff000000);
	addr2.set_addr4(0x00ff0000);
	addr3.set_addr4(0x0000ff00);
	addr4.set_addr4(0x000000ff);

	DhtID key1, key2, key3, key4, key5;
	key1.id[0] = 1;
	key2.id[0] = 2;
	key3.id[0] = 3;
	key4.id[0] = 4;
	key5.id[0] = 5;

	time_t g_cur_time = time(NULL);

	// make a hash of the address for the DataStores to use to record usage of an item
	sha1_hash hash1 = sha1_callback(reinterpret_cast<const byte*>(addr1.get_hash_key()), addr1.get_hash_key_len());
	sha1_hash hash2 = sha1_callback(reinterpret_cast<const byte*>(addr2.get_hash_key()), addr2.get_hash_key_len());
	sha1_hash hash3 = sha1_callback(reinterpret_cast<const byte*>(addr3.get_hash_key()), addr3.get_hash_key_len());
	sha1_hash hash4 = sha1_callback(reinterpret_cast<const byte*>(addr4.get_hash_key()), addr4.get_hash_key_len());

	// put the initial items into the list using hash1
	ds.AddPairToList(hash1, key1,11,&containerPtr,0);
	ds.AddPairToList(hash1, key2,22,&containerPtr,0);
	ds.AddPairToList(hash1, key3,33,&containerPtr,0);
	ds.AddPairToList(hash1, key4,44,&containerPtr,0);

	// put activity onto items 1, 2, and 4 (no activity on item 3)
	ds.FindInList(key1, g_cur_time, hash2);
	ds.FindInList(key2, g_cur_time, hash2);
	ds.FindInList(key4, g_cur_time, hash2);
	ds.FindInList(key1, g_cur_time, hash3);
	ds.FindInList(key2, g_cur_time, hash3);

	try
	{
		numEliminated = ds.EvictLeastUsed();
	}
	catch(...)
	{
		FAIL() << "An exception was thrown when Evicting an unused item from the list";
	}
	EXPECT_EQ(1,numEliminated) << "The item to be removed was not in the list, nothing should have been removed";
	EXPECT_EQ(3,ds.pair_list.size());

	// look for key 3 - it should have been evicted
	it = ds.FindInList(key3, g_cur_time, hash4);
	ASSERT_FALSE(it != ds.end()) << "The item that should have been removed is still in the list.";

	// make an update happen, then add all items back so everything is in the current bloom filter.
	// Items 1, 2, and 4 should now have a history in the previous bloom filter estimated count.
	ds.UpdateUsage(400); // use a time greater than half of the max age (500) specified in the constructor
	ds.AddPairToList(hash1, key1,11,&containerPtr,450);
	ds.AddPairToList(hash1, key2,22,&containerPtr,450);
	ds.AddPairToList(hash1, key3,33,&containerPtr,450);
	ds.AddPairToList(hash1, key4,44,&containerPtr,450);
	// again, item 3 should be evicted
	try
	{
		numEliminated = ds.EvictLeastUsed();
	}
	catch(...)
	{
		FAIL() << "An exception was thrown when Evicting an unused item from the list";
	}
	EXPECT_EQ(1,numEliminated) << "The item to be removed was not in the list, nothing should have been removed";
	EXPECT_EQ(3,ds.pair_list.size());

	// look for key 3 - it should have been evicted
	it = ds.FindInList(key3, g_cur_time, hash4);
	ASSERT_TRUE(it == ds.end()) << "The item that should have been removed is still in the list.";

	// add a new item to the end of the list and see that it is evicted without error
	ds.AddPairToList(hash1, key5,55,&containerPtr,455);
	try
	{
		numEliminated = ds.EvictLeastUsed();
	}
	catch(...)
	{
		FAIL() << "An exception was thrown when Evicting an unused item from the list";
	}
	EXPECT_EQ(1,numEliminated) << "The item to be removed was not in the list, nothing should have been removed";
	EXPECT_EQ(3,ds.pair_list.size());

	// look for key 5 - it should have been evicted
	it = ds.FindInList(key3, g_cur_time, hash4);
	ASSERT_TRUE(it == ds.end()) << "The item that should have been removed is still in the list.";

	// make sure items 1,2, and 4 are still in the list
	EXPECT_TRUE(ds.FindInList(key1, g_cur_time, hash4) != ds.end()) << "Item 1 should still be in the list";
	EXPECT_TRUE(ds.FindInList(key2, g_cur_time, hash4) != ds.end()) << "Item 2 should still be in the list";
	EXPECT_TRUE(ds.FindInList(key4, g_cur_time, hash4) != ds.end()) << "Item 4 should still be in the list";

	// add items 3 and 5
	// see that item 3 is evicted in favor of 5 when adding 5 to a full list
	ds.AddPairToList(hash2, key1,11,&containerPtr,459);
	ds.AddPairToList(hash2, key2,22,&containerPtr,459);
	ds.AddPairToList(hash2, key3,33,&containerPtr,459);
	ds.AddPairToList(hash2, key4,44,&containerPtr,459);
	ds.AddPairToList(hash2, key5,55,&containerPtr,459);
	EXPECT_EQ(4,ds.pair_list.size()) << "The list should be at the maximum size specified:  4";
	EXPECT_FALSE(ds.FindInList(key3, g_cur_time, hash4) != ds.end()) << "Item 3 should have been evicted";
	EXPECT_TRUE(ds.FindInList(key5, g_cur_time, hash4) != ds.end()) << "Item 5 should be in the list";
}


// ***************************************************************************************
// DhtImpl class tests
// ***************************************************************************************

TEST(TestDhtImpl, SimpleInitializationTest)
{
	smart_ptr<DhtImpl> impl( new DhtImpl(NULL, NULL) );
	impl->SetSHACallback(&sha1_callback);
	impl->Enable(true,0);
	ASSERT_EQ(0, impl->GetNumPeersTracked());
}

TEST(TestDhtImpl, PeersTest)
{
	const char* DHTTestStoreFilename = "dhtstore.test";
	smart_ptr<DhtImpl> impl( new DhtImpl(NULL, NULL) );
	impl->SetSHACallback(&sha1_callback);

	DhtID id;
	for (int i = 0; i < 5; ++i)
		id.id[i] = rand();

	impl->AddPeerToStore(id, DHTTestStoreFilename, SockAddr::parse_addr("10.0.1.0"), false);
	impl->AddPeerToStore(id, DHTTestStoreFilename, SockAddr::parse_addr("10.0.1.1"), false);
	impl->AddPeerToStore(id, DHTTestStoreFilename, SockAddr::parse_addr("10.0.1.2"), false);
	impl->AddPeerToStore(id, DHTTestStoreFilename, SockAddr::parse_addr("10.0.1.3"), true);
	impl->AddPeerToStore(id, DHTTestStoreFilename, SockAddr::parse_addr("10.0.1.4"), true);
	impl->AddPeerToStore(id, DHTTestStoreFilename, SockAddr::parse_addr("10.0.1.0"), true);

	DhtID correct_info_hash_id;
	memset(correct_info_hash_id.id, 0, 5);
	int info_hash_len = SHA1_DIGESTSIZE;
	str file_name = NULL;
	std::vector<StoredPeer> *peers = impl->GetPeersFromStore(id, info_hash_len, &correct_info_hash_id, &file_name, 200);
	EXPECT_TRUE(peers);
	if (peers) {
		ASSERT_EQ(5, peers->size()); // btprintf("Got %d peers from store\n", peers->GetCount()));
	}
}

TEST(TestDhtImpl, TestTheUnitTestUDPSocketClass)
{
	UnitTestUDPSocket TestSocket;
	SockAddr DummySockAddr;
	std::string resultData;
	// be careful with test data containing '\0' in the middle of the string.
	std::string testData("abcdefghijklmnopqrstuvwxyz\t1234567890\xf1\x04");
	std::string additionalData("More Data");
	std::string totalData = testData + additionalData;

	// "send" some data
	TestSocket.Send(DummySockAddr, "", (const byte*)(testData.c_str()), testData.size());
	TestSocket.Send(DummySockAddr, "", (const byte*)(additionalData.c_str()), additionalData.size());

	// see that the test socket faithfully represents the data.
	resultData = TestSocket.GetSentDataAsString();
	EXPECT_TRUE(resultData == totalData);
}

TEST(TestDhtImpl, TestSendTo)
{
	UnitTestUDPSocket socket4;
	UnitTestUDPSocket socket6;
	smart_ptr<DhtImpl> dhtTestObj(new DhtImpl(&socket4, &socket6));
	dhtTestObj->SetSHACallback(&sha1_callback);

	// the test data must be a valid bencoded string
	std::string testData("d1:ad2:id20:abcdefghij0123456789e1:q4:ping1:t2:aa1:y1:qe");
	DhtPeerID peerID;

	dhtTestObj->Enable(true,0);

	dhtTestObj->SendTo(peerID, (const byte*)(testData.c_str()), testData.size());
	EXPECT_TRUE(socket4.GetSentDataAsString() == testData);
}

TEST(TestDhtImplResponse, TestSendPings)
{
	UnitTestUDPSocket socket4;
	UnitTestUDPSocket socket6;
	BencodedDict bDictGetPeer;
	SockAddr sAddr(0x7a7a7a7a,0x7878); // ip = zzzz and socket = xx
	socket4.SetBindAddr(sAddr);
	smart_ptr<DhtImpl> dhtTestObj(new DhtImpl(&socket4, &socket6));
	dhtTestObj->SetSHACallback(&sha1_callback);

	// prepare the object for use
	dhtTestObj->Enable(true,0);
	SetDHT_my_id_Bytes(dhtTestObj);

	// put a peer into the dht for it to work with
	DhtPeerID peerID;
	peerID.id.id[0] = '1111'; // 1111
	peerID.id.id[1] = 'BBBB'; // BBBB
	peerID.id.id[2] = 'CCCC'; // CCCC
	peerID.id.id[3] = 'DDDD'; // DDDD
	peerID.id.id[4] = '0000'; // 0000
	peerID.addr.set_port(128);
	peerID.addr.set_addr4(0xf0f0f0f0);
	DhtPeer *pTestPeer = dhtTestObj->Update(peerID, 0, false);
	// Check that our node is in there
	ASSERT_EQ(1, dhtTestObj->GetNumPeers());
	Buffer peerIDBuffer;
	peerIDBuffer.len = 20;
	peerIDBuffer.b = (byte*)&peerID.id.id[0];
	// Send a NICE (non-bootstrap) ping to our fake node
	int bucketNo = dhtTestObj->GetBucket(peerID.id);
	dhtTestObj->PingStalestInBucket(bucketNo);

	std::string pingOut = socket4.GetSentDataAsString();

	BencEntity bEntity;

	// verify the bencoded string that went out the socket
	BencEntity::Parse((const byte *)pingOut.c_str(), bEntity, (const byte *)(pingOut.c_str() + pingOut.length()));

	// did we send a valid dictionary
	BencodedDict *dict = BencodedDict::AsDict(&bEntity);
	EXPECT_TRUE(dict);
	if (!dict) {
		FAIL() << "ERROR:  The outgoing message is not a bencoded dictionary";
	}

	// check the transaction ID:  length=2
	Buffer tid;
	tid.b = (byte*)dict->GetString("t", &tid.len);
	EXPECT_FALSE(!tid.b || tid.len > 16);
	if (!tid.b || tid.len > 16) {
		FAIL() << "ERROR:  There is either no transaction ID or its length is greater than 16 characters";
	}

	// specify and send the fake response
	char buf[256];
	char const* const end = buf + sizeof(buf);
	SimpleBencoder sb(buf);
	sb.put_buf((const unsigned char*)("d1:rd2:id20:"), strlen("d1:rd2:id20:"));
	sb.put_buf((const unsigned char*)(peerID.id.id), 20);
	sb.p += snprintf(sb.p, (end - sb.p), "e1:t%lu:", tid.len);
	sb.put_buf((const unsigned char*)(tid.b), tid.len);
	sb.put_buf((const unsigned char*)("1:v4:UTê`1:y1:re"), strlen("1:v4:UTê`1:y1:re"));

	// -2 means we think we have completed bootstrapping
	dhtTestObj->_dht_bootstrap = -2;
	dhtTestObj->_lastLeadingAddress = sAddr;	// prevent restart due to exgternal IP voting
	// Here, we send a response right away
	ASSERT_EQ(dhtTestObj->ProcessIncoming((byte *) buf, sb.p - buf, peerID.addr), true);

	// Now, ping the same peer, but pretend it is slow and/or doesn't answer
	DhtRequest *req = dhtTestObj->SendPing(peerID);
	req->_pListener = new DhtRequestListener<DhtImpl>(dhtTestObj.get(), &DhtImpl::OnBootStrapPingReply);
	req->time -= 1100;
	dhtTestObj->Tick();
	// Between 1 and 5 second is considered slow, not yet an error
	ASSERT_TRUE(req->slow_peer);

	// Now pretend it has taken longer than 5 seconds
	req->time -= 4000;
	dhtTestObj->Tick();

	// Ensure the error count has increased
	ASSERT_EQ(1, pTestPeer->num_fail);

	// Next, after the second failure (FAIL_THRES), the node gets removed.
	req = dhtTestObj->SendPing(peerID);
	req->_pListener = new DhtRequestListener<DhtImpl>(dhtTestObj.get(), &DhtImpl::OnBootStrapPingReply);
	req->time -= 5100;
	dhtTestObj->Tick();

	// Make sure our peer has been deleted due to the errors
	ASSERT_EQ(0, dhtTestObj->GetNumPeers());

}

TEST(TestDhtImpl, TestPingRPC_ipv4)
{
	UnitTestUDPSocket socket4;
	UnitTestUDPSocket socket6;
	smart_ptr<DhtImpl> dhtTestObj(new DhtImpl(&socket4, &socket6));
	dhtTestObj->SetSHACallback(&sha1_callback);
	SockAddr sAddr(0x7a7a7a7a,0x7878); // ip = zzzz and socket = xx

	// prepare the object for use
	dhtTestObj->Enable(true,0);
	SetDHT_my_id_Bytes(dhtTestObj);

	// specify, parse, and send the message
	std::string testData("d1:ad2:id20:abcdefghij0123456789e1:q4:ping1:t2:aa1:y1:qe");
	dhtTestObj->ProcessIncoming((byte*)testData.c_str(), testData.size(), sAddr);

	// get the bencoded string out of the socket
	std::string bencMessage = socket4.GetSentDataAsString();
	BencEntity bEntity;

	// verify the bencoded string that went out the socket
	BencEntity::Parse((const byte *)bencMessage.c_str(), bEntity, (const byte *)(bencMessage.c_str() + bencMessage.length()));

	// did we get a valid dictionary
	BencodedDict *dict = BencodedDict::AsDict(&bEntity);
	EXPECT_TRUE(dict);
	if (!dict) {
		FAIL() << "ERROR:  The response is not a bencoded dictionary";
	}

	// is there a type and is it "r" for response
	cstr type = dict->GetString("y", 1);
	EXPECT_TRUE(type);
	if (!type) {
		FAIL() << "ERROR:  Failed to extract 'y' type from response";
	}
	ASSERT_EQ('r', *type);

	// check the transaction ID:  length=2, value = "aa"
	Buffer tid;
	tid.b = (byte*)dict->GetString("t", &tid.len);
	EXPECT_FALSE(!tid.b || tid.len > 16);
	if (!tid.b || tid.len > 16) {
		FAIL() << "ERROR:  There is either no transaction ID or its length is greater than 16 characters";
	}
	ASSERT_EQ(2, tid.len);
	EXPECT_FALSE(memcmp((const void*)tid.b, (const void *)"aa", 2));

	// check the ipv4 address we supplied in SocketAddr sAddr(...) above
	Buffer ip;
	ip.b = (byte*)dict->GetString("ip", &ip.len);
	ASSERT_EQ(6, ip.len) << "ERROR:  The length of the ip address extracted from the response arguments is the wrong size";
	EXPECT_FALSE(memcmp((const void*)ip.b, (const void *)"zzzz", 4));
	EXPECT_FALSE(memcmp((const void*)(ip.b + 4), (const void *)"xx", 2));

	// now look into the response data
	BencodedDict *reply = dict->GetDict("r");
	if (!reply) {
		FAIL() << "ERROR:  Failed to extract 'r' dictionary from response";
	}

	byte *id = (byte*)reply->GetString("id", 20);
	if(!id){
		FAIL() << "ERROR:  Failed to extract 'id' from the reply data";
	}
	EXPECT_FALSE(memcmp((const void*)id, (const void *)"AAAABBBBCCCCDDDDEEEE", 20));

}

TEST(TestDhtImpl, TestPingRPC_ipv4_ParseKnownPackets)
{
	// this test is aimed at the ParseKnownPackets member function that is optimized for a specific ping message format
	// as quoted from the code itself:
	//
	// currently we only know one packet type, the most common uT ping:
	// 'd1:ad2:id20:\t9\x93\xd4\xb7G\x10,Q\x9b\xf4\xc5\xfc\t\x87\x89\xeb\x93Q,e1:q4:ping1:t4:\x95\x00\x00\x001:v4:UT#\xa31:y1:qe'

	UnitTestUDPSocket socket4;
	UnitTestUDPSocket socket6;
	smart_ptr<DhtImpl> dhtTestObj(new DhtImpl(&socket4, &socket6));
	dhtTestObj->SetSHACallback(&sha1_callback);
	SockAddr sAddr(0x7a7a7a7a,0x7878); // ip = zzzz and socket = xx

	// prepare the object for use
	dhtTestObj->Enable(true,0);
	SetDHT_my_id_Bytes(dhtTestObj);

	// specify, parse, and send the message
	std::string testData("d1:ad2:id20:abcdefghij0123456789e1:q4:ping1:t4:wxyz1:v4:UTUT1:y1:qe");
	dhtTestObj->ProcessIncoming((byte*)testData.c_str(), testData.size(), sAddr);

	// get the bencoded string out of the socket
	std::string bencMessage = socket4.GetSentDataAsString();
	BencEntity bEntity;

	// verify the bencoded string that went out the socket
	BencEntity::Parse((const byte *)bencMessage.c_str(), bEntity, (const byte *)(bencMessage.c_str() + bencMessage.length()));

	// did we get a valid dictionary
	BencodedDict *dict = BencodedDict::AsDict(&bEntity);
	EXPECT_TRUE(dict);
	if (!dict) {
		FAIL() << "ERROR:  The response is not a bencoded dictionary";
	}

	// is there a type and is it "r" for response
	cstr type = dict->GetString("y", 1);
	EXPECT_TRUE(type);
	if (!type) {
		FAIL() << "ERROR:  Failed to extract 'y' type from response";
	}
	ASSERT_EQ('r', *type);

	// check the transaction ID:  length=4, value = "wxyz"
	Buffer tid;
	tid.b = (byte*)dict->GetString("t", &tid.len);
	EXPECT_FALSE(!tid.b || tid.len > 16);
	if (!tid.b || tid.len > 16) {
		FAIL() << "ERROR:  There is either no transaction ID or its length is greater than 16 characters";
	}
	ASSERT_EQ(4, tid.len);
	EXPECT_FALSE(memcmp((const void*)tid.b, (const void *)"wxyz", 4));

	// check the ipv4 address we supplied in SocketAddr sAddr(...) above
	Buffer ip;
	ip.b = (byte*)dict->GetString("ip", &ip.len);
	ASSERT_EQ(6, ip.len) << "ERROR:  The length of the ip address extracted from the response arguments is the wrong size";
	EXPECT_FALSE(memcmp((const void*)ip.b, (const void *)"zzzz", 4));
	EXPECT_FALSE(memcmp((const void*)(ip.b + 4), (const void *)"xx", 2));

	// now look into the response data
	BencodedDict *reply = dict->GetDict("r");
	if (!reply) {
		FAIL() << "ERROR:  Failed to extract 'r' dictionary from response";
	}

	byte *id = (byte*)reply->GetString("id", 20);
	if(!id){
		FAIL() << "ERROR:  Failed to extract 'id' from the reply data";
	}
	EXPECT_FALSE(memcmp((const void*)id, (const void *)"AAAABBBBCCCCDDDDEEEE", 20));

}

TEST(TestDhtImpl, TestGetPeersRPC_ipv4)
{
	UnitTestUDPSocket socket4;
	UnitTestUDPSocket socket6;
	smart_ptr<DhtImpl> dhtTestObj(new DhtImpl(&socket4, &socket6));
	dhtTestObj->SetSHACallback(&sha1_callback);
	SockAddr sAddr(0x7a7a7a7a,0x7878); // ip = zzzz and socket = xx

	// prepare the object for use
	dhtTestObj->Enable(true,0);
	SetDHT_my_id_Bytes(dhtTestObj);

	// specify, parse, and send the message
	std::string testData("d1:ad2:id20:abcdefghij01010101019:info_hash20:mnopqrstuvwxyz123456e1:q9:get_peers1:t2:aa1:y1:qe");
	dhtTestObj->ProcessIncoming((byte*)testData.c_str(), testData.size(), sAddr);

	// get the bencoded string out of the socket
	std::string bencMessage = socket4.GetSentDataAsString();
	BencEntity bEntity;

	// verify the bencoded string that went out the socket
	BencEntity::Parse((const byte *)bencMessage.c_str(), bEntity, (const byte *)(bencMessage.c_str() + bencMessage.length()));

	// did we get a valid dictionary
	BencodedDict *dict = BencodedDict::AsDict(&bEntity);
	EXPECT_TRUE(dict);
	if (!dict) {
		FAIL() << "ERROR:  The response is not a bencoded dictionary";
	}

	// check the ipv4 address we supplied in SocketAddr sAddr(...) above
	Buffer ip;
	ip.b = (byte*)dict->GetString("ip", &ip.len);
	ASSERT_EQ(6, ip.len) << "ERROR:  The length of the ip address extracted from the response arguments is the wrong size";
	EXPECT_FALSE(memcmp((const void*)ip.b, (const void *)"zzzz", 4));
	EXPECT_FALSE(memcmp((const void*)(ip.b + 4), (const void *)"xx", 2));

	// is there a type and is it "r" for response
	cstr type = dict->GetString("y", 1);
	EXPECT_TRUE(type);
	if (!type) {
		FAIL() << "ERROR:  Failed to extract 'y' type from response";
	}
	ASSERT_EQ('r', *type);

	// check the transaction ID:  length=2, value = "aa"
	Buffer tid;
	tid.b = (byte*)dict->GetString("t", &tid.len);
	EXPECT_FALSE(!tid.b || tid.len > 16);
	if (!tid.b || tid.len > 16) {
		FAIL() << "ERROR:  There is either no transaction ID or its length is greater than 16 characters";
	}
	ASSERT_EQ(2, tid.len);
	EXPECT_FALSE(memcmp((const void*)tid.b, (const void *)"aa", tid.len));

	// now look into the response data
	BencodedDict *reply = dict->GetDict("r");
	if (!reply) {
		FAIL() << "ERROR:  Failed to extract 'r' dictionary from response";
	}

	byte *id = (byte*)reply->GetString("id", 20);
	if(!id){
		FAIL() << "ERROR:  Failed to extract 'id' from the reply data";
	}
	EXPECT_FALSE(memcmp((const void*)id, (const void *)"AAAABBBBCCCCDDDDEEEE", 20));


	// in the test environment there are no peers.  There should however be a node - this one
	// expect back the id provided in the query, ip=zzzz port=xx (since the querying node and this node are the same in this test)
	Buffer nodes;
	nodes.b = (byte*)reply->GetString("nodes", &nodes.len);
	ASSERT_EQ(26, nodes.len) << "ERROR:  The length of the 26 byte node info extracted from the response arguments is the wrong size";
	EXPECT_FALSE(memcmp((const void*)nodes.b, (const void *)"abcdefghij0101010101zzzzxx", nodes.len));

	// check that there is a token
	Buffer token;
	token.b = (byte*)reply->GetString("token", &token.len);
	EXPECT_TRUE(token.len) << "There should have been a token of non-zero length";
}

TEST(TestDhtImpl, TestFindNodeRPC_ipv4)
{
	UnitTestUDPSocket socket4;
	UnitTestUDPSocket socket6;
	smart_ptr<DhtImpl> dhtTestObj(new DhtImpl(&socket4, &socket6));
	dhtTestObj->SetSHACallback(&sha1_callback);
	SockAddr sAddr(0x7a7a7a7a,0x7878); // ip = zzzz and socket = xx

	// prepare the object for use
	dhtTestObj->Enable(true,0);
	SetDHT_my_id_Bytes(dhtTestObj);

	// specify, parse, and send the message
	std::string testData("d1:ad2:id20:abcdefghij01234567896:target20:mnopqrstuvwxyz123456e1:q9:find_node1:t2:aa1:y1:qe");
	dhtTestObj->ProcessIncoming((byte*)testData.c_str(), testData.size(), sAddr);

	// get the bencoded string out of the socket
	std::string bencMessage = socket4.GetSentDataAsString();
	BencEntity bEntity;

	// verify the bencoded string that went out the socket
	BencEntity::Parse((const byte *)bencMessage.c_str(), bEntity, (const byte *)(bencMessage.c_str() + bencMessage.length()));

	// did we get a valid dictionary
	BencodedDict *dict = BencodedDict::AsDict(&bEntity);
	EXPECT_TRUE(dict);
	if (!dict) {
		FAIL() << "ERROR:  The response is not a bencoded dictionary";
	}

	// is there a type and is it "r" for response
	cstr type = dict->GetString("y", 1);
	EXPECT_TRUE(type);
	if (!type) {
		FAIL() << "ERROR:  Failed to extract 'y' type from response";
	}
	ASSERT_EQ('r', *type);

	// check the transaction ID:  length=2, value = "aa"
	Buffer tid;
	tid.b = (byte*)dict->GetString("t", &tid.len);
	EXPECT_FALSE(!tid.b || tid.len > 16);
	if (!tid.b || tid.len > 16) {
		FAIL() << "ERROR:  There is either no transaction ID or its length is greater than 16 characters";
	}
	ASSERT_EQ(2, tid.len);
	EXPECT_FALSE(memcmp((const void*)tid.b, (const void *)"aa", tid.len));

	// now look into the response data
	BencodedDict *reply = dict->GetDict("r");
	if (!reply) {
		FAIL() << "ERROR:  Failed to extract 'r' dictionary from response";
	}

	byte *id = (byte*)reply->GetString("id", 20);
	if(!id){
		FAIL() << "ERROR:  Failed to extract 'id' from the reply data";
	}
	EXPECT_FALSE(memcmp((const void*)id, (const void *)"AAAABBBBCCCCDDDDEEEE", 20));

	// There should be a single node - this one
	// expect back the id provided in the query, ip=zzzz port=xx (since the querying node and this node are the same in this test)
	Buffer nodes;
	nodes.b = (byte*)reply->GetString("nodes", &nodes.len);
	ASSERT_EQ(26, nodes.len) << "ERROR:  The length of the 26 byte node info extracted from the response arguments is the wrong size";
	EXPECT_FALSE(memcmp((const void*)nodes.b, (const void *)"abcdefghij0123456789zzzzxx", nodes.len));
}

void put_call_back(void * ctx, std::vector<char>& buffer){
	buffer = { 's', 'a', 'm', 'p', 'l', 'e' };
}
void ed255callback(unsigned char * sig, const unsigned char * v, unsigned long long size, const unsigned char * key)
{
  for(int i = 0; i < 64; i++){
    sig[i] ='a'; 
  }
} 
TEST(TestDhtImpl, TestPutRPC_ipv4)
{
	UnitTestUDPSocket socket4;
	UnitTestUDPSocket socket6;
	BencodedDict bDictGetPeer;
	SockAddr sAddr(0x7a7a7a7a,0x7878); // ip = zzzz and socket = xx
	socket4.SetBindAddr(sAddr);
	smart_ptr<DhtImpl> dhtTestObj(new DhtImpl(&socket4, &socket6));
	dhtTestObj->SetSHACallback(&sha1_callback);
	dhtTestObj->SetEd25519SignCallback(&ed255callback);

	// prepare the object for use
	dhtTestObj->Enable(true,0);
	SetDHT_my_id_Bytes(dhtTestObj);

	// put a peer into the dht for it to work with
	DhtPeerID peerID;
	peerID.id.id[0] = '1111'; // 1111
	peerID.id.id[1] = 'BBBB'; // BBBB
	peerID.id.id[2] = 'CCCC'; // CCCC
	peerID.id.id[3] = 'DDDD'; // DDDD
	peerID.id.id[4] = '0000'; // 0000
	peerID.addr.set_port(128);
	peerID.addr.set_addr4(0xf0f0f0f0);
	dhtTestObj->Update(peerID, 0, false);
	Buffer peerIDBuffer;
	peerIDBuffer.len = 20;
	peerIDBuffer.b = (byte*)&peerID.id.id[0];

	DhtID target;
	target.id[0] = 'FFFF'; // FFFF
	target.id[1] = 'GGGG'; // GGGG
	target.id[2] = 'HHHH'; // HHHH
	target.id[3] = 'IIII'; // IIII
	target.id[4] = 'JJJJ'; // JJJJ

	// *****************************************************
	// Make the dht emit an announce message (the get_peers rpc)
	// Just tell it that the target is only 16 bytes long (instead of 20)
	// *****************************************************
	byte * pkey = (byte *)"dhuieheuu383y8yr7yy3hd3hdh3gfhg3";
	byte * skey = (byte *)"dhuieheuu383y8yr7yy3hd3hdh3gfhg3dhuieheuu383y8yr7yy3hd3hdh3gfhg3";
	EXPECT_FALSE(dhtTestObj->IsBusy()) << "The dht should not be busy yet";
	dhtTestObj->Put(pkey, skey, &put_call_back, NULL, 0);
	//EXPECT_TRUE(dhtTestObj->IsBusy()) << "The dht should be busy";

	// *****************************************************
	// grab from the socket the emitted message and extract
	// the transaction ID and verify the remainder of the
	// message
	// *****************************************************
	std::string getOutput = socket4.GetSentDataAsString();
	BencEntity bEntityGetQuery;
	// verify the bencoded string that went out the socket
	BencEntity::Parse((const byte *)getOutput.c_str(), bEntityGetQuery, (const byte *)(getOutput.c_str() + getOutput.length()));

	// get the query dictionary
	BencodedDict *dictForGet = BencodedDict::AsDict(&bEntityGetQuery);
	EXPECT_TRUE(dictForGet);
	if (!dictForGet) {
		FAIL() << "ERROR:  The dht did not emit a bencoded dictionary for announce";
	}

	Buffer type;
	type.b = (byte*)dictForGet->GetString("y" ,&type.len);
	ASSERT_EQ(1, type.len) << "ERROR: the 'y' type length is wrong (should be 1 for 'q', 'r', or 'e')";
	ASSERT_EQ('q', type.b[0]) << "ERROR: 'y' type is wrong; should be 'q' for query instead of:  " << type.b[0];

	Buffer command;
	command.b = (byte*)dictForGet->GetString("q" ,&command.len);
	EXPECT_EQ(3, command.len);
	EXPECT_FALSE(memcmp("get", command.b, 3)) << "ERROR: 'q' command is wrong";

	// get the transaction ID to use later
	Buffer tid;
	tid.b = (byte*)dictForGet->GetString("t" ,&tid.len);
	EXPECT_EQ(4, tid.len) << "transaction ID is wrong size";

	// now look into the query data
	BencodedDict *getQuery = dictForGet->GetDict("a");
	if (!getQuery) {
		FAIL() << "ERROR:  Failed to extract 'a' dictionary from get_peer response";
	}

	Buffer id;
	id.b = (byte*)getQuery->GetString("id" ,&id.len);
	EXPECT_EQ(20, id.len);
	EXPECT_FALSE(memcmp("AAAABBBBCCCCDDDDEEEE", id.b, 20)) << "ERROR: announced id is wrong";


	Buffer pkey_buf;
	pkey_buf.b = (byte*)getQuery->GetString("target" ,&pkey_buf.len);
	EXPECT_EQ(20, pkey_buf.len);
	EXPECT_FALSE(memcmp(sha1_callback(pkey, sizeof(pkey)).value, pkey_buf.b, 20)) << "ERROR: pkey is not the correct target";

	std::vector<byte>	messageBytes;
	std::vector<byte>	replyDictionaryBytes;

	std::string responseToken("20_byte_reply_token.");
	//std::string nearistNode  ("26_byte_nearist_node_addr.");
	std::string nearistNode  ("");

	std::string v("sample");

	int seq = 0;
	// construct the message bytes
	BencStartDictionary(replyDictionaryBytes);
	{
		BencAddNameValuePair(replyDictionaryBytes,"id",peerIDBuffer);
		BencAddNameValuePair(replyDictionaryBytes,"nodes",nearistNode);
		BencAddNameValuePair(replyDictionaryBytes,"token",responseToken);
		BencAddNameValuePair(replyDictionaryBytes,"seq",seq);
		BencAddNameValuePair(replyDictionaryBytes,"v",v);		
	}
	BencEndDictionary(replyDictionaryBytes);

	BencStartDictionary(messageBytes);
	{
		BencAddNameValuePair(messageBytes,"ip","abcdxy");
		BencAddNameAndBencodedDictionary(messageBytes,"r",replyDictionaryBytes);
		BencAddNameValuePair(messageBytes,"t",tid);
		BencAddNameValuePair(messageBytes,"y","r");
	}
	BencEndDictionary(messageBytes);

	// clear the socket and "send" the reply

	socket4.Reset();
	dhtTestObj->ProcessIncoming((byte*)&messageBytes.front(), messageBytes.size(), peerID.addr);

	EXPECT_TRUE(dhtTestObj->IsBusy()) << "The dht should still be busy";

	//Checking the put messages

	std::string putOutput = socket4.GetSentDataAsString();
	BencEntity bEntityPutQuery;
	// verify the bencoded string that went out the socket
	BencEntity::Parse((const byte *)putOutput.c_str(), bEntityPutQuery, (const byte *)(putOutput.c_str() + putOutput.length()));

	// get the query dictionary
	BencodedDict *dictForPut = BencodedDict::AsDict(&bEntityPutQuery);
	EXPECT_TRUE(dictForPut);
	if (!dictForPut) {
		FAIL() << "ERROR:  The dht did not emit a bencoded dictionary for announce";
	}

	type.b = (byte*)dictForPut->GetString("y" ,&type.len);
	ASSERT_EQ(1, type.len) << "ERROR: the 'y' type length is wrong (should be 1 for 'q', 'r', or 'e')";
	ASSERT_EQ('q', type.b[0]) << "ERROR: 'y' type is wrong; should be 'q' for query instead of:  " << type.b[0];

	command.b = (byte*)dictForPut->GetString("q" ,&command.len);
	EXPECT_EQ(3, command.len);
	EXPECT_FALSE(memcmp("put", command.b, 3)) << "ERROR: 'q' command is wrong";

	// get the transaction ID to use later
	tid.b = (byte*)dictForPut->GetString("t" ,&tid.len);
	EXPECT_EQ(4, tid.len) << "transaction ID is wrong size";

	// now look into the query data
	BencodedDict *putQuery = dictForPut->GetDict("a");
	if (!putQuery) {
		FAIL() << "ERROR:  Failed to extract 'a' dictionary from put_peer response";
	}

	id.b = (byte*)putQuery->GetString("id" ,&id.len);
	EXPECT_EQ(20, id.len);
	EXPECT_FALSE(memcmp("AAAABBBBCCCCDDDDEEEE", id.b, 20)) << "ERROR: announced id is wrong";

	EXPECT_EQ(seq+1, putQuery->GetInt("seq"));

	Buffer sig;
	sig.b = (byte*)putQuery->GetString("sig" ,&sig.len);
	EXPECT_EQ(64, sig.len);

	Buffer token;
	token.b = (byte*)putQuery->GetString("token" ,&token.len);
	EXPECT_EQ(20, token.len);
	EXPECT_FALSE(memcmp(responseToken.c_str(), token.b, 20)) << "ERROR: announced token is wrong";

	Buffer v_out;
	v_out.b = (byte*)putQuery->GetString("v" ,&v_out.len);
	EXPECT_EQ(v.size(), v_out.len);
	EXPECT_FALSE(memcmp(v.c_str(), v_out.b, v.size())) << "ERROR: v is wrong";

}

TEST(TestDhtImpl, TestPutRPC_ipv4_cas)
{
	UnitTestUDPSocket socket4;
	UnitTestUDPSocket socket6;
	BencodedDict bDictGetPeer;
	SockAddr sAddr(0x7a7a7a7a,0x7878); // ip = zzzz and socket = xx
	socket4.SetBindAddr(sAddr);
	smart_ptr<DhtImpl> dhtTestObj(new DhtImpl(&socket4, &socket6));
	dhtTestObj->SetSHACallback(&sha1_callback);
	dhtTestObj->SetEd25519SignCallback(&ed255callback);

	// prepare the object for use
	dhtTestObj->Enable(true,0);
	SetDHT_my_id_Bytes(dhtTestObj);

	// put a peer into the dht for it to work with
	DhtPeerID peerID;
	peerID.id.id[0] = '1111'; // 1111
	peerID.id.id[1] = 'BBBB'; // BBBB
	peerID.id.id[2] = 'CCCC'; // CCCC
	peerID.id.id[3] = 'DDDD'; // DDDD
	peerID.id.id[4] = '0000'; // 0000
	peerID.addr.set_port(128);
	peerID.addr.set_addr4(0xf0f0f0f0);
	dhtTestObj->Update(peerID, 0, false);
	Buffer peerIDBuffer;
	peerIDBuffer.len = 20;
	peerIDBuffer.b = (byte*)&peerID.id.id[0];

	DhtID target;
	target.id[0] = 'FFFF'; // FFFF
	target.id[1] = 'GGGG'; // GGGG
	target.id[2] = 'HHHH'; // HHHH
	target.id[3] = 'IIII'; // IIII
	target.id[4] = 'JJJJ'; // JJJJ

	// *****************************************************
	// Make the dht emit an announce message (the get_peers rpc)
	// Just tell it that the target is only 16 bytes long (instead of 20)
	// *****************************************************
	byte * pkey = (byte *)"dhuieheuu383y8yr7yy3hd3hdh3gfhg3";
	byte * skey = (byte *)"dhuieheuu383y8yr7yy3hd3hdh3gfhg3dhuieheuu383y8yr7yy3hd3hdh3gfhg3";
	EXPECT_FALSE(dhtTestObj->IsBusy()) << "The dht should not be busy yet";
	dhtTestObj->Put(pkey, skey, &put_call_back, NULL, IDht::with_cas);
	//EXPECT_TRUE(dhtTestObj->IsBusy()) << "The dht should be busy";

	// *****************************************************
	// grab from the socket the emitted message and extract
	// the transaction ID and verify the remainder of the
	// message
	// *****************************************************
	std::string getOutput = socket4.GetSentDataAsString();
	BencEntity bEntityGetQuery;
	// verify the bencoded string that went out the socket
	BencEntity::Parse((const byte *)getOutput.c_str(), bEntityGetQuery, (const byte *)(getOutput.c_str() + getOutput.length()));

	// get the query dictionary
	BencodedDict *dictForGet = BencodedDict::AsDict(&bEntityGetQuery);
	EXPECT_TRUE(dictForGet);
	if (!dictForGet) {
		FAIL() << "ERROR:  The dht did not emit a bencoded dictionary for announce";
	}

	Buffer type;
	type.b = (byte*)dictForGet->GetString("y" ,&type.len);
	ASSERT_EQ(1, type.len) << "ERROR: the 'y' type length is wrong (should be 1 for 'q', 'r', or 'e')";
	ASSERT_EQ('q', type.b[0]) << "ERROR: 'y' type is wrong; should be 'q' for query instead of:  " << type.b[0];

	Buffer command;
	command.b = (byte*)dictForGet->GetString("q" ,&command.len);
	EXPECT_EQ(3, command.len);
	EXPECT_FALSE(memcmp("get", command.b, 3)) << "ERROR: 'q' command is wrong";

	// get the transaction ID to use later
	Buffer tid;
	tid.b = (byte*)dictForGet->GetString("t" ,&tid.len);
	EXPECT_EQ(4, tid.len) << "transaction ID is wrong size";

	// now look into the query data
	BencodedDict *getQuery = dictForGet->GetDict("a");
	if (!getQuery) {
		FAIL() << "ERROR:  Failed to extract 'a' dictionary from get_peer response";
	}

	Buffer id;
	id.b = (byte*)getQuery->GetString("id" ,&id.len);
	EXPECT_EQ(20, id.len);
	EXPECT_FALSE(memcmp("AAAABBBBCCCCDDDDEEEE", id.b, 20)) << "ERROR: announced id is wrong";


	Buffer pkey_buf;
	pkey_buf.b = (byte*)getQuery->GetString("target" ,&pkey_buf.len);
	EXPECT_EQ(20, pkey_buf.len);
	EXPECT_FALSE(memcmp(sha1_callback(pkey, sizeof(pkey)).value, pkey_buf.b, 20)) << "ERROR: pkey is not the correct target";

	std::vector<byte>	messageBytes;
	std::vector<byte>	replyDictionaryBytes;

	std::string responseToken("20_byte_reply_token.");
	std::string nearestNode  ("");

	std::string v("sample");

	int seq = 0;

	byte to_hash[800];
	int written = snprintf(reinterpret_cast<char*>(to_hash), 800, "3:seqi%ie1:v%lu:", seq, v.size());
	memcpy(to_hash + written, v.c_str(), v.size());
	//fprintf(stderr, "in test: %s\n", (char*)to_hash);
	sha1_hash cas = sha1_callback(to_hash, written + v.size());
	Buffer cas_buf(cas.value, 20);

	// construct the message bytes
	BencStartDictionary(replyDictionaryBytes);
	{
		BencAddNameValuePair(replyDictionaryBytes,"cas", cas_buf);
		BencAddNameValuePair(replyDictionaryBytes,"id",peerIDBuffer);
		BencAddNameValuePair(replyDictionaryBytes,"nodes",nearestNode);
		BencAddNameValuePair(replyDictionaryBytes,"token",responseToken);
		BencAddNameValuePair(replyDictionaryBytes,"seq",seq);
		BencAddNameValuePair(replyDictionaryBytes,"v",v);
	}
	BencEndDictionary(replyDictionaryBytes);

	BencStartDictionary(messageBytes);
	{
		BencAddNameValuePair(messageBytes,"ip","abcdxy");
		BencAddNameAndBencodedDictionary(messageBytes,"r",replyDictionaryBytes);
		BencAddNameValuePair(messageBytes,"t",tid);
		BencAddNameValuePair(messageBytes,"y","r");
	}
	BencEndDictionary(messageBytes);

	// clear the socket and "send" the reply

	socket4.Reset();
	dhtTestObj->ProcessIncoming((byte*)&messageBytes.front(), messageBytes.size(), peerID.addr);

	EXPECT_TRUE(dhtTestObj->IsBusy()) << "The dht should still be busy";

	//Checking the put messages

	std::string putOutput = socket4.GetSentDataAsString();
	BencEntity bEntityPutQuery;
	// verify the bencoded string that went out the socket
	BencEntity::Parse((const byte *)putOutput.c_str(), bEntityPutQuery, (const byte *)(putOutput.c_str() + putOutput.length()));

	// get the query dictionary
	BencodedDict *dictForPut = BencodedDict::AsDict(&bEntityPutQuery);
	EXPECT_TRUE(dictForPut);
	if (!dictForPut) {
		FAIL() << "ERROR:  The dht did not emit a bencoded dictionary for announce";
	}

	type.b = (byte*)dictForPut->GetString("y" ,&type.len);
	ASSERT_EQ(1, type.len) << "ERROR: the 'y' type length is wrong (should be 1 for 'q', 'r', or 'e')";
	ASSERT_EQ('q', type.b[0]) << "ERROR: 'y' type is wrong; should be 'q' for query instead of:  " << type.b[0];

	command.b = (byte*)dictForPut->GetString("q" ,&command.len);
	EXPECT_EQ(3, command.len);
	EXPECT_FALSE(memcmp("put", command.b, 3)) << "ERROR: 'q' command is wrong";

	// get the transaction ID to use later
	tid.b = (byte*)dictForPut->GetString("t" ,&tid.len);
	EXPECT_EQ(4, tid.len) << "transaction ID is wrong size";

	// now look into the query data
	BencodedDict *putQuery = dictForPut->GetDict("a");
	if (!putQuery) {
		FAIL() << "ERROR:  Failed to extract 'a' dictionary from put_peer response";
	}

	ASSERT_NE(nullptr, cas_buf.b);
	EXPECT_EQ(20, cas_buf.len);
	EXPECT_FALSE(memcmp(cas.value, cas_buf.b, 20)) << "ERROR: wrong cas";

	id.b = (byte*)putQuery->GetString("id" ,&id.len);
	EXPECT_EQ(20, id.len);
	EXPECT_FALSE(memcmp("AAAABBBBCCCCDDDDEEEE", id.b, 20)) << "ERROR: announced id is wrong";

	EXPECT_EQ(seq+1, putQuery->GetInt("seq"));

	Buffer sig;
	sig.b = (byte*)putQuery->GetString("sig" ,&sig.len);
	EXPECT_EQ(64, sig.len);

	Buffer token;
	token.b = (byte*)putQuery->GetString("token" ,&token.len);
	EXPECT_EQ(20, token.len);
	EXPECT_FALSE(memcmp(responseToken.c_str(), token.b, 20)) << "ERROR: announced token is wrong";

	Buffer v_out;
	v_out.b = (byte*)putQuery->GetString("v" ,&v_out.len);
	EXPECT_EQ(v.size(), v_out.len);
	EXPECT_FALSE(memcmp(v.c_str(), v_out.b, v.size())) << "ERROR: v is wrong";

}

TEST(TestDhtImpl, TestAnnouncePeerRPC_ipv4)
{
	UnitTestUDPSocket socket4;
	UnitTestUDPSocket socket6;
	smart_ptr<DhtImpl> dhtTestObj(new DhtImpl(&socket4, &socket6));
	dhtTestObj->SetSHACallback(&sha1_callback);
	BencodedDict bDictGetPeer;
	SockAddr sAddr(0x7a7a7a7a,0x7878); // ip = zzzz and socket = xx

	// before we can announce_peer, we must use get_peers to obtain a token
	// use this to get a token
	std::string bEncodedGetPeers("d1:ad2:id20:abcdefghij01010101019:info_hash20:mnopqrstuvwxyz123456e1:q9:get_peers1:t2:aa1:y1:qe");

	// insert the token between these two strings
	std::string testDataPart1("d1:ad2:id20:abcdefghij01234567899:info_hash20:mnopqrstuvwxyz1234564:porti6881e5:token");
	std::string testDataPart2("e1:q13:announce_peer1:t2:aa1:y1:qe");
	std::string testData;

	std::vector<byte> testDataBytes;

	// prepare the object for use
	dhtTestObj->Enable(true,0);
	SetDHT_my_id_Bytes(dhtTestObj);

	// first do the GetPeers to obtain a token
	dhtTestObj->ProcessIncoming((byte*)bEncodedGetPeers.c_str(), bEncodedGetPeers.size(), sAddr);

	// get the bencoded string out of the socket
	std::string bencMessageGetPeerResponse = socket4.GetSentDataAsString();
	BencEntity bEntityGetPeer;
	// verify the bencoded string that went out the socket
	BencEntity::Parse((const byte *)bencMessageGetPeerResponse.c_str(), bEntityGetPeer, (const byte *)(bencMessageGetPeerResponse.c_str() + bencMessageGetPeerResponse.length()));

	// get the response dictionary for our get_peers query
	BencodedDict *dictForPeer = BencodedDict::AsDict(&bEntityGetPeer);
	EXPECT_TRUE(dictForPeer);
	if (!dictForPeer) {
		FAIL() << "ERROR:  The response is not a bencoded dictionary for a get_peers query";
	}

	// check the ipv4 address we supplied in SocketAddr sAddr(...) above
	Buffer ip;
	ip.b = (byte*)dictForPeer->GetString("ip", &ip.len);
	ASSERT_EQ(6, ip.len) << "ERROR:  The length of the ip address extracted from the response arguments is the wrong size";
	EXPECT_FALSE(memcmp((const void*)ip.b, (const void *)"zzzz", 4));
	EXPECT_FALSE(memcmp((const void*)(ip.b + 4), (const void *)"xx", 2));

	// now look into the response data
	BencodedDict *replyGetPeer = dictForPeer->GetDict("r");
	if (!replyGetPeer) {
		FAIL() << "ERROR:  Failed to extract 'r' dictionary from get_peer response";
	}

	// Finally! Now get the token to use
	Buffer token;
	token.b = (byte*)replyGetPeer->GetString("token", &token.len);
	EXPECT_TRUE(token.len) << "ERROR:  There is no token (zero bytes)";

	// build the announce_peer test string with the token
	fillTestDataBytes(testDataBytes, token, testDataPart1, testDataPart2);

	// clear the socket
	socket4.Reset();

	// use Tick() to reset the _dht_quota
	dhtTestObj->Tick();

	// now we can start testing the response to announce_peer
	// Send the announce_peer query
	dhtTestObj->ProcessIncoming((byte*)&testDataBytes.front(), testDataBytes.size(), sAddr);

	// get the bencoded string out of the socket
	std::string bencMessage = socket4.GetSentDataAsString();
	BencEntity bEntity;

	// verify the bencoded string that went out the socket
	BencEntity::Parse((const byte *)bencMessage.c_str(), bEntity, (const byte *)(bencMessage.c_str() + bencMessage.length()));

	// did we get a valid dictionary
	BencodedDict *dict = BencodedDict::AsDict(&bEntity);
	EXPECT_TRUE(dict);
	if (!dict) {
		FAIL() << "ERROR:  The response is not a bencoded dictionary";
	}


	// is there a type and is it "r" for response
	cstr type = dict->GetString("y", 1);
	EXPECT_TRUE(type);
	if (!type) {
		FAIL() << "ERROR:  Failed to extract 'y' type from response";
	}
	ASSERT_EQ('r', *type);

	// check the transaction ID:  length=2, value = "aa"
	Buffer tid;
	tid.b = (byte*)dict->GetString("t", &tid.len);
	EXPECT_FALSE(!tid.b || tid.len > 16);
	if (!tid.b || tid.len > 16) {
		FAIL() << "ERROR:  There is either no transaction ID or its length is greater than 16 characters";
	}
	ASSERT_EQ(2, tid.len);
	EXPECT_FALSE(memcmp((const void*)tid.b, (const void *)"aa", 2));

	// now look into the response data
	BencodedDict *reply = dict->GetDict("r");
	if (!reply) {
		FAIL() << "ERROR:  Failed to extract 'r' dictionary from response";
	}

	// did we get the correct id back
	byte *id = (byte*)reply->GetString("id", 20);
	if(!id){
		FAIL() << "ERROR:  Failed to extract 'id' from the reply data";
	}
	EXPECT_FALSE(memcmp((const void*)id, (const void *)"AAAABBBBCCCCDDDDEEEE", 20));

}

TEST(TestDhtImpl, TestAnnouncePeerWithImpliedport)
{
	UnitTestUDPSocket socket4;
	UnitTestUDPSocket socket6;
	smart_ptr<DhtImpl> dhtTestObj(new DhtImpl(&socket4, &socket6));
	dhtTestObj->SetSHACallback(&sha1_callback);
	BencodedDict bDictGetPeer;
	SockAddr sAddr(0x7a7a7a7a,0x0101); // note the port 0x0101

	// before we can announce_peer, we must use get_peers to obtain a token
	// use this to get a token
	std::string bEncodedGetPeers("d1:ad2:id20:abcdefghij01010101019:info_hash20:mnopqrstuvwxyz123456e1:q9:get_peers1:t2:aa1:y1:qe");

	// insert the token between these two strings
	std::string testDataPart1("d1:ad2:id20:abcdefghij012345678912:implied_porti1e9:info_hash20:mnopqrstuvwxyz1234564:porti6881e5:token");
	std::string testDataPart2("e1:q13:announce_peer1:t2:aa1:y1:qe");
	std::string testData;

	std::vector<byte> testDataBytes;

	// prepare the object for use
	dhtTestObj->Enable(true,0);
	SetDHT_my_id_Bytes(dhtTestObj);

	// first do the GetPeers to obtain a token
	dhtTestObj->ProcessIncoming((byte*)bEncodedGetPeers.c_str(), bEncodedGetPeers.size(), sAddr);

	// get the bencoded string out of the socket
	std::string bencMessageGetPeerResponse = socket4.GetSentDataAsString();
	BencEntity bEntityGetPeer;
	// verify the bencoded string that went out the socket
	BencEntity::Parse((const byte *)bencMessageGetPeerResponse.c_str(), bEntityGetPeer, (const byte *)(bencMessageGetPeerResponse.c_str() + bencMessageGetPeerResponse.length()));

	// get the response dictionary for our get_peers query
	BencodedDict *dictForPeer = BencodedDict::AsDict(&bEntityGetPeer);
	EXPECT_TRUE(dictForPeer);
	if (!dictForPeer) {
		FAIL() << "ERROR:  The response is not a bencoded dictionary for a get_peers query";
	}

	// now look into the response data
	BencodedDict *replyGetPeer = dictForPeer->GetDict("r");
	if (!replyGetPeer) {
		FAIL() << "ERROR:  Failed to extract 'r' dictionary from get_peer response";
	}

	// Finally! Now get the token to use
	Buffer token;
	token.b = (byte*)replyGetPeer->GetString("token", &token.len);
	EXPECT_TRUE(token.len) << "ERROR:  There is no token (zero bytes)";

	// build the announce_peer test string with the token
	fillTestDataBytes(testDataBytes, token, testDataPart1, testDataPart2);

	// clear the socket
	socket4.Reset();

	// use Tick() to reset the _dht_quota
	dhtTestObj->Tick();

	// now we can start testing the response to announce_peer
	// Send the announce_peer query
	dhtTestObj->ProcessIncoming((byte*)&testDataBytes.front(), testDataBytes.size(), sAddr);

	DhtID id;
	CopyBytesToDhtID(id, (byte*)(&(testDataPart1.c_str()[12]))); // grab the id typed into the string at the top

	std::vector<StoredContainer>::iterator it = dhtTestObj->GetStorageForID(id);
	ASSERT_TRUE(it != dhtTestObj->_peer_store.end()) << "The item was not stored";
	ASSERT_EQ(1, it->peers.size()) << "there should be exactly one item in the store";

	EXPECT_EQ(0x01, it->peers[0].port[0]) << "The port low byte is wrong";
	EXPECT_EQ(0x01, it->peers[0].port[1]) << "The port High byte is wrong";
}


TEST(TestDhtImpl, TestAnnouncePeerWithOutImpliedport)
{
	UnitTestUDPSocket socket4;
	UnitTestUDPSocket socket6;
	smart_ptr<DhtImpl> dhtTestObj(new DhtImpl(&socket4, &socket6));
	dhtTestObj->SetSHACallback(&sha1_callback);
	BencodedDict bDictGetPeer;
	SockAddr sAddr(0x7a7a7a7a,0xF0F0); // note the port is different from 0x0202 encoded in the bstring below

	// before we can announce_peer, we must use get_peers to obtain a token
	// use this to get a token
	std::string bEncodedGetPeers("d1:ad2:id20:abcdefghij01010101019:info_hash20:mnopqrstuvwxyz123456e1:q9:get_peers1:t2:aa1:y1:qe");

	// insert the token between these two strings
	// note that the port integer is decimal of 0x0202
	std::string testDataPart1("d1:ad2:id20:abcdefghij01234567899:info_hash20:mnopqrstuvwxyz1234564:porti514e5:token");
	std::string testDataPart2("e1:q13:announce_peer1:t2:aa1:y1:qe");
	std::string testData;

	std::vector<byte> testDataBytes;

	// prepare the object for use
	dhtTestObj->Enable(true,0);
	SetDHT_my_id_Bytes(dhtTestObj);

	// first do the GetPeers to obtain a token
	dhtTestObj->ProcessIncoming((byte*)bEncodedGetPeers.c_str(), bEncodedGetPeers.size(), sAddr);

	// get the bencoded string out of the socket
	std::string bencMessageGetPeerResponse = socket4.GetSentDataAsString();
	BencEntity bEntityGetPeer;
	// verify the bencoded string that went out the socket
	BencEntity::Parse((const byte *)bencMessageGetPeerResponse.c_str(), bEntityGetPeer, (const byte *)(bencMessageGetPeerResponse.c_str() + bencMessageGetPeerResponse.length()));

	// get the response dictionary for our get_peers query
	BencodedDict *dictForPeer = BencodedDict::AsDict(&bEntityGetPeer);
	EXPECT_TRUE(dictForPeer);
	if (!dictForPeer) {
		FAIL() << "ERROR:  The response is not a bencoded dictionary for a get_peers query";
	}

	// now look into the response data
	BencodedDict *replyGetPeer = dictForPeer->GetDict("r");
	if (!replyGetPeer) {
		FAIL() << "ERROR:  Failed to extract 'r' dictionary from get_peer response";
	}

	// Finally! Now get the token to use
	Buffer token;
	token.b = (byte*)replyGetPeer->GetString("token", &token.len);
	EXPECT_TRUE(token.len) << "ERROR:  There is no token (zero bytes)";

	// build the announce_peer test string with the token
	fillTestDataBytes(testDataBytes, token, testDataPart1, testDataPart2);

	// clear the socket
	socket4.Reset();

	// use Tick() to reset the _dht_quota
	dhtTestObj->Tick();

	// now we can start testing the response to announce_peer
	// Send the announce_peer query
	dhtTestObj->ProcessIncoming((byte*)&testDataBytes.front(), testDataBytes.size(), sAddr);

	DhtID id;
	CopyBytesToDhtID(id, (byte*)(&(testDataPart1.c_str()[12]))); // grab the id typed into the string at the top

	std::vector<StoredContainer>::iterator it = dhtTestObj->GetStorageForID(id);
	ASSERT_TRUE(it != dhtTestObj->_peer_store.end()) << "The item was not stored";
	ASSERT_EQ(1, it->peers.size()) << "there should be exactly one item in the store";

	EXPECT_EQ(0x02, it->peers[0].port[0]) << "The port low byte is wrong";
	EXPECT_EQ(0x02, it->peers[0].port[1]) << "The port High byte is wrong";
}

TEST(TestDhtImpl, TestVoteRPC_ipv4)
{
	std::vector<byte>	messageBytes;
	std::vector<byte>	argumentBytes;

	UnitTestUDPSocket socket4;
	UnitTestUDPSocket socket6;
	smart_ptr<DhtImpl> dhtTestObj(new DhtImpl(&socket4, &socket6));
	dhtTestObj->SetSHACallback(&sha1_callback);
	BencodedDict bDictGetPeer;
	SockAddr sAddr(0x7a7a7a7a,0x7878); // ip = zzzz and socket = xx

	// prepare the object for use
	dhtTestObj->Enable(true,0);
	SetDHT_my_id_Bytes(dhtTestObj);

	// get a token to use
	std::vector<byte> token;
	if(!GetToken(dhtTestObj, token, socket4)){
		FAIL() << "Unable to obtain a token";
	}

	BencStartDictionary(argumentBytes);
	{
		BencAddNameValuePair(argumentBytes,"id","abcdefghij0123456789");
		BencAddNameValuePair(argumentBytes,"target",MakeRandomKey20());
		BencAddNameValuePair(argumentBytes,"token",token);
		BencAddNameValuePair(argumentBytes,"vote",1);
	}
	BencEndDictionary(argumentBytes);

	BencStartDictionary(messageBytes);
	{
		BencAddNameAndBencodedDictionary(messageBytes,"a",argumentBytes);
		BencAddNameValuePair(messageBytes,"q","vote");
		BencAddNameValuePair(messageBytes,"t","aa");
		BencAddNameValuePair(messageBytes,"y","q");
	}
	BencEndDictionary(messageBytes);

	// parse and send the message constructed above
	dhtTestObj->ProcessIncoming((byte*)&messageBytes.front(), messageBytes.size(), sAddr);

	// get the bencoded string out of the socket
	std::string bencMessage = socket4.GetSentDataAsString();
	BencEntity bEntity;

	// verify the bencoded string that went out the socket
	BencEntity::Parse((const byte *)bencMessage.c_str(), bEntity, (const byte *)(bencMessage.c_str() + bencMessage.length()));

	// did we get a valid dictionary
	BencodedDict *dict = BencodedDict::AsDict(&bEntity);
	EXPECT_TRUE(dict);
	if (!dict) {
		FAIL() << "ERROR:  The response is not a bencoded dictionary";
	}

	// is there a type and is it "r" for response
	cstr type = dict->GetString("y", 1);
	EXPECT_TRUE(type);
	if (!type) {
		FAIL() << "ERROR:  Failed to extract 'y' type from response";
	}
	ASSERT_EQ('r', *type);

	// check the transaction ID:  length=2, value = "aa"
	Buffer tid;
	tid.b = (byte*)dict->GetString("t", &tid.len);
	EXPECT_FALSE(!tid.b || tid.len > 16);
	if (!tid.b || tid.len > 16) {
		FAIL() << "ERROR:  There is either no transaction ID or its length is greater than 16 characters";
	}
	ASSERT_EQ(2, tid.len);
	EXPECT_FALSE(memcmp((const void*)tid.b, (const void *)"aa", tid.len));

	// check the ipv4 address we supplied in SocketAddr sAddr(...) above
	Buffer ip;
	ip.b = (byte*)dict->GetString("ip", &ip.len);
	ASSERT_EQ(6, ip.len) << "ERROR:  The length of the ip address extracted from the response arguments is the wrong size";
	EXPECT_FALSE(memcmp((const void*)ip.b, (const void *)"zzzz", 4));
	EXPECT_FALSE(memcmp((const void*)(ip.b + 4), (const void *)"xx", 2));

	// now look into the response data
	BencodedDict *reply = dict->GetDict("r");
	if (!reply) {
		FAIL() << "ERROR:  Failed to extract 'r' dictionary from response";
	}

	byte *id = (byte*)reply->GetString("id", 20);
	if(!id){
		FAIL() << "ERROR:  Failed to extract 'id' from the reply data";
	}
	EXPECT_FALSE(memcmp((const void*)id, (const void *)"AAAABBBBCCCCDDDDEEEE", 20));


	// get the votes out of the dictionary
	BencodedList *voteList = reply->GetList("v");
	if(!voteList){
		FAIL() << "ERROR:  Failed to extract 'v' (vote list) from the reply data";
	}

	// is the list the right length
	ASSERT_EQ(5, voteList->GetCount());

	// expect 1, 0, 0, 0, 0
	ASSERT_EQ(1, voteList->GetInt(0)) << "Expected 1 0 0 0 0 but received 0 - - - -";
	ASSERT_EQ(0, voteList->GetInt(1)) << "Expected 1 0 0 0 0 but received 1 1 - - -";
	ASSERT_EQ(0, voteList->GetInt(2)) << "Expected 1 0 0 0 0 but received 1 0 1 - -";
	ASSERT_EQ(0, voteList->GetInt(3)) << "Expected 1 0 0 0 0 but received 1 0 0 1 -";
	ASSERT_EQ(0, voteList->GetInt(4)) << "Expected 1 0 0 0 0 but received 1 0 0 0 1";
}

// verify that multiple votes to the same target are recorded
TEST(TestDhtImpl, TestVoteRPC_ipv4_MultipleVotes)
{
	std::vector<byte>	messageBytes;
	std::vector<byte>	argumentBytes;

	UnitTestUDPSocket socket4;
	UnitTestUDPSocket socket6;
	smart_ptr<DhtImpl> dhtTestObj(new DhtImpl(&socket4, &socket6));
	dhtTestObj->SetSHACallback(&sha1_callback);
	BencodedDict bDictGetPeer;
	SockAddr sAddr(0x7a7a7a7a,0x7878); // ip = zzzz and socket = xx

	// prepare the object for use
	dhtTestObj->Enable(true,0);
	SetDHT_my_id_Bytes(dhtTestObj);

	// get a token to use
	std::vector<byte> token;
	if(!GetToken(dhtTestObj, token, socket4)){
		FAIL() << "Unable to obtain a token";
	}

	// make a target key to use
	std::vector<byte> target = MakeRandomKey20();

	// make the first vote message with a vote of 5
	BencStartDictionary(argumentBytes);
	{
		BencAddNameValuePair(argumentBytes,"id","abcdefghij0123456789");
		BencAddNameValuePair(argumentBytes,"target",target);
		BencAddNameValuePair(argumentBytes,"token",token);
		BencAddNameValuePair(argumentBytes,"vote",5);
	}
	BencEndDictionary(argumentBytes);

	BencStartDictionary(messageBytes);
	{
		BencAddNameAndBencodedDictionary(messageBytes,"a",argumentBytes);
		BencAddNameValuePair(messageBytes,"q","vote");
		BencAddNameValuePair(messageBytes,"t","aa");
		BencAddNameValuePair(messageBytes,"y","q");
	}
	BencEndDictionary(messageBytes);

	// parse and send the first vote message
	dhtTestObj->ProcessIncoming((byte*)&messageBytes.front(), messageBytes.size(), sAddr);

	// prepare to send the second vote message
	dhtTestObj->Tick();
	socket4.Reset();
	argumentBytes.clear();
	messageBytes.clear();

	// make the second vote message with a vote of 2
	BencStartDictionary(argumentBytes);
	{
		BencAddNameValuePair(argumentBytes,"id","abcdefghij0123456789");
		BencAddNameValuePair(argumentBytes,"target",target);
		BencAddNameValuePair(argumentBytes,"token",token);
		BencAddNameValuePair(argumentBytes,"vote",2);
	}
	BencEndDictionary(argumentBytes);

	BencStartDictionary(messageBytes);
	{
		BencAddNameAndBencodedDictionary(messageBytes,"a",argumentBytes);
		BencAddNameValuePair(messageBytes,"q","vote");
		BencAddNameValuePair(messageBytes,"t","aa");
		BencAddNameValuePair(messageBytes,"y","q");
	}
	BencEndDictionary(messageBytes);

	// parse and send the second vote message
	dhtTestObj->ProcessIncoming((byte*)&messageBytes.front(), messageBytes.size(), sAddr);

	// get the bencoded string out of the socket
	std::string bencMessage = socket4.GetSentDataAsString();
	BencEntity bEntity;

	// verify the bencoded string that went out the socket
	BencEntity::Parse((const byte *)bencMessage.c_str(), bEntity, (const byte *)(bencMessage.c_str() + bencMessage.length()));

	// did we get a valid dictionary
	BencodedDict *dict = BencodedDict::AsDict(&bEntity);
	EXPECT_TRUE(dict);
	if (!dict) {
		FAIL() << "ERROR:  The response is not a bencoded dictionary";
	}

	// is there a type and is it "r" for response
	cstr type = dict->GetString("y", 1);
	EXPECT_TRUE(type);
	if (!type) {
		FAIL() << "ERROR:  Failed to extract 'y' type from response";
	}
	ASSERT_EQ('r', *type);

	// check the transaction ID:  length=2, value = "aa"
	Buffer tid;
	tid.b = (byte*)dict->GetString("t", &tid.len);
	EXPECT_FALSE(!tid.b || tid.len > 16);
	if (!tid.b || tid.len > 16) {
		FAIL() << "ERROR:  There is either no transaction ID or its length is greater than 16 characters";
	}
	ASSERT_EQ(2, tid.len);
	EXPECT_FALSE(memcmp((const void*)tid.b, (const void *)"aa", tid.len));

	// check the ipv4 address we supplied in SocketAddr sAddr(...) above
	Buffer ip;
	ip.b = (byte*)dict->GetString("ip", &ip.len);
	ASSERT_EQ(6, ip.len) << "ERROR:  The length of the ip address extracted from the response arguments is the wrong size";
	EXPECT_FALSE(memcmp((const void*)ip.b, (const void *)"zzzz", 4));
	EXPECT_FALSE(memcmp((const void*)(ip.b + 4), (const void *)"xx", 2));

	// now look into the response data
	BencodedDict *reply = dict->GetDict("r");
	if (!reply) {
		FAIL() << "ERROR:  Failed to extract 'r' dictionary from response";
	}

	byte *id = (byte*)reply->GetString("id", 20);
	if(!id){
		FAIL() << "ERROR:  Failed to extract 'id' from the reply data";
	}
	EXPECT_FALSE(memcmp((const void*)id, (const void *)"AAAABBBBCCCCDDDDEEEE", 20));


	// get the votes out of the dictionary
	BencodedList *voteList = reply->GetList("v");
	if(!voteList){
		FAIL() << "ERROR:  Failed to extract 'v' (vote list) from the reply data";
	}

	// is the list the right length
	ASSERT_EQ(5, voteList->GetCount());

	// expect 0, 1, 0, 0, 1
	ASSERT_EQ(0, voteList->GetInt(0)) << "Expected 0 1 0 0 1 but received 1 - - - -";
	ASSERT_EQ(1, voteList->GetInt(1)) << "Expected 0 1 0 0 1 but received 0 0 - - -";
	ASSERT_EQ(0, voteList->GetInt(2)) << "Expected 0 1 0 0 1 but received 0 1 1 - -";
	ASSERT_EQ(0, voteList->GetInt(3)) << "Expected 0 1 0 0 1 but received 0 1 0 1 -";
	ASSERT_EQ(1, voteList->GetInt(4)) << "Expected 0 1 0 0 1 but received 0 1 0 0 0";
}

bool AnnounceAndVerify(smart_ptr<DhtImpl> &dhtTestObj, std::vector<byte> &messageBytes, UnitTestUDPSocket &socket4)
{
	dhtTestObj->ProcessIncoming((byte*)&messageBytes.front(), messageBytes.size(), sAddr);

	// get the bencoded string out of the socket
	std::string bencMessage = socket4.GetSentDataAsString();
	BencEntity bEntity;

	// verify the bencoded string that went out the socket
	BencEntity::Parse((const byte *)bencMessage.c_str(), bEntity, (const byte *)(bencMessage.c_str() + bencMessage.length()));

	// did we get a valid dictionary
	BencodedDict *dict = BencodedDict::AsDict(&bEntity);
	if (!dict) {
		return false;
	}

	// is there a type and is it "r" for response
	cstr type = dict->GetString("y", 1);
	if (!type) {
		return false;
	}
	if((*type) != 'r'){
		return false;
	}

	// check the ipv4 address we supplied in SocketAddr sAddr(...) above
	Buffer ip;
	ip.b = (byte*)dict->GetString("ip", &ip.len);
	if(!ip.b){
		return false;
	}

	// now look into the response data
	BencodedDict *reply = dict->GetDict("r");
	if (!reply) {
		return false;
	}

	byte *id = (byte*)reply->GetString("id", 20);
	if(!id){
		return false;
	}
	if(memcmp((const void*)id, (const void *)DHTID_BYTES.c_str(), 20)){
		return false;
	}

	if(ip.len != (sAddr_AddressAsString.size() + sAddr_PortAsString.size())){
		return false;
	}
	if(memcmp((const void*)ip.b, (const void *)sAddr_AddressAsString.c_str(), sAddr_AddressAsString.size())){
		return false;
	}
	if(memcmp((const void*)(ip.b + sAddr_AddressAsString.size()), (const void *)sAddr_PortAsString.c_str(), sAddr_PortAsString.size())){
		return false;
	}

	socket4.Reset();
	dhtTestObj->Tick();
	return true;
}

TEST(TestDhtImpl, TestDHTScrapeSeed0_ipv4)
{
	std::vector<byte>	messageBytes;
	std::vector<byte>	argumentBytes;

	UnitTestUDPSocket socket4;
	UnitTestUDPSocket socket6;

	smart_ptr<DhtImpl> dhtTestObj(new DhtImpl(&socket4, &socket6));
	dhtTestObj->SetSHACallback(&sha1_callback);
	SetDHT_my_id_Bytes(dhtTestObj);
	dhtTestObj->Enable(true,0);

	// get a token to use
	std::vector<byte> token;
	if(!GetToken(dhtTestObj, token, socket4)){
		FAIL() << "Unable to obtain a token";
	}

	// make a random info_hash key to use
	std::vector<byte> infoHashKey = MakeRandomKey20();

	// prepare the first anounce_peer with seed = 0
	BencStartDictionary(argumentBytes);
	{
		BencAddNameValuePair(argumentBytes,"id","abcdefghij0101010101");
		BencAddNameValuePair(argumentBytes,"info_hash",infoHashKey);
		BencAddNameValuePair(argumentBytes,"port",6881);
		BencAddNameValuePair(argumentBytes,"seed",0);
		BencAddNameValuePair(argumentBytes,"token",token);
		BencAddNameValuePair(argumentBytes,"name","test torrent");
	}
	BencEndDictionary(argumentBytes);

	BencStartDictionary(messageBytes);
	{
		BencAddNameAndBencodedDictionary(messageBytes,"a",argumentBytes);
		BencAddNameValuePair(messageBytes,"q","announce_peer");
		BencAddNameValuePair(messageBytes,"t","aa");
		BencAddNameValuePair(messageBytes,"y","q");
	}
	BencEndDictionary(messageBytes);

	// send the announce_peer message
	if(!AnnounceAndVerify(dhtTestObj, messageBytes, socket4)){
		FAIL() << "Unable to announce_peer";
	}

	// now make a get_peers message for scrape
	argumentBytes.clear();
	messageBytes.clear();
	BencStartDictionary(argumentBytes);
	{
		BencAddNameValuePair(argumentBytes,"id","abcdefghij0101010101");
		BencAddNameValuePair(argumentBytes,"info_hash",infoHashKey);
		BencAddNameValuePair(argumentBytes,"port",6881);
		BencAddNameValuePair(argumentBytes,"scrape",1);
	}
	BencEndDictionary(argumentBytes);

	BencStartDictionary(messageBytes);
	{
		BencAddNameAndBencodedDictionary(messageBytes,"a",argumentBytes);
		BencAddNameValuePair(messageBytes,"q","get_peers");
		BencAddNameValuePair(messageBytes,"t","aa");
		BencAddNameValuePair(messageBytes,"y","q");
	}
	BencEndDictionary(messageBytes);

	// send the get_peers message
	dhtTestObj->ProcessIncoming((byte*)&messageBytes.front(), messageBytes.size(), sAddr);

	// get the bencoded data out of the socket and into a benc entity
	Buffer socketData;
	socketData.len = socket4.GetSentByteVector().size();
	socketData.b = (byte *)&(socket4.GetSentByteVector().front());

	BencEntity bEntity;
	BencEntity::Parse((const byte *)&(socket4.GetSentByteVector().front()), bEntity
		, (const byte *)(&(socket4.GetSentByteVector().front()) + socket4.GetSentByteVector().size()));

	// get the whole response dictionary
	BencodedDict *dict = BencodedDict::AsDict(&bEntity);
	if (!dict) {
		FAIL() << "ERROR:  The response is not a bencoded dictionary";
	}

	// is there a type and is it "r" for response
	cstr type = dict->GetString("y", 1);
	EXPECT_TRUE(type);
	if (!type) {
		FAIL() << "ERROR:  Failed to extract 'y' type from response";
	}
	ASSERT_EQ('r', *type);

	// now extract the reply data dictionary
	BencodedDict *reply = dict->GetDict("r");
	if (!reply) {
		FAIL() << "ERROR:  Failed to extract 'r' dictionary from response";
	}

	byte *id = (byte*)reply->GetString("id", 20);
	if(!id){
		FAIL() << "ERROR:  Failed to extract 'id' from the reply data";
	}
	EXPECT_FALSE(memcmp((const void*)id, (const void *)DHTID_BYTES.c_str(), 20));

	// verify that BFsd and BFpe are present
	// see BEP #33 for details of BFsd & BFpe
	Buffer bfsd;
	bfsd.b = (byte*)reply->GetString("BFsd", &bfsd.len);
	if(!bfsd.b || bfsd.len != 256){
		FAIL() << "ERROR:  Failed extracting BFsd from scrape reply";
	}
	EXPECT_EQ(0, CountSetBits(bfsd)) << "ERROR:  Expected exactly 0 bits to be set in the seeds bloom filter 'BFsd'";

	Buffer bfpe;
	bfpe.b = (byte*)reply->GetString("BFpe", &bfpe.len);
	if(!bfpe.b || bfpe.len != 256){
		FAIL() << "ERROR:  Failed extracting BFpe from scrape reply";
	}
	EXPECT_EQ(2, CountSetBits(bfpe)) << "ERROR:  Expected exactly 2 bits to be set in the peers bloom filter 'BFpe'";
}

TEST(TestDhtImpl, TestDHTScrapeSeed1_ipv4)
{
	std::vector<byte>	messageBytes;
	std::vector<byte>	argumentBytes;

	UnitTestUDPSocket socket4;
	UnitTestUDPSocket socket6;

	smart_ptr<DhtImpl> dhtTestObj(new DhtImpl(&socket4, &socket6));
	dhtTestObj->SetSHACallback(&sha1_callback);
	SetDHT_my_id_Bytes(dhtTestObj);
	dhtTestObj->Enable(true,0);

	// get a token to use
	std::vector<byte> token;
	if(!GetToken(dhtTestObj, std::string("abcdefghij0123456789"), token, socket4)){
		FAIL() << "Unable to obtain a token";
	}

	// make a random info_hash key to use
	std::vector<byte> infoHashKey = MakeRandomKey20();

	// prepare the first anounce_peer with seed = 0
	BencStartDictionary(argumentBytes);
	{
		BencAddNameValuePair(argumentBytes,"id","abcdefghij0123456789");
		BencAddNameValuePair(argumentBytes,"info_hash",infoHashKey);
		BencAddNameValuePair(argumentBytes,"port",6881);
		BencAddNameValuePair(argumentBytes,"seed",1);
		BencAddNameValuePair(argumentBytes,"token",token);
	}
	BencEndDictionary(argumentBytes);

	BencStartDictionary(messageBytes);
	{
		BencAddNameAndBencodedDictionary(messageBytes,"a",argumentBytes);
		BencAddNameValuePair(messageBytes,"q","announce_peer");
		BencAddNameValuePair(messageBytes,"t","aa");
		BencAddNameValuePair(messageBytes,"y","q");
	}
	BencEndDictionary(messageBytes);

	// send the announce_peer message
	if(!AnnounceAndVerify(dhtTestObj, messageBytes, socket4)){
		FAIL() << "Unable to announce_peer";
	}

	// now make a get_peers message for scrape
	argumentBytes.clear();
	messageBytes.clear();
	BencStartDictionary(argumentBytes);
	{
		BencAddNameValuePair(argumentBytes,"id","abcdefghij0123456789");
		BencAddNameValuePair(argumentBytes,"info_hash",infoHashKey);
		BencAddNameValuePair(argumentBytes,"port",6881);
		BencAddNameValuePair(argumentBytes,"scrape",1);
	}
	BencEndDictionary(argumentBytes);

	BencStartDictionary(messageBytes);
	{
		BencAddNameAndBencodedDictionary(messageBytes,"a",argumentBytes);
		BencAddNameValuePair(messageBytes,"q","get_peers");
		BencAddNameValuePair(messageBytes,"t","aa");
		BencAddNameValuePair(messageBytes,"y","q");
	}
	BencEndDictionary(messageBytes);

	// send the get_peers message
	dhtTestObj->ProcessIncoming((byte*)&messageBytes.front(), messageBytes.size(), sAddr);

	// get the bencoded data out of the socket and into a benc entity
	Buffer socketData;
	socketData.len = socket4.GetSentByteVector().size();
	socketData.b = (byte *)&(socket4.GetSentByteVector().front());

	BencEntity bEntity;
	BencEntity::Parse((const byte *)&(socket4.GetSentByteVector().front()), bEntity, (const byte *)(&(socket4.GetSentByteVector().front()) + socket4.GetSentByteVector().size()));

	// get the whole response dictionary
	BencodedDict *dict = BencodedDict::AsDict(&bEntity);
	if (!dict) {
		FAIL() << "ERROR:  The response is not a bencoded dictionary";
	}

	// is there a type and is it "r" for response
	cstr type = dict->GetString("y", 1);
	EXPECT_TRUE(type);
	if (!type) {
		FAIL() << "ERROR:  Failed to extract 'y' type from response";
	}
	ASSERT_EQ('r', *type);

	// now extract the reply data dictionary
	BencodedDict *reply = dict->GetDict("r");
	if (!reply) {
		FAIL() << "ERROR:  Failed to extract 'r' dictionary from response";
	}

	byte *id = (byte*)reply->GetString("id", 20);
	if(!id){
		FAIL() << "ERROR:  Failed to extract 'id' from the reply data";
	}
	EXPECT_FALSE(memcmp((const void*)id, (const void *)DHTID_BYTES.c_str(), 20));

	// verify that BFsd and BFpe are present
	// see BEP #33 for details of BFsd & BFpe
	Buffer bfsd;
	bfsd.b = (byte*)reply->GetString("BFsd", &bfsd.len);
	if(!bfsd.b || bfsd.len != 256){
		FAIL() << "ERROR:  Failed extracting BFsd from scrape reply";
	}
	ASSERT_EQ(2, CountSetBits(bfsd)) << "ERROR:  Expected exactly 0 bits to be set in the seeds bloom filter 'BFsd'";

	Buffer bfpe;
	bfpe.b = (byte*)reply->GetString("BFpe", &bfpe.len);
	if(!bfpe.b || bfpe.len != 256){
		FAIL() << "ERROR:  Failed extracting BFpe from scrape reply";
	}
	ASSERT_EQ(0, CountSetBits(bfpe)) << "ERROR:  Expected exactly 2 bits to be set in the peers bloom filter 'BFpe'";
}

TEST(TestDhtImpl, TestDHTForNonexistantPeers_ipv4)
{
	std::vector<byte>	messageBytes;
	std::vector<byte>	argumentBytes;

	UnitTestUDPSocket socket4;
	UnitTestUDPSocket socket6;

	smart_ptr<DhtImpl> dhtTestObj(new DhtImpl(&socket4, &socket6));
	dhtTestObj->SetSHACallback(&sha1_callback);
	dhtTestObj->Enable(true,0);

	// get a token to use
	std::vector<byte> token;
	if(!GetToken(dhtTestObj, token, socket4)){
		FAIL() << "Unable to obtain a token";
	}

	int port = 6881;
	std::string id("abcdefghij0123456789");

	// announce several peers
	EXPECT_TRUE(AnnouncePeer(dhtTestObj, id, MakeRandomKey20(), port, std::string("name01"), socket4));
	EXPECT_TRUE(AnnouncePeer(dhtTestObj, id, MakeRandomKey20(), port, std::string("name02"), socket4));
	EXPECT_TRUE(AnnouncePeer(dhtTestObj, id, MakeRandomKey20(), port, std::string("name03"), socket4));
	EXPECT_TRUE(AnnouncePeer(dhtTestObj, id, MakeRandomKey20(), port, std::string("name04"), socket4));
	EXPECT_TRUE(AnnouncePeer(dhtTestObj, id, MakeRandomKey20(), port, std::string("name05"), socket4));
	EXPECT_TRUE(AnnouncePeer(dhtTestObj, id, MakeRandomKey20(), port, std::string("name06"), socket4));
	EXPECT_TRUE(AnnouncePeer(dhtTestObj, id, MakeRandomKey20(), port, std::string("name07"), socket4));
	EXPECT_TRUE(AnnouncePeer(dhtTestObj, id, MakeRandomKey20(), port, std::string("name08"), socket4));
	EXPECT_TRUE(AnnouncePeer(dhtTestObj, id, MakeRandomKey20(), port, std::string("name09"), socket4));
	EXPECT_TRUE(AnnouncePeer(dhtTestObj, id, MakeRandomKey20(), port, std::string("name10"), socket4));
	EXPECT_TRUE(AnnouncePeer(dhtTestObj, id, MakeRandomKey20(), port, std::string("name11"), socket4));
	EXPECT_TRUE(AnnouncePeer(dhtTestObj, id, MakeRandomKey20(), port, std::string("name12"), socket4));
	EXPECT_TRUE(AnnouncePeer(dhtTestObj, id, MakeRandomKey20(), port, std::string("name13"), socket4));

	// now make a get_peers message with a nonexistant hash
	argumentBytes.clear();
	messageBytes.clear();
	BencStartDictionary(argumentBytes);
	{
		BencAddNameValuePair(argumentBytes,"id","abcdefghij0123456789");
		BencAddNameValuePair(argumentBytes,"info_hash","__nonexistenthash___");
		BencAddNameValuePair(argumentBytes,"port",6881);
	}
	BencEndDictionary(argumentBytes);

	BencStartDictionary(messageBytes);
	{
		BencAddNameAndBencodedDictionary(messageBytes,"a",argumentBytes);
		BencAddNameValuePair(messageBytes,"q","get_peers");
		BencAddNameValuePair(messageBytes,"t","aa");
		BencAddNameValuePair(messageBytes,"y","q");
	}
	BencEndDictionary(messageBytes);

	// send the get_peers message
	dhtTestObj->ProcessIncoming((byte*)&messageBytes.front(), messageBytes.size(), sAddr);

	// get the bencoded data out of the socket and into a benc entity
	Buffer socketData;
	socketData.len = socket4.GetSentByteVector().size();

	BencEntity bEntity;
	BencEntity::Parse((const byte *)&(socket4.GetSentByteVector().front()), bEntity, (const byte *)(&(socket4.GetSentByteVector().front()) + socket4.GetSentByteVector().size()));

	// get the whole response dictionary
	BencodedDict *dict = BencodedDict::AsDict(&bEntity);
	if (!dict) {
		FAIL() << "ERROR:  The response is not a bencoded dictionary";
	}

	// is there a type and is it "r" for response
	cstr type = dict->GetString("y", 1);
	EXPECT_TRUE(type);
	if (!type) {
		FAIL() << "ERROR:  Failed to extract 'y' type from response";
	}
	ASSERT_EQ('r', *type);

	// now extract the reply data dictionary
	BencodedDict *reply = dict->GetDict("r");
	if (!reply) {
		FAIL() << "ERROR:  Failed to extract 'r' dictionary from response";
	}

	// check that there is NOT a 'values' key in the reply dictionary
	cstr values = reply->GetString("values", 6);
	EXPECT_FALSE(values) << "ERROR:  There is a 'values' key in the reply dictionary for a non-existant hash";
}

TEST(TestDhtImpl, TestFutureCmdAsFindNode01_ipv4)
{
	// unknown messages with either a 'target'
	// or an 'info-hash' argument are treated
	// as a find node to not block future extensions

	UnitTestUDPSocket socket4;
	UnitTestUDPSocket socket6;
	smart_ptr<DhtImpl> dhtTestObj(new DhtImpl(&socket4, &socket6));
	dhtTestObj->SetSHACallback(&sha1_callback);
	SockAddr sAddr(0x7a7a7a7a,0x7878); // ip = zzzz and socket = xx

	// prepare the object for use
	dhtTestObj->Enable(true,0);
	SetDHT_my_id_Bytes(dhtTestObj);

	// specify, parse, and send the message
	// Set a TARGET with a 'future_cmd' command in this test
	// it sould be treated as a find_node command
	std::string testData("d1:ad2:id20:abcdefghij01234567896:target20:mnopqrstuvwxyz123456e1:q10:future_cmd1:t2:aa1:y1:qe");
	dhtTestObj->ProcessIncoming((byte*)testData.c_str(), testData.size(), sAddr);

	// get the bencoded string out of the socket
	std::string bencMessage = socket4.GetSentDataAsString();
	BencEntity bEntity;

	// verify the bencoded string that went out the socket
	BencEntity::Parse((const byte *)bencMessage.c_str(), bEntity, (const byte *)(bencMessage.c_str() + bencMessage.length()));

	// did we get a valid dictionary
	BencodedDict *dict = BencodedDict::AsDict(&bEntity);
	EXPECT_TRUE(dict);
	if (!dict) {
		FAIL() << "ERROR:  The response is not a bencoded dictionary";
	}

	// is there a type and is it "r" for response
	cstr type = dict->GetString("y", 1);
	EXPECT_TRUE(type);
	if (!type) {
		FAIL() << "ERROR:  Failed to extract 'y' type from response";
	}
	ASSERT_EQ('r', *type);

	// check the transaction ID:  length=2, value = "aa"
	Buffer tid;
	tid.b = (byte*)dict->GetString("t", &tid.len);
	EXPECT_FALSE(!tid.b || tid.len > 16);
	if (!tid.b || tid.len > 16) {
		FAIL() << "ERROR:  There is either no transaction ID or its length is greater than 16 characters";
	}
	ASSERT_EQ(2, tid.len);
	EXPECT_FALSE(memcmp((const void*)tid.b, (const void *)"aa", tid.len));

	// now look into the response data
	BencodedDict *reply = dict->GetDict("r");
	if (!reply) {
		FAIL() << "ERROR:  Failed to extract 'r' dictionary from response";
	}

	byte *id = (byte*)reply->GetString("id", 20);
	if(!id){
		FAIL() << "ERROR:  Failed to extract 'id' from the reply data";
	}
	EXPECT_FALSE(memcmp((const void*)id, (const void *)"AAAABBBBCCCCDDDDEEEE", 20));

	// There should be a single node - this one
	// expect back the id provided in the query, ip=zzzz port=xx (since the querying node and this node are the same in this test)
	Buffer nodes;
	nodes.b = (byte*)reply->GetString("nodes", &nodes.len);
	ASSERT_EQ(26, nodes.len) << "ERROR:  The length of the 26 byte node info extracted from the response arguments is the wrong size";
	EXPECT_FALSE(memcmp((const void*)nodes.b, (const void *)"abcdefghij0123456789zzzzxx", nodes.len));
}

TEST(TestDhtImpl, TestFutureCmdAsFindNode02_ipv4)
{
	// unknown messages with either a 'target'
	// or an 'info-hash' argument are treated
	// as a find node to not block future extensions

	UnitTestUDPSocket socket4;
	UnitTestUDPSocket socket6;
	smart_ptr<DhtImpl> dhtTestObj(new DhtImpl(&socket4, &socket6));
	dhtTestObj->SetSHACallback(&sha1_callback);
	SockAddr sAddr(0x7a7a7a7a,0x7878); // ip = zzzz and socket = xx

	// prepare the object for use
	dhtTestObj->Enable(true,0);
	SetDHT_my_id_Bytes(dhtTestObj);

	// specify, parse, and send the message
	// Set an INFO_HASH with a 'future_cmd' command in this test
	// it sould be treated as a find_node command
	std::string testData("d1:ad2:id20:abcdefghij01234567899:info_hash20:mnopqrstuvwxyz123456e1:q10:future_cmd1:t2:aa1:y1:qe");
	dhtTestObj->ProcessIncoming((byte*)testData.c_str(), testData.size(), sAddr);

	// get the bencoded string out of the socket
	std::string bencMessage = socket4.GetSentDataAsString();
	BencEntity bEntity;

	// verify the bencoded string that went out the socket
	BencEntity::Parse((const byte *)bencMessage.c_str(), bEntity, (const byte *)(bencMessage.c_str() + bencMessage.length()));

	// did we get a valid dictionary
	BencodedDict *dict = BencodedDict::AsDict(&bEntity);
	EXPECT_TRUE(dict);
	if (!dict) {
		FAIL() << "ERROR:  The response is not a bencoded dictionary";
	}

	// is there a type and is it "r" for response
	cstr type = dict->GetString("y", 1);
	EXPECT_TRUE(type);
	if (!type) {
		FAIL() << "ERROR:  Failed to extract 'y' type from response";
	}
	ASSERT_EQ('r', *type);

	// check the transaction ID:  length=2, value = "aa"
	Buffer tid;
	tid.b = (byte*)dict->GetString("t", &tid.len);
	EXPECT_FALSE(!tid.b || tid.len > 16);
	if (!tid.b || tid.len > 16) {
		FAIL() << "ERROR:  There is either no transaction ID or its length is greater than 16 characters";
	}
	ASSERT_EQ(2, tid.len);
	EXPECT_FALSE(memcmp((const void*)tid.b, (const void *)"aa", tid.len));

	// now look into the response data
	BencodedDict *reply = dict->GetDict("r");
	if (!reply) {
		FAIL() << "ERROR:  Failed to extract 'r' dictionary from response";
	}

	byte *id = (byte*)reply->GetString("id", 20);
	if(!id){
		FAIL() << "ERROR:  Failed to extract 'id' from the reply data";
	}
	EXPECT_FALSE(memcmp((const void*)id, (const void *)"AAAABBBBCCCCDDDDEEEE", 20));

	// There should be a single node - this one
	// expect back the id provided in the query, ip=zzzz port=xx (since the querying node and this node are the same in this test)
	Buffer nodes;
	nodes.b = (byte*)reply->GetString("nodes", &nodes.len);
	ASSERT_EQ(26, nodes.len) << "ERROR:  The length of the 26 byte node info extracted from the response arguments is the wrong size";
	EXPECT_FALSE(memcmp((const void*)nodes.b, (const void *)"abcdefghij0123456789zzzzxx", nodes.len));
}

TEST(TestDhtImpl, TestUnknownCmdNotProcessed_ipv4)
{
	// unknown messages with either a 'target'
	// or an 'info-hash' argument are treated
	// as a find node to not block future extensions

	UnitTestUDPSocket socket4;
	UnitTestUDPSocket socket6;
	smart_ptr<DhtImpl> dhtTestObj(new DhtImpl(&socket4, &socket6));
	dhtTestObj->SetSHACallback(&sha1_callback);
	SockAddr sAddr(0x7a7a7a7a,0x7878); // ip = zzzz and socket = xx

	// prepare the object for use
	dhtTestObj->Enable(true,0);
	SetDHT_my_id_Bytes(dhtTestObj);

	// specify, parse, and send the message
	// DO NOT set a target or info_hash with this 'unknown_cmd' command in this test
	// it sould NOT be treated as anything
	std::string testData("d1:ad2:id20:abcdefghij012345678911:unknown_arg20:mnopqrstuvwxyz123456e1:q11:unknown_cmd1:t2:aa1:y1:qe");
	dhtTestObj->ProcessIncoming((byte*)testData.c_str(), testData.size(), sAddr);

	// get the bencoded string out of the socket
	std::string bencMessage = socket4.GetSentDataAsString();
	BencEntity bEntity;

	// verify the bencoded string that went out the socket
	BencEntity::Parse((const byte *)bencMessage.c_str(), bEntity, (const byte *)(bencMessage.c_str() + bencMessage.length()));

	// did we get a valid dictionary
	BencodedDict *dict = BencodedDict::AsDict(&bEntity);
	EXPECT_FALSE(dict) << "ERROR:  a valid dictionary was returned for an unknown command without either a target or info_hash argument to be considered as a find_nodes command";
}

TEST(TestDhtImpl, TestImmutablePutRPC_ipv4)
{
	std::vector<byte>	messageBytes;
	std::vector<byte>	argumentBytes;

	UnitTestUDPSocket socket4;
	UnitTestUDPSocket socket6;
	smart_ptr<DhtImpl> dhtTestObj(new DhtImpl(&socket4, &socket6));
	dhtTestObj->SetSHACallback(&sha1_callback);
	BencodedDict bDictGetPeer;

	// prepare the object for use
	dhtTestObj->Enable(true,0);
	SetDHT_my_id_Bytes(dhtTestObj);

	// get a token to use
	std::vector<byte> token;
	if(!GetToken(dhtTestObj, token, socket4)){
		FAIL() << "Unable to obtain a token";
	}

	BencStartDictionary(argumentBytes);
	{
		BencAddNameValuePair(argumentBytes,"id","abcdefghij0123456789");
		BencAddNameValuePair(argumentBytes,"token",token);
		BencAddNameValuePair(argumentBytes,"v","Immutable put test");
	}
	BencEndDictionary(argumentBytes);

	BencStartDictionary(messageBytes);
	{
		BencAddNameAndBencodedDictionary(messageBytes,"a",argumentBytes);
		BencAddNameValuePair(messageBytes,"q","put");
		BencAddNameValuePair(messageBytes,"t","aa");
		BencAddNameValuePair(messageBytes,"y","q");
	}
	BencEndDictionary(messageBytes);

	// parse and send the message constructed above
	dhtTestObj->ProcessIncoming((byte*)&messageBytes.front(), messageBytes.size(), sAddr);

	// get the bencoded string out of the socket
	std::string bencMessage = socket4.GetSentDataAsString();
	BencEntity bEntity;

	// verify the bencoded string that went out the socket
	BencEntity::Parse((const byte *)bencMessage.c_str(), bEntity, (const byte *)(bencMessage.c_str() + bencMessage.length()));

	// did we get a valid dictionary
	BencodedDict *dict = BencodedDict::AsDict(&bEntity);
	EXPECT_TRUE(dict);
	if (!dict) {
		FAIL() << "ERROR:  The response is not a bencoded dictionary";
	}

	// is there a type and is it "r" for response
	cstr type = dict->GetString("y", 1);
	EXPECT_TRUE(type);
	if (!type) {
		FAIL() << "ERROR:  Failed to extract 'y' type from response";
	}
	ASSERT_EQ('r', *type);

	// check the transaction ID:  length=2, value = "aa"
	Buffer tid;
	tid.b = (byte*)dict->GetString("t", &tid.len);
	EXPECT_FALSE(!tid.b || tid.len > 16);
	if (!tid.b || tid.len > 16) {
		FAIL() << "ERROR:  There is either no transaction ID or its length is greater than 16 characters";
	}
	ASSERT_EQ(2, tid.len);
	EXPECT_FALSE(memcmp((const void*)tid.b, (const void *)"aa", tid.len));

	// now look into the response data
	BencodedDict *reply = dict->GetDict("r");
	if (!reply) {
		FAIL() << "ERROR:  Failed to extract 'r' dictionary from response";
	}

	byte *id = (byte*)reply->GetString("id", 20);
	if(!id){
		FAIL() << "ERROR:  Failed to extract 'id' from the reply data";
	}
	EXPECT_FALSE(memcmp((const void*)id, (const void *)DHTID_BYTES.c_str(), 20));
}

TEST(TestDhtImpl, TestImmutableGetRPC_ipv4)
{
	std::vector<byte>	messageBytes;
	std::vector<byte>	argumentBytes;

	UnitTestUDPSocket socket4;
	UnitTestUDPSocket socket6;
	smart_ptr<DhtImpl> dhtTestObj(new DhtImpl(&socket4, &socket6));
	dhtTestObj->SetSHACallback(&sha1_callback);
	BencodedDict bDictGetPeer;

	// prepare the object for use
	dhtTestObj->Enable(true,0);
	SetDHT_my_id_Bytes(dhtTestObj);

	// *** FIRST: put something in ***
	{
		// get a token to use
		std::vector<byte> tokenForPut;
		if(!GetToken(dhtTestObj, tokenForPut, socket4)){
			FAIL() << "Unable to obtain a token";
		}

		BencStartDictionary(argumentBytes);
		{
			BencAddNameValuePair(argumentBytes,"id","abcdefghij0123456789");
			BencAddNameValuePair(argumentBytes,"token",tokenForPut);
			BencAddNameValuePair(argumentBytes,"v","Immutable get test");
		}
		BencEndDictionary(argumentBytes);

		BencStartDictionary(messageBytes);
		{
			BencAddNameAndBencodedDictionary(messageBytes,"a",argumentBytes);
			BencAddNameValuePair(messageBytes,"q","put");
			BencAddNameValuePair(messageBytes,"t","aa");
			BencAddNameValuePair(messageBytes,"y","q");
		}
		BencEndDictionary(messageBytes);

		// parse and send the message constructed above
		dhtTestObj->ProcessIncoming((byte*)&messageBytes.front(), messageBytes.size(), sAddr);

		// get the bencoded string out of the socket
		std::string bencMessage = socket4.GetSentDataAsString();
		BencEntity bEntity;

		// verify the bencoded string that went out the socket
		BencEntity::Parse((const byte *)bencMessage.c_str(), bEntity, (const byte *)(bencMessage.c_str() + bencMessage.length()));

		// did we get a valid dictionary
		BencodedDict *dict = BencodedDict::AsDict(&bEntity);
		EXPECT_TRUE(dict);
		if (!dict) {
			FAIL() << "ERROR:  The response is not a bencoded dictionary - unable to do immutable put to test immutable get";
		}
	}
	// *** SECOND: get something out ***
	argumentBytes.clear();
	messageBytes.clear();

	sha1_hash target = sha1_callback(reinterpret_cast<const byte*>("18:Immutable get test"),21);
	Buffer hashInfo;
	hashInfo.b = (byte*)target.value;
	hashInfo.len = 20;
	BencStartDictionary(argumentBytes);
	{
		BencAddNameValuePair(argumentBytes,"id","abcdefghij0123456789");
		BencAddNameValuePair(argumentBytes,"target",hashInfo);
	}
	BencEndDictionary(argumentBytes);

	BencStartDictionary(messageBytes);
	{
		BencAddNameAndBencodedDictionary(messageBytes,"a",argumentBytes);
		BencAddNameValuePair(messageBytes,"q","get");
		BencAddNameValuePair(messageBytes,"t","aa");
		BencAddNameValuePair(messageBytes,"y","q");
	}
	BencEndDictionary(messageBytes);

	// parse and send the message constructed above
	socket4.Reset();
	dhtTestObj->ProcessIncoming((byte*)&messageBytes.front(), messageBytes.size(), sAddr);

	// get the bencoded string out of the socket
	std::string bencMessage = socket4.GetSentDataAsString();
	BencEntity bEntity;

	// verify the bencoded string that went out the socket
	BencEntity::Parse((const byte *)bencMessage.c_str(), bEntity, (const byte *)(bencMessage.c_str() + bencMessage.length()));

	// did we get a valid dictionary
	BencodedDict *dict = BencodedDict::AsDict(&bEntity);
	EXPECT_TRUE(dict);
	if (!dict) {
		FAIL() << "ERROR:  The response is not a bencoded dictionary";
	}

	// is there a type and is it "r" for response
	cstr type = dict->GetString("y", 1);
	EXPECT_TRUE(type);
	if (!type) {
		FAIL() << "ERROR:  Failed to extract 'y' type from response";
	}
	ASSERT_EQ('r', *type);

	// check the transaction ID:  length=2, value = "aa"
	Buffer tid;
	tid.b = (byte*)dict->GetString("t", &tid.len);
	EXPECT_FALSE(!tid.b || tid.len > 16);
	if (!tid.b || tid.len > 16) {
		FAIL() << "ERROR:  There is either no transaction ID or its length is greater than 16 characters";
	}
	ASSERT_EQ(2, tid.len);
	EXPECT_FALSE(memcmp((const void*)tid.b, (const void *)"aa", tid.len));

	// now look into the response data
	BencodedDict *reply = dict->GetDict("r");
	if (!reply) {
		FAIL() << "ERROR:  Failed to extract 'r' dictionary from response";
	}

	byte *id = (byte*)reply->GetString("id", 20);
	if(!id){
		FAIL() << "ERROR:  Failed to extract 'id' from the reply data";
	}
	EXPECT_FALSE(memcmp((const void*)id, (const void *)DHTID_BYTES.c_str(), 20));

	// check that there is a token
	Buffer token;
	reply->GetString("token", &token.len);
	EXPECT_TRUE(token.len) << "There should have been a token of non-zero length";

	// get the nodes
	Buffer nodes;
	nodes.b = (byte*)reply->GetString("nodes", &nodes.len);
	EXPECT_TRUE(nodes.len) << "There should have been a node";

	// get the value "v"
	// v should be an bencentity of "18:Immutable get test".  Using the GetString will strip out the 18 and just return the text.
	Buffer value;
	value.b = (byte*)reply->GetString("v", &value.len);
	ASSERT_EQ(18, value.len) << "The value is the wrong length";
	EXPECT_FALSE(memcmp((const void*)value.b, (const void *)"Immutable get test", 18));
}


TEST(TestDhtImpl, TestMultipleImmutablePutRPC_ipv4)
{
	std::vector<byte>	messageBytes;
	std::vector<byte>	argumentBytes;

	UnitTestUDPSocket socket4;
	UnitTestUDPSocket socket6;
	smart_ptr<DhtImpl> dhtTestObj(new DhtImpl(&socket4, &socket6));
	dhtTestObj->SetSHACallback(&sha1_callback);
	BencodedDict bDictGetPeer;

	// prepare the object for use
	dhtTestObj->Enable(true,0);
	SetDHT_my_id_Bytes(dhtTestObj);

	// if the same thing gets put multiple times there should only be one copy of it stored
	//                                                 20_byte_dhtid_val_
	EXPECT_TRUE(PutBencString(dhtTestObj, std::string("20_byte_dhtid_val_00"), std::string("i-1e"), socket4)) << "_00";
	EXPECT_TRUE(PutBencString(dhtTestObj, std::string("20_byte_dhtid_val_01"), std::string("i-1e"), socket4)) << "_01";
	EXPECT_TRUE(PutBencString(dhtTestObj, std::string("20_byte_dhtid_val_02"), std::string("i-1e"), socket4)) << "_02";
	EXPECT_TRUE(PutBencString(dhtTestObj, std::string("20_byte_dhtid_val_03"), std::string("i-1e"), socket4)) << "_03";
	EXPECT_TRUE(PutBencString(dhtTestObj, std::string("20_byte_dhtid_val_04"), std::string("i-1e"), socket4)) << "_04";
	EXPECT_EQ(1,dhtTestObj->GetNumPutItems()) << "ERROR:  multiple instances of the same thing stored";

	// now add different things and see the count increase
	EXPECT_TRUE(PutBencString(dhtTestObj, std::string("20_byte_dhtid_val_00"), std::string("i2e"), socket4)) << "_00";
	EXPECT_TRUE(PutBencString(dhtTestObj, std::string("20_byte_dhtid_val_01"), std::string("i3e"), socket4)) << "_01";
	EXPECT_TRUE(PutBencString(dhtTestObj, std::string("20_byte_dhtid_val_02"), std::string("i4e"), socket4)) << "_02";
	EXPECT_TRUE(PutBencString(dhtTestObj, std::string("20_byte_dhtid_val_03"), std::string("i5e"), socket4)) << "_03";
	EXPECT_TRUE(PutBencString(dhtTestObj, std::string("20_byte_dhtid_val_04"), std::string("i6e"), socket4)) << "_04";
	EXPECT_EQ(6,dhtTestObj->GetNumPutItems()) << "ERROR:  several different thinigs did not get stored";
}


TEST(TestDhtImpl, TestMultipleImmutablePutAndGetRPC_ipv4)
{
	std::vector<byte> hashes[5];
	std::string putValues[5];
	std::vector<byte>	messageBytes;
	std::vector<byte>	argumentBytes;
	MutableComponents getData;

	UnitTestUDPSocket socket4;
	UnitTestUDPSocket socket6;
	smart_ptr<DhtImpl> dhtTestObj(new DhtImpl(&socket4, &socket6));
	dhtTestObj->SetSHACallback(&sha1_callback);
	BencodedDict bDictGetPeer;

	// prepare the object for use
	dhtTestObj->Enable(true,0);
	SetDHT_my_id_Bytes(dhtTestObj);

	putValues[0] = ("i5e"); // test an integer
	putValues[1] = ("l4:spam4:eggse"); // list
	putValues[2] = ("d4:spaml1:a1:bee"); // dictionary with list
	putValues[3] = ("4:spam"); // string
	putValues[4] = ("d3:cow3:moo4:spam4:eggse"); // dictionary

	for(int x=0; x<5; ++x){
		sha1_hash hash = sha1_callback(reinterpret_cast<const byte*>(putValues[x].c_str()), putValues[x].size());
		hashes[x].insert(hashes[x].end(), hash.value, hash.value + 20);
	}

	// put data in
	EXPECT_TRUE(PutBencString(dhtTestObj, std::string("20_byte_dhtid_val_00"), putValues[0], socket4)) << "_00";
	EXPECT_TRUE(PutBencString(dhtTestObj, std::string("20_byte_dhtid_val_01"), putValues[1], socket4)) << "_01";
	EXPECT_TRUE(PutBencString(dhtTestObj, std::string("20_byte_dhtid_val_02"), putValues[2], socket4)) << "_02";
	EXPECT_TRUE(PutBencString(dhtTestObj, std::string("20_byte_dhtid_val_03"), putValues[3], socket4)) << "_03";
	EXPECT_TRUE(PutBencString(dhtTestObj, std::string("20_byte_dhtid_val_04"), putValues[4], socket4)) << "_04";
	EXPECT_EQ(5,dhtTestObj->GetNumPutItems()) << "ERROR:  several different thinigs did not get stored";

	// get the data out and see that it matches what was put
	for(int x=0; x<5; ++x){
		getData = GetComponents(dhtTestObj, hashes[x], socket4, true, true);
		// there should only be the string value that was put
		EXPECT_TRUE(getData.valueData == putValues[x]) << "Should have been:  '" << putValues[x] << "'  Instead of:  " << getData.valueData;
		// there should not be any key or signature information
		EXPECT_EQ(0, getData.key.size());
		EXPECT_EQ(0, getData.signature.size());
	}
}


TEST(TestDhtImpl, TestMutablePutRPC_ipv4)
{
#if ENABLE_SRP
	std::vector<byte>	messageBytes;
	std::vector<byte>	argumentBytes;

	UnitTestUDPSocket socket4;
	UnitTestUDPSocket socket6;
	smart_ptr<DhtImpl> dhtTestObj(new DhtImpl(&socket4, &socket6));
	dhtTestObj->SetSHACallback(&sha1_callback);
	BencodedDict bDictGetPeer;

	// prepare the object for use
	dhtTestObj->Enable(true,2000);
	SetDHT_my_id_Bytes(dhtTestObj);

	// get a token to use
	std::vector<byte> token;
	if(!GetToken(dhtTestObj, token, socket4)){
		FAIL() << "Unable to obtain a token";
	}

	// register tomcrypt algorithms
	register_prng(&rc4_desc);
	register_cipher(&aes_desc);
	register_hash(&sha1_desc);
	// use libtommatha
	ltc_mp = ltm_desc;

	// make a valid key and signature for the test to  use
	prng_state prngState;
	bool validKey = true;
	rsa_key key;
	unsigned long publicKeyLen = keyBufferSize;
	unsigned char publicKeyBytes[keyBufferSize];
	unsigned long signatureLen = keyBufferSize;
	unsigned char signatureBytes[keyBufferSize];
	byte sha1Digest[SHA1_DIGESTSIZE];
	int err;

	Buffer publicKeyBuf; // just point this to PublicKeyBytes
	Buffer signatureBuf; // just point this to signatureBytes

	rng_make_prng(512, find_prng("rc4"), &prngState, NULL);
	int hash_idx = find_hash("sha1");
	int prng_idx = find_prng("rc4");
	if ((err=rsa_make_key(&prngState, prng_idx, 256, 65537, &key)) != CRYPT_OK )
	{	FAIL() << "ERROR:  Unable to generate a key for the test; error:  " << err;
	}

	// export the public key
	err = der_encode_sequence_multi(publicKeyBytes, &publicKeyLen,
		LTC_ASN1_INTEGER, 1UL,  key.N,
		LTC_ASN1_INTEGER, 1UL,  key.e,
		LTC_ASN1_EOL,     0UL,  NULL);
	publicKeyBuf.b = (byte*)publicKeyBytes;
	publicKeyBuf.len = publicKeyLen;

	// The string below must be the bencoding of what is put into the argumentBytes
	// for the sequence number and the 'v' element
	std::string sequenceToHash("3:seqi55e1:v16:Mutable Put Test");
	SHA1::Hash((void*)sequenceToHash.c_str(), sequenceToHash.size(), (byte*)sha1Digest);
	err = rsa_sign_hash((unsigned char*)sha1Digest, 20,
		                (unsigned char*)signatureBytes, &signatureLen,
						&prngState, 0,
						0, 0,
						&key);
	signatureBuf.b = (byte*)signatureBytes;
	signatureBuf.len = signatureLen;

	// free memory used by rsa
	if(validKey) rsa_free(&key);

	BencStartDictionary(argumentBytes);
	{
		BencAddNameValuePair(argumentBytes,"id","abcdefghij0123456789");
		BencAddNameValuePair(argumentBytes,"k", publicKeyBuf);
		BencAddNameValuePair(argumentBytes,"seq",55);
		BencAddNameValuePair(argumentBytes,"sig",signatureBuf);
		BencAddNameValuePair(argumentBytes,"token",token);
		BencAddNameValuePair(argumentBytes,"v","Mutable Put Test");
	}
	BencEndDictionary(argumentBytes);

	BencStartDictionary(messageBytes);
	{
		BencAddNameAndBencodedDictionary(messageBytes,"a",argumentBytes);
		BencAddNameValuePair(messageBytes,"q","put");
		BencAddNameValuePair(messageBytes,"t","aa");
		BencAddNameValuePair(messageBytes,"y","q");
	}
	BencEndDictionary(messageBytes);

	// parse and send the message constructed above
	dhtTestObj->ProcessIncoming((byte*)&messageBytes.front(), messageBytes.size(), sAddr);

	// get the bencoded string out of the socket
	std::string bencMessage = socket4.GetSentDataAsString();
	BencEntity bEntity;

	// verify the bencoded string that went out the socket
	BencEntity::Parse((const byte *)bencMessage.c_str(), bEntity, (const byte *)(bencMessage.c_str() + bencMessage.length()));

	// did we get a valid dictionary
	BencodedDict *dict = BencodedDict::AsDict(&bEntity);
	EXPECT_TRUE(dict);
	if (!dict) {
		FAIL() << "ERROR:  The response is not a bencoded dictionary";
	}

	// is there a type and is it "r" for response
	cstr type = dict->GetString("y", 1);
	EXPECT_TRUE(type);
	if (!type) {
		FAIL() << "ERROR:  Failed to extract 'y' type from response";
	}
	ASSERT_EQ('r', *type);

	// check the transaction ID:  length=2, value = "aa"
	Buffer tid;
	tid.b = (byte*)dict->GetString("t", &tid.len);
	EXPECT_FALSE(!tid.b || tid.len > 16);
	if (!tid.b || tid.len > 16) {
		FAIL() << "ERROR:  There is either no transaction ID or its length is greater than 16 characters";
	}
	ASSERT_EQ(2, tid.len);
	EXPECT_FALSE(memcmp((const void*)tid.b, (const void *)"aa", tid.len));

	// now look into the response data
	BencodedDict *reply = dict->GetDict("r");
	if (!reply) {
		FAIL() << "ERROR:  Failed to extract 'r' dictionary from response";
	}

	byte *id = (byte*)reply->GetString("id", 20);
	if(!id){
		FAIL() << "ERROR:  Failed to extract 'id' from the reply data";
	}
	EXPECT_FALSE(memcmp((const void*)id, (const void *)DHTID_BYTES.c_str(), 20));
#else
	const ::testing::TestInfo* const test_info = ::testing::UnitTest::GetInstance()->current_test_info();
	std::cout << "----> " << test_info->name() << ":  ENABLE_SRP must be true for this test to execute.\n";
#endif
}

TEST(TestDhtImpl, TestMutableGetRPC_ipv4)
{
#if ENABLE_SRP
	std::vector<byte>	messageBytes;
	std::vector<byte>	argumentBytes;

	UnitTestUDPSocket socket4;
	UnitTestUDPSocket socket6;
	smart_ptr<DhtImpl> dhtTestObj(new DhtImpl(&socket4, &socket6));
	dhtTestObj->SetSHACallback(&sha1_callback);
	BencodedDict bDictGetPeer;

	// prepare the object for use
	dhtTestObj->Enable(true,2000);
	SetDHT_my_id_Bytes(dhtTestObj);

	// get a token to use
	std::vector<byte> token;
	if(!GetToken(dhtTestObj, token, socket4)){
		FAIL() << "Unable to obtain a token";
	}

	// register tomcrypt algorithms
	register_prng(&rc4_desc);
	register_cipher(&aes_desc);
	register_hash(&sha1_desc);
	// use libtommatha
	ltc_mp = ltm_desc;

	// make a valid key and signature for the test to  use
	prng_state prngState;
	bool validKey = true;
	rsa_key key;
	unsigned long publicKeyLen = keyBufferSize;
	unsigned char publicKeyBytes[keyBufferSize];
	unsigned long signatureLen = keyBufferSize;
	unsigned char signatureBytes[keyBufferSize];
	byte sha1Digest[SHA1_DIGESTSIZE];
	int err;

	Buffer publicKeyBuf; // just point this to PublicKeyBytes
	Buffer signatureBuf; // just point this to signatureBytes

	// ***********************************
	// *** first perform a mutable put ***
	// ***********************************

	rng_make_prng(512, find_prng("rc4"), &prngState, NULL);
	int hash_idx = find_hash("sha1");
	int prng_idx = find_prng("rc4");
	if ((err=rsa_make_key(&prngState, prng_idx, 256, 65537, &key)) != CRYPT_OK )
	{	FAIL() << "ERROR:  Unable to generate a key for the test; error:  " << err;
	}

	// export the public key
	err = der_encode_sequence_multi(publicKeyBytes, &publicKeyLen,
		LTC_ASN1_INTEGER, 1UL,  key.N,
		LTC_ASN1_INTEGER, 1UL,  key.e,
		LTC_ASN1_EOL,     0UL,  NULL);
	//if(err=rsa_export(publicKeyBytes, &publicKeyLen, PK_PUBLIC, &key) != CRYPT_OK)
	//{	FAIL() << "ERROR:  Unable to export a public key for the test; error:  " << err;
	//}
	publicKeyBuf.b = (byte*)publicKeyBytes;
	publicKeyBuf.len = publicKeyLen;

	// The string below must be the bencoding of what is put into the argumentBytes
	// for the sequence number and the 'v' element
	std::string sequenceToHash("3:seqi55e1:v16:Mutable GET Test");
	SHA1::Hash((void*)sequenceToHash.c_str(), sequenceToHash.size(), (byte*)sha1Digest);
	err = rsa_sign_hash((unsigned char*)sha1Digest, 20,
		                (unsigned char*)signatureBytes, &signatureLen,
						&prngState, 0,
						0, 0,
						&key);
	signatureBuf.b = (byte*)signatureBytes;
	signatureBuf.len = signatureLen;

	// free memory used by rsa
	if(validKey) rsa_free(&key);

	BencStartDictionary(argumentBytes);
	{
		BencAddNameValuePair(argumentBytes,"id","abcdefghij0123456789");
		BencAddNameValuePair(argumentBytes,"k", publicKeyBuf);
		BencAddNameValuePair(argumentBytes,"seq",55);
		BencAddNameValuePair(argumentBytes,"sig",signatureBuf);
		BencAddNameValuePair(argumentBytes,"token",token);
		BencAddNameValuePair(argumentBytes,"v","Mutable GET Test");
	}
	BencEndDictionary(argumentBytes);

	BencStartDictionary(messageBytes);
	{
		BencAddNameAndBencodedDictionary(messageBytes,"a",argumentBytes);
		BencAddNameValuePair(messageBytes,"q","put");
		BencAddNameValuePair(messageBytes,"t","aa");
		BencAddNameValuePair(messageBytes,"y","q");
	}
	BencEndDictionary(messageBytes);

	// parse and send the message constructed above
	dhtTestObj->ProcessIncoming((byte*)&messageBytes.front(), messageBytes.size(), sAddr);

	// get the bencoded string out of the socket
	std::string bencMessage = socket4.GetSentDataAsString();
	BencEntity bEntity;

	// verify the bencoded string that went out the socket
	BencEntity::Parse((const byte *)bencMessage.c_str(), bEntity, (const byte *)(bencMessage.c_str() + bencMessage.length()));

	// did we get a valid dictionary
	BencodedDict *dict = BencodedDict::AsDict(&bEntity);
	EXPECT_TRUE(dict);
	if (!dict) {
		FAIL() << "ERROR:  The response is not a bencoded dictionary";
	}

	// is there a type and is it "r" for response
	cstr type = dict->GetString("y", 1);
	EXPECT_TRUE(type);
	if (!type) {
		FAIL() << "ERROR:  Failed to extract 'y' type from response";
	}
	ASSERT_EQ('r', *type);

	// check the transaction ID:  length=2, value = "aa"
	Buffer tid;
	tid.b = (byte*)dict->GetString("t", &tid.len);
	EXPECT_FALSE(!tid.b || tid.len > 16);
	if (!tid.b || tid.len > 16) {
		FAIL() << "ERROR:  There is either no transaction ID or its length is greater than 16 characters";
	}
	ASSERT_EQ(2, tid.len);
	EXPECT_FALSE(memcmp((const void*)tid.b, (const void *)"aa", tid.len));

	// now look into the response data
	BencodedDict *reply = dict->GetDict("r");
	if (!reply) {
		FAIL() << "ERROR:  Failed to extract 'r' dictionary from response";
	}

	byte *id = (byte*)reply->GetString("id", 20);
	if(!id){
		FAIL() << "ERROR:  Failed to extract 'id' from the reply data";
	}
	EXPECT_FALSE(memcmp((const void*)id, (const void *)DHTID_BYTES.c_str(), 20));

	// ***********************************
	// *** Now perform the mutable get ***
	// ***********************************

	argumentBytes.clear();
	messageBytes.clear();

	// sha1 hash the key for the 'target', put the whole key in 'key'
	Buffer targetBytes;
	Buffer keyBytes;
	byte hashBytes[SHA1_DIGESTSIZE];
	SHA1::Hash((const void*)publicKeyBytes, publicKeyLen, hashBytes);
	targetBytes.b = (byte*)hashBytes;
	targetBytes.len = SHA1_DIGESTSIZE;
	keyBytes.b = (byte*)publicKeyBytes;
	keyBytes.len = publicKeyLen;

	// assemble the queary
	BencStartDictionary(argumentBytes);
	{
		BencAddNameValuePair(argumentBytes,"id","abcdefghij0123456789");
		BencAddNameValuePair(argumentBytes,"k",keyBytes);
		BencAddNameValuePair(argumentBytes,"target",targetBytes);
	}
	BencEndDictionary(argumentBytes);

	BencStartDictionary(messageBytes);
	{
		BencAddNameAndBencodedDictionary(messageBytes,"a",argumentBytes);
		BencAddNameValuePair(messageBytes,"q","get");
		BencAddNameValuePair(messageBytes,"t","aa");
		BencAddNameValuePair(messageBytes,"y","q");
	}
	BencEndDictionary(messageBytes);
	// parse and send the message constructed above
	socket4.Reset();
	dhtTestObj->ProcessIncoming((byte*)&messageBytes.front(), messageBytes.size(), sAddr);

	// get the bencoded string out of the socket
	bencMessage = socket4.GetSentDataAsString();

	// verify the bencoded string that went out the socket
	BencEntity::Parse((const byte *)bencMessage.c_str(), bEntity, (const byte *)(bencMessage.c_str() + bencMessage.length()));

	// did we get a valid dictionary
	dict = BencodedDict::AsDict(&bEntity);
	EXPECT_TRUE(dict);
	if (!dict) {
		FAIL() << "ERROR:  The response is not a bencoded dictionary";
	}

	// is there a type and is it "r" for response
	type = dict->GetString("y", 1);
	EXPECT_TRUE(type);
	if (!type) {
		FAIL() << "ERROR:  Failed to extract 'y' type from response";
	}
	ASSERT_EQ('r', *type);

	// check the transaction ID:  length=2, value = "aa"
	tid.b = (byte*)dict->GetString("t", &tid.len);
	EXPECT_FALSE(!tid.b || tid.len > 16);
	if (!tid.b || tid.len > 16) {
		FAIL() << "ERROR:  There is either no transaction ID or its length is greater than 16 characters";
	}
	ASSERT_EQ(2, tid.len);
	EXPECT_FALSE(memcmp((const void*)tid.b, (const void *)"aa", tid.len));

	// now look into the response data
	reply = dict->GetDict("r");
	if (!reply) {
		FAIL() << "ERROR:  Failed to extract 'r' dictionary from response";
	}

	id = (byte*)reply->GetString("id", 20);
	if(!id){
		FAIL() << "ERROR:  Failed to extract 'id' from the reply data";
	}
	EXPECT_FALSE(memcmp((const void*)id, (const void *)DHTID_BYTES.c_str(), 20));

	// check that there is a token
	Buffer token2;
	token2.b = (byte*)reply->GetString("token", &token2.len);
	EXPECT_TRUE(token2.len) << "There should have been a token of non-zero length";

	// get the nodes
	Buffer nodes;
	nodes.b = (byte*)reply->GetString("nodes", &nodes.len);
	EXPECT_TRUE(nodes.len) << "There should have been a node";

	// get the value "v"
	// v should be an bencentity of "18:Immutable get test".  Using the GetString will strip out the 18 and just return the text.
	Buffer value;
	value.b = (byte*)reply->GetString("v", &value.len);
	ASSERT_EQ(16, value.len) << "The value is the wrong length";
	EXPECT_FALSE(memcmp((const void*)value.b, (const void *)"Mutable GET Test", 16));

	// verify the key returned is the same as what we put
	value.b = (byte*)reply->GetString("key", &value.len);
	ASSERT_EQ(publicKeyBuf.len, value.len) << "The length of the key returned by 'get' is different from the length of the key used in 'put'";
	EXPECT_FALSE(memcmp((const void*)publicKeyBuf.b, (const void*)publicKeyBuf.b, publicKeyBuf.len)) << "The public key returned by 'get' does not match the key that was 'put'.";

	// verify the signature returned is the same as what we put
	value.b = (byte*)reply->GetString("sig", &value.len);
	ASSERT_EQ(signatureBuf.len, value.len) << "The length of the signature returned by 'get' is different from the length of the signature used in 'put'";
	EXPECT_FALSE(memcmp((const void*)signatureBuf.b, (const void*)signatureBuf.b, signatureBuf.len)) << "The public signature returned by 'get' does not match the signature that was 'put'.";
#else
	const ::testing::TestInfo* const test_info = ::testing::UnitTest::GetInstance()->current_test_info();
	std::cout << "----> " << test_info->name() << ":  ENABLE_SRP must be true for this test to execute.\n";
#endif
}


/**
This test uses the version of mutable get that puts the first 20 bytes of the public
key in the 'target' element and the remainder of the bytes in the 'key' element
*/
TEST(TestDhtImpl, TestMultipleMutablePut_and_Get_ipv4)
{
#if ENABLE_SRP
	const unsigned int NumItems = 5;

	rsa_key keys[NumItems];
	std::vector<byte> exportedPublicKeys[NumItems];
	std::vector<byte> signatures[NumItems];
	std::string putValues[NumItems];
	MutableComponents getData;

	UnitTestUDPSocket socket4;
	UnitTestUDPSocket socket6;
	smart_ptr<DhtImpl> dhtTestObj(new DhtImpl(&socket4, &socket6));
	dhtTestObj->SetSHACallback(&sha1_callback);
	BencodedDict bDictGetPeer;

	// prepare the object for use
	dhtTestObj->Enable(true,4000);
	SetDHT_my_id_Bytes(dhtTestObj);

	// ****** Step 1 ******
	// do the mutable puts with sequence number 1
	putValues[0] = ("i5e"); // test an integer
	putValues[1] = ("l4:spam4:eggse"); // list
	putValues[2] = ("d4:spaml1:a1:bee"); // dictionary with list
	putValues[3] = ("4:spam"); // string
	putValues[4] = ("d3:cow3:moo4:spam4:eggse"); // dictionary
	for(unsigned int x=0; x<NumItems; ++x){
		EXPECT_TRUE(MakeRsaKey(keys[x], exportedPublicKeys[x])) << "*** Could not make keys ***"; // make a key for each thing to be put
		EXPECT_TRUE(MutablePutBencString(dhtTestObj, std::string("20_byte_dhtid_val_00"), putValues[x], 1, keys[x], socket4, signatures[x])) << "*Step 1* FAILED to put index[" << x << "]";
	}
	// see that we get back what we put
	for(unsigned int x=0; x<NumItems; ++x){
		getData = GetComponents(dhtTestObj, exportedPublicKeys[x], socket4, true);
		EXPECT_TRUE(getData.valueData == putValues[x]) << "*Step 1* Should have been:  '" << putValues[x] << "'  Instead of:  " << getData.valueData;
		EXPECT_TRUE(exportedPublicKeys[x] == getData.key) << "*Step 1* The put and get keys did not match";
		EXPECT_TRUE(signatures[x] == getData.signature) << "*Step 1* The put and get signatures did not match";
	}

	// ****** Step 2 ******
	// attempt to put data with the same sequence number 1; keep the signature from Step 1 - signature should not change, data should not change
	// it should not update the data
	for(unsigned int x=0; x<NumItems; ++x){
		EXPECT_TRUE(MutablePutBencString(dhtTestObj, std::string("20_byte_dhtid_val_00"), std::string("9:junk_data"), 1, keys[x], socket4)) << "*Step 2* FAILED to put index[" << x << "]";
	}
	// see that we get back the original data we put in step 1 above
	for(unsigned int x=0; x<NumItems; ++x){
		getData = GetComponents(dhtTestObj, exportedPublicKeys[x], socket4, true);
		EXPECT_TRUE(getData.valueData == putValues[x]) << "*Step 2* Should have been:  '" << putValues[x] << "'  Instead of:  " << getData.valueData;
		EXPECT_TRUE(exportedPublicKeys[x] == getData.key) << "*Step 2* The put and get keys did not match";
		EXPECT_TRUE(signatures[x] == getData.signature) << "*Step 2* The put and get signatures did not match";
	}

	// ****** Step 3 ******
	// change the data to be put
	putValues[0] = ("l4:zzzz4:eggse"); // list
	putValues[1] = ("d4:zzzzl1:a1:bee"); // dictionary with list
	putValues[2] = ("4:zzzz"); // string
	putValues[3] = ("d3:cow3:zzz4:spam4:eggse"); // dictionary
	putValues[4] = ("i8423e"); // test an integer
	// now put the data with the next sequence number:  2
	for(unsigned int x=0; x<NumItems; ++x){
		EXPECT_TRUE(MutablePutBencString(dhtTestObj, std::string("20_byte_dhtid_val_00"), putValues[x], 2, keys[x], socket4, signatures[x])) << "*Step 3* FAILED to put index[" << x << "]";
	}
	// see that we get back what we put
	for(unsigned int x=0; x<NumItems; ++x){
		getData = GetComponents(dhtTestObj, exportedPublicKeys[x], socket4, true);
		EXPECT_TRUE(getData.valueData == putValues[x]) << "*Step 3* Should have been:  '" << putValues[x] << "'  Instead of:  " << getData.valueData;
		EXPECT_TRUE(exportedPublicKeys[x] == getData.key) << "*Step 3* The put and get keys did not match";
		EXPECT_TRUE(signatures[x] == getData.signature) << "*Step 3* The put and get signatures did not match";
	}

	// ****** Step 4 ******
	// change the data to be put
	putValues[0] = ("d4:iiiil1:a1:bee"); // dictionary with list
	putValues[1] = ("4:iiii"); // string
	putValues[2] = ("d3:iii3:moo4:spam4:eggse"); // dictionary
	putValues[3] = ("i-673e"); // test an integer
	putValues[4] = ("l4:iiii4:eggse"); // list
	// now put the data with a large sequence number jump:
	for(unsigned int x=0; x<NumItems; ++x){
		EXPECT_TRUE(MutablePutBencString(dhtTestObj, std::string("20_byte_dhtid_val_00"), putValues[x], (x+1)*100, keys[x], socket4, signatures[x])) << "*Step 4* FAILED to put index[" << x << "]";
	}
	// see that we get back what we put
	for(unsigned int x=0; x<NumItems; ++x){
		getData = GetComponents(dhtTestObj, exportedPublicKeys[x], socket4, true);
		EXPECT_TRUE(getData.valueData == putValues[x]) << "*Step 4* Should have been:  '" << putValues[x] << "'  Instead of:  " << getData.valueData;
		EXPECT_TRUE(exportedPublicKeys[x] == getData.key) << "*Step 4* The put and get keys did not match";
		EXPECT_TRUE(signatures[x] == getData.signature) << "*Step 4* The put and get signatures did not match";
	}

	// ****** Step 5 ******
	// attempt to put data with a lower sequence number:  1
	// keep the current signature since it should not change - if it changes, something is wrong
	// it should not update the data
	for(unsigned int x=0; x<NumItems; ++x){
		EXPECT_TRUE(MutablePutBencString(dhtTestObj, std::string("20_byte_dhtid_val_00"), std::string("9:junk_data"), 1, keys[x], socket4)) << "*Step 5* FAILED to put index[" << x << "]";
	}
	// see that we get back the original data we put in step 1 above
	for(unsigned int x=0; x<NumItems; ++x){
		getData = GetComponents(dhtTestObj, exportedPublicKeys[x], socket4, true);
		EXPECT_TRUE(getData.valueData == putValues[x]) << "*Step 5* Should have been:  '" << putValues[x] << "'  Instead of:  " << getData.valueData;
		EXPECT_TRUE(exportedPublicKeys[x] == getData.key) << "*Step 5* The put and get keys did not match";
		EXPECT_TRUE(signatures[x] == getData.signature) << "*Step 5* The put and get signatures did not match";
	}

	// ****** Step 6 ******
	// attempt to retrieve data with a key not used to put data
	rsa_key nonDatakey;
	std::vector<byte> exportedNonDataKey;
	EXPECT_TRUE(MakeRsaKey(nonDatakey, exportedNonDataKey)) << "*** Could not make key for Step 6 test ***"; // make a key for each thing to be put
	// see that we get nothing back for this key
	getData = GetComponents(dhtTestObj, exportedNonDataKey, socket4, true);
	EXPECT_TRUE(getData.valueData == "") << "*Step 6* Should have been nothing (empty, no data) Instead of:  " << getData.valueData;
#else
	const ::testing::TestInfo* const test_info = ::testing::UnitTest::GetInstance()->current_test_info();
	std::cout << "----> " << test_info->name() << ":  ENABLE_SRP must be true for this test to execute.\n";
#endif
}


/**
This tests uses the 'get' rpc in both modes.  The 'target' element will be either
the sha1 of an immutable get or the sha1 of a public key for a mutable get.
*/
TEST(TestDhtImpl, TestGetUsingShaHashOfKey_ipv4)
{
#if ENABLE_SRP
	const unsigned int NumItems = 3;

	rsa_key keys[NumItems];
	std::vector<byte> exportedPublicKeys[NumItems];
	std::vector<byte> signatures[NumItems];
	std::string putValues[NumItems];
	MutableComponents getData;

	UnitTestUDPSocket socket4;
	UnitTestUDPSocket socket6;
	smart_ptr<DhtImpl> dhtTestObj(new DhtImpl(&socket4, &socket6));
	dhtTestObj->SetSHACallback(&sha1_callback);
	BencodedDict bDictGetPeer;

	// prepare the object for use
	dhtTestObj->Enable(true,4000);
	SetDHT_my_id_Bytes(dhtTestObj);

	// ****** Step 1 ******
	// do the mutable puts with sequence number 1
	putValues[0] = ("i5e"); // test an integer
	putValues[1] = ("l4:spam4:eggse"); // list
	putValues[2] = ("d4:spaml1:a1:bee"); // dictionary with list
	for(unsigned int x=0; x<NumItems; ++x){
		EXPECT_TRUE(MakeRsaKey(keys[x], exportedPublicKeys[x])) << "*** Could not make keys ***"; // make a key for each thing to be put
		EXPECT_TRUE(MutablePutBencString(dhtTestObj, std::string("20_byte_dhtid_val_00"), putValues[x], 1, keys[x], socket4, signatures[x])) << "*Step 1* FAILED to put index[" << x << "]";
	}
	// see that we get back what we put
	for(unsigned int x=0; x<NumItems; ++x){
		getData = GetComponents(dhtTestObj, exportedPublicKeys[x], socket4, true);
		EXPECT_TRUE(getData.valueData == putValues[x]) << "*Step 1* Should have been:  '" << putValues[x] << "'  Instead of:  " << getData.valueData;
		EXPECT_TRUE(exportedPublicKeys[x] == getData.key) << "*Step 1* The put and get keys did not match";
		EXPECT_TRUE(signatures[x] == getData.signature) << "*Step 1* The put and get signatures did not match";
	}

	// ****** Step 2 ******
	// attempt to put data with the same sequence number 1; keep the signature from Step 1 - signature should not change, data should not change
	// it should not update the data
	for(unsigned int x=0; x<NumItems; ++x){
		EXPECT_TRUE(MutablePutBencString(dhtTestObj, std::string("20_byte_dhtid_val_00"), std::string("9:junk_data"), 1, keys[x], socket4)) << "*Step 2* FAILED to put index[" << x << "]";
	}
	// see that we get back the original data we put in step 1 above
	for(unsigned int x=0; x<NumItems; ++x){
		getData = GetComponents(dhtTestObj, exportedPublicKeys[x], socket4, true);
		EXPECT_TRUE(getData.valueData == putValues[x]) << "*Step 2* Should have been:  '" << putValues[x] << "'  Instead of:  " << getData.valueData;
		EXPECT_TRUE(exportedPublicKeys[x] == getData.key) << "*Step 2* The put and get keys did not match";
		EXPECT_TRUE(signatures[x] == getData.signature) << "*Step 2* The put and get signatures did not match";
	}

	// ****** Step 3 ******
	// change the data to be put
	putValues[0] = ("l4:zzzz4:eggse"); // list
	putValues[1] = ("d4:zzzzl1:a1:bee"); // dictionary with list
	putValues[2] = ("4:zzzz"); // string
	// now put the data with the next sequence number:  2
	for(unsigned int x=0; x<NumItems; ++x){
		EXPECT_TRUE(MutablePutBencString(dhtTestObj, std::string("20_byte_dhtid_val_00"), putValues[x], 2, keys[x], socket4, signatures[x])) << "*Step 3* FAILED to put index[" << x << "]";
	}
	// see that we get back what we put
	for(unsigned int x=0; x<NumItems; ++x){
		getData = GetComponents(dhtTestObj, exportedPublicKeys[x], socket4, true);
		EXPECT_TRUE(getData.valueData == putValues[x]) << "*Step 3* Should have been:  '" << putValues[x] << "'  Instead of:  " << getData.valueData;
		EXPECT_TRUE(exportedPublicKeys[x] == getData.key) << "*Step 3* The put and get keys did not match";
		EXPECT_TRUE(signatures[x] == getData.signature) << "*Step 3* The put and get signatures did not match";
	}

	// ****** Step 4 ******
	// change the data to be put
	putValues[0] = ("d4:iiiil1:a1:bee"); // dictionary with list
	putValues[1] = ("4:iiii"); // string
	putValues[2] = ("d3:iii3:moo4:spam4:eggse"); // dictionary
	// now put the data with a large sequence number jump:
	for(unsigned int x=0; x<NumItems; ++x){
		EXPECT_TRUE(MutablePutBencString(dhtTestObj, std::string("20_byte_dhtid_val_00"), putValues[x], (x+1)*100, keys[x], socket4, signatures[x])) << "*Step 4* FAILED to put index[" << x << "]";
	}
	// see that we get back what we put
	for(unsigned int x=0; x<NumItems; ++x){
		getData = GetComponents(dhtTestObj, exportedPublicKeys[x], socket4, true);
		EXPECT_TRUE(getData.valueData == putValues[x]) << "*Step 4* Should have been:  '" << putValues[x] << "'  Instead of:  " << getData.valueData;
		EXPECT_TRUE(exportedPublicKeys[x] == getData.key) << "*Step 4* The put and get keys did not match";
		EXPECT_TRUE(signatures[x] == getData.signature) << "*Step 4* The put and get signatures did not match";
	}

	// ****** Step 5 ******
	// attempt to put data with a lower sequence number:  1
	// keep the current signature since it should not change - if it changes, something is wrong
	// it should not update the data
	for(unsigned int x=0; x<NumItems; ++x){
		EXPECT_TRUE(MutablePutBencString(dhtTestObj, std::string("20_byte_dhtid_val_00"), std::string("9:junk_data"), 1, keys[x], socket4)) << "*Step 5* FAILED to put index[" << x << "]";
	}
	// see that we get back the original data we put in step 1 above
	for(unsigned int x=0; x<NumItems; ++x){
		getData = GetComponents(dhtTestObj, exportedPublicKeys[x], socket4, true);
		EXPECT_TRUE(getData.valueData == putValues[x]) << "*Step 5* Should have been:  '" << putValues[x] << "'  Instead of:  " << getData.valueData;
		EXPECT_TRUE(exportedPublicKeys[x] == getData.key) << "*Step 5* The put and get keys did not match";
		EXPECT_TRUE(signatures[x] == getData.signature) << "*Step 5* The put and get signatures did not match";
	}

	// ****** Step 6 ******
	// attempt to retrieve data with a key not used to put data
	rsa_key nonDatakey;
	std::vector<byte> exportedNonDataKey;
	EXPECT_TRUE(MakeRsaKey(nonDatakey, exportedNonDataKey)) << "*** Could not make key for Step 6 test ***"; // make a key for each thing to be put
	// see that we get nothing back for this key
	getData = GetComponents(dhtTestObj, exportedNonDataKey, socket4, true);
	EXPECT_TRUE(getData.valueData == "") << "*Step 6* Should have been nothing (empty, no data) Instead of:  " << getData.valueData;
#else
	const ::testing::TestInfo* const test_info = ::testing::UnitTest::GetInstance()->current_test_info();
	std::cout << "----> " << test_info->name() << ":  ENABLE_SRP must be true for this test to execute.\n";
#endif
}


/**
This tests uses the 'get' rpc in both modes.  The 'target' element will be either
the sha1 of an immutable get or the sha1 of a public key for a mutable get.
*/
TEST(TestDhtImpl, TestCombinedMutableImmutablePutGet_ipv4)
{
#if ENABLE_SRP
	const unsigned int NumItems = 5;

	byte hashBytes[SHA1_DIGESTSIZE];
	rsa_key keys[NumItems];
	std::vector<byte> exportedPublicKeys[NumItems];
	std::vector<byte> keyHashes[NumItems];
	std::vector<byte> signatures[NumItems];
	std::string mutablePutValues[NumItems];
	std::string immutablePutValues[NumItems];
	std::vector<byte> immutablePutHashes[NumItems];
	MutableComponents getData;

	UnitTestUDPSocket socket4;
	UnitTestUDPSocket socket6;
	smart_ptr<DhtImpl> dhtTestObj(new DhtImpl(&socket4, &socket6));
	dhtTestObj->SetSHACallback(&sha1_callback);
	BencodedDict bDictGetPeer;

	// prepare the object for use
	dhtTestObj->Enable(true,4000);
	SetDHT_my_id_Bytes(dhtTestObj);

	// do the mutable puts with sequence number 1
	mutablePutValues[0] = ("i5e"); // test an integer
	mutablePutValues[1] = ("l4:spam4:eggse"); // list
	mutablePutValues[2] = ("d4:spaml1:a1:bee"); // dictionary with list
	mutablePutValues[3] = ("4:spam"); // string
	mutablePutValues[4] = ("d3:cow3:moo4:spam4:eggse"); // dictionary
	for(unsigned int x=0; x<NumItems; ++x){
		EXPECT_TRUE(MakeRsaKey(keys[x], exportedPublicKeys[x])) << "*** Could not make keys ***"; // make a key for each thing to be put
		// hash the key
		for(int i=0; i<SHA1_DIGESTSIZE; ++i){
			SHA1::Hash((void*)&exportedPublicKeys[x].front(), exportedPublicKeys[x].size(), hashBytes);
			keyHashes[x].push_back(hashBytes[i]);
		}

		EXPECT_TRUE(MutablePutBencString(dhtTestObj, std::string("20_byte_dhtid_val_00"), mutablePutValues[x], 1, keys[x], socket4, signatures[x])) << "* FAILED mutable put of index[" << x << "]";
	}

	// now put the immutable items
	immutablePutValues[2] = ("d5:aaaaal1:b1:cee"); // dictionary with list
	immutablePutValues[3] = ("7:torrent"); // string
	immutablePutValues[0] = ("i-995e"); // test an integer
	immutablePutValues[4] = ("d3:bug5:splat7:chicken5:clucke"); // dictionary
	immutablePutValues[1] = ("l3:ham4:tofue"); // list
	for(int x=0; x<NumItems; ++x){
		SHA1::Hash((void*)immutablePutValues[x].c_str(), immutablePutValues[x].size(), hashBytes);
		for(int i=0; i<20; ++i){
			immutablePutHashes[x].push_back(hashBytes[i]);
		}
	}
	for(int x=0; x<NumItems; ++x){
		EXPECT_TRUE(PutBencString(dhtTestObj, std::string("20_byte_dhtid_val_04"), immutablePutValues[x], socket4)) << "* FAILED immutable put of index[" << x << "]";
	}

	// see that we get back what we put for MUTABLE data using the hash of the key
	for(unsigned int x=0; x<NumItems; ++x){
		dhtTestObj->Tick();
		getData = GetComponents(dhtTestObj, keyHashes[x], socket4, true, true);
		EXPECT_TRUE(getData.valueData == mutablePutValues[x]) << "Should have been:  '" << mutablePutValues[x] << "'  Instead of:  " << getData.valueData;
		EXPECT_TRUE(exportedPublicKeys[x] == getData.key) << "The put and get keys did not match";
		EXPECT_TRUE(signatures[x] == getData.signature) << "The put and get signatures did not match";
	}

	// see that we get back what we put for IMMUTABLE data using the hash of the key
	for(unsigned int x=0; x<NumItems; ++x){
		dhtTestObj->Tick();
		getData = GetComponents(dhtTestObj, immutablePutHashes[x], socket4, true, true);
		EXPECT_TRUE(getData.valueData == immutablePutValues[x]) << "Should have been:  '" << mutablePutValues[x] << "'  Instead of:  " << getData.valueData;
		// there should be no key or signature data for an immutable get
		EXPECT_EQ(0, getData.key.size()) << "key information was returned for an immutable get";
		EXPECT_EQ(0, getData.signature.size()) << "signature information was returned for an immutable get";
	}
#else
	const ::testing::TestInfo* const test_info = ::testing::UnitTest::GetInstance()->current_test_info();
	std::cout << "----> " << test_info->name() << ":  ENABLE_SRP must be true for this test to execute.\n";
#endif
}


// *******************************************************************
//
// Speed Tests
//
// *******************************************************************

const unsigned long maxIterations = 25*speedTestFactor;


TEST(SpeedTestDhtImpl, PingKnownPacketSpeedTest)
{
	std::vector<byte>	messageBytes;
	std::vector<byte>	argumentBytes;

	UnitTestUDPSocket socket4;
	UnitTestUDPSocket socket6;
	smart_ptr<DhtImpl> dhtTestObj(new DhtImpl(&socket4, &socket6));
	dhtTestObj->SetSHACallback(&sha1_callback);

	// prepare the object for use
	dhtTestObj->Enable(true,2000);
	SetDHT_my_id_Bytes(dhtTestObj);
	dhtTestObj->Tick();

	// the test data
	char buffer[1024]; // use this since the string will be modified as it is processed
	std::string knownPingString("d1:ad2:id20:abcdefghij0123456789e1:q4:ping1:t4:wxyz1:v4:UTUT1:y1:qe");

	for(unsigned long x=0; x<maxIterations; ++x)
	{
		strcpy(buffer, knownPingString.c_str());
		dhtTestObj->ProcessIncoming((byte*)buffer, knownPingString.size(), sAddr);
		dhtTestObj->Tick();
		if(!socket4.GetSentByteVector().size()) FAIL() << "no bytes sent";
		socket4.Reset();

		strcpy(buffer, knownPingString.c_str());
		dhtTestObj->ProcessIncoming((byte*)buffer, knownPingString.size(), sAddr);
		dhtTestObj->Tick();
		if(!socket4.GetSentByteVector().size()) FAIL() << "no bytes sent";
		socket4.Reset();
	}
}

TEST(SpeedTestDhtImpl, PingArbitraryPacketSpeedTest)
{
	std::vector<byte>	messageBytes;
	std::vector<byte>	argumentBytes;

	UnitTestUDPSocket socket4;
	UnitTestUDPSocket socket6;
	smart_ptr<DhtImpl> dhtTestObj(new DhtImpl(&socket4, &socket6));
	dhtTestObj->SetSHACallback(&sha1_callback);

	// prepare the object for use
	dhtTestObj->Enable(true,2000);
	SetDHT_my_id_Bytes(dhtTestObj);
	dhtTestObj->Tick();

	// the test data
	char buffer[1024]; // use this since the string will be modified as it is processed
	std::string pingString("d1:ad2:id20:abcdefghij0123456789e1:q4:ping1:t2:aa1:y1:qe");

	for(unsigned long x=0; x<maxIterations; ++x)
	{
		strcpy(buffer, pingString.c_str());
		dhtTestObj->ProcessIncoming((byte*)buffer, pingString.size(), sAddr);
		dhtTestObj->Tick();
		if(!socket4.GetSentByteVector().size()) FAIL() << "no bytes sent";
		socket4.Reset();

		strcpy(buffer, pingString.c_str());
		dhtTestObj->ProcessIncoming((byte*)buffer, pingString.size(), sAddr);
		dhtTestObj->Tick();
		if(!socket4.GetSentByteVector().size()) FAIL() << "no bytes sent";
		socket4.Reset();
	}
}

TEST(SpeedTestDhtImpl, PingQueriesSpeedTest)
{
	std::vector<byte>	messageBytes;
	std::vector<byte>	argumentBytes;

	UnitTestUDPSocket socket4;
	UnitTestUDPSocket socket6;
	smart_ptr<DhtImpl> dhtTestObj(new DhtImpl(&socket4, &socket6));
	dhtTestObj->SetSHACallback(&sha1_callback);

	// prepare the object for use
	dhtTestObj->Enable(true,2000);
	SetDHT_my_id_Bytes(dhtTestObj);
	dhtTestObj->Tick();

	// the test data
	char buffer[1024]; // use this since the string will be modified as it is processed
	std::string pingString("d1:ad2:id20:abcdefghij0123456789e1:q4:ping1:t2:aa1:y1:qe");
	std::string knownPingString("d1:ad2:id20:abcdefghij0123456789e1:q4:ping1:t4:wxyz1:v4:UTUT1:y1:qe");

	for(unsigned long x=0; x<maxIterations; ++x)
	{
		strcpy(buffer, pingString.c_str());
		dhtTestObj->ProcessIncoming((byte*)buffer, pingString.size(), sAddr);
		dhtTestObj->Tick();
		if(!socket4.GetSentByteVector().size()) FAIL() << "no bytes sent";
		socket4.Reset();

		strcpy(buffer, knownPingString.c_str());
		dhtTestObj->ProcessIncoming((byte*)buffer, knownPingString.size(), sAddr);
		dhtTestObj->Tick();
		if(!socket4.GetSentByteVector().size()) FAIL() << "no bytes sent";
		socket4.Reset();
	}
}

TEST(SpeedTestDhtImpl, FindNodeSpeedTest)
{
	UnitTestUDPSocket socket4;
	UnitTestUDPSocket socket6;
	smart_ptr<DhtImpl> dhtTestObj(new DhtImpl(&socket4, &socket6));
	dhtTestObj->SetSHACallback(&sha1_callback);

	// prepare the object for use
	dhtTestObj->Enable(true,2000);
	SetDHT_my_id_Bytes(dhtTestObj);
	dhtTestObj->Tick();

	// the test data
	char buffer[1024]; // use this since the string will be modified as it is processed
	std::string findNodeString("d1:ad2:id20:abcdefghij01234567896:target20:mnopqrstuvwxyz123456e1:q9:find_node1:t2:aa1:y1:qe");

	for(unsigned long x=0; x<maxIterations; ++x)
	{
		strcpy(buffer, findNodeString.c_str());
		dhtTestObj->ProcessIncoming((byte*)buffer, findNodeString.size(), sAddr);
		dhtTestObj->Tick();
		if(!socket4.GetSentByteVector().size()) FAIL() << "no bytes sent";
		socket4.Reset();

		strcpy(buffer, findNodeString.c_str());
		dhtTestObj->ProcessIncoming((byte*)buffer, findNodeString.size(), sAddr);
		dhtTestObj->Tick();
		if(!socket4.GetSentByteVector().size()) FAIL() << "no bytes sent";
		socket4.Reset();
	}
}

TEST(SpeedTestDhtImpl, GetPeersSpeedTest)
{
	UnitTestUDPSocket socket4;
	UnitTestUDPSocket socket6;
	smart_ptr<DhtImpl> dhtTestObj(new DhtImpl(&socket4, &socket6));
	dhtTestObj->SetSHACallback(&sha1_callback);

	// prepare the object for use
	dhtTestObj->Enable(true,2000);
	SetDHT_my_id_Bytes(dhtTestObj);
	dhtTestObj->Tick();

	// the test data
	char buffer[1024]; // use this since the string will be modified as it is processed
	std::string getPeersString("d1:ad2:id20:abcdefghij01010101019:info_hash20:mnopqrstuvwxyz123456e1:q9:get_peers1:t2:aa1:y1:qe");

	for(unsigned long x=0; x<maxIterations; ++x)
	{
		strcpy(buffer, getPeersString.c_str());
		dhtTestObj->ProcessIncoming((byte*)buffer, getPeersString.size(), sAddr);
		dhtTestObj->Tick();
		if(!socket4.GetSentByteVector().size()) FAIL() << "no bytes sent";
		socket4.Reset();

		strcpy(buffer, getPeersString.c_str());
		dhtTestObj->ProcessIncoming((byte*)buffer, getPeersString.size(), sAddr);
		dhtTestObj->Tick();
		if(!socket4.GetSentByteVector().size()) FAIL() << "no bytes sent";
		socket4.Reset();
	}
}

TEST(SpeedTestDhtImpl, AnnouncePeerSpeedTest)
{
	UnitTestUDPSocket socket4;
	UnitTestUDPSocket socket6;
	std::vector<byte> token;
	std::vector<byte> testDataBytes;
	smart_ptr<DhtImpl> dhtTestObj(new DhtImpl(&socket4, &socket6));
	dhtTestObj->SetSHACallback(&sha1_callback);

	// prepare the object for use
	dhtTestObj->Enable(true,2000);
	SetDHT_my_id_Bytes(dhtTestObj);
	dhtTestObj->Tick();

	// insert the token between these two strings
	std::string testDataPart1("d1:ad2:id20:abcdefghij01234567899:info_hash20:mnopqrstuvwxyz1234564:porti6881e5:token");
	std::string testDataPart2("e1:q13:announce_peer1:t2:aa1:y1:qe");

	std::vector<byte> bufferVec(1024); // use this since the string will be modified as it is processed
	for(unsigned long x=0; x<maxIterations; ++x)
	{
		if(!(x & 0x0000007f)) // the token needs to be refreshed periodically
		{
			// get a new token and re-generate the test data
			socket4.Reset();
			if(!GetToken(dhtTestObj, token, socket4) || token.size()==0)
			{	FAIL() << "unable to get a token to use";
			}
			// build the announce_peer test string with the token
			testDataBytes.clear();
			fillTestDataBytes(testDataBytes, Buffer(&token[0], token.size()), testDataPart1, testDataPart2);
		}
		bufferVec = testDataBytes;
		dhtTestObj->ProcessIncoming(&bufferVec.front(), bufferVec.size(), sAddr);
		dhtTestObj->Tick();
		if(!socket4.GetSentByteVector().size()) FAIL() << "no bytes sent";
		socket4.Reset();

		bufferVec = testDataBytes;
		dhtTestObj->ProcessIncoming(&bufferVec.front(), bufferVec.size(), sAddr);
		dhtTestObj->Tick();
		if(!socket4.GetSentByteVector().size()) FAIL() << "no bytes sent";
		socket4.Reset();
	}
}

TEST(SpeedTestDhtImpl, VoteSpeedTest)
{
	std::vector<byte> messageBytes1;
	std::vector<byte> argumentBytes1;
	std::vector<byte> messageBytes2;
	std::vector<byte> argumentBytes2;
	std::vector<byte> token;

	UnitTestUDPSocket socket4;
	UnitTestUDPSocket socket6;
	smart_ptr<DhtImpl> dhtTestObj(new DhtImpl(&socket4, &socket6));
	dhtTestObj->SetSHACallback(&sha1_callback);

	// prepare the object for use
	dhtTestObj->Enable(true,2000);
	SetDHT_my_id_Bytes(dhtTestObj);
	dhtTestObj->Tick();


	std::vector<byte> bufferVec(1024); // use this since the string will be modified as it is processed
	for(unsigned long x=0; x<maxIterations; ++x)
	{
		if(!(x & 0x0000007f)) // the token needs to be refreshed periodically
		{
			// get a new token and re-generate the test data
			socket4.Reset();
			if(!GetToken(dhtTestObj, token, socket4) || token.size()==0)
			{	FAIL() << "unable to get a token to use";
			}
			// make a target key to use
			std::vector<byte> target = MakeRandomKey20();

			// make the first vote message with a vote of 5
			argumentBytes1.clear();
			BencStartDictionary(argumentBytes1);
			{
				BencAddNameValuePair(argumentBytes1,"id","abcdefghij0123456789");
				BencAddNameValuePair(argumentBytes1,"target",target);
				BencAddNameValuePair(argumentBytes1,"token",token);
				BencAddNameValuePair(argumentBytes1,"vote",5);
			}
			BencEndDictionary(argumentBytes1);
			messageBytes1.clear();
			BencStartDictionary(messageBytes1);
			{
				BencAddNameAndBencodedDictionary(messageBytes1,"a",argumentBytes1);
				BencAddNameValuePair(messageBytes1,"q","vote");
				BencAddNameValuePair(messageBytes1,"t","aa");
				BencAddNameValuePair(messageBytes1,"y","q");
			}
			BencEndDictionary(messageBytes1);

			// make the second vote message with a vote of 2
			argumentBytes2.clear();
			BencStartDictionary(argumentBytes2);
			{
				BencAddNameValuePair(argumentBytes2,"id","abcdefghij0123456789");
				BencAddNameValuePair(argumentBytes2,"target",target);
				BencAddNameValuePair(argumentBytes2,"token",token);
				BencAddNameValuePair(argumentBytes2,"vote",2);
			}
			BencEndDictionary(argumentBytes2);
			messageBytes2.clear();
			BencStartDictionary(messageBytes2);
			{
				BencAddNameAndBencodedDictionary(messageBytes2,"a",argumentBytes2);
				BencAddNameValuePair(messageBytes2,"q","vote");
				BencAddNameValuePair(messageBytes2,"t","aa");
				BencAddNameValuePair(messageBytes2,"y","q");
			}
			BencEndDictionary(messageBytes2);
		}
		bufferVec = messageBytes1;
		dhtTestObj->ProcessIncoming(&bufferVec.front(), bufferVec.size(), sAddr);
		dhtTestObj->Tick();
		if(!socket4.GetSentByteVector().size()) FAIL() << "no bytes sent";
		socket4.Reset();

		bufferVec = messageBytes2;
		dhtTestObj->ProcessIncoming(&bufferVec.front(), bufferVec.size(), sAddr);
		dhtTestObj->Tick();
		if(!socket4.GetSentByteVector().size()) FAIL() << "no bytes sent";
		socket4.Reset();
	}
}

class AddNodesCallBackDataItem
{
public:
	byte infoHash[20];
	unsigned int numPeers;
	std::vector<byte> compactPeerAddressBytes;

	bool operator==(AddNodesCallBackDataItem &right);
};

bool AddNodesCallBackDataItem::operator==(AddNodesCallBackDataItem &right)
{
	if(memcmp(infoHash, right.infoHash, 20)==0
	   && numPeers == right.numPeers
	   && compactPeerAddressBytes == right.compactPeerAddressBytes)
		return true;
	return false;
}

class AddNodesCallbackDummy
{
public:
	static std::vector<AddNodesCallBackDataItem> callbackData;

	AddNodesCallbackDummy(){}
	~AddNodesCallbackDummy(){}
	static void Callback(void *ctx, const byte *info_hash, const byte *peers, uint num_peers);
	static void Reset();
};

std::vector<AddNodesCallBackDataItem> AddNodesCallbackDummy::callbackData;

void AddNodesCallbackDummy::Callback(void *ctx, const byte *info_hash, const byte *peers, uint num_peers)
{
	AddNodesCallBackDataItem data;
	unsigned int x;

	for(x=0; x<20; ++x)
		data.infoHash[x] = info_hash[x];

	data.numPeers = num_peers;
	for(x=0; x<6*data.numPeers; ++x) // 6 bytes of compact address per peer
		data.compactPeerAddressBytes.push_back(peers[x]);

	callbackData.push_back(data);
}

void AddNodesCallbackDummy::Reset()
{
	callbackData.clear();
}


class PartialHashCallbackDummy
{
public:
	static int callbackCtr;
	static byte hash[20]; // contains the 20 bytes of info_hash from the last invocation of PartialHashCallback()

	PartialHashCallbackDummy(){}
	~PartialHashCallbackDummy(){}
	static void PartialHashCallback(void *ctx, const byte* info_hash);
	static void Reset();
};

int PartialHashCallbackDummy::callbackCtr;
byte PartialHashCallbackDummy::hash[20];

// info_hash should be 20 bytes
void PartialHashCallbackDummy::PartialHashCallback(void *ctx, const byte* info_hash)
{
	callbackCtr++;
	for(int x=0; x<20; ++x)
		hash[x] = info_hash[x];
}

void PartialHashCallbackDummy::Reset()
{
	callbackCtr = 0;
}



/**
          Test                    |                  DHT
----------------------------------|--------------------------------------------
1) invoke doAnnounce()            |
                                  | Responds by emitting a 'get_peers' query
								  |
2) Fabricate and "send" a         |
   response to get_peers that     |
   has only compact node info     |
                                  | Responds by emitting another 'get_peers' query
								  |
*/
TEST(TestDhtImplResponse, Announce_ReplyWithNodes)
{
	UnitTestUDPSocket socket4;
	UnitTestUDPSocket socket6;
	BencodedDict bDictGetPeer;
	SockAddr sAddr(0x7a7a7a7a,0x7878); // ip = zzzz and socket = xx
	socket4.SetBindAddr(sAddr);
	smart_ptr<DhtImpl> dhtTestObj(new DhtImpl(&socket4, &socket6));
	dhtTestObj->SetSHACallback(&sha1_callback);

	// prepare the object for use
	dhtTestObj->Enable(true,0);
	SetDHT_my_id_Bytes(dhtTestObj);

	// put a peer into the dht for it to work with
	DhtPeerID peerID;
	peerID.id.id[0] = '1111'; // 1111
	peerID.id.id[1] = 'BBBB'; // BBBB
	peerID.id.id[2] = 'CCCC'; // CCCC
	peerID.id.id[3] = 'DDDD'; // DDDD
	peerID.id.id[4] = '0000'; // 0000
	peerID.addr.set_port(128);
	peerID.addr.set_addr4(0xf0f0f0f0);
	dhtTestObj->Update(peerID, 0, false);
	Buffer peerIDBuffer;
	peerIDBuffer.len = 20;
	peerIDBuffer.b = (byte*)&peerID.id.id[0];

	DhtID target;
	target.id[0] = 'FFFF'; // FFFF
	target.id[1] = 'GGGG'; // GGGG
	target.id[2] = 'HHHH'; // HHHH
	target.id[3] = 'IIII'; // IIII
	target.id[4] = 'JJJJ'; // JJJJ

	// make sure the callback dummy is clear
	AddNodesCallbackDummy::Reset();

	// *****************************************************
	// make the dht emit an announce message (the get_peers rpc)
	// *****************************************************
	EXPECT_FALSE(dhtTestObj->IsBusy()) << "The dht should not be busy yet";
	dhtTestObj->DoAnnounce(target, 20, NULL, &AddNodesCallbackDummy::Callback, NULL, "filename.txt", NULL, 0);
	EXPECT_TRUE(dhtTestObj->IsBusy()) << "The dht should be busy";

	// *****************************************************
	// grab from the socket the emitted message and extract
	// the transaction ID and verify the remainder of the
	// message
	// *****************************************************
	std::string doAnnounceOutput = socket4.GetSentDataAsString();
	BencEntity bEntityAnounceQuery;
	// verify the bencoded string that went out the socket
	BencEntity::Parse((const byte *)doAnnounceOutput.c_str(), bEntityAnounceQuery, (const byte *)(doAnnounceOutput.c_str() + doAnnounceOutput.length()));

	// get the query dictionary
	BencodedDict *dictForAnnounce = BencodedDict::AsDict(&bEntityAnounceQuery);
	EXPECT_TRUE(dictForAnnounce);
	if (!dictForAnnounce) {
		FAIL() << "ERROR:  The dht did not emit a bencoded dictionary for announce";
	}

	Buffer type;
	type.b = (byte*)dictForAnnounce->GetString("y" ,&type.len);
	ASSERT_EQ(1, type.len) << "ERROR: the 'y' type length is wrong (should be 1 for 'q', 'r', or 'e')";
	ASSERT_EQ('q', type.b[0]) << "ERROR: 'y' type is wrong; should be 'q' for query instead of:  " << type.b[0];

	Buffer command;
	command.b = (byte*)dictForAnnounce->GetString("q" ,&command.len);
	EXPECT_EQ(9, command.len);
	EXPECT_FALSE(memcmp("get_peers", command.b, 9)) << "ERROR: 'q' command is wrong";

	// get the transaction ID to use later
	Buffer tid;
	tid.b = (byte*)dictForAnnounce->GetString("t" ,&tid.len);
	EXPECT_EQ(4, tid.len) << "transaction ID is wrong size";

	// now look into the query data
	BencodedDict *announceQuery = dictForAnnounce->GetDict("a");
	if (!announceQuery) {
		FAIL() << "ERROR:  Failed to extract 'a' dictionary from get_peer response";
	}

	Buffer id;
	id.b = (byte*)announceQuery->GetString("id" ,&id.len);
	EXPECT_EQ(20, id.len);
	EXPECT_FALSE(memcmp("AAAABBBBCCCCDDDDEEEE", id.b, 20)) << "ERROR: announced id is wrong";

	Buffer infoHash;
	infoHash.b = (byte*)announceQuery->GetString("info_hash" ,&infoHash.len);
	EXPECT_EQ(20, infoHash.len);
	EXPECT_FALSE(memcmp("FFFFGGGGHHHHIIIIJJJJ", infoHash.b, 20)) << "ERROR: info_hash is not the correct target";

	// *****************************************************
	// now fabricate a nodes response message using the
	// transaction ID extracted above and include a token
	// *****************************************************
	std::vector<byte>	messageBytes;
	std::vector<byte>	replyDictionaryBytes;

	std::string responseToken("20_byte_reply_token.");
	std::string nearistNode  ("26_byte_nearist_node_addr.");

	// construct the message bytes
	BencStartDictionary(replyDictionaryBytes);
	{
		BencAddNameValuePair(replyDictionaryBytes,"id",peerIDBuffer);
		BencAddNameValuePair(replyDictionaryBytes,"nodes",nearistNode);
		BencAddNameValuePair(replyDictionaryBytes,"token",responseToken);
	}
	BencEndDictionary(replyDictionaryBytes);

	BencStartDictionary(messageBytes);
	{
		BencAddNameAndBencodedDictionary(messageBytes,"r",replyDictionaryBytes);
		BencAddNameValuePair(messageBytes,"t",tid);
		BencAddNameValuePair(messageBytes,"y","r");
	}
	BencEndDictionary(messageBytes);

	// clear the socket and "send" the reply
	socket4.Reset();
	dhtTestObj->ProcessIncoming((byte*)&messageBytes.front(), messageBytes.size(), peerID.addr);

	EXPECT_TRUE(dhtTestObj->IsBusy()) << "The dht should still be busy";

	// *****************************************************
	// get the bencoded string out of the socket and verify
	// it.
	// *****************************************************
	std::string bencMessage = socket4.GetSentDataAsString();
	BencEntity bEntity;

	// verify the bencoded string that went out the socket
	BencEntity::Parse((const byte *)bencMessage.c_str(), bEntity, (const byte *)(bencMessage.c_str() + bencMessage.length()));

	// did we get a valid dictionary
	BencodedDict *dict = BencodedDict::AsDict(&bEntity);
	EXPECT_TRUE(dict);
	if (!dict) {
		FAIL() << "ERROR:  The emitted query is not a bencoded dictionary";
	}

	Buffer qType;
	qType.b = (byte*)dict->GetString("y", &qType.len);
	EXPECT_EQ(1, qType.len);
	EXPECT_EQ('q', qType.b[0]) << "The 'y' type should be 'q'";

	Buffer qCommand;
	qCommand.b = (byte*)dict->GetString("q", &qCommand.len);
	EXPECT_EQ(9, qCommand.len);
	EXPECT_FALSE(memcmp(qCommand.b, "get_peers", qCommand.len)) << "The command is wrong; should be get_peers";

	// get the 'a' arguments dictionary
	BencodedDict *emittedQueryArgs = dict->GetDict("a");
	EXPECT_TRUE(emittedQueryArgs);
	if (!dict) {
		FAIL() << "ERROR:  The emitted query did not contain an 'a' dictionary";
	}

	Buffer qID;
	qID.b = (byte*)emittedQueryArgs->GetString("id", &qID.len);
	EXPECT_EQ(20, qID.len);
	EXPECT_FALSE(memcmp(qID.b, "AAAABBBBCCCCDDDDEEEE", qID.len)) << "The id is wrong";

	Buffer qInfoHash;
	qInfoHash.b = (byte*)emittedQueryArgs->GetString("info_hash", &qInfoHash.len);
	EXPECT_EQ(20, qInfoHash.len);
	EXPECT_FALSE(memcmp(qInfoHash.b, (byte*)target.id, qInfoHash.len)) << "The target info_hash is wrong";

	// *****************************************************
	// look in the addnodes call back dummy to see what was
	// passed through (should be nothing)
	// *****************************************************
	EXPECT_EQ(0, AddNodesCallbackDummy::callbackData.size()) << "no callback events should have been made";
	EXPECT_TRUE(dhtTestObj->IsBusy()) << "The dht should still be busy";

	DhtRequest* req = dhtTestObj->LookupRequest(Read32(tid.b));
	EXPECT_FALSE(req) << "The outstanding transaction id was not removed by the response";
}

/**
          Test                    |                  DHT
----------------------------------|--------------------------------------------
1) invoke doAnnounce()            |
                                  | Responds by emitting a 'get_peers' query
								  |
2) Fabricate and "send" a         |
   response to get_peers that     |
   has compact IP-address/port    |
   info for a peer                |
                                  | Responds by emitting 'announce_peer' query
								  |
*/
TEST(TestDhtImplResponse, Announce_ReplyWithPeers)
{
	UnitTestUDPSocket socket4;
	UnitTestUDPSocket socket6;
	BencodedDict bDictGetPeer;
	SockAddr sAddr(0x7a7a7a7a,0x7878); // ip = zzzz and socket = xx
	socket4.SetBindAddr(sAddr);
	smart_ptr<DhtImpl> dhtTestObj(new DhtImpl(&socket4, &socket6));
	dhtTestObj->SetSHACallback(&sha1_callback);

	// prepare the object for use
	dhtTestObj->Enable(true,0);
	SetDHT_my_id_Bytes(dhtTestObj);

	// put a peer into the dht for it to work with
	DhtPeerID peerID;
	peerID.id.id[0] = '1111'; // 1111
	peerID.id.id[1] = 'BBBB'; // BBBB
	peerID.id.id[2] = 'CCCC'; // CCCC
	peerID.id.id[3] = 'DDDD'; // DDDD
	peerID.id.id[4] = '0000'; // 0000
	peerID.addr.set_port(('8' << 8) + '8'); // 88
	peerID.addr.set_addr4('aaaa'); // aaaa
	dhtTestObj->Update(peerID, 0, false);
	Buffer peerIDBuffer;
	peerIDBuffer.len = 20;
	peerIDBuffer.b = (byte*)&peerID.id.id[0];

	DhtID target;
	target.id[0] = 'FFFF'; // FFFF
	target.id[1] = 'GGGG'; // GGGG
	target.id[2] = 'HHHH'; // HHHH
	target.id[3] = 'IIII'; // IIII
	target.id[4] = 'JJJJ'; // JJJJ

	// make sure the callback dummy is clear
	AddNodesCallbackDummy::Reset();

	EXPECT_EQ(1, dhtTestObj->GetNumPeers());
	EXPECT_EQ(0, dhtTestObj->GetNumPeersTracked());

	DhtPeerID *ids[16];
	uint num = dhtTestObj->FindNodes(target, ids, 8, 8, 0); // Find 8 good ones and 8 bad ones
	EXPECT_EQ(1, num) << "Num Nodes: " << num;
	EXPECT_FALSE(dhtTestObj->IsBusy()) << "The dht should not be busy yet";

	// *****************************************************
	// make the dht emit an announce message (the get_peers rpc)
	// *****************************************************
	std::string filenameTxt("This is a filaname that is very long like a file name that would be found in the wild.txt");
	dhtTestObj->DoAnnounce(target, 20, NULL, &AddNodesCallbackDummy::Callback, NULL, filenameTxt.c_str(), NULL, 0);
	EXPECT_TRUE(dhtTestObj->IsBusy()) << "The dht should be busy";

	// *****************************************************
	// grab from the socket the emitted message and extract
	// the transaction ID and verify the remainder of the
	// message
	// *****************************************************
	std::string doAnnounceOutput = socket4.GetSentDataAsString();
	BencEntity bEntityAnounceQuery;
	// verify the bencoded string that went out the socket
	BencEntity::Parse((const byte *)doAnnounceOutput.c_str(), bEntityAnounceQuery, (const byte *)(doAnnounceOutput.c_str() + doAnnounceOutput.length()));

	// get the query dictionary
	BencodedDict *dictForAnnounce = BencodedDict::AsDict(&bEntityAnounceQuery);
	EXPECT_TRUE(dictForAnnounce);
	if (!dictForAnnounce) {
		FAIL() << "ERROR:  The dht did not emit a bencoded dictionary for announce";
	}

	Buffer type;
	type.b = (byte*)dictForAnnounce->GetString("y" ,&type.len);
	ASSERT_EQ(1, type.len) << "ERROR: the 'y' type length is wrong (should be 1 for 'q', 'r', or 'e')";
	ASSERT_EQ('q', type.b[0]) << "ERROR: 'y' type is wrong; should be 'q' for query instead of:  " << type.b[0];

	Buffer command;
	command.b = (byte*)dictForAnnounce->GetString("q" ,&command.len);
	EXPECT_EQ(9, command.len);
	EXPECT_FALSE(memcmp("get_peers", command.b, 9)) << "ERROR: 'q' command is wrong; should be 'get_peers'";

	// get the transaction ID to use later
	Buffer tid;
	tid.b = (byte*)dictForAnnounce->GetString("t" ,&tid.len);
	EXPECT_EQ(4, tid.len) << "transaction ID is wrong size";

	// now look into the query data
	BencodedDict *announceQuery = dictForAnnounce->GetDict("a");
	if (!announceQuery) {
		FAIL() << "ERROR:  Failed to extract 'a' dictionary from get_peer response";
	}

	Buffer id;
	id.b = (byte*)announceQuery->GetString("id" ,&id.len);
	EXPECT_EQ(20, id.len);
	EXPECT_FALSE(memcmp("AAAABBBBCCCCDDDDEEEE", id.b, 20)) << "ERROR: announced id is wrong";

	Buffer infoHash;
	infoHash.b = (byte*)announceQuery->GetString("info_hash" ,&infoHash.len);
	EXPECT_EQ(20, infoHash.len);
	EXPECT_FALSE(memcmp("FFFFGGGGHHHHIIIIJJJJ", infoHash.b, 20)) << "ERROR: info_hash is not the correct target";

	int noseed = announceQuery->GetInt("noseed");
	EXPECT_EQ(0,noseed) << "'noseed' is set when it should not be.";

	// *****************************************************
	// now fabricate a nodes response message using the
	// transaction ID extracted above and include a token
	// that the dht should return to us.  Provide the compact IP
	// of a peer for the dht to use in the 'announce_peer'
	// message it should emit next
	// *****************************************************
	std::vector<byte>	messageBytes;
	std::vector<byte>	replyDictionaryBytes;

	std::string responseToken("20_byte_reply_token.");
	std::string compactIP("aaaa88");

	// construct the message bytes
	BencStartDictionary(replyDictionaryBytes);
	{
		BencAddNameValuePair(replyDictionaryBytes,"id",peerIDBuffer);
		BencAddNameValuePair(replyDictionaryBytes,"token",responseToken);
		BencAddString(replyDictionaryBytes,"values");
		BencStartList(replyDictionaryBytes);
		{
			BencAddString(replyDictionaryBytes, compactIP);
		}
		BencEndList(replyDictionaryBytes);
	}
	BencEndDictionary(replyDictionaryBytes);

	BencStartDictionary(messageBytes);
	{
		BencAddNameAndBencodedDictionary(messageBytes,"r",replyDictionaryBytes);
		BencAddNameValuePair(messageBytes,"t",tid);
		BencAddNameValuePair(messageBytes,"y","r");
	}
	BencEndDictionary(messageBytes);

	// clear the socket and "send" the reply and capture the announce_peer emitted by the dht
	socket4.Reset();
	dhtTestObj->ProcessIncoming((byte*)&messageBytes.front(), messageBytes.size(), peerID.addr);
	std::string announceString = socket4.GetSentDataAsString();

	EXPECT_TRUE(dhtTestObj->IsBusy()) << "The dht should still be busy";

	// *****************************************************
	// verify the announce_peer message emitted by the dht
	// *****************************************************
	BencEntity::Parse((const byte *)announceString.c_str(), bEntityAnounceQuery, (const byte *)(announceString.c_str() + announceString.length()));

	// get the query dictionary
	dictForAnnounce = BencodedDict::AsDict(&bEntityAnounceQuery);
	EXPECT_TRUE(dictForAnnounce);
	if (!dictForAnnounce) {
		FAIL() << "ERROR:  The dht did not emit a bencoded dictionary for announce";
	}

	type.b = (byte*)dictForAnnounce->GetString("y" ,&type.len);
	ASSERT_EQ(1, type.len) << "ERROR: the 'y' type length is wrong (should be 1 for 'q', 'r', or 'e')";
	ASSERT_EQ('q', type.b[0]) << "ERROR: 'y' type is wrong; should be 'q' for query instead of:  " << type.b[0];

	command.b = (byte*)dictForAnnounce->GetString("q" ,&command.len);
	EXPECT_EQ(13, command.len);
	EXPECT_FALSE(memcmp("announce_peer", command.b, 13)) << "ERROR: 'q' command is wrong; should be 'announce_peer'";

	// get the transaction ID to use later
	tid.b = (byte*)dictForAnnounce->GetString("t" ,&tid.len);
	EXPECT_EQ(4, tid.len) << "transaction ID is wrong size";

	// now look into the query data
	announceQuery = dictForAnnounce->GetDict("a");
	if (!announceQuery) {
		FAIL() << "ERROR:  Failed to extract 'a' dictionary from get_peer response";
	}

	id.b = (byte*)announceQuery->GetString("id" ,&id.len);
	EXPECT_EQ(20, id.len);
	EXPECT_FALSE(memcmp("AAAABBBBCCCCDDDDEEEE", id.b, 20)) << "ERROR: announced id is wrong";

	infoHash.b = (byte*)announceQuery->GetString("info_hash" ,&infoHash.len);
	EXPECT_EQ(20, infoHash.len);
	EXPECT_FALSE(memcmp("FFFFGGGGHHHHIIIIJJJJ", infoHash.b, 20)) << "ERROR: info_hash is not the correct target";

	Buffer name;
	name.b = (byte*)announceQuery->GetString("name" ,&name.len);
	EXPECT_EQ(filenameTxt.size(), name.len);
	EXPECT_FALSE(strcmp(filenameTxt.c_str(), (char*)name.b));

	int port;
	port = announceQuery->GetInt("port");
	EXPECT_EQ(0x7878, port) << "Expected 0x7878 ('XX) for port; actual value = " << port;

	Buffer token;
	token.b = (byte*)announceQuery->GetString("token" ,&token.len);
	EXPECT_EQ(20, token.len);
	EXPECT_FALSE(strcmp(responseToken.c_str(), (char*)token.b));

	int seed = announceQuery->GetInt("seed");
	EXPECT_EQ(0,seed) << "'seed' is set when it should not be.";

	// if no port callback is specified, default is to enable implied port
	int impliedPort = announceQuery->GetInt("implied_port");
	EXPECT_EQ(1,impliedPort) << "'implied_port' not is set when it should be.";

	// *****************************************************
	// create and send a response to the 'announce_peer
	// message
	// *****************************************************
	messageBytes.clear();
	replyDictionaryBytes.clear();

	// construct the message bytes
	BencStartDictionary(replyDictionaryBytes);
	{
		BencAddNameValuePair(replyDictionaryBytes,"id",peerIDBuffer);
	}
	BencEndDictionary(replyDictionaryBytes);

	BencStartDictionary(messageBytes);
	{
		BencAddNameAndBencodedDictionary(messageBytes,"r",replyDictionaryBytes);
		BencAddNameValuePair(messageBytes,"t",tid);
		BencAddNameValuePair(messageBytes,"y","r");
	}
	BencEndDictionary(messageBytes);

	// clear the socket and "send" the reply;
	socket4.Reset();
	dhtTestObj->ProcessIncoming((byte*)&messageBytes.front(), messageBytes.size(), peerID.addr);

	// check that nothing went out the socket.
	EXPECT_EQ(0, socket4.GetSentByteVector().size()) << "Nothing should be sent out the socket in response to the reply to the dht's 'announce_peer' query";

	// *****************************************************
	// look in the addnodes call back dummy to see what was
	// passed through
	// *****************************************************
	ASSERT_EQ(2, AddNodesCallbackDummy::callbackData.size()) << "Expected two callback events";

	// verify the first callback event
	EXPECT_FALSE(memcmp("FFFFGGGGHHHHIIIIJJJJ", AddNodesCallbackDummy::callbackData[0].infoHash, 20));
	EXPECT_EQ(1, AddNodesCallbackDummy::callbackData[0].numPeers);
	EXPECT_FALSE(memcmp(compactIP.c_str(), &AddNodesCallbackDummy::callbackData[0].compactPeerAddressBytes[0], compactIP.size()));

	// verify the second callback event
	EXPECT_FALSE(memcmp("FFFFGGGGHHHHIIIIJJJJ", AddNodesCallbackDummy::callbackData[1].infoHash, 20));
	EXPECT_EQ(0, AddNodesCallbackDummy::callbackData[1].numPeers);
	EXPECT_EQ(1, dhtTestObj->GetNumPeers());
	EXPECT_EQ(0, dhtTestObj->GetNumPeersTracked());
	num = dhtTestObj->FindNodes(target, ids, 8, 8, 0); // Find 8 good ones and 8 bad ones
	EXPECT_EQ(1, num) << "Num Nodes: " << num;

	DhtRequest* req = dhtTestObj->LookupRequest(Read32(tid.b));
	EXPECT_FALSE(req) << "The outstanding transaction id was not removed by the response";

	EXPECT_FALSE(dhtTestObj->IsBusy()) << "The dht should no longer be busy";
}


/**
          Test                    |                  DHT
----------------------------------|--------------------------------------------
1) invoke doAnnounce()            |
                                  | Responds by emitting a 'get_peers' query
								  |
2) Fabricate and "send" a         |
   response to get_peers that     |
   has no peer or node info       |
                                  | No response
								  |
*/
TEST(TestDhtImplResponse, Announce_ReplyWithoutPeersOrNodes)
{
	UnitTestUDPSocket socket4;
	UnitTestUDPSocket socket6;
	BencodedDict bDictGetPeer;
	SockAddr sAddr(0x7a7a7a7a,0x7878); // ip = zzzz and socket = xx
	socket4.SetBindAddr(sAddr);
	smart_ptr<DhtImpl> dhtTestObj(new DhtImpl(&socket4, &socket6));
	dhtTestObj->SetSHACallback(&sha1_callback);

	// prepare the object for use
	dhtTestObj->Enable(true,0);
	SetDHT_my_id_Bytes(dhtTestObj);

	// put a peer into the dht for it to work with
	DhtPeerID peerID;
	peerID.id.id[0] = '1111'; // 1111
	peerID.id.id[1] = 'BBBB'; // BBBB
	peerID.id.id[2] = 'CCCC'; // CCCC
	peerID.id.id[3] = 'DDDD'; // DDDD
	peerID.id.id[4] = '0000'; // 0000
	peerID.addr.set_port(('8' << 8) + '8'); // 88
	peerID.addr.set_addr4('aaaa'); // aaaa
	dhtTestObj->Update(peerID, 0, false);
	Buffer peerIDBuffer;
	peerIDBuffer.len = 20;
	peerIDBuffer.b = (byte*)&peerID.id.id[0];

	DhtID target;
	target.id[0] = 'FFFF'; // FFFF
	target.id[1] = 'GGGG'; // GGGG
	target.id[2] = 'HHHH'; // HHHH
	target.id[3] = 'IIII'; // IIII
	target.id[4] = 'JJJJ'; // JJJJ

	// make sure the callback dummy is clear
	AddNodesCallbackDummy::Reset();

	EXPECT_EQ(1, dhtTestObj->GetNumPeers());
	EXPECT_EQ(0, dhtTestObj->GetNumPeersTracked());

	DhtPeerID *ids[16];
	uint num = dhtTestObj->FindNodes(target, ids, 8, 8, 0); // Find 8 good ones and 8 bad ones
	EXPECT_EQ(1, num) << "Num Nodes: " << num;
	EXPECT_FALSE(dhtTestObj->IsBusy()) << "The dht should not be busy yet";

	// *****************************************************
	// make the dht emit an announce message (the get_peers rpc)
	// *****************************************************
	std::string filenameTxt("filaname.txt");
	dhtTestObj->DoAnnounce(target, 20, NULL, &AddNodesCallbackDummy::Callback, NULL, filenameTxt.c_str(), NULL, 0);
	EXPECT_TRUE(dhtTestObj->IsBusy()) << "The dht should be busy";

	// *****************************************************
	// grab from the socket the emitted message and extract
	// the transaction ID and verify the remainder of the
	// message
	// *****************************************************
	std::string doAnnounceOutput = socket4.GetSentDataAsString();
	BencEntity bEntityAnounceQuery;
	// verify the bencoded string that went out the socket
	BencEntity::Parse((const byte *)doAnnounceOutput.c_str(), bEntityAnounceQuery, (const byte *)(doAnnounceOutput.c_str() + doAnnounceOutput.length()));

	// get the query dictionary
	BencodedDict *dictForAnnounce = BencodedDict::AsDict(&bEntityAnounceQuery);
	EXPECT_TRUE(dictForAnnounce);
	if (!dictForAnnounce) {
		FAIL() << "ERROR:  The dht did not emit a bencoded dictionary for announce";
	}

	Buffer type;
	type.b = (byte*)dictForAnnounce->GetString("y" ,&type.len);
	ASSERT_EQ(1, type.len) << "ERROR: the 'y' type length is wrong (should be 1 for 'q', 'r', or 'e')";
	ASSERT_EQ('q', type.b[0]) << "ERROR: 'y' type is wrong; should be 'q' for query instead of:  " << type.b[0];

	Buffer command;
	command.b = (byte*)dictForAnnounce->GetString("q" ,&command.len);
	EXPECT_EQ(9, command.len);
	EXPECT_FALSE(memcmp("get_peers", command.b, 9)) << "ERROR: 'q' command is wrong; should be 'get_peers'";

	// get the transaction ID to use later
	Buffer tid;
	tid.b = (byte*)dictForAnnounce->GetString("t" ,&tid.len);
	EXPECT_EQ(4, tid.len) << "transaction ID is wrong size";

	// now look into the query data
	BencodedDict *announceQuery = dictForAnnounce->GetDict("a");
	if (!announceQuery) {
		FAIL() << "ERROR:  Failed to extract 'a' dictionary from get_peer response";
	}

	Buffer id;
	id.b = (byte*)announceQuery->GetString("id" ,&id.len);
	EXPECT_EQ(20, id.len);
	EXPECT_FALSE(memcmp("AAAABBBBCCCCDDDDEEEE", id.b, 20)) << "ERROR: announced id is wrong";

	Buffer infoHash;
	infoHash.b = (byte*)announceQuery->GetString("info_hash" ,&infoHash.len);
	EXPECT_EQ(20, infoHash.len);
	EXPECT_FALSE(memcmp("FFFFGGGGHHHHIIIIJJJJ", infoHash.b, 20)) << "ERROR: info_hash is not the correct target";

	// *****************************************************
	// now fabricate a nodes response message using the
	// transaction ID extracted above and include a token
	// that the dht should return to us.
	//
	// Do not include compact IP or node info in the reply
	// *****************************************************
	std::vector<byte>	messageBytes;
	std::vector<byte>	replyDictionaryBytes;

	std::string responseToken("20_byte_reply_token.");

	// construct the message bytes
	BencStartDictionary(replyDictionaryBytes);
	{
		BencAddNameValuePair(replyDictionaryBytes,"id",peerIDBuffer);
		BencAddNameValuePair(replyDictionaryBytes,"token",responseToken);
	}
	BencEndDictionary(replyDictionaryBytes);

	BencStartDictionary(messageBytes);
	{
		BencAddNameAndBencodedDictionary(messageBytes,"r",replyDictionaryBytes);
		BencAddNameValuePair(messageBytes,"t",tid);
		BencAddNameValuePair(messageBytes,"y","r");
	}
	BencEndDictionary(messageBytes);

	// clear the socket and "send" the reply and capture the announce_peer emitted by the dht
	socket4.Reset();
	dhtTestObj->ProcessIncoming((byte*)&messageBytes.front(), messageBytes.size(), peerID.addr);
	std::string announceString = socket4.GetSentDataAsString();

	EXPECT_TRUE(announceString == "") << "Nothing should have been sent out.  The response with a filename should terminate this process.";
	EXPECT_FALSE(dhtTestObj->IsBusy()) << "The dht should not be busy";

	// *****************************************************
	// look in the addnodes call back dummy to see what was
	// passed through
	// *****************************************************
	ASSERT_EQ(1, AddNodesCallbackDummy::callbackData.size()) << "Expected two callback events";

	// verify the first callback event
	EXPECT_FALSE(memcmp("FFFFGGGGHHHHIIIIJJJJ", AddNodesCallbackDummy::callbackData[0].infoHash, 20));
	EXPECT_EQ(0, AddNodesCallbackDummy::callbackData[0].numPeers);

	EXPECT_EQ(1, dhtTestObj->GetNumPeers());
	EXPECT_EQ(0, dhtTestObj->GetNumPeersTracked());
	num = dhtTestObj->FindNodes(target, ids, 8, 8, 0); // Find 8 good ones and 8 bad ones
	EXPECT_EQ(1, num) << "Num Nodes: " << num;

	DhtRequest* req = dhtTestObj->LookupRequest(Read32(tid.b));
	EXPECT_FALSE(req) << "The outstanding transaction id was not removed by the response";

	EXPECT_FALSE(dhtTestObj->IsBusy()) << "The dht should no longer be busy";
}

/**
          Test                    |                  DHT
----------------------------------|--------------------------------------------
1) invoke doAnnounce()            |
                                  | Responds by emitting a 'get_peers' query
								  |
2) Capture the outputted bencoded |
   string and feed it back to the |
   DHT via ParseIncommingICMP     |
                                  | Ceases pursuing the request
								  |
*/
TEST(TestDhtImplResponse, Announce_ReplyWith_ICMP)
{
	UnitTestUDPSocket socket4;
	UnitTestUDPSocket socket6;
	BencodedDict bDictGetPeer;
	SockAddr sAddr(0x7a7a7a7a,0x7878); // ip = zzzz and socket = xx
	socket4.SetBindAddr(sAddr);
	smart_ptr<DhtImpl> dhtTestObj(new DhtImpl(&socket4, &socket6));
	dhtTestObj->SetSHACallback(&sha1_callback);
	DhtRequest* req;

	// prepare the object for use
	dhtTestObj->Enable(true,0);
	SetDHT_my_id_Bytes(dhtTestObj);

	// put a peer into the dht for it to work with
	DhtPeerID peerID;
	peerID.id.id[0] = '1111'; // 1111
	peerID.id.id[1] = 'BBBB'; // BBBB
	peerID.id.id[2] = 'CCCC'; // CCCC
	peerID.id.id[3] = 'DDDD'; // DDDD
	peerID.id.id[4] = '0000'; // 0000
	peerID.addr.set_port(128);
	peerID.addr.set_addr4(0xf0f0f0f0);
	dhtTestObj->Update(peerID, 0, false);
	Buffer peerIDBuffer;
	peerIDBuffer.len = 20;
	peerIDBuffer.b = (byte*)&peerID.id.id[0];

	DhtID target;
	target.id[0] = 'FFFF'; // FFFF
	target.id[1] = 'GGGG'; // GGGG
	target.id[2] = 'HHHH'; // HHHH
	target.id[3] = 'IIII'; // IIII
	target.id[4] = 'JJJJ'; // JJJJ

	// make sure the callback dummy is clear
	AddNodesCallbackDummy::Reset();

	// *****************************************************
	// make the dht emit an announce message (the get_peers rpc)
	// *****************************************************
	EXPECT_FALSE(dhtTestObj->IsBusy()) << "The dht should not be busy yet";
	dhtTestObj->DoAnnounce(target, 20, NULL, &AddNodesCallbackDummy::Callback, NULL, "filename.txt", NULL, 0);
	EXPECT_TRUE(dhtTestObj->IsBusy()) << "The dht should be busy";

	// *****************************************************
	// grab from the socket the emitted message and turn it
	// into a bencentity.  Feed it back to the dht as an
	// ICMP message
	// *****************************************************
	std::string doAnnounceOutput = socket4.GetSentDataAsString();
	BencEntity bEntityAnounceQuery;
	// verify the bencoded string that went out the socket
	BencEntity::Parse((const byte *)doAnnounceOutput.c_str(), bEntityAnounceQuery, (const byte *)(doAnnounceOutput.c_str() + doAnnounceOutput.length()));

	// get the transaction ID to use later
	BencodedDict *dictForAnnounce = BencodedDict::AsDict(&bEntityAnounceQuery);
	Buffer tid;
	tid.b = (byte*)dictForAnnounce->GetString("t" ,&tid.len);

	EXPECT_TRUE(dhtTestObj->ParseIncomingICMP(bEntityAnounceQuery, peerID.addr));

	// *****************************************************
	// look in the addnodes call back dummy to see what was
	// passed through (should be nothing)
	// *****************************************************
	EXPECT_EQ(1, AddNodesCallbackDummy::callbackData.size()) << "ONE callback event should have been made";

	req = dhtTestObj->LookupRequest(Read32(tid.b));
	EXPECT_FALSE(req) << "The outstanding transaction id was not removed by the response";
	EXPECT_FALSE(dhtTestObj->IsBusy()) << "The dht should no longer be busy";
}


TEST(TestDhtImplResponse, Announce_ReplyWith_ICMP_AfterAnnounce)
{
	UnitTestUDPSocket socket4;
	UnitTestUDPSocket socket6;
	BencodedDict bDictGetPeer;
	SockAddr sAddr(0x7a7a7a7a,0x7878); // ip = zzzz and socket = xx
	socket4.SetBindAddr(sAddr);
	smart_ptr<DhtImpl> dhtTestObj(new DhtImpl(&socket4, &socket6));
	dhtTestObj->SetSHACallback(&sha1_callback);
	DhtRequest* req;

	// prepare the object for use
	dhtTestObj->Enable(true,0);
	SetDHT_my_id_Bytes(dhtTestObj);

	// put a peer into the dht for it to work with
	DhtPeerID peerID;
	peerID.id.id[0] = '1111'; // 1111
	peerID.id.id[1] = 'BBBB'; // BBBB
	peerID.id.id[2] = 'CCCC'; // CCCC
	peerID.id.id[3] = 'DDDD'; // DDDD
	peerID.id.id[4] = '0000'; // 0000
	peerID.addr.set_port(128);
	peerID.addr.set_addr4(0xf0f0f0f0);
	dhtTestObj->Update(peerID, 0, false);
	Buffer peerIDBuffer;
	peerIDBuffer.len = 20;
	peerIDBuffer.b = (byte*)&peerID.id.id[0];

	DhtID target;
	target.id[0] = 'FFFF'; // FFFF
	target.id[1] = 'GGGG'; // GGGG
	target.id[2] = 'HHHH'; // HHHH
	target.id[3] = 'IIII'; // IIII
	target.id[4] = 'JJJJ'; // JJJJ

	// make sure the callback dummy is clear
	AddNodesCallbackDummy::Reset();

	// *****************************************************
	// make the dht emit an announce message (the get_peers rpc)
	// *****************************************************
	EXPECT_FALSE(dhtTestObj->IsBusy()) << "The dht should not be busy yet";
	dhtTestObj->DoAnnounce(target, 20, NULL, &AddNodesCallbackDummy::Callback, NULL, "filename.txt", NULL, 0);
	EXPECT_TRUE(dhtTestObj->IsBusy()) << "The dht should be busy";

	// *****************************************************
	// grab from the socket the emitted message and extract
	// the transaction ID and verify the remainder of the
	// message
	// *****************************************************
	std::string doAnnounceOutput = socket4.GetSentDataAsString();
	BencEntity bEntityAnounceQuery;
	// verify the bencoded string that went out the socket
	BencEntity::Parse((const byte *)doAnnounceOutput.c_str(), bEntityAnounceQuery, (const byte *)(doAnnounceOutput.c_str() + doAnnounceOutput.length()));

	// get the query dictionary
	BencodedDict *dictForAnnounce = BencodedDict::AsDict(&bEntityAnounceQuery);
	EXPECT_TRUE(dictForAnnounce);
	if (!dictForAnnounce) {
		FAIL() << "ERROR:  The dht did not emit a bencoded dictionary for announce";
	}

	Buffer type;
	type.b = (byte*)dictForAnnounce->GetString("y" ,&type.len);
	ASSERT_EQ(1, type.len) << "ERROR: the 'y' type length is wrong (should be 1 for 'q', 'r', or 'e')";
	ASSERT_EQ('q', type.b[0]) << "ERROR: 'y' type is wrong; should be 'q' for query instead of:  " << type.b[0];

	Buffer command;
	command.b = (byte*)dictForAnnounce->GetString("q" ,&command.len);
	EXPECT_EQ(9, command.len);
	EXPECT_FALSE(memcmp("get_peers", command.b, 9)) << "ERROR: 'q' command is wrong; should be 'get_peers'";

	// get the transaction ID to use later
	Buffer tid;
	tid.b = (byte*)dictForAnnounce->GetString("t" ,&tid.len);
	EXPECT_EQ(4, tid.len) << "transaction ID is wrong size";

	// now look into the query data
	BencodedDict *announceQuery = dictForAnnounce->GetDict("a");
	if (!announceQuery) {
		FAIL() << "ERROR:  Failed to extract 'a' dictionary from get_peer response";
	}

	Buffer id;
	id.b = (byte*)announceQuery->GetString("id" ,&id.len);
	EXPECT_EQ(20, id.len);
	EXPECT_FALSE(memcmp("AAAABBBBCCCCDDDDEEEE", id.b, 20)) << "ERROR: announced id is wrong";

	Buffer infoHash;
	infoHash.b = (byte*)announceQuery->GetString("info_hash" ,&infoHash.len);
	EXPECT_EQ(20, infoHash.len);
	EXPECT_FALSE(memcmp("FFFFGGGGHHHHIIIIJJJJ", infoHash.b, 20)) << "ERROR: info_hash is not the correct target";

	// *****************************************************
	// now fabricate a nodes response message using the
	// transaction ID extracted above and include a token
	// that the dht should return to us.  Provide the compact IP
	// of a peer for the dht to use in the 'announce_peer'
	// message it should emit next
	// *****************************************************
	std::vector<byte>	messageBytes;
	std::vector<byte>	replyDictionaryBytes;

	std::string responseToken("20_byte_reply_token.");
	std::string compactIP("aaaa88");

	// construct the message bytes
	BencStartDictionary(replyDictionaryBytes);
	{
		BencAddNameValuePair(replyDictionaryBytes,"id",peerIDBuffer);
		BencAddNameValuePair(replyDictionaryBytes,"token",responseToken);
		BencAddString(replyDictionaryBytes,"values");
		BencStartList(replyDictionaryBytes);
		{
			BencAddString(replyDictionaryBytes, compactIP);
		}
		BencEndList(replyDictionaryBytes);
	}
	BencEndDictionary(replyDictionaryBytes);

	BencStartDictionary(messageBytes);
	{
		BencAddNameAndBencodedDictionary(messageBytes,"r",replyDictionaryBytes);
		BencAddNameValuePair(messageBytes,"t",tid);
		BencAddNameValuePair(messageBytes,"y","r");
	}
	BencEndDictionary(messageBytes);

	// clear the socket and "send" the reply and capture the announce_peer emitted by the dht
	socket4.Reset();
	dhtTestObj->ProcessIncoming((byte*)&messageBytes.front(), messageBytes.size(), peerID.addr);

	EXPECT_TRUE(dhtTestObj->IsBusy()) << "The dht should still be busy";

	// *****************************************************
	// grab from the socket the emitted message and turn it
	// into a bencentity.  Feed it back to the dht as an
	// ICMP message
	// *****************************************************
	std::string announceString = socket4.GetSentDataAsString();
	BencEntity bEntity;
	// verify the bencoded string that went out the socket
	BencEntity::Parse((const byte *)announceString.c_str(), bEntity, (const byte *)(announceString.c_str() + announceString.length()));

	// get the transaction ID to use later
	BencodedDict* announceDict = BencodedDict::AsDict(&bEntity);
	tid.b = (byte*)announceDict->GetString("t" ,&tid.len);

	EXPECT_TRUE(dhtTestObj->ParseIncomingICMP(bEntity, peerID.addr));

	// *****************************************************
	// look in the addnodes call back dummy to see what was
	// passed through (should be nothing)
	// *****************************************************
	EXPECT_EQ(2, AddNodesCallbackDummy::callbackData.size()) << "Two callback events should have been made";

	req = dhtTestObj->LookupRequest(Read32(tid.b));
	EXPECT_FALSE(req) << "The outstanding transaction id was not removed by the response";
	EXPECT_FALSE(dhtTestObj->IsBusy()) << "The dht should no longer be busy";
}

/**
          Test                    |                  DHT
----------------------------------|--------------------------------------------
1) invoke doAnnounce()            |
                                  | Responds by emitting a 'get_peers' query
								  |
2) Fabricate and "send" a         |
   response to get_peers that     |
   has compact IP-address/port    |
   info for a peer                |
                                  | Responds by emitting 'announce_peer' query
								  |
*/
TEST(TestDhtImplResponse, AnnounceSeed_ReplyWithPeers)
{
	UnitTestUDPSocket socket4;
	UnitTestUDPSocket socket6;
	BencodedDict bDictGetPeer;
	SockAddr sAddr(0x7a7a7a7a,0x7878); // ip = zzzz and socket = xx
	socket4.SetBindAddr(sAddr);
	smart_ptr<DhtImpl> dhtTestObj(new DhtImpl(&socket4, &socket6));
	dhtTestObj->SetSHACallback(&sha1_callback);

	// prepare the object for use
	dhtTestObj->Enable(true,0);
	SetDHT_my_id_Bytes(dhtTestObj);

	// put a peer into the dht for it to work with
	DhtPeerID peerID;
	peerID.id.id[0] = '1111'; // 1111
	peerID.id.id[1] = 'BBBB'; // BBBB
	peerID.id.id[2] = 'CCCC'; // CCCC
	peerID.id.id[3] = 'DDDD'; // DDDD
	peerID.id.id[4] = '0000'; // 0000
	peerID.addr.set_port(('8' << 8) + '8'); // 88
	peerID.addr.set_addr4('aaaa'); // aaaa
	dhtTestObj->Update(peerID, 0, false);
	Buffer peerIDBuffer;
	peerIDBuffer.len = 20;
	peerIDBuffer.b = (byte*)&peerID.id.id[0];

	DhtID target;
	target.id[0] = 'FFFF'; // FFFF
	target.id[1] = 'GGGG'; // GGGG
	target.id[2] = 'HHHH'; // HHHH
	target.id[3] = 'IIII'; // IIII
	target.id[4] = 'JJJJ'; // JJJJ

	// make sure the callback dummy is clear
	AddNodesCallbackDummy::Reset();

	EXPECT_EQ(1, dhtTestObj->GetNumPeers());
	EXPECT_EQ(0, dhtTestObj->GetNumPeersTracked());

	DhtPeerID *ids[16];
	uint num = dhtTestObj->FindNodes(target, ids, 8, 8, 0); // Find 8 good ones and 8 bad ones
	EXPECT_EQ(1, num) << "Num Nodes: " << num;
	EXPECT_FALSE(dhtTestObj->IsBusy()) << "The dht should not be busy yet";

	// *****************************************************
	// make the dht emit an announce message (the get_peers rpc)
	// *****************************************************
	std::string filenameTxt("filaname.txt");
	dhtTestObj->DoAnnounce(target, 20, NULL, &AddNodesCallbackDummy::Callback, NULL, filenameTxt.c_str(), NULL, IDht::announce_seed);
	EXPECT_TRUE(dhtTestObj->IsBusy()) << "The dht should be busy";

	// *****************************************************
	// grab from the socket the emitted message and extract
	// the transaction ID and verify the remainder of the
	// message
	// *****************************************************
	std::string doAnnounceOutput = socket4.GetSentDataAsString();
	BencEntity bEntityAnounceQuery;
	// verify the bencoded string that went out the socket
	BencEntity::Parse((const byte *)doAnnounceOutput.c_str(), bEntityAnounceQuery, (const byte *)(doAnnounceOutput.c_str() + doAnnounceOutput.length()));

	// get the query dictionary
	BencodedDict *dictForAnnounce = BencodedDict::AsDict(&bEntityAnounceQuery);
	EXPECT_TRUE(dictForAnnounce);
	if (!dictForAnnounce) {
		FAIL() << "ERROR:  The dht did not emit a bencoded dictionary for announce";
	}

	Buffer type;
	type.b = (byte*)dictForAnnounce->GetString("y" ,&type.len);
	ASSERT_EQ(1, type.len) << "ERROR: the 'y' type length is wrong (should be 1 for 'q', 'r', or 'e')";
	ASSERT_EQ('q', type.b[0]) << "ERROR: 'y' type is wrong; should be 'q' for query instead of:  " << type.b[0];

	Buffer command;
	command.b = (byte*)dictForAnnounce->GetString("q" ,&command.len);
	EXPECT_EQ(9, command.len);
	EXPECT_FALSE(memcmp("get_peers", command.b, 9)) << "ERROR: 'q' command is wrong; should be 'get_peers'";

	// get the transaction ID to use later
	Buffer tid;
	tid.b = (byte*)dictForAnnounce->GetString("t" ,&tid.len);
	EXPECT_EQ(4, tid.len) << "transaction ID is wrong size";

	// now look into the query data
	BencodedDict *announceQuery = dictForAnnounce->GetDict("a");
	if (!announceQuery) {
		FAIL() << "ERROR:  Failed to extract 'a' dictionary from get_peer response";
	}

	Buffer id;
	id.b = (byte*)announceQuery->GetString("id" ,&id.len);
	EXPECT_EQ(20, id.len);
	EXPECT_FALSE(memcmp("AAAABBBBCCCCDDDDEEEE", id.b, 20)) << "ERROR: announced id is wrong";

	Buffer infoHash;
	infoHash.b = (byte*)announceQuery->GetString("info_hash" ,&infoHash.len);
	EXPECT_EQ(20, infoHash.len);
	EXPECT_FALSE(memcmp("FFFFGGGGHHHHIIIIJJJJ", infoHash.b, 20)) << "ERROR: info_hash is not the correct target";

	int noseed = announceQuery->GetInt("noseed");
	EXPECT_EQ(1,noseed) << "'noseed' is not set when it should be.";

	// *****************************************************
	// now fabricate a nodes response message using the
	// transaction ID extracted above and include a token
	// that the dht should return to us.  Provide the compact IP
	// of a peer for the dht to use in the 'announce_peer'
	// message it should emit next
	// *****************************************************
	std::vector<byte>	messageBytes;
	std::vector<byte>	replyDictionaryBytes;

	std::string responseToken("20_byte_reply_token.");
	std::string compactIP("aaaa88");

	// construct the message bytes
	BencStartDictionary(replyDictionaryBytes);
	{
		BencAddNameValuePair(replyDictionaryBytes,"id",peerIDBuffer);
		BencAddNameValuePair(replyDictionaryBytes,"token",responseToken);
		BencAddString(replyDictionaryBytes,"values");
		BencStartList(replyDictionaryBytes);
		{
			BencAddString(replyDictionaryBytes, compactIP);
		}
		BencEndList(replyDictionaryBytes);
	}
	BencEndDictionary(replyDictionaryBytes);

	BencStartDictionary(messageBytes);
	{
		BencAddNameAndBencodedDictionary(messageBytes,"r",replyDictionaryBytes);
		BencAddNameValuePair(messageBytes,"t",tid);
		BencAddNameValuePair(messageBytes,"y","r");
	}
	BencEndDictionary(messageBytes);

	// clear the socket and "send" the reply and capture the announce_peer emitted by the dht
	socket4.Reset();
	dhtTestObj->ProcessIncoming((byte*)&messageBytes.front(), messageBytes.size(), peerID.addr);
	std::string announceString = socket4.GetSentDataAsString();

	EXPECT_TRUE(dhtTestObj->IsBusy()) << "The dht should still be busy";

	// *****************************************************
	// verify the announce_peer message emitted by the dht
	// *****************************************************
	BencEntity::Parse((const byte *)announceString.c_str(), bEntityAnounceQuery, (const byte *)(announceString.c_str() + announceString.length()));

	// get the query dictionary
	dictForAnnounce = BencodedDict::AsDict(&bEntityAnounceQuery);
	EXPECT_TRUE(dictForAnnounce);
	if (!dictForAnnounce) {
		FAIL() << "ERROR:  The dht did not emit a bencoded dictionary for announce";
	}

	type.b = (byte*)dictForAnnounce->GetString("y" ,&type.len);
	ASSERT_EQ(1, type.len) << "ERROR: the 'y' type length is wrong (should be 1 for 'q', 'r', or 'e')";
	ASSERT_EQ('q', type.b[0]) << "ERROR: 'y' type is wrong; should be 'q' for query instead of:  " << type.b[0];

	command.b = (byte*)dictForAnnounce->GetString("q" ,&command.len);
	EXPECT_EQ(13, command.len);
	EXPECT_FALSE(memcmp("announce_peer", command.b, 13)) << "ERROR: 'q' command is wrong; should be 'announce_peer'";

	// get the transaction ID to use later
	tid.b = (byte*)dictForAnnounce->GetString("t" ,&tid.len);
	EXPECT_EQ(4, tid.len) << "transaction ID is wrong size";

	// now look into the query data
	announceQuery = dictForAnnounce->GetDict("a");
	if (!announceQuery) {
		FAIL() << "ERROR:  Failed to extract 'a' dictionary from get_peer response";
	}

	id.b = (byte*)announceQuery->GetString("id" ,&id.len);
	EXPECT_EQ(20, id.len);
	EXPECT_FALSE(memcmp("AAAABBBBCCCCDDDDEEEE", id.b, 20)) << "ERROR: announced id is wrong";

	infoHash.b = (byte*)announceQuery->GetString("info_hash" ,&infoHash.len);
	EXPECT_EQ(20, infoHash.len);
	EXPECT_FALSE(memcmp("FFFFGGGGHHHHIIIIJJJJ", infoHash.b, 20)) << "ERROR: info_hash is not the correct target";

	Buffer name;
	name.b = (byte*)announceQuery->GetString("name" ,&name.len);
	EXPECT_EQ(filenameTxt.size(), name.len);
	EXPECT_FALSE(strcmp(filenameTxt.c_str(), (char*)name.b));

	int port;
	port = announceQuery->GetInt("port");
	EXPECT_EQ(0x7878, port) << "Expected 0x7878 ('XX) for port; actual value = " << port;

	Buffer token;
	token.b = (byte*)announceQuery->GetString("token" ,&token.len);
	EXPECT_EQ(20, token.len);
	EXPECT_FALSE(strcmp(responseToken.c_str(), (char*)token.b));

	int seed = announceQuery->GetInt("seed");
	EXPECT_EQ(1,seed) << "'seed' is not set when it should be.";

	// *****************************************************
	// create and send a response to the 'announce_peer
	// message
	// *****************************************************
	messageBytes.clear();
	replyDictionaryBytes.clear();

	// construct the message bytes
	BencStartDictionary(replyDictionaryBytes);
	{
		BencAddNameValuePair(replyDictionaryBytes,"id",peerIDBuffer);
	}
	BencEndDictionary(replyDictionaryBytes);

	BencStartDictionary(messageBytes);
	{
		BencAddNameAndBencodedDictionary(messageBytes,"r",replyDictionaryBytes);
		BencAddNameValuePair(messageBytes,"t",tid);
		BencAddNameValuePair(messageBytes,"y","r");
	}
	BencEndDictionary(messageBytes);

	// clear the socket and "send" the reply;
	socket4.Reset();
	dhtTestObj->ProcessIncoming((byte*)&messageBytes.front(), messageBytes.size(), peerID.addr);

	// check that nothing went out the socket.
	EXPECT_EQ(0, socket4.GetSentByteVector().size()) << "Nothing should be sent out the socket in response to the reply to the dht's 'announce_peer' query";

	// *****************************************************
	// look in the addnodes call back dummy to see what was
	// passed through
	// *****************************************************
	ASSERT_EQ(2, AddNodesCallbackDummy::callbackData.size()) << "Expected two callback events";

	// verify the first callback event
	EXPECT_FALSE(memcmp("FFFFGGGGHHHHIIIIJJJJ", AddNodesCallbackDummy::callbackData[0].infoHash, 20));
	EXPECT_EQ(1, AddNodesCallbackDummy::callbackData[0].numPeers);
	EXPECT_FALSE(memcmp(compactIP.c_str(), &AddNodesCallbackDummy::callbackData[0].compactPeerAddressBytes[0], compactIP.size()));

	// verify the second callback event
	EXPECT_FALSE(memcmp("FFFFGGGGHHHHIIIIJJJJ", AddNodesCallbackDummy::callbackData[1].infoHash, 20));
	EXPECT_EQ(0, AddNodesCallbackDummy::callbackData[1].numPeers);
	EXPECT_EQ(1, dhtTestObj->GetNumPeers());
	EXPECT_EQ(0, dhtTestObj->GetNumPeersTracked());
	num = dhtTestObj->FindNodes(target, ids, 8, 8, 0); // Find 8 good ones and 8 bad ones
	EXPECT_EQ(1, num) << "Num Nodes: " << num;

	DhtRequest* req = dhtTestObj->LookupRequest(Read32(tid.b));
	EXPECT_FALSE(req) << "The outstanding transaction id was not removed by the response";

	EXPECT_FALSE(dhtTestObj->IsBusy()) << "The dht should no longer be busy";
}


/**
          Test                    |                  DHT
----------------------------------|--------------------------------------------
1) invoke doAnnounce()            |
                                  | Responds by emitting a 'get_peers' query
								  |
2) Fabricate and "send" a         |
   response to get_peers that     |
   has only compact node info     |
                                  | Responds by emitting another 'get_peers' query
								  |
*/
TEST(TestDhtImplResponse, AnnouncePartialInfoHash_ReplyWithNodes)
{
	UnitTestUDPSocket socket4;
	UnitTestUDPSocket socket6;
	BencodedDict bDictGetPeer;
	SockAddr sAddr(0x7a7a7a7a,0x7878); // ip = zzzz and socket = xx
	socket4.SetBindAddr(sAddr);
	smart_ptr<DhtImpl> dhtTestObj(new DhtImpl(&socket4, &socket6));
	dhtTestObj->SetSHACallback(&sha1_callback);

	// prepare the object for use
	dhtTestObj->Enable(true,0);
	SetDHT_my_id_Bytes(dhtTestObj);

	// put a peer into the dht for it to work with
	DhtPeerID peerID;
	peerID.id.id[0] = '1111'; // 1111
	peerID.id.id[1] = 'BBBB'; // BBBB
	peerID.id.id[2] = 'CCCC'; // CCCC
	peerID.id.id[3] = 'DDDD'; // DDDD
	peerID.id.id[4] = '0000'; // 0000
	peerID.addr.set_port(128);
	peerID.addr.set_addr4(0xf0f0f0f0);
	dhtTestObj->Update(peerID, 0, false);
	Buffer peerIDBuffer;
	peerIDBuffer.len = 20;
	peerIDBuffer.b = (byte*)&peerID.id.id[0];

	DhtID target;
	target.id[0] = 'FFFF'; // FFFF
	target.id[1] = 'GGGG'; // GGGG
	target.id[2] = 'HHHH'; // HHHH
	target.id[3] = 'IIII'; // IIII
	target.id[4] = 'JJJJ'; // JJJJ

	// make sure the callback dummy is clear
	AddNodesCallbackDummy::Reset();
	PartialHashCallbackDummy::Reset();

	// *****************************************************
	// Make the dht emit an announce message (the get_peers rpc)
	// Just tell it that the target is only 16 bytes long (instead of 20)
	// *****************************************************
	EXPECT_FALSE(dhtTestObj->IsBusy()) << "The dht should not be busy yet";
	dhtTestObj->AnnounceInfoHash((byte*)&target.id[0], 16, &PartialHashCallbackDummy::PartialHashCallback, &AddNodesCallbackDummy::Callback, NULL, "filename.txt", NULL, IDht::announce_seed);
	EXPECT_TRUE(dhtTestObj->IsBusy()) << "The dht should be busy";

	// *****************************************************
	// grab from the socket the emitted message and extract
	// the transaction ID and verify the remainder of the
	// message
	// *****************************************************
	std::string doAnnounceOutput = socket4.GetSentDataAsString();
	BencEntity bEntityAnounceQuery;
	// verify the bencoded string that went out the socket
	BencEntity::Parse((const byte *)doAnnounceOutput.c_str(), bEntityAnounceQuery, (const byte *)(doAnnounceOutput.c_str() + doAnnounceOutput.length()));

	// get the query dictionary
	BencodedDict *dictForAnnounce = BencodedDict::AsDict(&bEntityAnounceQuery);
	EXPECT_TRUE(dictForAnnounce);
	if (!dictForAnnounce) {
		FAIL() << "ERROR:  The dht did not emit a bencoded dictionary for announce";
	}

	Buffer type;
	type.b = (byte*)dictForAnnounce->GetString("y" ,&type.len);
	ASSERT_EQ(1, type.len) << "ERROR: the 'y' type length is wrong (should be 1 for 'q', 'r', or 'e')";
	ASSERT_EQ('q', type.b[0]) << "ERROR: 'y' type is wrong; should be 'q' for query instead of:  " << type.b[0];

	Buffer command;
	command.b = (byte*)dictForAnnounce->GetString("q" ,&command.len);
	EXPECT_EQ(9, command.len);
	EXPECT_FALSE(memcmp("get_peers", command.b, 9)) << "ERROR: 'q' command is wrong";

	// get the transaction ID to use later
	Buffer tid;
	tid.b = (byte*)dictForAnnounce->GetString("t" ,&tid.len);
	EXPECT_EQ(4, tid.len) << "transaction ID is wrong size";

	// now look into the query data
	BencodedDict *announceQuery = dictForAnnounce->GetDict("a");
	if (!announceQuery) {
		FAIL() << "ERROR:  Failed to extract 'a' dictionary from get_peer response";
	}

	Buffer id;
	id.b = (byte*)announceQuery->GetString("id" ,&id.len);
	EXPECT_EQ(20, id.len);
	EXPECT_FALSE(memcmp("AAAABBBBCCCCDDDDEEEE", id.b, 20)) << "ERROR: announced id is wrong";

	int infoHashLength;
	infoHashLength = announceQuery->GetInt("ifhpfxl");
	EXPECT_EQ(16, infoHashLength);

	Buffer infoHash;
	infoHash.b = (byte*)announceQuery->GetString("info_hash" ,&infoHash.len);
	EXPECT_EQ(20, infoHash.len);
	EXPECT_FALSE(memcmp("FFFFGGGGHHHHIIIIJJJJ", infoHash.b, 20)) << "ERROR: info_hash is not the correct target";

	// *****************************************************
	// now fabricate a nodes response message using the
	// transaction ID extracted above and include a token
	// *****************************************************
	std::vector<byte>	messageBytes;
	std::vector<byte>	replyDictionaryBytes;

	std::string responseToken("20_byte_reply_token.");
	std::string nearistNode  ("26_byte_nearist_node_addr.");

	// construct the message bytes
	BencStartDictionary(replyDictionaryBytes);
	{
		BencAddNameValuePair(replyDictionaryBytes,"id",peerIDBuffer);
		BencAddNameValuePair(replyDictionaryBytes,"nodes",nearistNode);
		BencAddNameValuePair(replyDictionaryBytes,"token",responseToken);
	}
	BencEndDictionary(replyDictionaryBytes);

	BencStartDictionary(messageBytes);
	{
		BencAddNameAndBencodedDictionary(messageBytes,"r",replyDictionaryBytes);
		BencAddNameValuePair(messageBytes,"t",tid);
		BencAddNameValuePair(messageBytes,"y","r");
	}
	BencEndDictionary(messageBytes);

	// clear the socket and "send" the reply
	socket4.Reset();
	dhtTestObj->ProcessIncoming((byte*)&messageBytes.front(), messageBytes.size(), peerID.addr);

	EXPECT_TRUE(dhtTestObj->IsBusy()) << "The dht should still be busy";

	// *****************************************************
	// get the bencoded string out of the socket and verify
	// it.
	// *****************************************************
	std::string bencMessage = socket4.GetSentDataAsString();
	BencEntity bEntity;

	// verify the bencoded string that went out the socket
	BencEntity::Parse((const byte *)bencMessage.c_str(), bEntity, (const byte *)(bencMessage.c_str() + bencMessage.length()));

	// did we get a valid dictionary
	BencodedDict *dict = BencodedDict::AsDict(&bEntity);
	EXPECT_TRUE(dict);
	if (!dict) {
		FAIL() << "ERROR:  The emitted query is not a bencoded dictionary";
	}

	Buffer qType;
	qType.b = (byte*)dict->GetString("y", &qType.len);
	EXPECT_EQ(1, qType.len);
	EXPECT_EQ('q', qType.b[0]) << "The 'y' type should be 'q'";

	Buffer qCommand;
	qCommand.b = (byte*)dict->GetString("q", &qCommand.len);
	EXPECT_EQ(9, qCommand.len);
	EXPECT_FALSE(memcmp(qCommand.b, "get_peers", qCommand.len)) << "The command is wrong; should be get_peers";

	// get the 'a' arguments dictionary
	BencodedDict *emittedQueryArgs = dict->GetDict("a");
	EXPECT_TRUE(emittedQueryArgs);
	if (!dict) {
		FAIL() << "ERROR:  The emitted query did not contain an 'a' dictionary";
	}

	Buffer qID;
	qID.b = (byte*)emittedQueryArgs->GetString("id", &qID.len);
	EXPECT_EQ(20, qID.len);
	EXPECT_FALSE(memcmp(qID.b, "AAAABBBBCCCCDDDDEEEE", qID.len)) << "The id is wrong";

	Buffer qInfoHash;
	qInfoHash.b = (byte*)emittedQueryArgs->GetString("info_hash", &qInfoHash.len);
	EXPECT_EQ(20, qInfoHash.len);
	EXPECT_FALSE(memcmp(qInfoHash.b, (byte*)target.id, qInfoHash.len)) << "The target info_hash is wrong";

	// *****************************************************
	// look in the addnodes call back dummy to see what was
	// passed through (should be nothing)
	// *****************************************************
	EXPECT_EQ(0, AddNodesCallbackDummy::callbackData.size()) << "no callback events should have been made";
	EXPECT_TRUE(dhtTestObj->IsBusy()) << "The dht should still be busy";

	DhtRequest* req = dhtTestObj->LookupRequest(Read32(tid.b));
	EXPECT_FALSE(req) << "The outstanding transaction id was not removed by the response";
}

class FindNodeCallbackDummy : public IDhtProcessCallbackListener
{
public:
	int callbackCount;
	FindNodeCallbackDummy(){callbackCount = 0;}
	~FindNodeCallbackDummy(){}
	virtual void ProcessCallback();
};

void FindNodeCallbackDummy::ProcessCallback()
{
	++callbackCount;
}

TEST(TestDhtImplResponse, DoFindNodes_OnReplyCallback)
{
	UnitTestUDPSocket socket4;
	UnitTestUDPSocket socket6;
	BencodedDict bDictGetPeer;
	SockAddr sAddr(0x7a7a7a7a,0x7878); // ip = zzzz and socket = xx
	socket4.SetBindAddr(sAddr);
	smart_ptr<DhtImpl> dhtTestObj(new DhtImpl(&socket4, &socket6));
	dhtTestObj->SetSHACallback(&sha1_callback);
	DhtRequest* req;

	// prepare the object for use
	dhtTestObj->Enable(true,0);
	SetDHT_my_id_Bytes(dhtTestObj);

	// put a peer into the dht for it to work with
	DhtPeerID peerID;
	peerID.id.id[0] = '1111'; // 1111
	peerID.id.id[1] = 'BBBB'; // BBBB
	peerID.id.id[2] = 'CCCC'; // CCCC
	peerID.id.id[3] = 'DDDD'; // DDDD
	peerID.id.id[4] = '0000'; // 0000
	peerID.addr.set_port(128);
	peerID.addr.set_addr4(0xf0f0f0f0);
	dhtTestObj->Update(peerID, 0, false);
	Buffer peerIDBuffer;
	peerIDBuffer.len = 20;
	peerIDBuffer.b = (byte*)&peerID.id.id[0];

	DhtID target;
	target.id[0] = 'FFFF'; // FFFF
	target.id[1] = 'GGGG'; // GGGG
	target.id[2] = 'HHHH'; // HHHH
	target.id[3] = 'IIII'; // IIII
	target.id[4] = 'JJJJ'; // JJJJ

	// *****************************************************
	// tell the dht to issue a find_nodes request and
	// capture the query string that goes out the socket
	// *****************************************************
	EXPECT_FALSE(dhtTestObj->IsBusy()) << "The dht should not be busy yet";
	FindNodeCallbackDummy CallbackObj;
	dhtTestObj->DoFindNodes(target, 20, &CallbackObj);
	std::string doFindNodesOutput = socket4.GetSentDataAsString();
	EXPECT_TRUE(dhtTestObj->IsBusy()) << "The dht should be busy";

	// *****************************************************
	// decode and verify the find_nodes query string
	// be sure to keep the transaction id
	// *****************************************************
	BencEntity bEntityAnounceQuery;
	// verify the bencoded string that went out the socket
	BencEntity::Parse((const byte *)doFindNodesOutput.c_str(), bEntityAnounceQuery, (const byte *)(doFindNodesOutput.c_str() + doFindNodesOutput.length()));

	// get the query dictionary
	BencodedDict *dictForAnnounce = BencodedDict::AsDict(&bEntityAnounceQuery);
	EXPECT_TRUE(dictForAnnounce);
	if (!dictForAnnounce) {
		FAIL() << "ERROR:  The dht did not emit a bencoded dictionary for announce";
	}

	Buffer type;
	type.b = (byte*)dictForAnnounce->GetString("y" ,&type.len);
	ASSERT_EQ(1, type.len) << "ERROR: the 'y' type length is wrong (should be 1 for 'q', 'r', or 'e')";
	ASSERT_EQ('q', type.b[0]) << "ERROR: 'y' type is wrong; should be 'q' for query instead of:  " << type.b[0];

	Buffer command;
	command.b = (byte*)dictForAnnounce->GetString("q" ,&command.len);
	EXPECT_EQ(9, command.len);
	EXPECT_FALSE(memcmp("find_node", command.b, 9)) << "ERROR: 'q' command is wrong; should be 'find_node'";

	// get the transaction ID to use later
	Buffer tid;
	tid.b = (byte*)dictForAnnounce->GetString("t" ,&tid.len);
	EXPECT_EQ(4, tid.len) << "transaction ID is wrong size";

	// see that the request has been queued
	req = dhtTestObj->LookupRequest(Read32(tid.b));
	ASSERT_TRUE(req) << "The outstanding transaction id does not exist";

	// now look into the query data
	BencodedDict *announceQuery = dictForAnnounce->GetDict("a");
	if (!announceQuery) {
		FAIL() << "ERROR:  Failed to extract 'a' dictionary from find_node rpc";
	}

	Buffer id;
	id.b = (byte*)announceQuery->GetString("id" ,&id.len);
	EXPECT_EQ(20, id.len);
	EXPECT_FALSE(memcmp("AAAABBBBCCCCDDDDEEEE", id.b, 20)) << "ERROR: announced id is wrong";

	Buffer infoHash;
	infoHash.b = (byte*)announceQuery->GetString("target" ,&infoHash.len);
	EXPECT_EQ(20, infoHash.len);
	EXPECT_FALSE(memcmp("FFFFGGGGHHHHIIIIJJJJ", infoHash.b, 20)) << "ERROR: info_hash is not the correct target";

	// now fabricate a nodes response message using the transaction ID extracted above
	std::vector<byte>	messageBytes;
	std::vector<byte>	replyDictionaryBytes;

	// *****************************************************
	// make a response message to the above query.  Use the
	// transaction id extracted above.  Note the "compact
	// node" information for later use
	// *****************************************************
	std::string responseToken("20_byte_reply_token.");
	// encode the compact node with IP address: 'aaaa' , port: '88' (aaaa88) and use this in the second response below
	std::string compactNode("WWWWWXXXXXYYYYYZZZZZaaaa88");

	// construct the message bytes
	BencStartDictionary(replyDictionaryBytes);
	{
		BencAddNameValuePair(replyDictionaryBytes,"id",peerIDBuffer);
		BencAddNameValuePair(replyDictionaryBytes,"nodes",compactNode);
		BencAddNameValuePair(replyDictionaryBytes,"token",responseToken);
	}
	BencEndDictionary(replyDictionaryBytes);

	BencStartDictionary(messageBytes);
	{
		BencAddNameAndBencodedDictionary(messageBytes,"r",replyDictionaryBytes);
		BencAddNameValuePair(messageBytes,"t",tid);
		BencAddNameValuePair(messageBytes,"y","r");
	}
	BencEndDictionary(messageBytes);

	// *****************************************************
	// clear the socket, "send" the reply, and capture the
	// second query string to be issued by the dht
	// *****************************************************
	socket4.Reset();
	dhtTestObj->ProcessIncoming((byte*)&messageBytes.front(), messageBytes.size(), peerID.addr);
	std::string secondtime = socket4.GetSentDataAsString();
	EXPECT_TRUE(dhtTestObj->IsBusy()) << "The dht should be busy";

	// *****************************************************
	// verify the next bencoded string that went out the socket.
	// again capture the transaction id
	// *****************************************************
	BencEntity::Parse((const byte *)secondtime.c_str(), bEntityAnounceQuery, (const byte *)(secondtime.c_str() + secondtime.length()));

	// get the query dictionary
	dictForAnnounce = BencodedDict::AsDict(&bEntityAnounceQuery);
	EXPECT_TRUE(dictForAnnounce);
	if (!dictForAnnounce) {
		FAIL() << "ERROR:  The dht did not emit a bencoded dictionary for find_node";
	}

	type.b = (byte*)dictForAnnounce->GetString("y" ,&type.len);
	ASSERT_EQ(1, type.len) << "ERROR: the 'y' type length is wrong (should be 1 for 'q', 'r', or 'e')";
	ASSERT_EQ('q', type.b[0]) << "ERROR: 'y' type is wrong; should be 'q' for query instead of:  " << type.b[0];

	command.b = (byte*)dictForAnnounce->GetString("q" ,&command.len);
	EXPECT_EQ(9, command.len);
	EXPECT_FALSE(memcmp("find_node", command.b, 9)) << "ERROR: 'q' command is wrong; should be 'find_node'";

	// get the transaction ID to use later
	tid.b = (byte*)dictForAnnounce->GetString("t" ,&tid.len);
	EXPECT_EQ(4, tid.len) << "transaction ID is wrong size";

	// see that the request has been queued
	req = dhtTestObj->LookupRequest(Read32(tid.b));
	ASSERT_TRUE(req) << "The outstanding transaction id does not exist";

	// now look into the query data
	announceQuery = dictForAnnounce->GetDict("a");
	if (!announceQuery) {
		FAIL() << "ERROR:  Failed to extract 'a' dictionary from find_node response";
	}

	id.b = (byte*)announceQuery->GetString("id" ,&id.len);
	EXPECT_EQ(20, id.len);
	EXPECT_FALSE(memcmp("AAAABBBBCCCCDDDDEEEE", id.b, 20)) << "ERROR: announced id is wrong";

	infoHash.b = (byte*)announceQuery->GetString("target" ,&infoHash.len);
	EXPECT_EQ(20, infoHash.len);
	EXPECT_FALSE(memcmp("FFFFGGGGHHHHIIIIJJJJ", infoHash.b, 20)) << "ERROR: info_hash is not the correct target";

	EXPECT_TRUE(dhtTestObj->IsBusy()) << "The dht should still be busy";

	// *****************************************************
	// now fabricate a nodes response message using the
	// transaction ID extracted above.  ALSO, use the IP
	// address and port that were returned to the dht
	// in the response to it's initial query (aaaa88)
	// *****************************************************
	messageBytes.clear();
	replyDictionaryBytes.clear();

	// construct the message bytes
	BencStartDictionary(replyDictionaryBytes);
	{
		BencAddNameValuePair(replyDictionaryBytes,"id","WWWWWXXXXXYYYYYZZZZZ");
		BencAddNameValuePair(replyDictionaryBytes,"nodes",compactNode);
		BencAddNameValuePair(replyDictionaryBytes,"token",responseToken);
	}
	BencEndDictionary(replyDictionaryBytes);

	BencStartDictionary(messageBytes);
	{
		BencAddNameAndBencodedDictionary(messageBytes,"r",replyDictionaryBytes);
		BencAddNameValuePair(messageBytes,"t",tid);
		BencAddNameValuePair(messageBytes,"y","r");
	}
	BencEndDictionary(messageBytes);

	// clear the socket and "send" the reply
	socket4.Reset();
	DhtPeerID secondPeerID;
	secondPeerID.addr.set_addr4('aaaa'); // aaaa
	secondPeerID.addr.set_port(('8' << 8) + '8'); //88

	dhtTestObj->ProcessIncoming((byte*)&messageBytes.front(), messageBytes.size(), secondPeerID.addr);

	// *****************************************************
	// The DhtProcess object that is internally called back to uses private members
	// and member functions with no access points.  So, only circumstantial evidence
	// can be used to see if things are working as they should.
	// *****************************************************

	// see that our call back was invoked (this may be invoked even if there is an internal error)
	EXPECT_EQ(1, CallbackObj.callbackCount) << "Our callback object should have been invoked 1 time";

	req = dhtTestObj->LookupRequest(Read32(tid.b));
	EXPECT_FALSE(req) << "The outstanding transaction id was not removed by the response";
	EXPECT_FALSE(dhtTestObj->IsBusy()) << "The dht should no longer be busy";
}

TEST(TestDhtImplResponse, DoFindNodes_NoNodesInReply)
{
	UnitTestUDPSocket socket4;
	UnitTestUDPSocket socket6;
	BencodedDict bDictGetPeer;
	SockAddr sAddr(0x7a7a7a7a,0x7878); // ip = zzzz and socket = xx
	socket4.SetBindAddr(sAddr);
	smart_ptr<DhtImpl> dhtTestObj(new DhtImpl(&socket4, &socket6));
	dhtTestObj->SetSHACallback(&sha1_callback);
	DhtRequest* req;

	// prepare the object for use
	dhtTestObj->Enable(true,0);
	SetDHT_my_id_Bytes(dhtTestObj);

	// put a peer into the dht for it to work with
	DhtPeerID peerID;
	peerID.id.id[0] = '1111'; // 1111
	peerID.id.id[1] = 'BBBB'; // BBBB
	peerID.id.id[2] = 'CCCC'; // CCCC
	peerID.id.id[3] = 'DDDD'; // DDDD
	peerID.id.id[4] = '0000'; // 0000
	peerID.addr.set_port(128);
	peerID.addr.set_addr4(0xf0f0f0f0);
	dhtTestObj->Update(peerID, 0, false);
	Buffer peerIDBuffer;
	peerIDBuffer.len = 20;
	peerIDBuffer.b = (byte*)&peerID.id.id[0];

	DhtID target;
	target.id[0] = 'FFFF'; // FFFF
	target.id[1] = 'GGGG'; // GGGG
	target.id[2] = 'HHHH'; // HHHH
	target.id[3] = 'IIII'; // IIII
	target.id[4] = 'JJJJ'; // JJJJ

	// *****************************************************
	// tell the dht to issue a find_nodes request and
	// capture the query string that goes out the socket
	// *****************************************************
	EXPECT_FALSE(dhtTestObj->IsBusy()) << "The dht should not be busy yet";
	FindNodeCallbackDummy CallbackObj;
	dhtTestObj->DoFindNodes(target, 20, &CallbackObj);
	std::string doFindNodesOutput = socket4.GetSentDataAsString();
	EXPECT_TRUE(dhtTestObj->IsBusy()) << "The dht should be busy";

	// *****************************************************
	// decode and verify the find_nodes query string
	// be sure to keep the transaction id
	// *****************************************************
	BencEntity bEntityAnounceQuery;
	// verify the bencoded string that went out the socket
	BencEntity::Parse((const byte *)doFindNodesOutput.c_str(), bEntityAnounceQuery, (const byte *)(doFindNodesOutput.c_str() + doFindNodesOutput.length()));

	// get the query dictionary
	BencodedDict *dictForAnnounce = BencodedDict::AsDict(&bEntityAnounceQuery);
	EXPECT_TRUE(dictForAnnounce);
	if (!dictForAnnounce) {
		FAIL() << "ERROR:  The dht did not emit a bencoded dictionary for announce";
	}

	Buffer type;
	type.b = (byte*)dictForAnnounce->GetString("y" ,&type.len);
	ASSERT_EQ(1, type.len) << "ERROR: the 'y' type length is wrong (should be 1 for 'q', 'r', or 'e')";
	ASSERT_EQ('q', type.b[0]) << "ERROR: 'y' type is wrong; should be 'q' for query instead of:  " << type.b[0];

	Buffer command;
	command.b = (byte*)dictForAnnounce->GetString("q" ,&command.len);
	EXPECT_EQ(9, command.len);
	EXPECT_FALSE(memcmp("find_node", command.b, 9)) << "ERROR: 'q' command is wrong; should be 'find_node'";

	// get the transaction ID to use later
	Buffer tid;
	tid.b = (byte*)dictForAnnounce->GetString("t" ,&tid.len);
	EXPECT_EQ(4, tid.len) << "transaction ID is wrong size";

	// see that the request has been queued
	req = dhtTestObj->LookupRequest(Read32(tid.b));
	ASSERT_TRUE(req) << "The outstanding transaction id does not exist";

	// now look into the query data
	BencodedDict *announceQuery = dictForAnnounce->GetDict("a");
	if (!announceQuery) {
		FAIL() << "ERROR:  Failed to extract 'a' dictionary from get_peer response";
	}

	Buffer id;
	id.b = (byte*)announceQuery->GetString("id" ,&id.len);
	EXPECT_EQ(20, id.len);
	EXPECT_FALSE(memcmp("AAAABBBBCCCCDDDDEEEE", id.b, 20)) << "ERROR: announced id is wrong";

	Buffer infoHash;
	infoHash.b = (byte*)announceQuery->GetString("target" ,&infoHash.len);
	EXPECT_EQ(20, infoHash.len);
	EXPECT_FALSE(memcmp("FFFFGGGGHHHHIIIIJJJJ", infoHash.b, 20)) << "ERROR: info_hash is not the correct target";

	// now fabricate a nodes response message using the transaction ID extracted above
	std::vector<byte>	messageBytes;
	std::vector<byte>	replyDictionaryBytes;

	// *****************************************************
	// make a response message to the above query.  Use the
	// transaction id extracted above.
	//
	// For this test, DO NOT include any "compact node"
	// information in the response
	// *****************************************************
	std::string responseToken("20_byte_reply_token.");

	// construct the message bytes
	BencStartDictionary(replyDictionaryBytes);
	{
		BencAddNameValuePair(replyDictionaryBytes,"id",peerIDBuffer);
		BencAddNameValuePair(replyDictionaryBytes,"token",responseToken);
	}
	BencEndDictionary(replyDictionaryBytes);

	BencStartDictionary(messageBytes);
	{
		BencAddNameAndBencodedDictionary(messageBytes,"r",replyDictionaryBytes);
		BencAddNameValuePair(messageBytes,"t",tid);
		BencAddNameValuePair(messageBytes,"y","r");
	}
	BencEndDictionary(messageBytes);

	// *****************************************************
	// clear the socket, "send" the reply, and capture the
	// second query string to be issued by the dht
	// *****************************************************
	socket4.Reset();
	dhtTestObj->ProcessIncoming((byte*)&messageBytes.front(), messageBytes.size(), peerID.addr);
	std::string secondtime = socket4.GetSentDataAsString();
	EXPECT_FALSE(dhtTestObj->IsBusy()) << "The dht should no longer be busy";

	// *****************************************************
	// The DhtProcess object that is internally called back to uses private members
	// and member functions with no access points.  So, only circumstantial evidence
	// can be used to see if things are working as they should.
	// *****************************************************

	// see that our call back was invoked (this may be invoked even if there is an internal error)
	EXPECT_EQ(1, CallbackObj.callbackCount) << "Our callback object should have been invoked 1 time";

	req = dhtTestObj->LookupRequest(Read32(tid.b));
	EXPECT_FALSE(req) << "The outstanding transaction id was not removed by the response";
	EXPECT_FALSE(dhtTestObj->IsBusy()) << "The dht should no longer be busy";
}


TEST(TestDhtImplResponse, DoFindNodes_ReplyWith_ICMP)
{
	UnitTestUDPSocket socket4;
	UnitTestUDPSocket socket6;
	BencodedDict bDictGetPeer;
	SockAddr sAddr(0x7a7a7a7a,0x7878); // ip = zzzz and socket = xx
	socket4.SetBindAddr(sAddr);
	smart_ptr<DhtImpl> dhtTestObj(new DhtImpl(&socket4, &socket6));
	dhtTestObj->SetSHACallback(&sha1_callback);
	DhtRequest* req;

	// prepare the object for use
	dhtTestObj->Enable(true,0);
	SetDHT_my_id_Bytes(dhtTestObj);

	// put a peer into the dht for it to work with
	DhtPeerID peerID;
	peerID.id.id[0] = '1111'; // 1111
	peerID.id.id[1] = 'BBBB'; // BBBB
	peerID.id.id[2] = 'CCCC'; // CCCC
	peerID.id.id[3] = 'DDDD'; // DDDD
	peerID.id.id[4] = '0000'; // 0000
	peerID.addr.set_port(128);
	peerID.addr.set_addr4(0xf0f0f0f0);
	dhtTestObj->Update(peerID, 0, false);
	Buffer peerIDBuffer;
	peerIDBuffer.len = 20;
	peerIDBuffer.b = (byte*)&peerID.id.id[0];

	DhtID target;
	target.id[0] = 'FFFF'; // FFFF
	target.id[1] = 'GGGG'; // GGGG
	target.id[2] = 'HHHH'; // HHHH
	target.id[3] = 'IIII'; // IIII
	target.id[4] = 'JJJJ'; // JJJJ

	// *****************************************************
	// tell the dht to issue a find_nodes request and
	// capture the query string that goes out the socket
	// *****************************************************
	EXPECT_FALSE(dhtTestObj->IsBusy()) << "The dht should not be busy yet";
	FindNodeCallbackDummy CallbackObj;
	dhtTestObj->DoFindNodes(target, 20, &CallbackObj);
	std::string doFindNodesOutput = socket4.GetSentDataAsString();
	EXPECT_TRUE(dhtTestObj->IsBusy()) << "The dht should be busy";

	// *****************************************************
	// grab from the socket the emitted message and turn it
	// into a bencentity.  Feed it back to the dht as an
	// ICMP message
	// *****************************************************
	std::string doFindNodes = socket4.GetSentDataAsString();
	BencEntity bEntity;
	// verify the bencoded string that went out the socket
	BencEntity::Parse((const byte *)doFindNodes.c_str(), bEntity, (const byte *)(doFindNodes.c_str() + doFindNodes.length()));

	// get the transaction ID to use later
	BencodedDict *dictForFindNodes = BencodedDict::AsDict(&bEntity);
	Buffer tid;
	tid.b = (byte*)dictForFindNodes->GetString("t" ,&tid.len);

	EXPECT_TRUE(dhtTestObj->ParseIncomingICMP(bEntity, peerID.addr));

	// *****************************************************
	// The DhtProcess object that is internally called back to uses private members
	// and member functions with no access points.  So, only circumstantial evidence
	// can be used to see if things are working as they should.
	// *****************************************************

	// see that our call back was invoked (this may be invoked even if there is an internal error)
	EXPECT_EQ(1, CallbackObj.callbackCount) << "Our callback object should have been invoked 1 time";

	req = dhtTestObj->LookupRequest(Read32(tid.b));
	EXPECT_FALSE(req) << "The outstanding transaction id was not removed by the response";
	EXPECT_FALSE(dhtTestObj->IsBusy()) << "The dht should no longer be busy";
}


class VoteCallbackDummy
{
public:
	static int callbackCtr;
	VoteCallbackDummy(){}
	~VoteCallbackDummy(){}
	static void VoteCallback(void *ctx, const byte* info_hash, int const* votes);
	static void Reset();
};

int VoteCallbackDummy::callbackCtr;

void VoteCallbackDummy::VoteCallback(void *ctx, const byte* info_hash, int const* votes)
{
	callbackCtr++;
}

void VoteCallbackDummy::Reset()
{
	callbackCtr = 0;
}

/**
          Test                    |                  DHT
----------------------------------|--------------------------------------------
1) invoke DoVote()                |
                                  | Responds by emitting a 'get_peers' query
								  |
2) Fabricate and "send" a         |
   response to get_peers that     |
   has only compact node info     |
                                  | Responds by emitting another 'get_peers' query
								  |
*/
TEST(TestDhtImplResponse, DoVoteWithNodeReply)
{
	UnitTestUDPSocket socket4;
	UnitTestUDPSocket socket6;
	BencodedDict bDictGetPeer;
	SockAddr sAddr(0x7a7a7a7a,0x7878); // ip = zzzz and socket = xx
	socket4.SetBindAddr(sAddr);
	smart_ptr<DhtImpl> dhtTestObj(new DhtImpl(&socket4, &socket6));
	dhtTestObj->SetSHACallback(&sha1_callback);

	// prepare the object for use
	dhtTestObj->Enable(true,0);
	SetDHT_my_id_Bytes(dhtTestObj);

	// put a peer into the dht for it to work with
	DhtPeerID peerID;
	peerID.id.id[0] = '1111'; // 1111
	peerID.id.id[1] = 'BBBB'; // BBBB
	peerID.id.id[2] = 'CCCC'; // CCCC
	peerID.id.id[3] = 'DDDD'; // DDDD
	peerID.id.id[4] = '0000'; // 0000
	peerID.addr.set_port(128);
	peerID.addr.set_addr4(0xf0f0f0f0);
	dhtTestObj->Update(peerID, 0, false);
	Buffer peerIDBuffer;
	peerIDBuffer.len = 20;
	peerIDBuffer.b = (byte*)&peerID.id.id[0];

	DhtID target;
	target.id[0] = 'FFFF'; // FFFF
	target.id[1] = 'GGGG'; // GGGG
	target.id[2] = 'HHHH'; // HHHH
	target.id[3] = 'IIII'; // IIII
	target.id[4] = 'JJJJ'; // JJJJ

	VoteCallbackDummy::Reset();

	// *****************************************************
	// make the dht emit an announce message (the get_peers rpc)
	// *****************************************************
	EXPECT_FALSE(dhtTestObj->IsBusy()) << "The dht should not be busy yet";
	dhtTestObj->DoVote(target, 1, &VoteCallbackDummy::VoteCallback, NULL);
	EXPECT_TRUE(dhtTestObj->IsBusy()) << "The dht should be busy";

	// *****************************************************
	// grab from the socket the emitted message and extract
	// the transaction ID and verify the remainder of the
	// message
	// *****************************************************
	std::string doVoteOutput = socket4.GetSentDataAsString();
	BencEntity bEntityAnounceQuery;
	// verify the bencoded string that went out the socket
	BencEntity::Parse((const byte *)doVoteOutput.c_str(), bEntityAnounceQuery, (const byte *)(doVoteOutput.c_str() + doVoteOutput.length()));

	// get the query dictionary
	BencodedDict *dictForAnnounce = BencodedDict::AsDict(&bEntityAnounceQuery);
	EXPECT_TRUE(dictForAnnounce);
	if (!dictForAnnounce) {
		FAIL() << "ERROR:  The dht did not emit a bencoded dictionary for announce";
	}

	Buffer type;
	type.b = (byte*)dictForAnnounce->GetString("y" ,&type.len);
	ASSERT_EQ(1, type.len) << "ERROR: the 'y' type length is wrong (should be 1 for 'q', 'r', or 'e')";
	ASSERT_EQ('q', type.b[0]) << "ERROR: 'y' type is wrong; should be 'q' for query instead of:  " << type.b[0];

	Buffer command;
	command.b = (byte*)dictForAnnounce->GetString("q" ,&command.len);
	EXPECT_EQ(9, command.len);
	EXPECT_FALSE(memcmp("get_peers", command.b, 9)) << "ERROR: 'q' command is wrong";

	// get the transaction ID to use later
	Buffer tid;
	tid.b = (byte*)dictForAnnounce->GetString("t" ,&tid.len);
	EXPECT_EQ(4, tid.len) << "transaction ID is wrong size";

	// now look into the query data
	BencodedDict *announceQuery = dictForAnnounce->GetDict("a");
	if (!announceQuery) {
		FAIL() << "ERROR:  Failed to extract 'a' dictionary from get_peer response";
	}

	Buffer id;
	id.b = (byte*)announceQuery->GetString("id" ,&id.len);
	EXPECT_EQ(20, id.len);
	EXPECT_FALSE(memcmp("AAAABBBBCCCCDDDDEEEE", id.b, 20)) << "ERROR: announced id is wrong";

	Buffer infoHash;
	infoHash.b = (byte*)announceQuery->GetString("info_hash" ,&infoHash.len);
	EXPECT_EQ(20, infoHash.len);
	EXPECT_FALSE(memcmp("FFFFGGGGHHHHIIIIJJJJ", infoHash.b, 20)) << "ERROR: info_hash is not the correct target";

	// *****************************************************
	// now fabricate a nodes response message using the
	// transaction ID extracted above and include a token
	// *****************************************************
	std::vector<byte>	messageBytes;
	std::vector<byte>	replyDictionaryBytes;

	std::string responseToken("20_byte_reply_token.");
	std::string compactIP("abcd88");
	std::string compactNode("WWWWWXXXXXYYYYYZZZZZaaaa88");

	// construct the message bytes
	BencStartDictionary(replyDictionaryBytes);
	{
		BencAddNameValuePair(replyDictionaryBytes,"id",peerIDBuffer);
		BencAddNameValuePair(replyDictionaryBytes,"nodes",compactNode);
		BencAddNameValuePair(replyDictionaryBytes,"token",responseToken);
	}
	BencEndDictionary(replyDictionaryBytes);

	BencStartDictionary(messageBytes);
	{
		BencAddNameAndBencodedDictionary(messageBytes,"r",replyDictionaryBytes);
		BencAddNameValuePair(messageBytes,"t",tid);
		BencAddNameValuePair(messageBytes,"y","r");
	}
	BencEndDictionary(messageBytes);

	// clear the socket and "send" the reply
	socket4.Reset();
	dhtTestObj->ProcessIncoming((byte*)&messageBytes.front(), messageBytes.size(), peerID.addr);
	EXPECT_TRUE(dhtTestObj->IsBusy()) << "The dht should be busy";

	// *****************************************************
	// get the bencoded string out of the socket and verify
	// it. (should be another 'get_peers')
	// *****************************************************
	std::string voteString = socket4.GetSentDataAsString();

	// verify the bencoded string that went out the socket
	BencEntity bEntity;
	BencEntity::Parse((const byte *)voteString.c_str(), bEntity, (const byte *)(voteString.c_str() + voteString.length()));

	// did we get a valid dictionary
	BencodedDict *dict = BencodedDict::AsDict(&bEntity);
	EXPECT_TRUE(dict);
	if (!dict) {
		FAIL() << "ERROR:  The emitted query is not a bencoded dictionary";
	}

	Buffer qType;
	qType.b = (byte*)dict->GetString("y", &qType.len);
	EXPECT_EQ(1, qType.len);
	EXPECT_EQ('q', qType.b[0]) << "The 'y' type should be 'q'";

	Buffer qCommand;
	qCommand.b = (byte*)dict->GetString("q", &qCommand.len);
	EXPECT_EQ(9, qCommand.len);
	EXPECT_FALSE(memcmp(qCommand.b, "get_peers", qCommand.len)) << "The command is wrong; should be get_peers";

	// get the 'a' arguments dictionary
	BencodedDict *emittedQueryArgs = dict->GetDict("a");
	EXPECT_TRUE(emittedQueryArgs);
	if (!dict) {
		FAIL() << "ERROR:  The emitted query did not contain an 'a' dictionary";
	}

	Buffer qID;
	qID.b = (byte*)emittedQueryArgs->GetString("id", &qID.len);
	EXPECT_EQ(20, qID.len);
	EXPECT_FALSE(memcmp(qID.b, "AAAABBBBCCCCDDDDEEEE", qID.len)) << "The id is wrong";

	Buffer qInfoHash;
	qInfoHash.b = (byte*)emittedQueryArgs->GetString("info_hash", &qInfoHash.len);
	EXPECT_EQ(20, qInfoHash.len);
	EXPECT_FALSE(memcmp(qInfoHash.b, (byte*)target.id, qInfoHash.len)) << "The target info_hash is wrong";

	// *****************************************************
	// look in the vote call back dummy for callback events
	// *****************************************************
	EXPECT_EQ(0, VoteCallbackDummy::callbackCtr) << "no callback events should have been made";
	EXPECT_TRUE(dhtTestObj->IsBusy()) << "The dht should still be busy";
}


/**
          Test                    |                  DHT
----------------------------------|--------------------------------------------
1) invoke DoVote()                |
                                  | Responds by emitting a 'get_peers' query
								  |
2) Fabricate and "send" a         |
   response to get_peers that     |
   has compact IP-address/port    |
   info for a peer                |
                                  | Responds by emitting 'vote' query
								  |
*/
TEST(TestDhtImplResponse, DoVoteWithPeerReply)
{
	UnitTestUDPSocket socket4;
	UnitTestUDPSocket socket6;
	BencodedDict bDictGetPeer;
	SockAddr sAddr(0x7a7a7a7a,0x7878); // ip = zzzz and socket = xx
	socket4.SetBindAddr(sAddr);
	smart_ptr<DhtImpl> dhtTestObj(new DhtImpl(&socket4, &socket6));
	dhtTestObj->SetSHACallback(&sha1_callback);

	// prepare the object for use
	dhtTestObj->Enable(true,0);
	SetDHT_my_id_Bytes(dhtTestObj);

	// put a peer into the dht for it to work with
	DhtPeerID peerID;
	peerID.id.id[0] = '1111'; // 1111
	peerID.id.id[1] = 'BBBB'; // BBBB
	peerID.id.id[2] = 'CCCC'; // CCCC
	peerID.id.id[3] = 'DDDD'; // DDDD
	peerID.id.id[4] = '0000'; // 0000
	peerID.addr.set_port(128);
	peerID.addr.set_addr4(0xf0f0f0f0);
	dhtTestObj->Update(peerID, 0, false);
	Buffer peerIDBuffer;
	peerIDBuffer.len = 20;
	peerIDBuffer.b = (byte*)&peerID.id.id[0];

	DhtID target;
	target.id[0] = 'FFFF'; // FFFF
	target.id[1] = 'GGGG'; // GGGG
	target.id[2] = 'HHHH'; // HHHH
	target.id[3] = 'IIII'; // IIII
	target.id[4] = 'JJJJ'; // JJJJ

	VoteCallbackDummy::Reset();

	// *****************************************************
	// make the dht emit an announce message (the get_peers rpc)
	// note that the value of '3' should be retrieved from
	// the 'vote' message
	// *****************************************************
	EXPECT_FALSE(dhtTestObj->IsBusy()) << "The dht should not be busy yet";
	dhtTestObj->DoVote(target, 3, &VoteCallbackDummy::VoteCallback, NULL);
	EXPECT_TRUE(dhtTestObj->IsBusy()) << "The dht should be busy";

	// *****************************************************
	// grab from the socket the emitted message and extract
	// the transaction ID and verify the remainder of the
	// message
	// *****************************************************
	std::string doVoteOutput = socket4.GetSentDataAsString();
	BencEntity bEntityAnounceQuery;
	// verify the bencoded string that went out the socket
	BencEntity::Parse((const byte *)doVoteOutput.c_str(), bEntityAnounceQuery, (const byte *)(doVoteOutput.c_str() + doVoteOutput.length()));

	// get the query dictionary
	BencodedDict *dictForAnnounce = BencodedDict::AsDict(&bEntityAnounceQuery);
	EXPECT_TRUE(dictForAnnounce);
	if (!dictForAnnounce) {
		FAIL() << "ERROR:  The dht did not emit a bencoded dictionary for announce";
	}

	Buffer type;
	type.b = (byte*)dictForAnnounce->GetString("y" ,&type.len);
	ASSERT_EQ(1, type.len) << "ERROR: the 'y' type length is wrong (should be 1 for 'q', 'r', or 'e')";
	ASSERT_EQ('q', type.b[0]) << "ERROR: 'y' type is wrong; should be 'q' for query instead of:  " << type.b[0];

	Buffer command;
	command.b = (byte*)dictForAnnounce->GetString("q" ,&command.len);
	EXPECT_EQ(9, command.len);
	EXPECT_FALSE(memcmp("get_peers", command.b, 9)) << "ERROR: 'q' command is wrong";

	// get the transaction ID to use later
	Buffer tid;
	tid.b = (byte*)dictForAnnounce->GetString("t" ,&tid.len);
	EXPECT_EQ(4, tid.len) << "transaction ID is wrong size";

	// now look into the query data
	BencodedDict *announceQuery = dictForAnnounce->GetDict("a");
	if (!announceQuery) {
		FAIL() << "ERROR:  Failed to extract 'a' dictionary from get_peer response";
	}

	Buffer id;
	id.b = (byte*)announceQuery->GetString("id" ,&id.len);
	EXPECT_EQ(20, id.len);
	EXPECT_FALSE(memcmp("AAAABBBBCCCCDDDDEEEE", id.b, 20)) << "ERROR: announced id is wrong";

	Buffer infoHash;
	infoHash.b = (byte*)announceQuery->GetString("info_hash" ,&infoHash.len);
	EXPECT_EQ(20, infoHash.len);
	EXPECT_FALSE(memcmp("FFFFGGGGHHHHIIIIJJJJ", infoHash.b, 20)) << "ERROR: info_hash is not the correct target";

	// *****************************************************
	// now fabricate a nodes response message using the
	// transaction ID extracted above and include a token
	// *****************************************************
	std::vector<byte>	messageBytes;
	std::vector<byte>	replyDictionaryBytes;

	std::string responseToken("20_byte_reply_token.");
	std::string compactIP("aaaa88");

	// construct the message bytes
	BencStartDictionary(replyDictionaryBytes);
	{
		BencAddNameValuePair(replyDictionaryBytes,"id",peerIDBuffer);
		BencAddString(replyDictionaryBytes,"values");
		BencStartList(replyDictionaryBytes);
		{
			BencAddString(replyDictionaryBytes, compactIP);
		}
		BencEndList(replyDictionaryBytes);
		BencAddNameValuePair(replyDictionaryBytes,"token",responseToken);
	}
	BencEndDictionary(replyDictionaryBytes);

	BencStartDictionary(messageBytes);
	{
		BencAddNameAndBencodedDictionary(messageBytes,"r",replyDictionaryBytes);
		BencAddNameValuePair(messageBytes,"t",tid);
		BencAddNameValuePair(messageBytes,"y","r");
	}
	BencEndDictionary(messageBytes);

	// clear the socket and "send" the reply
	socket4.Reset();
	dhtTestObj->ProcessIncoming((byte*)&messageBytes.front(), messageBytes.size(), peerID.addr);
	EXPECT_TRUE(dhtTestObj->IsBusy()) << "The dht should be busy";

	// *****************************************************
	// verify the 'vote' message emitted by the dht
	// *****************************************************
	std::string voteString = socket4.GetSentDataAsString();
	BencEntity::Parse((const byte *)voteString.c_str(), bEntityAnounceQuery, (const byte *)(voteString.c_str() + voteString.length()));

	// get the query dictionary
	BencodedDict *dictForVote = BencodedDict::AsDict(&bEntityAnounceQuery);
	EXPECT_TRUE(dictForVote);
	if (!dictForVote) {
		FAIL() << "ERROR:  The dht did not emit a bencoded dictionary for announce";
	}

	type.b = (byte*)dictForVote->GetString("y" ,&type.len);
	ASSERT_EQ(1, type.len) << "ERROR: the 'y' type length is wrong (should be 1 for 'q', 'r', or 'e')";
	ASSERT_EQ('q', type.b[0]) << "ERROR: 'y' type is wrong; should be 'q' for query instead of:  " << type.b[0];

	command.b = (byte*)dictForVote->GetString("q" ,&command.len);
	EXPECT_EQ(4, command.len);
	EXPECT_FALSE(memcmp("vote", command.b, 4)) << "ERROR: 'q' command is wrong; should be 'vote' instead of:  " << command.b;

	// get the transaction ID to use later
	tid.b = (byte*)dictForVote->GetString("t" ,&tid.len);
	EXPECT_EQ(4, tid.len) << "transaction ID is wrong size";

	// now look into the query data
	BencodedDict* voteQuery = dictForVote->GetDict("a");
	if (!voteQuery) {
		FAIL() << "ERROR:  Failed to extract 'a' dictionary from get_peer response";
	}

	id.b = (byte*)voteQuery->GetString("id" ,&id.len);
	EXPECT_EQ(20, id.len);
	EXPECT_FALSE(memcmp("AAAABBBBCCCCDDDDEEEE", id.b, 20)) << "ERROR: announced id is wrong";

	Buffer targetBuf;
	targetBuf.b = (byte*)voteQuery->GetString("target" ,&targetBuf.len);
	EXPECT_EQ(20, targetBuf.len);
	EXPECT_FALSE(memcmp("FFFFGGGGHHHHIIIIJJJJ", targetBuf.b, 20)) << "ERROR: info_hash is not the correct target";

	Buffer token;
	token.b = (byte*)voteQuery->GetString("token" ,&token.len);
	EXPECT_EQ(20, token.len);
	EXPECT_FALSE(strcmp(responseToken.c_str(), (char*)token.b));

	int voteValue;
	voteValue = voteQuery->GetInt("vote");
	EXPECT_EQ(3, voteValue);

	// *****************************************************
	// create and send a response to the 'vote' message
	// *****************************************************
	messageBytes.clear();
	replyDictionaryBytes.clear();

	// construct the message bytes
	BencStartDictionary(replyDictionaryBytes);
	{
		BencAddNameValuePair(replyDictionaryBytes,"id",peerIDBuffer);
	}
	BencEndDictionary(replyDictionaryBytes);

	BencStartDictionary(messageBytes);
	{
		BencAddNameAndBencodedDictionary(messageBytes,"r",replyDictionaryBytes);
		BencAddNameValuePair(messageBytes,"t",tid);
		BencAddNameValuePair(messageBytes,"y","r");
	}
	BencEndDictionary(messageBytes);

	// clear the socket and "send" the reply;
	socket4.Reset();
	dhtTestObj->ProcessIncoming((byte*)&messageBytes.front(), messageBytes.size(), peerID.addr);

	// check that nothing went out the socket.
	EXPECT_EQ(0, socket4.GetSentByteVector().size()) << "Nothing should be sent out the socket in response to the reply to the dht's 'announce_peer' query";

	// *****************************************************
	// look in the vote call back dummy for callback events
	// *****************************************************
	EXPECT_EQ(1, VoteCallbackDummy::callbackCtr) << "1 callback should have been made";
	EXPECT_FALSE(dhtTestObj->IsBusy()) << "The dht should no longer be busy";
}

/**
          Test                    |                  DHT
----------------------------------|--------------------------------------------
1) invoke DoVote()                |
                                  | Responds by emitting a 'get_peers' query
								  |
2) Capture the outputted bencoded |
   string and feed it back to the |
   DHT via ParseIncommingICMP     |
                                  | Ceases pursuing the request
								  |
*/
TEST(TestDhtImplResponse, DoVote_ReplyWith_ICMP)
{
	UnitTestUDPSocket socket4;
	UnitTestUDPSocket socket6;
	BencodedDict bDictGetPeer;
	SockAddr sAddr(0x7a7a7a7a,0x7878); // ip = zzzz and socket = xx
	socket4.SetBindAddr(sAddr);
	smart_ptr<DhtImpl> dhtTestObj(new DhtImpl(&socket4, &socket6));
	dhtTestObj->SetSHACallback(&sha1_callback);

	// prepare the object for use
	dhtTestObj->Enable(true,0);
	SetDHT_my_id_Bytes(dhtTestObj);

	// put a peer into the dht for it to work with
	DhtPeerID peerID;
	peerID.id.id[0] = '1111'; // 1111
	peerID.id.id[1] = 'BBBB'; // BBBB
	peerID.id.id[2] = 'CCCC'; // CCCC
	peerID.id.id[3] = 'DDDD'; // DDDD
	peerID.id.id[4] = '0000'; // 0000
	peerID.addr.set_port(128);
	peerID.addr.set_addr4(0xf0f0f0f0);
	dhtTestObj->Update(peerID, 0, false);
	Buffer peerIDBuffer;
	peerIDBuffer.len = 20;
	peerIDBuffer.b = (byte*)&peerID.id.id[0];

	DhtID target;
	target.id[0] = 'FFFF'; // FFFF
	target.id[1] = 'GGGG'; // GGGG
	target.id[2] = 'HHHH'; // HHHH
	target.id[3] = 'IIII'; // IIII
	target.id[4] = 'JJJJ'; // JJJJ

	VoteCallbackDummy::Reset();

	// *****************************************************
	// make the dht emit an announce message (the get_peers rpc)
	// note that the value of '3' should be retrieved from
	// the 'vote' message
	// *****************************************************
	EXPECT_FALSE(dhtTestObj->IsBusy()) << "The dht should not be busy yet";
	dhtTestObj->DoVote(target, 3, &VoteCallbackDummy::VoteCallback, NULL);
	EXPECT_TRUE(dhtTestObj->IsBusy()) << "The dht should be busy";

	// *****************************************************
	// grab from the socket the emitted message and turn it
	// into a bencentity.  Feed it back to the dht as an
	// ICMP message
	// *****************************************************
	std::string doVoteOutput = socket4.GetSentDataAsString();
	BencEntity bEntity;
	// verify the bencoded string that went out the socket
	BencEntity::Parse((const byte *)doVoteOutput.c_str(), bEntity, (const byte *)(doVoteOutput.c_str() + doVoteOutput.length()));

	// get the transaction ID to use later
	BencodedDict *dictForVote = BencodedDict::AsDict(&bEntity);
	Buffer tid;
	tid.b = (byte*)dictForVote->GetString("t" ,&tid.len);

	EXPECT_TRUE(dhtTestObj->ParseIncomingICMP(bEntity, peerID.addr));

	// *****************************************************
	// look in the vote call back dummy for callback events
	// *****************************************************
	EXPECT_EQ(0, VoteCallbackDummy::callbackCtr) << "NO callbacks should have been made";
	EXPECT_FALSE(dhtTestObj->IsBusy()) << "The dht should no longer be busy";
	DhtRequest* req = dhtTestObj->LookupRequest(Read32(tid.b));
	EXPECT_FALSE(req) << "The outstanding transaction id was not removed by the response";
}


/**
          Test                    |                  DHT
----------------------------------|--------------------------------------------
1) invoke DoVote()                |
                                  | Responds by emitting a 'get_peers' query
								  |
2) Fabricate and "send" a         |
   response to get_peers that     |
   has compact IP-address/port    |
   info for a peer                |
                                  | Responds by emitting 'vote' query
								  |
3) Send an ICMP message back      |
                                  |
*/
TEST(TestDhtImplResponse, DoVote_ReplyWith_ICMP_AfterVote)
{
	UnitTestUDPSocket socket4;
	UnitTestUDPSocket socket6;
	BencodedDict bDictGetPeer;
	SockAddr sAddr(0x7a7a7a7a,0x7878); // ip = zzzz and socket = xx
	socket4.SetBindAddr(sAddr);
	smart_ptr<DhtImpl> dhtTestObj(new DhtImpl(&socket4, &socket6));
	dhtTestObj->SetSHACallback(&sha1_callback);

	// prepare the object for use
	dhtTestObj->Enable(true,0);
	SetDHT_my_id_Bytes(dhtTestObj);

	// put a peer into the dht for it to work with
	DhtPeerID peerID;
	peerID.id.id[0] = '1111'; // 1111
	peerID.id.id[1] = 'BBBB'; // BBBB
	peerID.id.id[2] = 'CCCC'; // CCCC
	peerID.id.id[3] = 'DDDD'; // DDDD
	peerID.id.id[4] = '0000'; // 0000
	peerID.addr.set_port(128);
	peerID.addr.set_addr4(0xf0f0f0f0);
	dhtTestObj->Update(peerID, 0, false);
	Buffer peerIDBuffer;
	peerIDBuffer.len = 20;
	peerIDBuffer.b = (byte*)&peerID.id.id[0];

	DhtID target;
	target.id[0] = 'FFFF'; // FFFF
	target.id[1] = 'GGGG'; // GGGG
	target.id[2] = 'HHHH'; // HHHH
	target.id[3] = 'IIII'; // IIII
	target.id[4] = 'JJJJ'; // JJJJ

	VoteCallbackDummy::Reset();

	// *****************************************************
	// make the dht emit an announce message (the get_peers rpc)
	// note that the value of '3' should be retrieved from
	// the 'vote' message
	// *****************************************************
	EXPECT_FALSE(dhtTestObj->IsBusy()) << "The dht should not be busy yet";
	dhtTestObj->DoVote(target, 3, &VoteCallbackDummy::VoteCallback, NULL);
	EXPECT_TRUE(dhtTestObj->IsBusy()) << "The dht should be busy";

	// *****************************************************
	// grab from the socket the emitted message and extract
	// the transaction ID and verify the remainder of the
	// message
	// *****************************************************
	std::string doVoteOutput = socket4.GetSentDataAsString();
	BencEntity bEntityAnounceQuery;
	// verify the bencoded string that went out the socket
	BencEntity::Parse((const byte *)doVoteOutput.c_str(), bEntityAnounceQuery, (const byte *)(doVoteOutput.c_str() + doVoteOutput.length()));

	// get the query dictionary
	BencodedDict *dictForAnnounce = BencodedDict::AsDict(&bEntityAnounceQuery);
	EXPECT_TRUE(dictForAnnounce);
	if (!dictForAnnounce) {
		FAIL() << "ERROR:  The dht did not emit a bencoded dictionary for announce";
	}

	Buffer type;
	type.b = (byte*)dictForAnnounce->GetString("y" ,&type.len);
	ASSERT_EQ(1, type.len) << "ERROR: the 'y' type length is wrong (should be 1 for 'q', 'r', or 'e')";
	ASSERT_EQ('q', type.b[0]) << "ERROR: 'y' type is wrong; should be 'q' for query instead of:  " << type.b[0];

	Buffer command;
	command.b = (byte*)dictForAnnounce->GetString("q" ,&command.len);
	EXPECT_EQ(9, command.len);
	EXPECT_FALSE(memcmp("get_peers", command.b, 9)) << "ERROR: 'q' command is wrong";

	// get the transaction ID to use later
	Buffer tid;
	tid.b = (byte*)dictForAnnounce->GetString("t" ,&tid.len);
	EXPECT_EQ(4, tid.len) << "transaction ID is wrong size";

	// now look into the query data
	BencodedDict *announceQuery = dictForAnnounce->GetDict("a");
	if (!announceQuery) {
		FAIL() << "ERROR:  Failed to extract 'a' dictionary from get_peer response";
	}

	Buffer id;
	id.b = (byte*)announceQuery->GetString("id" ,&id.len);
	EXPECT_EQ(20, id.len);
	EXPECT_FALSE(memcmp("AAAABBBBCCCCDDDDEEEE", id.b, 20)) << "ERROR: announced id is wrong";

	Buffer infoHash;
	infoHash.b = (byte*)announceQuery->GetString("info_hash" ,&infoHash.len);
	EXPECT_EQ(20, infoHash.len);
	EXPECT_FALSE(memcmp("FFFFGGGGHHHHIIIIJJJJ", infoHash.b, 20)) << "ERROR: info_hash is not the correct target";

	// *****************************************************
	// now fabricate a nodes response message using the
	// transaction ID extracted above and include a token
	// *****************************************************
	std::vector<byte>	messageBytes;
	std::vector<byte>	replyDictionaryBytes;

	std::string responseToken("20_byte_reply_token.");
	std::string compactIP("aaaa88");

	// construct the message bytes
	BencStartDictionary(replyDictionaryBytes);
	{
		BencAddNameValuePair(replyDictionaryBytes,"id",peerIDBuffer);
		BencAddString(replyDictionaryBytes,"values");
		BencStartList(replyDictionaryBytes);
		{
			BencAddString(replyDictionaryBytes, compactIP);
		}
		BencEndList(replyDictionaryBytes);
		BencAddNameValuePair(replyDictionaryBytes,"token",responseToken);
	}
	BencEndDictionary(replyDictionaryBytes);

	BencStartDictionary(messageBytes);
	{
		BencAddNameAndBencodedDictionary(messageBytes,"r",replyDictionaryBytes);
		BencAddNameValuePair(messageBytes,"t",tid);
		BencAddNameValuePair(messageBytes,"y","r");
	}
	BencEndDictionary(messageBytes);

	// clear the socket and "send" the reply
	socket4.Reset();
	dhtTestObj->ProcessIncoming((byte*)&messageBytes.front(), messageBytes.size(), peerID.addr);
	EXPECT_TRUE(dhtTestObj->IsBusy()) << "The dht should be busy";

	// *****************************************************
	// grab from the socket the emitted message and turn it
	// into a bencentity.  Feed it back to the dht as an
	// ICMP message
	// *****************************************************
	doVoteOutput = socket4.GetSentDataAsString();
	BencEntity bEntity;
	// verify the bencoded string that went out the socket
	BencEntity::Parse((const byte *)doVoteOutput.c_str(), bEntity, (const byte *)(doVoteOutput.c_str() + doVoteOutput.length()));

	// get the transaction ID to use later
	BencodedDict *dictForVote = BencodedDict::AsDict(&bEntity);
//	Buffer tid;
	tid.b = (byte*)dictForVote->GetString("t" ,&tid.len);

	EXPECT_TRUE(dhtTestObj->ParseIncomingICMP(bEntity, peerID.addr));

	// *****************************************************
	// look in the vote call back dummy for callback events
	// *****************************************************
	EXPECT_EQ(0, VoteCallbackDummy::callbackCtr) << "NO callbacks should have been made";
	EXPECT_FALSE(dhtTestObj->IsBusy()) << "The dht should no longer be busy";
	DhtRequest* req = dhtTestObj->LookupRequest(Read32(tid.b));
	EXPECT_FALSE(req) << "The outstanding transaction id was not removed by the response";
}



TEST(TestDhtImplResponse, TestResponseToPing)
{
	UnitTestUDPSocket socket4;
	UnitTestUDPSocket socket6;
	smart_ptr<DhtImpl> dhtTestObj(new DhtImpl(&socket4, &socket6));
	dhtTestObj->SetSHACallback(&sha1_callback);
	BencodedDict bDictGetPeer;
	SockAddr sAddr(0x7a7a7a7a,0x7878); // ip = zzzz and socket = xx

	// prepare the object for use
	byte myId[] = {'v','v','v','v','v','v','v','v','v','v','v','v','v','v','v','v','v','v','v','v'};
	dhtTestObj->SetId(myId);
	dhtTestObj->Enable(true,0);
	//SetDHT_my_id_Bytes(dhtTestObj);

	// put a peer into the dht for it to work with
	DhtPeerID peerID;
	peerID.id.id[0] = '1111'; // 1111
	peerID.id.id[1] = 'BBBB'; // BBBB
	peerID.id.id[2] = 'CCCC'; // CCCC
	peerID.id.id[3] = 'DDDD'; // DDDD
	peerID.id.id[4] = '0000'; // 0000
	peerID.addr.set_port(128);
	peerID.addr.set_addr4(0xf0f0f0f0);
	dhtTestObj->Update(peerID, 0, false);
	Buffer peerIDBuffer;
	peerIDBuffer.len = 20;
	peerIDBuffer.b = (byte*)&peerID.id.id[0];

	DhtID target;
	target.id[0] = 'FFFF'; // FFFF
	target.id[1] = 'GGGG'; // GGGG
	target.id[2] = 'HHHH'; // HHHH
	target.id[3] = 'IIII'; // IIII
	target.id[4] = 'JJJJ'; // JJJJ

	// invoke AddNode to emit a bootstrap ping message
	EXPECT_FALSE(dhtTestObj->IsBusy()) << "The dht should not be busy yet";
	dhtTestObj->AddNode(peerID.addr, NULL, 0);
	// grab from the socket the emitted message and extract the transaction ID
	std::string addNodeOutput = socket4.GetSentDataAsString();
	BencEntity bEntityAnounceQuery;
	// verify the bencoded string that went out the socket
	BencEntity::Parse((const byte *)addNodeOutput.c_str(), bEntityAnounceQuery, (const byte *)(addNodeOutput.c_str() + addNodeOutput.length()));

	// get the query dictionary
	BencodedDict *dictForAnnounce = BencodedDict::AsDict(&bEntityAnounceQuery);
	EXPECT_TRUE(dictForAnnounce);
	if (!dictForAnnounce) {
		FAIL() << "ERROR:  The dht did not emit a bencoded dictionary for ping";
	}

	Buffer type;
	type.b = (byte*)dictForAnnounce->GetString("y" ,&type.len);
	ASSERT_EQ(1, type.len) << "ERROR: the 'y' type length is wrong (should be 1 for 'q', 'r', or 'e')";
	ASSERT_EQ('q', type.b[0]) << "ERROR: 'y' type is wrong; should be 'q' for query instead of:  " << type.b[0];

	Buffer command;
	command.b = (byte*)dictForAnnounce->GetString("q" ,&command.len);
	EXPECT_EQ(4, command.len);
	EXPECT_FALSE(memcmp("ping", command.b, 4)) << "ERROR: 'q' command is wrong";

	// get the transaction ID to use later
	Buffer tid;
	tid.b = (byte*)dictForAnnounce->GetString("t" ,&tid.len);
	EXPECT_EQ(4, tid.len) << "transaction ID is wrong size";

	// now look into the query data
	BencodedDict *announceQuery = dictForAnnounce->GetDict("a");
	if (!announceQuery) {
		FAIL() << "ERROR:  Failed to extract 'a' dictionary from get_peer response";
	}

	Buffer id;
	id.b = (byte*)announceQuery->GetString("id" ,&id.len);
	EXPECT_EQ(20, id.len);
	EXPECT_FALSE(memcmp("vvvvvvvvvvvvvvvvvvvv", id.b, 20)) << "ERROR: announced id is wrong";

	// construct the reply message
	std::vector<byte>	messageBytes;
	std::vector<byte>	replyDictionaryBytes;
	BencStartDictionary(replyDictionaryBytes);
	{
		BencAddNameValuePair(replyDictionaryBytes,"id","qqqqqqqqqqqqqqqqqqqq");
	}
	BencEndDictionary(replyDictionaryBytes);

	BencStartDictionary(messageBytes);
	{
		BencAddNameAndBencodedDictionary(messageBytes,"r",replyDictionaryBytes);
		BencAddNameValuePair(messageBytes,"t",tid);
		BencAddNameValuePair(messageBytes,"y","r");
	}
	BencEndDictionary(messageBytes);

	// clear the socket and "send" the reply
	socket4.Reset();
	dhtTestObj->ProcessIncoming((byte*)&messageBytes.front(), messageBytes.size(), peerID.addr);
	EXPECT_TRUE(dhtTestObj->IsBusy()) << "The dht should be busy";

	std::string findNodeString = socket4.GetSentDataAsString();

	// *****************************************************
	// verify the next bencoded string that went out the socket.
	// *****************************************************
	BencEntity::Parse((const byte *)findNodeString.c_str(), bEntityAnounceQuery, (const byte *)(findNodeString.c_str() + findNodeString.length()));

	// get the query dictionary
	dictForAnnounce = BencodedDict::AsDict(&bEntityAnounceQuery);
	EXPECT_TRUE(dictForAnnounce);
	if (!dictForAnnounce) {
		FAIL() << "ERROR:  The dht did not emit a bencoded dictionary for find_node";
	}

	type.b = (byte*)dictForAnnounce->GetString("y" ,&type.len);
	ASSERT_EQ(1, type.len) << "ERROR: the 'y' type length is wrong (should be 1 for 'q', 'r', or 'e')";
	ASSERT_EQ('q', type.b[0]) << "ERROR: 'y' type is wrong; should be 'q' for query instead of:  " << type.b[0];

	command.b = (byte*)dictForAnnounce->GetString("q" ,&command.len);
	EXPECT_EQ(9, command.len);
	EXPECT_FALSE(memcmp("find_node", command.b, 9)) << "ERROR: 'q' command is wrong; should be 'find_node'";

	// get the transaction ID to use later
	tid.b = (byte*)dictForAnnounce->GetString("t" ,&tid.len);
	EXPECT_EQ(4, tid.len) << "transaction ID is wrong size";

	// see that the request has been queued
	DhtRequest* req;
	req = dhtTestObj->LookupRequest(Read32(tid.b));
	ASSERT_TRUE(req) << "The outstanding transaction id does not exist";

	// now look into the query data
	announceQuery = dictForAnnounce->GetDict("a");
	if (!announceQuery) {
		FAIL() << "ERROR:  Failed to extract 'a' dictionary from get_peer response";
	}

	id.b = (byte*)announceQuery->GetString("id" ,&id.len);
	EXPECT_EQ(20, id.len);
	EXPECT_FALSE(memcmp("vvvvvvvvvvvvvvvvvvvv", id.b, 20)) << "ERROR: announced id is wrong";

	Buffer targetBuf;
	targetBuf.b = (byte*)announceQuery->GetString("target" ,&targetBuf.len);
	EXPECT_EQ(20, targetBuf.len);
	// the dht xor's the last word of its id with 0x00000001, so the last letter changes from 'v' to 'w' for the target
	EXPECT_FALSE(memcmp("vvvvvvvvvvvvvvvvvvvw", targetBuf.b, 20)) << "ERROR: the target is wrong";
	EXPECT_TRUE(dhtTestObj->IsBusy()) << "The dht should still be busy";
}


TEST(TestDhtImplResponse, TestResponseToPing_ReplyWith_ICMP)
{
	UnitTestUDPSocket socket4;
	UnitTestUDPSocket socket6;
	smart_ptr<DhtImpl> dhtTestObj(new DhtImpl(&socket4, &socket6));
	dhtTestObj->SetSHACallback(&sha1_callback);
	BencodedDict bDictGetPeer;
	SockAddr sAddr(0x7a7a7a7a,0x7878); // ip = zzzz and socket = xx

	// prepare the object for use
	byte myId[] = {'v','v','v','v','v','v','v','v','v','v','v','v','v','v','v','v','v','v','v','v'};
	dhtTestObj->SetId(myId);
	dhtTestObj->Enable(true,0);
	//SetDHT_my_id_Bytes(dhtTestObj);

	// put a peer into the dht for it to work with
	DhtPeerID peerID;
	peerID.id.id[0] = '1111'; // 1111
	peerID.id.id[1] = 'BBBB'; // BBBB
	peerID.id.id[2] = 'CCCC'; // CCCC
	peerID.id.id[3] = 'DDDD'; // DDDD
	peerID.id.id[4] = '0000'; // 0000
	peerID.addr.set_port(128);
	peerID.addr.set_addr4(0xf0f0f0f0);
	dhtTestObj->Update(peerID, 0, false);
	Buffer peerIDBuffer;
	peerIDBuffer.len = 20;
	peerIDBuffer.b = (byte*)&peerID.id.id[0];

	DhtID target;
	target.id[0] = 'FFFF'; // FFFF
	target.id[1] = 'GGGG'; // GGGG
	target.id[2] = 'HHHH'; // HHHH
	target.id[3] = 'IIII'; // IIII
	target.id[4] = 'JJJJ'; // JJJJ

	// invoke AddNode to emit a bootstrap ping message
	EXPECT_FALSE(dhtTestObj->IsBusy()) << "The dht should not be busy yet";
	dhtTestObj->AddNode(peerID.addr, NULL, 0);

	// *****************************************************
	// grab from the socket the emitted message and turn it
	// into a bencentity.  Feed it back to the dht as an
	// ICMP message
	// *****************************************************
	std::string doAnnounceOutput = socket4.GetSentDataAsString();
	BencEntity bEntityAnounceQuery;
	// verify the bencoded string that went out the socket
	BencEntity::Parse((const byte *)doAnnounceOutput.c_str(), bEntityAnounceQuery, (const byte *)(doAnnounceOutput.c_str() + doAnnounceOutput.length()));

	// get the transaction ID to use later
	BencodedDict *dictForAnnounce = BencodedDict::AsDict(&bEntityAnounceQuery);
	Buffer tid;
	tid.b = (byte*)dictForAnnounce->GetString("t" ,&tid.len);

	socket4.Reset();
	EXPECT_TRUE(dhtTestObj->ParseIncomingICMP(bEntityAnounceQuery, peerID.addr));

	// *****************************************************
	// verify that nothing went out the socket in response to ICMP message
	// *****************************************************
	std::string emptyStr = socket4.GetSentDataAsString();
	EXPECT_EQ(0,emptyStr.size()) << "Nothing should have gone out the socket";
	EXPECT_FALSE(dhtTestObj->IsBusy()) << "The dht should NOT be busy";
}



class ScrapeCallbackDummy
{
public:
	static byte infoHash[20];
	static int numDownloaders;
	static int numSeeds;

	ScrapeCallbackDummy(){}
	~ScrapeCallbackDummy(){}
	static void Callback(void *ctx, const byte *info_hash, int downloaders, int seeds);
	static void Reset();
};

byte ScrapeCallbackDummy::infoHash[20];
int ScrapeCallbackDummy::numDownloaders;
int ScrapeCallbackDummy::numSeeds;

void ScrapeCallbackDummy::Callback(void *ctx, const byte *info_hash, int downloaders, int seeds)
{
	for(unsigned int x=0; x<20; ++x)
		infoHash[x] = info_hash[x];
	numDownloaders = downloaders;
	numSeeds = seeds;
}

void ScrapeCallbackDummy::Reset()
{
	for(unsigned int x=0; x<20; ++x)
		infoHash[x] = 0;
	numDownloaders = numSeeds = 0;
}

/**
          Test                    |                  DHT
----------------------------------|--------------------------------------------
1) invoke DoScrape()              |
                                  | Responds by emitting a 'get_peers' query
								  |
2) Fabricate and "send" a         |
   response to get_peers that     |
   has only compact node info     |
                                  | Responds by emitting another 'get_peers' query
								  |
*/
TEST(TestDhtImplResponse, DoScrape_ReplyWithNodes)
{
	UnitTestUDPSocket socket4;
	UnitTestUDPSocket socket6;
	BencodedDict bDictGetPeer;
	SockAddr sAddr(0x7a7a7a7a,0x7878); // ip = zzzz and socket = xx
	socket4.SetBindAddr(sAddr);
	smart_ptr<DhtImpl> dhtTestObj(new DhtImpl(&socket4, &socket6));
	dhtTestObj->SetSHACallback(&sha1_callback);

	// prepare the object for use
	dhtTestObj->Enable(true,0);
	SetDHT_my_id_Bytes(dhtTestObj);

	// put a peer into the dht for it to work with
	DhtPeerID peerID;
	peerID.id.id[0] = '1111'; // 1111
	peerID.id.id[1] = 'BBBB'; // BBBB
	peerID.id.id[2] = 'CCCC'; // CCCC
	peerID.id.id[3] = 'DDDD'; // DDDD
	peerID.id.id[4] = '0000'; // 0000
	peerID.addr.set_port(128);
	peerID.addr.set_addr4(0xf0f0f0f0);
	dhtTestObj->Update(peerID, 0, false);
	Buffer peerIDBuffer;
	peerIDBuffer.len = 20;
	peerIDBuffer.b = (byte*)&peerID.id.id[0];

	DhtID target;
	target.id[0] = 'FFFF'; // FFFF
	target.id[1] = 'GGGG'; // GGGG
	target.id[2] = 'HHHH'; // HHHH
	target.id[3] = 'IIII'; // IIII
	target.id[4] = 'JJJJ'; // JJJJ

	// make sure the callback dummy is clear
	ScrapeCallbackDummy::Reset();

	// *****************************************************
	// make the dht emit a scrape message (the get_peers rpc)
	// *****************************************************
	EXPECT_FALSE(dhtTestObj->IsBusy()) << "The dht should not be busy yet";
	dhtTestObj->DoScrape(target, &ScrapeCallbackDummy::Callback, NULL);
	EXPECT_TRUE(dhtTestObj->IsBusy()) << "The dht should be busy";

	// *****************************************************
	// grab from the socket the emitted message and extract
	// the transaction ID and verify the remainder of the
	// message
	// *****************************************************
	std::string doAnnounceOutput = socket4.GetSentDataAsString();
	BencEntity bEntityAnounceQuery;
	// verify the bencoded string that went out the socket
	BencEntity::Parse((const byte *)doAnnounceOutput.c_str(), bEntityAnounceQuery, (const byte *)(doAnnounceOutput.c_str() + doAnnounceOutput.length()));

	// get the query dictionary
	BencodedDict *dictForAnnounce = BencodedDict::AsDict(&bEntityAnounceQuery);
	EXPECT_TRUE(dictForAnnounce);
	if (!dictForAnnounce) {
		FAIL() << "ERROR:  The dht did not emit a bencoded dictionary for announce";
	}

	Buffer type;
	type.b = (byte*)dictForAnnounce->GetString("y" ,&type.len);
	ASSERT_EQ(1, type.len) << "ERROR: the 'y' type length is wrong (should be 1 for 'q', 'r', or 'e')";
	ASSERT_EQ('q', type.b[0]) << "ERROR: 'y' type is wrong; should be 'q' for query instead of:  " << type.b[0];

	Buffer command;
	command.b = (byte*)dictForAnnounce->GetString("q" ,&command.len);
	EXPECT_EQ(9, command.len);
	EXPECT_FALSE(memcmp("get_peers", command.b, 9)) << "ERROR: 'q' command is wrong";

	// get the transaction ID to use later
	Buffer tid;
	tid.b = (byte*)dictForAnnounce->GetString("t" ,&tid.len);
	EXPECT_EQ(4, tid.len) << "transaction ID is wrong size";

	// now look into the query data
	BencodedDict *announceQuery = dictForAnnounce->GetDict("a");
	if (!announceQuery) {
		FAIL() << "ERROR:  Failed to extract 'a' dictionary from get_peer response";
	}

	Buffer id;
	id.b = (byte*)announceQuery->GetString("id" ,&id.len);
	EXPECT_EQ(20, id.len);
	EXPECT_FALSE(memcmp("AAAABBBBCCCCDDDDEEEE", id.b, 20)) << "ERROR: announced id is wrong";

	Buffer infoHash;
	infoHash.b = (byte*)announceQuery->GetString("info_hash" ,&infoHash.len);
	EXPECT_EQ(20, infoHash.len);
	EXPECT_FALSE(memcmp("FFFFGGGGHHHHIIIIJJJJ", infoHash.b, 20)) << "ERROR: info_hash is not the correct target";

	int scrapeVal = announceQuery->GetInt("scrape");
	EXPECT_EQ(1, scrapeVal);

	// *****************************************************
	// now fabricate a nodes response message using the
	// transaction ID extracted above and include a token
	// *****************************************************
	std::vector<byte>	messageBytes;
	std::vector<byte>	replyDictionaryBytes;

	std::string responseToken("20_byte_reply_token.");
	std::string nearistNode  ("26_byte_nearist_node_addr.");

	// construct the message bytes
	BencStartDictionary(replyDictionaryBytes);
	{
		BencAddNameValuePair(replyDictionaryBytes,"id",peerIDBuffer);
		BencAddNameValuePair(replyDictionaryBytes,"nodes",nearistNode);
		BencAddNameValuePair(replyDictionaryBytes,"token",responseToken);
	}
	BencEndDictionary(replyDictionaryBytes);

	BencStartDictionary(messageBytes);
	{
		BencAddNameAndBencodedDictionary(messageBytes,"r",replyDictionaryBytes);
		BencAddNameValuePair(messageBytes,"t",tid);
		BencAddNameValuePair(messageBytes,"y","r");
	}
	BencEndDictionary(messageBytes);

	// clear the socket and "send" the reply
	socket4.Reset();
	dhtTestObj->ProcessIncoming((byte*)&messageBytes.front(), messageBytes.size(), peerID.addr);
	EXPECT_TRUE(dhtTestObj->IsBusy()) << "The dht should be busy";

	// *****************************************************
	// get the bencoded string out of the socket and verify
	// it.
	// *****************************************************
	std::string bencMessage = socket4.GetSentDataAsString();
	BencEntity bEntity;

	// verify the bencoded string that went out the socket
	BencEntity::Parse((const byte *)bencMessage.c_str(), bEntity, (const byte *)(bencMessage.c_str() + bencMessage.length()));

	// did we get a valid dictionary
	BencodedDict *dict = BencodedDict::AsDict(&bEntity);
	EXPECT_TRUE(dict);
	if (!dict) {
		FAIL() << "ERROR:  The emitted query is not a bencoded dictionary";
	}

	Buffer qType;
	qType.b = (byte*)dict->GetString("y", &qType.len);
	EXPECT_EQ(1, qType.len);
	EXPECT_EQ('q', qType.b[0]) << "The 'y' type should be 'q'";

	Buffer qCommand;
	qCommand.b = (byte*)dict->GetString("q", &qCommand.len);
	EXPECT_EQ(9, qCommand.len);
	EXPECT_FALSE(memcmp(qCommand.b, "get_peers", qCommand.len)) << "The command is wrong; should be get_peers";

	// get the 'a' arguments dictionary
	BencodedDict *emittedQueryArgs = dict->GetDict("a");
	EXPECT_TRUE(emittedQueryArgs);
	if (!dict) {
		FAIL() << "ERROR:  The emitted query did not contain an 'a' dictionary";
	}

	Buffer qID;
	qID.b = (byte*)emittedQueryArgs->GetString("id", &qID.len);
	EXPECT_EQ(20, qID.len);
	EXPECT_FALSE(memcmp(qID.b, "AAAABBBBCCCCDDDDEEEE", qID.len)) << "The id is wrong";

	Buffer qInfoHash;
	qInfoHash.b = (byte*)emittedQueryArgs->GetString("info_hash", &qInfoHash.len);
	EXPECT_EQ(20, qInfoHash.len);
	EXPECT_FALSE(memcmp(qInfoHash.b, (byte*)target.id, qInfoHash.len)) << "The target info_hash is wrong";

	scrapeVal = announceQuery->GetInt("scrape");
	EXPECT_EQ(1, scrapeVal);

	// *****************************************************
	// look in the addnodes call back dummy to see what was
	// passed through (should be nothing)
	// *****************************************************
	EXPECT_FALSE(memcmp("\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", ScrapeCallbackDummy::infoHash, 20)) << "The callback should not have been invoked";
	EXPECT_EQ(0, ScrapeCallbackDummy::numDownloaders) << "The callback should not have been invoked";
	EXPECT_EQ(0, ScrapeCallbackDummy::numSeeds) << "The callback should not have been invoked";
	EXPECT_TRUE(dhtTestObj->IsBusy()) << "The dht should still be busy";
}


/**
          Test                    |                  DHT
----------------------------------|--------------------------------------------
1) invoke DoScrape()              |
                                  | Responds by emitting a 'get_peers' query
								  |
2) Fabricate and "send" a         |
   response to get_peers that     |
   has compact IP-address/port    |
   info for a peer                |
                                  | no output response expected from dht
								  |

Note:  The values estimated for the number of downloaders and the number of seeds
       that are examined in the callback at end of the test may change if the
	   algorithm in the bloom filter for estimating those numbers changes.  They
	   will also change if the "BFpe" and "BFsd" byte strings are altered.
*/
TEST(TestDhtImplResponse, Scrape_ReplyWithPeers)
{
	UnitTestUDPSocket socket4;
	UnitTestUDPSocket socket6;
	BencodedDict bDictGetPeer;
	SockAddr sAddr(0x7a7a7a7a,0x7878); // ip = zzzz and socket = xx
	socket4.SetBindAddr(sAddr);
	smart_ptr<DhtImpl> dhtTestObj(new DhtImpl(&socket4, &socket6));
	dhtTestObj->SetSHACallback(&sha1_callback);

	// prepare the object for use
	dhtTestObj->Enable(true,0);
	SetDHT_my_id_Bytes(dhtTestObj);

	// put a peer into the dht for it to work with
	DhtPeerID peerID;
	peerID.id.id[0] = '1111'; // 1111
	peerID.id.id[1] = 'BBBB'; // BBBB
	peerID.id.id[2] = 'CCCC'; // CCCC
	peerID.id.id[3] = 'DDDD'; // DDDD
	peerID.id.id[4] = '0000'; // 0000
	peerID.addr.set_port(('8' << 8) + '8'); // 88
	peerID.addr.set_addr4('aaaa'); // aaaa
	dhtTestObj->Update(peerID, 0, false);
	Buffer peerIDBuffer;
	peerIDBuffer.len = 20;
	peerIDBuffer.b = (byte*)&peerID.id.id[0];

	DhtID target;
	target.id[0] = 'FFFF'; // FFFF
	target.id[1] = 'GGGG'; // GGGG
	target.id[2] = 'HHHH'; // HHHH
	target.id[3] = 'IIII'; // IIII
	target.id[4] = 'JJJJ'; // JJJJ

	// make sure the callback dummy is clear
	ScrapeCallbackDummy::Reset();

	EXPECT_EQ(1, dhtTestObj->GetNumPeers());
	EXPECT_EQ(0, dhtTestObj->GetNumPeersTracked());

	// *****************************************************
	// make the dht emit a scrape message (the get_peers rpc)
	// *****************************************************
	EXPECT_FALSE(dhtTestObj->IsBusy()) << "The dht should not be busy yet";
	dhtTestObj->DoScrape(target, &ScrapeCallbackDummy::Callback, NULL);
	EXPECT_TRUE(dhtTestObj->IsBusy()) << "The dht should be busy";

	// *****************************************************
	// grab from the socket the emitted message and extract
	// the transaction ID and verify the remainder of the
	// message
	// *****************************************************
	std::string doAnnounceOutput = socket4.GetSentDataAsString();
	BencEntity bEntityAnounceQuery;
	// verify the bencoded string that went out the socket
	BencEntity::Parse((const byte *)doAnnounceOutput.c_str(), bEntityAnounceQuery, (const byte *)(doAnnounceOutput.c_str() + doAnnounceOutput.length()));

	// get the query dictionary
	BencodedDict *dictForAnnounce = BencodedDict::AsDict(&bEntityAnounceQuery);
	EXPECT_TRUE(dictForAnnounce);
	if (!dictForAnnounce) {
		FAIL() << "ERROR:  The dht did not emit a bencoded dictionary for announce";
	}

	Buffer type;
	type.b = (byte*)dictForAnnounce->GetString("y" ,&type.len);
	ASSERT_EQ(1, type.len) << "ERROR: the 'y' type length is wrong (should be 1 for 'q', 'r', or 'e')";
	ASSERT_EQ('q', type.b[0]) << "ERROR: 'y' type is wrong; should be 'q' for query instead of:  " << type.b[0];

	Buffer command;
	command.b = (byte*)dictForAnnounce->GetString("q" ,&command.len);
	EXPECT_EQ(9, command.len);
	EXPECT_FALSE(memcmp("get_peers", command.b, 9)) << "ERROR: 'q' command is wrong; should be 'get_peers'";

	// get the transaction ID to use later
	Buffer tid;
	tid.b = (byte*)dictForAnnounce->GetString("t" ,&tid.len);
	EXPECT_EQ(4, tid.len) << "transaction ID is wrong size";

	// now look into the query data
	BencodedDict *announceQuery = dictForAnnounce->GetDict("a");
	if (!announceQuery) {
		FAIL() << "ERROR:  Failed to extract 'a' dictionary from get_peer response";
	}

	Buffer id;
	id.b = (byte*)announceQuery->GetString("id" ,&id.len);
	EXPECT_EQ(20, id.len);
	EXPECT_FALSE(memcmp("AAAABBBBCCCCDDDDEEEE", id.b, 20)) << "ERROR: announced id is wrong";

	Buffer infoHash;
	infoHash.b = (byte*)announceQuery->GetString("info_hash" ,&infoHash.len);
	EXPECT_EQ(20, infoHash.len);
	EXPECT_FALSE(memcmp("FFFFGGGGHHHHIIIIJJJJ", infoHash.b, 20)) << "ERROR: info_hash is not the correct target";

	int scrapeVal = announceQuery->GetInt("scrape");
	EXPECT_EQ(1, scrapeVal);

	// *****************************************************
	// now fabricate a nodes response message using the
	// transaction ID extracted above and include a token
	// that the dht should return to us.  Provide the compact IP
	// of a peer for the dht to use in the 'announce_peer'
	// message it should emit next
	// *****************************************************
	std::vector<byte>	messageBytes;
	std::vector<byte>	replyDictionaryBytes;

	std::string responseToken("20_byte_reply_token.");
	std::string compactIP("aaaa88");

	// construct the message bytes
	BencStartDictionary(replyDictionaryBytes);
	{
		BencAddNameValuePair(replyDictionaryBytes,"BFpe", std::vector<byte>(256, 'b'));
		BencAddNameValuePair(replyDictionaryBytes,"BFsd", std::vector<byte>(256, 'B'));
		BencAddNameValuePair(replyDictionaryBytes,"id", peerIDBuffer);
		BencAddNameValuePair(replyDictionaryBytes,"token", responseToken);
		BencAddString(replyDictionaryBytes,"values");
		BencStartList(replyDictionaryBytes);
		{
			BencAddString(replyDictionaryBytes, compactIP);
		}
		BencEndList(replyDictionaryBytes);
	}
	BencEndDictionary(replyDictionaryBytes);

	BencStartDictionary(messageBytes);
	{
		BencAddNameAndBencodedDictionary(messageBytes,"r",replyDictionaryBytes);
		BencAddNameValuePair(messageBytes,"t",tid);
		BencAddNameValuePair(messageBytes,"y","r");
	}
	BencEndDictionary(messageBytes);

	// clear the socket and "send" the reply and capture the announce_peer emitted by the dht
	socket4.Reset();
	dhtTestObj->ProcessIncoming((byte*)&messageBytes.front(), messageBytes.size(), peerID.addr);
	EXPECT_FALSE(dhtTestObj->IsBusy()) << "The dht should no longer be busy";

	// *****************************************************
	// verify that no message emitted by the dht
	// *****************************************************
	std::string emptyString = socket4.GetSentDataAsString();
	EXPECT_TRUE(emptyString == "") << "A response message was sent for a scrape reply when no response message was expected.";

	// *****************************************************
	// verify the callback event
	// *****************************************************
	EXPECT_FALSE(memcmp("FFFFGGGGHHHHIIIIJJJJ", ScrapeCallbackDummy::infoHash, 20));
	EXPECT_EQ(481, ScrapeCallbackDummy::numDownloaders) << "(NOTE if the estimate_count() algorithm changes for Bloom Filters, this value may change.";
	EXPECT_EQ(294, ScrapeCallbackDummy::numSeeds) << "(NOTE if the estimate_count() algorithm changes for Bloom Filters, this value may change.";
	EXPECT_EQ(1, dhtTestObj->GetNumPeers());
	EXPECT_EQ(0, dhtTestObj->GetNumPeersTracked());
}


/**
          Test                    |                  DHT
----------------------------------|--------------------------------------------
1) invoke DoScrape()              |
                                  | Responds by emitting a 'get_peers' query
								  |
2) Capture the outputted bencoded |
   string and feed it back to the |
   DHT via ParseIncommingICMP     |
                                  | Ceases pursuing the request
								  |
*/
TEST(TestDhtImplResponse, Scrape_ReplyWith_ICMP)
{
	UnitTestUDPSocket socket4;
	UnitTestUDPSocket socket6;
	BencodedDict bDictGetPeer;
	SockAddr sAddr(0x7a7a7a7a,0x7878); // ip = zzzz and socket = xx
	socket4.SetBindAddr(sAddr);
	smart_ptr<DhtImpl> dhtTestObj(new DhtImpl(&socket4, &socket6));
	dhtTestObj->SetSHACallback(&sha1_callback);

	// prepare the object for use
	dhtTestObj->Enable(true,0);
	SetDHT_my_id_Bytes(dhtTestObj);

	// put a peer into the dht for it to work with
	DhtPeerID peerID;
	peerID.id.id[0] = '1111'; // 1111
	peerID.id.id[1] = 'BBBB'; // BBBB
	peerID.id.id[2] = 'CCCC'; // CCCC
	peerID.id.id[3] = 'DDDD'; // DDDD
	peerID.id.id[4] = '0000'; // 0000
	peerID.addr.set_port(('8' << 8) + '8'); // 88
	peerID.addr.set_addr4('aaaa'); // aaaa
	dhtTestObj->Update(peerID, 0, false);
	Buffer peerIDBuffer;
	peerIDBuffer.len = 20;
	peerIDBuffer.b = (byte*)&peerID.id.id[0];

	DhtID target;
	target.id[0] = 'FFFF'; // FFFF
	target.id[1] = 'GGGG'; // GGGG
	target.id[2] = 'HHHH'; // HHHH
	target.id[3] = 'IIII'; // IIII
	target.id[4] = 'JJJJ'; // JJJJ

	// make sure the callback dummy is clear
	ScrapeCallbackDummy::Reset();

	EXPECT_EQ(1, dhtTestObj->GetNumPeers());
	EXPECT_EQ(0, dhtTestObj->GetNumPeersTracked());

	// *****************************************************
	// make the dht emit a scrape message (the get_peers rpc)
	// *****************************************************
	EXPECT_FALSE(dhtTestObj->IsBusy()) << "The dht should not be busy yet";
	dhtTestObj->DoScrape(target, &ScrapeCallbackDummy::Callback, NULL);
	EXPECT_TRUE(dhtTestObj->IsBusy()) << "The dht should be busy";

	// *****************************************************
	// grab from the socket the emitted message and turn it
	// into a bencentity.  Feed it back to the dht as an
	// ICMP message
	// *****************************************************
	std::string doAnnounceOutput = socket4.GetSentDataAsString();
	BencEntity bEntityAnounceQuery;
	// verify the bencoded string that went out the socket
	BencEntity::Parse((const byte *)doAnnounceOutput.c_str(), bEntityAnounceQuery, (const byte *)(doAnnounceOutput.c_str() + doAnnounceOutput.length()));

	// get the transaction ID to use later
	BencodedDict *dictForAnnounce = BencodedDict::AsDict(&bEntityAnounceQuery);
	Buffer tid;
	tid.b = (byte*)dictForAnnounce->GetString("t" ,&tid.len);

	socket4.Reset();
	EXPECT_TRUE(dhtTestObj->ParseIncomingICMP(bEntityAnounceQuery, peerID.addr));

	// *****************************************************
	// verify that no message emitted by the dht
	// *****************************************************
	std::string emptyString = socket4.GetSentDataAsString();
	EXPECT_EQ(0, emptyString.size()) << "A response message was sent for a scrape reply when no response message was expected.";

	// *****************************************************
	// verify the callback event
	// *****************************************************
	EXPECT_FALSE(memcmp("FFFFGGGGHHHHIIIIJJJJ", ScrapeCallbackDummy::infoHash, 20));
	EXPECT_EQ(0, ScrapeCallbackDummy::numDownloaders) << "(NOTE if the estimate_count() algorithm changes for Bloom Filters, this value may change.";
	EXPECT_EQ(0, ScrapeCallbackDummy::numSeeds) << "(NOTE if the estimate_count() algorithm changes for Bloom Filters, this value may change.";
	EXPECT_EQ(0, dhtTestObj->GetNumPeers());
	EXPECT_EQ(0, dhtTestObj->GetNumPeersTracked());
}



class ResolveNameCallbackDummy
{
public:
	static byte infoHash[20];
	static std::string name;
	static void Clear();
	static void Callback(void *ctx, const byte *info_hash, const byte *file_name);
};

byte ResolveNameCallbackDummy::infoHash[20];
std::string ResolveNameCallbackDummy::name;
void ResolveNameCallbackDummy::Callback(void *ctx, const byte *info_hash, const byte *filename)
{
	for(unsigned int x=0; x<20; ++x)
		infoHash[x] = info_hash[x];
	name = (const char*)filename;
}

void ResolveNameCallbackDummy::Clear()
{
	for(unsigned int x=0; x<20; ++x)
		infoHash[x] = 0;
	name.clear();
}

/**
          Test                    |                  DHT
----------------------------------|--------------------------------------------
1) invoke ResolveName()           |
                                  | Responds by emitting a 'get_peers' query
								  |
2) Fabricate and "send" a         |
   response to get_peers that     |
   has the 'n' argument in the    |
   dictionary set to a file name  |
                                  | no output response expected from dht
								  |
*/
TEST(TestDhtImplResponse, TestResolveName)
{
	UnitTestUDPSocket socket4;
	UnitTestUDPSocket socket6;
	BencodedDict bDictGetPeer;
	SockAddr sAddr(0x7a7a7a7a,0x7878); // ip = zzzz and socket = xx
	socket4.SetBindAddr(sAddr);
	smart_ptr<DhtImpl> dhtTestObj(new DhtImpl(&socket4, &socket6));
	dhtTestObj->SetSHACallback(&sha1_callback);

	// prepare the object for use
	dhtTestObj->Enable(true,0);
	SetDHT_my_id_Bytes(dhtTestObj);

	// put a peer into the dht for it to work with
	DhtPeerID peerID;
	peerID.id.id[0] = '1111'; // 1111
	peerID.id.id[1] = 'BBBB'; // BBBB
	peerID.id.id[2] = 'CCCC'; // CCCC
	peerID.id.id[3] = 'DDDD'; // DDDD
	peerID.id.id[4] = '0000'; // 0000
	peerID.addr.set_port(('8' << 8) + '8'); // 88
	peerID.addr.set_addr4('aaaa'); // aaaa
	dhtTestObj->Update(peerID, 0, false);
	Buffer peerIDBuffer;
	peerIDBuffer.len = 20;
	peerIDBuffer.b = (byte*)&peerID.id.id[0];

	DhtID target;
	target.id[0] = 'FFFF'; // FFFF
	target.id[1] = 'GGGG'; // GGGG
	target.id[2] = 'HHHH'; // HHHH
	target.id[3] = 'IIII'; // IIII
	target.id[4] = 'JJJJ'; // JJJJ

	// make sure the callback dummy is clear
	AddNodesCallbackDummy::Reset();

	EXPECT_EQ(1, dhtTestObj->GetNumPeers());
	EXPECT_EQ(0, dhtTestObj->GetNumPeersTracked());

	DhtPeerID *ids[16];
	uint num = dhtTestObj->FindNodes(target, ids, 8, 8, 0); // Find 8 good ones and 8 bad ones
	EXPECT_EQ(1, num) << "Num Nodes: " << num;

	// *****************************************************
	// make the dht emit an announce message (the get_peers rpc)
	// *****************************************************
	EXPECT_FALSE(dhtTestObj->IsBusy()) << "The dht should not be busy yet";
	ResolveNameCallbackDummy::Clear();
	dhtTestObj->ResolveName(target, &ResolveNameCallbackDummy::Callback, NULL);
	EXPECT_TRUE(dhtTestObj->IsBusy()) << "The dht should be busy";

	// *****************************************************
	// grab from the socket the emitted message and extract
	// the transaction ID and verify the remainder of the
	// message
	// *****************************************************
	std::string resolveNameOutput = socket4.GetSentDataAsString();
	BencEntity bEntityAnounceQuery;
	// verify the bencoded string that went out the socket
	BencEntity::Parse((const byte *)resolveNameOutput.c_str(), bEntityAnounceQuery, (const byte *)(resolveNameOutput.c_str() + resolveNameOutput.length()));

	// get the query dictionary
	BencodedDict *dictForAnnounce = BencodedDict::AsDict(&bEntityAnounceQuery);
	EXPECT_TRUE(dictForAnnounce);
	if (!dictForAnnounce) {
		FAIL() << "ERROR:  The dht did not emit a bencoded dictionary for announce";
	}

	Buffer type;
	type.b = (byte*)dictForAnnounce->GetString("y" ,&type.len);
	ASSERT_EQ(1, type.len) << "ERROR: the 'y' type length is wrong (should be 1 for 'q', 'r', or 'e')";
	ASSERT_EQ('q', type.b[0]) << "ERROR: 'y' type is wrong; should be 'q' for query instead of:  " << type.b[0];

	Buffer command;
	command.b = (byte*)dictForAnnounce->GetString("q" ,&command.len);
	EXPECT_EQ(9, command.len);
	EXPECT_FALSE(memcmp("get_peers", command.b, 9)) << "ERROR: 'q' command is wrong; should be 'get_peers'";

	// get the transaction ID to use later
	Buffer tid;
	tid.b = (byte*)dictForAnnounce->GetString("t" ,&tid.len);
	EXPECT_EQ(4, tid.len) << "transaction ID is wrong size";

	// now look into the query data
	BencodedDict *announceQuery = dictForAnnounce->GetDict("a");
	if (!announceQuery) {
		FAIL() << "ERROR:  Failed to extract 'a' dictionary from get_peer response";
	}

	Buffer id;
	id.b = (byte*)announceQuery->GetString("id" ,&id.len);
	EXPECT_EQ(20, id.len);
	EXPECT_FALSE(memcmp("AAAABBBBCCCCDDDDEEEE", id.b, 20)) << "ERROR: announced id is wrong";

	Buffer infoHash;
	infoHash.b = (byte*)announceQuery->GetString("info_hash" ,&infoHash.len);
	EXPECT_EQ(20, infoHash.len);
	EXPECT_FALSE(memcmp("FFFFGGGGHHHHIIIIJJJJ", infoHash.b, 20)) << "ERROR: info_hash is not the correct target";

	// *****************************************************
	// now fabricate a nodes response message using the
	// transaction ID extracted above and include a token
	// that the dht should return to us.  Provide the compact IP
	// of a peer for the dht to use in the 'announce_peer'
	// message it should emit next
	// *****************************************************
	std::vector<byte>	messageBytes;
	std::vector<byte>	replyDictionaryBytes;

	std::string responseToken("20_byte_reply_token.");
	std::string compactIP("aaaa88");
	std::string filename("test_filename.txt");

	// construct the message bytes
	BencStartDictionary(replyDictionaryBytes);
	{
		BencAddNameValuePair(replyDictionaryBytes,"id",peerIDBuffer);
		BencAddNameValuePair(replyDictionaryBytes,"n", filename);
		BencAddNameValuePair(replyDictionaryBytes,"token",responseToken);
	}
	BencEndDictionary(replyDictionaryBytes);

	BencStartDictionary(messageBytes);
	{
		BencAddNameAndBencodedDictionary(messageBytes,"r",replyDictionaryBytes);
		BencAddNameValuePair(messageBytes,"t",tid);
		BencAddNameValuePair(messageBytes,"y","r");
	}
	BencEndDictionary(messageBytes);

	// clear the socket and "send" the reply and capture the announce_peer emitted by the dht
	socket4.Reset();
	dhtTestObj->ProcessIncoming((byte*)&messageBytes.front(), messageBytes.size(), peerID.addr);
	std::string announceString = socket4.GetSentDataAsString();

	// *****************************************************
	// verify the announce_peer message emitted by the dht empty
	// *****************************************************
	EXPECT_TRUE(announceString == "") << "Nothing should have been sent out.  The response with a filename should terminate this process.";

	// *****************************************************
	// verify the callback was set with the file name
	// *****************************************************
	EXPECT_TRUE(ResolveNameCallbackDummy::name == filename) << "ERROR:  received:  " << ResolveNameCallbackDummy::name << "\nInstead of:  " << filename;
	EXPECT_FALSE(memcmp("FFFFGGGGHHHHIIIIJJJJ", ResolveNameCallbackDummy::infoHash, 20)) << "the target did not match";

	EXPECT_EQ(1, dhtTestObj->GetNumPeers());
	EXPECT_EQ(0, dhtTestObj->GetNumPeersTracked());
	num = dhtTestObj->FindNodes(target, ids, 8, 8, 0); // Find 8 good ones and 8 bad ones
	EXPECT_EQ(1, num) << "Num Nodes: " << num;
	EXPECT_FALSE(dhtTestObj->IsBusy()) << "The dht should no longer be busy";
}

/**
          Test                    |                  DHT
----------------------------------|--------------------------------------------
1) invoke ResolveName()           |
                                  | Responds by emitting a 'get_peers' query
								  |
2) Fabricate and "send" a         |
   response to get_peers that     |
   has no 'n' argument            |
                                  | no output response expected from dht
								  |
*/
TEST(TestDhtImplResponse, TestResolveName_NoNameInReply)
{
	UnitTestUDPSocket socket4;
	UnitTestUDPSocket socket6;
	BencodedDict bDictGetPeer;
	SockAddr sAddr(0x7a7a7a7a,0x7878); // ip = zzzz and socket = xx
	socket4.SetBindAddr(sAddr);
	smart_ptr<DhtImpl> dhtTestObj(new DhtImpl(&socket4, &socket6));
	dhtTestObj->SetSHACallback(&sha1_callback);

	// prepare the object for use
	dhtTestObj->Enable(true,0);
	SetDHT_my_id_Bytes(dhtTestObj);

	// put a peer into the dht for it to work with
	DhtPeerID peerID;
	peerID.id.id[0] = '1111'; // 1111
	peerID.id.id[1] = 'BBBB'; // BBBB
	peerID.id.id[2] = 'CCCC'; // CCCC
	peerID.id.id[3] = 'DDDD'; // DDDD
	peerID.id.id[4] = '0000'; // 0000
	peerID.addr.set_port(('8' << 8) + '8'); // 88
	peerID.addr.set_addr4('aaaa'); // aaaa
	dhtTestObj->Update(peerID, 0, false);
	Buffer peerIDBuffer;
	peerIDBuffer.len = 20;
	peerIDBuffer.b = (byte*)&peerID.id.id[0];

	DhtID target;
	target.id[0] = 'FFFF'; // FFFF
	target.id[1] = 'GGGG'; // GGGG
	target.id[2] = 'HHHH'; // HHHH
	target.id[3] = 'IIII'; // IIII
	target.id[4] = 'JJJJ'; // JJJJ

	// make sure the callback dummy is clear
	AddNodesCallbackDummy::Reset();

	EXPECT_EQ(1, dhtTestObj->GetNumPeers());
	EXPECT_EQ(0, dhtTestObj->GetNumPeersTracked());

	DhtPeerID *ids[16];
	uint num = dhtTestObj->FindNodes(target, ids, 8, 8, 0); // Find 8 good ones and 8 bad ones
	EXPECT_EQ(1, num) << "Num Nodes: " << num;

	// *****************************************************
	// make the dht emit an announce message (the get_peers rpc)
	// *****************************************************
	EXPECT_FALSE(dhtTestObj->IsBusy()) << "The dht should not be busy yet";
	ResolveNameCallbackDummy::Clear();
	dhtTestObj->ResolveName(target, &ResolveNameCallbackDummy::Callback, NULL);
	EXPECT_TRUE(dhtTestObj->IsBusy()) << "The dht should be busy";

	// *****************************************************
	// grab from the socket the emitted message and extract
	// the transaction ID and verify the remainder of the
	// message
	// *****************************************************
	std::string resolveNameOutput = socket4.GetSentDataAsString();
	BencEntity bEntityAnounceQuery;
	// verify the bencoded string that went out the socket
	BencEntity::Parse((const byte *)resolveNameOutput.c_str(), bEntityAnounceQuery, (const byte *)(resolveNameOutput.c_str() + resolveNameOutput.length()));

	// get the query dictionary
	BencodedDict *dictForAnnounce = BencodedDict::AsDict(&bEntityAnounceQuery);
	EXPECT_TRUE(dictForAnnounce);
	if (!dictForAnnounce) {
		FAIL() << "ERROR:  The dht did not emit a bencoded dictionary for announce";
	}

	Buffer type;
	type.b = (byte*)dictForAnnounce->GetString("y" ,&type.len);
	ASSERT_EQ(1, type.len) << "ERROR: the 'y' type length is wrong (should be 1 for 'q', 'r', or 'e')";
	ASSERT_EQ('q', type.b[0]) << "ERROR: 'y' type is wrong; should be 'q' for query instead of:  " << type.b[0];

	Buffer command;
	command.b = (byte*)dictForAnnounce->GetString("q" ,&command.len);
	EXPECT_EQ(9, command.len);
	EXPECT_FALSE(memcmp("get_peers", command.b, 9)) << "ERROR: 'q' command is wrong; should be 'get_peers'";

	// get the transaction ID to use later
	Buffer tid;
	tid.b = (byte*)dictForAnnounce->GetString("t" ,&tid.len);
	EXPECT_EQ(4, tid.len) << "transaction ID is wrong size";

	// now look into the query data
	BencodedDict *announceQuery = dictForAnnounce->GetDict("a");
	if (!announceQuery) {
		FAIL() << "ERROR:  Failed to extract 'a' dictionary from get_peer response";
	}

	Buffer id;
	id.b = (byte*)announceQuery->GetString("id" ,&id.len);
	EXPECT_EQ(20, id.len);
	EXPECT_FALSE(memcmp("AAAABBBBCCCCDDDDEEEE", id.b, 20)) << "ERROR: announced id is wrong";

	Buffer infoHash;
	infoHash.b = (byte*)announceQuery->GetString("info_hash" ,&infoHash.len);
	EXPECT_EQ(20, infoHash.len);
	EXPECT_FALSE(memcmp("FFFFGGGGHHHHIIIIJJJJ", infoHash.b, 20)) << "ERROR: info_hash is not the correct target";

	// *****************************************************
	// now fabricate a nodes response message using the
	// transaction ID extracted above and include a token
	// that the dht should return to us.  Provide the compact IP
	// of a peer for the dht to use in the 'announce_peer'
	// message it should emit next
	// *****************************************************
	std::vector<byte>	messageBytes;
	std::vector<byte>	replyDictionaryBytes;

	std::string responseToken("20_byte_reply_token.");
	std::string compactIP("aaaa88");

	// construct the message bytes
	BencStartDictionary(replyDictionaryBytes);
	{
		BencAddNameValuePair(replyDictionaryBytes,"id",peerIDBuffer);
		BencAddNameValuePair(replyDictionaryBytes,"token",responseToken);
	}
	BencEndDictionary(replyDictionaryBytes);

	BencStartDictionary(messageBytes);
	{
		BencAddNameAndBencodedDictionary(messageBytes,"r",replyDictionaryBytes);
		BencAddNameValuePair(messageBytes,"t",tid);
		BencAddNameValuePair(messageBytes,"y","r");
	}
	BencEndDictionary(messageBytes);

	// clear the socket and "send" the reply and capture the announce_peer emitted by the dht
	socket4.Reset();
	dhtTestObj->ProcessIncoming((byte*)&messageBytes.front(), messageBytes.size(), peerID.addr);
	std::string announceString = socket4.GetSentDataAsString();

	// *****************************************************
	// verify the announce_peer message emitted by the dht empty
	// *****************************************************
	EXPECT_TRUE(announceString == "") << "Nothing should have been sent out.  The response with a filename should terminate this process.";

	// *****************************************************
	// verify the callback was set with the file name
	// *****************************************************
	EXPECT_TRUE(ResolveNameCallbackDummy::name == "") << "ERROR:  received:  " << ResolveNameCallbackDummy::name << "\nInstead of:  \"\"";
	EXPECT_FALSE(memcmp("\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", ResolveNameCallbackDummy::infoHash, 20)) << "the target did not match";

	EXPECT_EQ(1, dhtTestObj->GetNumPeers());
	EXPECT_EQ(0, dhtTestObj->GetNumPeersTracked());
	num = dhtTestObj->FindNodes(target, ids, 8, 8, 0); // Find 8 good ones and 8 bad ones
	EXPECT_EQ(1, num) << "Num Nodes: " << num;
	EXPECT_FALSE(dhtTestObj->IsBusy()) << "The dht should no longer be busy";
}


/**
          Test                    |                  DHT
----------------------------------|--------------------------------------------
1) invoke ResolveName()           |
                                  | Responds by emitting a 'get_peers' query
								  |
2) Capture the outputted bencoded |
   string and feed it back to the |
   DHT via ParseIncommingICMP     |
                                  | no output response expected from dht
								  |
*/
TEST(TestDhtImplResponse, TestResolveName_ReplyWith_ICMP)
{
	UnitTestUDPSocket socket4;
	UnitTestUDPSocket socket6;
	BencodedDict bDictGetPeer;
	SockAddr sAddr(0x7a7a7a7a,0x7878); // ip = zzzz and socket = xx
	socket4.SetBindAddr(sAddr);
	smart_ptr<DhtImpl> dhtTestObj(new DhtImpl(&socket4, &socket6));
	dhtTestObj->SetSHACallback(&sha1_callback);

	// prepare the object for use
	dhtTestObj->Enable(true,0);
	SetDHT_my_id_Bytes(dhtTestObj);

	// put a peer into the dht for it to work with
	DhtPeerID peerID;
	peerID.id.id[0] = '1111'; // 1111
	peerID.id.id[1] = 'BBBB'; // BBBB
	peerID.id.id[2] = 'CCCC'; // CCCC
	peerID.id.id[3] = 'DDDD'; // DDDD
	peerID.id.id[4] = '0000'; // 0000
	peerID.addr.set_port(('8' << 8) + '8'); // 88
	peerID.addr.set_addr4('aaaa'); // aaaa
	dhtTestObj->Update(peerID, 0, false);
	Buffer peerIDBuffer;
	peerIDBuffer.len = 20;
	peerIDBuffer.b = (byte*)&peerID.id.id[0];

	DhtID target;
	target.id[0] = 'FFFF'; // FFFF
	target.id[1] = 'GGGG'; // GGGG
	target.id[2] = 'HHHH'; // HHHH
	target.id[3] = 'IIII'; // IIII
	target.id[4] = 'JJJJ'; // JJJJ

	// make sure the callback dummy is clear
	AddNodesCallbackDummy::Reset();

	EXPECT_EQ(1, dhtTestObj->GetNumPeers());
	EXPECT_EQ(0, dhtTestObj->GetNumPeersTracked());

	DhtPeerID *ids[16];
	uint num = dhtTestObj->FindNodes(target, ids, 8, 8, 0); // Find 8 good ones and 8 bad ones
	EXPECT_EQ(1, num) << "Num Nodes: " << num;

	// *****************************************************
	// make the dht emit an announce message (the get_peers rpc)
	// *****************************************************
	EXPECT_FALSE(dhtTestObj->IsBusy()) << "The dht should not be busy yet";
	ResolveNameCallbackDummy::Clear();
	dhtTestObj->ResolveName(target, &ResolveNameCallbackDummy::Callback, NULL);
	EXPECT_TRUE(dhtTestObj->IsBusy()) << "The dht should be busy";

	// *****************************************************
	// grab from the socket the emitted message and turn it
	// into a bencentity.  Feed it back to the dht as an
	// ICMP message
	// *****************************************************
	std::string doAnnounceOutput = socket4.GetSentDataAsString();
	BencEntity bEntityAnounceQuery;
	// verify the bencoded string that went out the socket
	BencEntity::Parse((const byte *)doAnnounceOutput.c_str(), bEntityAnounceQuery, (const byte *)(doAnnounceOutput.c_str() + doAnnounceOutput.length()));

	// get the transaction ID to use later
	BencodedDict *dictForAnnounce = BencodedDict::AsDict(&bEntityAnounceQuery);
	Buffer tid;
	tid.b = (byte*)dictForAnnounce->GetString("t" ,&tid.len);

	socket4.Reset();
	EXPECT_TRUE(dhtTestObj->ParseIncomingICMP(bEntityAnounceQuery, peerID.addr));

	std::string announceString = socket4.GetSentDataAsString();

	// *****************************************************
	// verify the announce_peer message emitted by the dht empty
	// *****************************************************
	EXPECT_TRUE(announceString == "") << "Nothing should have been sent out.  The response with a filename should terminate this process.";

	// *****************************************************
	// verify the callback was set with the file name
	// *****************************************************
	EXPECT_TRUE(ResolveNameCallbackDummy::name == "") << "ERROR:  received:  " << ResolveNameCallbackDummy::name << "\nInstead of:  \"\"";
	EXPECT_FALSE(memcmp("\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", ResolveNameCallbackDummy::infoHash, 20)) << "the target did not match";

	EXPECT_EQ(0, dhtTestObj->GetNumPeers());
	EXPECT_EQ(0, dhtTestObj->GetNumPeersTracked());
	num = dhtTestObj->FindNodes(target, ids, 8, 8, 0); // Find 8 good ones and 8 bad ones
	EXPECT_EQ(0, num) << "Num Nodes: " << num;
	EXPECT_FALSE(dhtTestObj->IsBusy()) << "The dht should no longer be busy";
}

DhtID random_id()
{
	byte bytes[20];
	for (int i = 0; i < 20; ++i) bytes[i] = rand();
	DhtID id;
	bool ok = CopyBytesToDhtID(id, bytes);
	EXPECT_TRUE(ok) << "copying of dht ID failed";
	return id;
}

SockAddr random_address()
{
	SockAddr ret;
	memset(ret._in._in6, 0, 16);
	for (int i  = 12; i < 16; ++i)
		ret._in._in6[i] = rand();
	ret.set_port((rand() % 1000) + 1024);
	return ret;
}

TEST(TestRoutingTable, TestRoutingTable)
{
	UnitTestUDPSocket socket4;
	UnitTestUDPSocket socket6;
	smart_ptr<DhtImpl> dhtTestObj(new DhtImpl(&socket4, &socket6));
	dhtTestObj->SetSHACallback(&sha1_callback);

	// prepare the object for use
	dhtTestObj->Enable(true,0);
	DhtID my_id = random_id();
	dhtTestObj->SetId(my_id);

	// insert 128 random IDs uniformly distributed
	// all RTTs are 500, later we'll test to make sure we can replace
	// them with lower RTT nodes

	for (int i = 0; i < 256; ++i) {
		DhtID id = random_id();
		id.id[0] = (uint(i) << 24) | 0xffffff;

		DhtPeerID p;
		p.id = id;
		p.addr = random_address();
		DhtPeer* k = dhtTestObj->Update(p, IDht::DHT_ORIGIN_INCOMING, true, 500);
		EXPECT_TRUE(k) << "a DHT node failed to be inserted";
	}

	EXPECT_EQ(256, dhtTestObj->GetNumPeers()) << "the number of nodes is not the number we inserted";
	EXPECT_EQ(32, dhtTestObj->NumBuckets()) << "the number buckets is supposed to be 32 still";

	// now, split the bucket
	DhtID id = random_id();
	// copy just the 8 most significant bits from our ID
	uint mask = 0xffffffff >> 8;
	id.id[0] &= mask;
	id.id[0] |= my_id.id[0] & ~mask;
	DhtPeerID p;
	p.id = id;
	p.addr = random_address();
	dhtTestObj->Update(p, IDht::DHT_ORIGIN_INCOMING, true, 500);

	EXPECT_EQ(33, dhtTestObj->NumBuckets()) << "the number buckets is supposed to be 33";

	// TODO: somehow assert that there are 14 nodes in bucket 1 and 128 nodes in bucket 0
}

TEST(TestDhtRestart, TestDhtRestart)
{
	UnitTestUDPSocket socket4;
	UnitTestUDPSocket socket6;
	smart_ptr<DhtImpl> dhtTestObj(new DhtImpl(&socket4, &socket6));
	dhtTestObj->SetSHACallback(&sha1_callback);

	// prepare the object for use
	dhtTestObj->Enable(true,0);
	DhtID my_id = random_id();
	dhtTestObj->SetId(my_id);

	// insert some nodes
	for (int i = 0; i < 10; ++i) {
		DhtPeerID p;
		p.id = random_id();
		p.addr = random_address();
		DhtPeer* k = dhtTestObj->Update(p, IDht::DHT_ORIGIN_INCOMING, true, 500);
		EXPECT_TRUE(k) << "a DHT node failed to be inserted";
	}

	dhtTestObj->Restart();
}

//*****************************************************************************
//
//
// DHT Process Speed Tests
//
//
//*****************************************************************************

TEST(DhtProcessSpeedTest, Announce_ReplyWithNodes)
{
	UnitTestUDPSocket socket4;
	UnitTestUDPSocket socket6;
	BencodedDict bDictGetPeer;
	SockAddr sAddr(0x7a7a7a7a,0x7878); // ip = zzzz and socket = xx
	socket4.SetBindAddr(sAddr);
	smart_ptr<DhtImpl> dhtTestObj(new DhtImpl(&socket4, &socket6));
	dhtTestObj->SetSHACallback(&sha1_callback);

	// prepare the object for use
	dhtTestObj->Enable(true,0);
	SetDHT_my_id_Bytes(dhtTestObj);

	// put a peer into the dht for it to work with
	DhtPeerID peerID;
	peerID.id.id[0] = '1111'; // 1111
	peerID.id.id[1] = 'BBBB'; // BBBB
	peerID.id.id[2] = 'CCCC'; // CCCC
	peerID.id.id[3] = 'DDDD'; // DDDD
	peerID.id.id[4] = '0000'; // 0000
	peerID.addr.set_port(('8' << 8) + '8'); // 88
	peerID.addr.set_addr4('aaaa'); // aaaa
	dhtTestObj->Update(peerID, 0, false);
	Buffer peerIDBuffer;
	peerIDBuffer.len = 20;
	peerIDBuffer.b = (byte*)&peerID.id.id[0];

	DhtID target;
	target.id[0] = 'FFFF'; // FFFF
	target.id[1] = 'GGGG'; // GGGG
	target.id[2] = 'HHHH'; // HHHH
	target.id[3] = 'IIII'; // IIII
	target.id[4] = 'JJJJ'; // JJJJ

	std::string filenameTxt("filaname.txt");
	std::string responseToken("20_byte_reply_token.");
	std::string compactIP("aaaa88");
	std::vector<byte>	messageBytes;
	std::vector<byte>	replyDictionaryBytes;
	BencEntity bEntityAnounceQuery;
	std::string announceString;
	std::string doAnnounceOutput;
	Buffer command;
	Buffer tid;

	for(unsigned int x=0; x<20*speedTestFactor; ++x)
	{
		// make sure the callback dummy is clear
		AddNodesCallbackDummy::Reset();

		// *****************************************************
		// make the dht emit an announce message (the get_peers rpc)
		// *****************************************************
		dhtTestObj->DoAnnounce(target, 20, NULL, &AddNodesCallbackDummy::Callback, NULL, filenameTxt.c_str(), NULL, 0);

		// *****************************************************
		// grab from the socket the emitted message and extract
		// the transaction ID and verify the remainder of the
		// message
		// *****************************************************
		doAnnounceOutput = socket4.GetSentDataAsString();
		// verify the bencoded string that went out the socket
		BencEntity::Parse((const byte *)doAnnounceOutput.c_str(), bEntityAnounceQuery, (const byte *)(doAnnounceOutput.c_str() + doAnnounceOutput.length()));

		// get the query dictionary
		BencodedDict *dictForAnnounce = BencodedDict::AsDict(&bEntityAnounceQuery);

		command.b = (byte*)dictForAnnounce->GetString("q" ,&command.len);
		ASSERT_FALSE(memcmp("get_peers", command.b, 9)) << "ERROR: 'q' command is wrong; should be 'get_peers'";

		// get the transaction ID to use later
		tid.b = (byte*)dictForAnnounce->GetString("t" ,&tid.len);

		// *****************************************************
		// now fabricate a nodes response message using the
		// transaction ID extracted above and include a token
		// that the dht should return to us.  Provide the compact IP
		// of a peer for the dht to use in the 'announce_peer'
		// message it should emit next
		// *****************************************************
		messageBytes.clear();
		replyDictionaryBytes.clear();

		// construct the message bytes
		BencStartDictionary(replyDictionaryBytes);
		{
			BencAddNameValuePair(replyDictionaryBytes,"id",peerIDBuffer);
			BencAddNameValuePair(replyDictionaryBytes,"token",responseToken);
			BencAddString(replyDictionaryBytes,"values");
			BencStartList(replyDictionaryBytes);
			{
				BencAddString(replyDictionaryBytes, compactIP);
			}
			BencEndList(replyDictionaryBytes);
		}
		BencEndDictionary(replyDictionaryBytes);

		BencStartDictionary(messageBytes);
		{
			BencAddNameAndBencodedDictionary(messageBytes,"r",replyDictionaryBytes);
			BencAddNameValuePair(messageBytes,"t",tid);
			BencAddNameValuePair(messageBytes,"y","r");
		}
		BencEndDictionary(messageBytes);

		// clear the socket and "send" the reply and capture the announce_peer emitted by the dht
		socket4.Reset();
		dhtTestObj->ProcessIncoming((byte*)&messageBytes.front(), messageBytes.size(), peerID.addr);
		announceString = socket4.GetSentDataAsString();


		// *****************************************************
		// verify the announce_peer message emitted by the dht
		// *****************************************************
		BencEntity::Parse((const byte *)announceString.c_str(), bEntityAnounceQuery, (const byte *)(announceString.c_str() + announceString.length()));

		// get the query dictionary
		dictForAnnounce = BencodedDict::AsDict(&bEntityAnounceQuery);
		command.b = (byte*)dictForAnnounce->GetString("q" ,&command.len);
		ASSERT_FALSE(memcmp("announce_peer", command.b, 13)) << "ERROR: 'q' command is wrong; should be 'announce_peer'";

		// get the transaction ID to use later
		tid.b = (byte*)dictForAnnounce->GetString("t" ,&tid.len);

		// *****************************************************
		// create and send a response to the 'announce_peer
		// message
		// *****************************************************
		messageBytes.clear();
		replyDictionaryBytes.clear();

		// construct the message bytes
		BencStartDictionary(replyDictionaryBytes);
		{
			BencAddNameValuePair(replyDictionaryBytes,"id",peerIDBuffer);
		}
		BencEndDictionary(replyDictionaryBytes);

		BencStartDictionary(messageBytes);
		{
			BencAddNameAndBencodedDictionary(messageBytes,"r",replyDictionaryBytes);
			BencAddNameValuePair(messageBytes,"t",tid);
			BencAddNameValuePair(messageBytes,"y","r");
		}
		BencEndDictionary(messageBytes);

		// clear the socket and "send" the reply;
		socket4.Reset();
		dhtTestObj->ProcessIncoming((byte*)&messageBytes.front(), messageBytes.size(), peerID.addr);
	}
}

bool PerformDoAnnounce(smart_ptr<DhtImpl> &dht, const DhtID &target, std::string &filename, std::vector<byte> &transactionIDBytesOut, UnitTestUDPSocket &socket4)
{
	dht->DoAnnounce(target, 20, NULL, &AddNodesCallbackDummy::Callback, NULL, filename.c_str(), NULL, 0);

	// *****************************************************
	// grab from the socket the emitted message and extract
	// the transaction ID
	// *****************************************************
	std::string doAnnounceOutput = socket4.GetSentDataAsString();
	BencEntity bEntityAnounceQuery;
	// verify the bencoded string that went out the socket
	BencEntity::Parse((const byte *)doAnnounceOutput.c_str(), bEntityAnounceQuery, (const byte *)(doAnnounceOutput.c_str() + doAnnounceOutput.length()));

	// get the query dictionary
	BencodedDict *dictForAnnounce = BencodedDict::AsDict(&bEntityAnounceQuery);
	if (!dictForAnnounce) {
		return false;
	}

	// get the transaction ID to return to the user
	Buffer tid;
	tid.b = (byte*)dictForAnnounce->GetString("t" ,&tid.len);
	if(tid.len != 4)
		return false;

	transactionIDBytesOut.clear();
	for(unsigned int x=0; x<tid.len; ++x){
		transactionIDBytesOut.push_back(tid.b[x]);
	}
	return true;
}

int PerformDoAnnounce(smart_ptr<DhtImpl> &dht, const DhtID &target, std::string &filename, std::vector<std::vector<byte> > &transactionIDBytesOut, UnitTestUDPSocket &socket4)
{
	const unsigned int numOutputBytesExpectedPerPeer = 106;
	transactionIDBytesOut.clear();

	dht->DoAnnounce(target, 20, NULL, &AddNodesCallbackDummy::Callback, NULL, filename.c_str(), NULL, 0);

	// *****************************************************
	// grab from the socket the emitted message(s) and extract
	// the transaction ID
	// *****************************************************
	std::string doAnnounceOutput = socket4.GetSentDataAsString();

	// see how many strings went out.
	// expect 106 characters output for each peer in the dht's list
	// for example: "d1:ad2:id20:AAAABBBBCCCCDDDDEEEE9:info_hash20:FFFFGGGGHHHHIIII0000e1:q9:get_peers1:t4:köÇn1:v4:UTê`1:y1:qe"
	unsigned int numResponseStrings = doAnnounceOutput.size() / numOutputBytesExpectedPerPeer;

	if(numResponseStrings == 0)
		return 0; // nothing came out of the dht

	// is it even
	if(doAnnounceOutput.size() % numOutputBytesExpectedPerPeer != 0)
		return 0; // something is wrong, there are leftover bytes

	// verify the bencoded string(s) that went out the socket
	for(unsigned int x=0; x<numResponseStrings; ++x){
		BencEntity bEntityAnounceQuery;
		unsigned int offset = x*numOutputBytesExpectedPerPeer;
		BencEntity::Parse((const byte *)doAnnounceOutput.c_str() + offset, bEntityAnounceQuery, (const byte *)(doAnnounceOutput.c_str() + offset + numOutputBytesExpectedPerPeer));

		// get the query dictionary
		BencodedDict *dictForAnnounce = BencodedDict::AsDict(&bEntityAnounceQuery);
		if (!dictForAnnounce) {
			return 0;
		}

		// get the transaction ID to return to the user
		Buffer tid;
		tid.b = (byte*)dictForAnnounce->GetString("t" ,&tid.len);
		if(tid.len != 4)
			return 0;

		std::vector<byte> tidBytes;
		for(unsigned int x=0; x<tid.len; ++x){
			tidBytes.push_back(tid.b[x]);
		}
		transactionIDBytesOut.push_back(tidBytes);
	}
	return numResponseStrings;
}

bool DoGetPeersReply(smart_ptr<DhtImpl> &dhtTestObj, const DhtPeerID &peerID, const std::string &responseToken, const std::vector<std::string> &values, const std::vector<byte> &transactionID, std::vector<byte> &transactionIDBytesOut, UnitTestUDPSocket &socket4)
{
	std::vector<byte>	messageBytes;
	std::vector<byte>	replyDictionaryBytes;
	Buffer peerIDBuffer;
	peerIDBuffer.len = 20;
	peerIDBuffer.b = (byte*)&peerID.id.id[0];

	BencStartDictionary(replyDictionaryBytes);
	{
		BencAddNameValuePair(replyDictionaryBytes,"id",peerIDBuffer);
		BencAddNameValuePair(replyDictionaryBytes,"token",responseToken);
		BencAddString(replyDictionaryBytes,"values");
		BencStartList(replyDictionaryBytes);
		for(unsigned int x=0; x<values.size(); ++x)
		{
			BencAddString(replyDictionaryBytes, values[x]);
		}
		BencEndList(replyDictionaryBytes);
	}
	BencEndDictionary(replyDictionaryBytes);

	BencStartDictionary(messageBytes);
	{
		BencAddNameAndBencodedDictionary(messageBytes,"r",replyDictionaryBytes);
		BencAddNameValuePair(messageBytes,"t",transactionID);
		BencAddNameValuePair(messageBytes,"y","r");
	}
	BencEndDictionary(messageBytes);

	// "send" the reply
	socket4.Reset();
	dhtTestObj->ProcessIncoming((byte*)&messageBytes.front(), messageBytes.size(), peerID.addr);

	// *****************************************************
	// grab from the socket the emitted message and extract
	// the transaction ID
	// *****************************************************
	std::string doAnnounceOutput = socket4.GetSentDataAsString();
	BencEntity bEntityAnounceQuery;
	// verify the bencoded string that went out the socket
	BencEntity::Parse((const byte *)doAnnounceOutput.c_str(), bEntityAnounceQuery, (const byte *)(doAnnounceOutput.c_str() + doAnnounceOutput.length()));

	// get the query dictionary
	BencodedDict *dictForAnnounce = BencodedDict::AsDict(&bEntityAnounceQuery);
	if (!dictForAnnounce) {
		return false;
	}

	// get the transaction ID to return to the user
	Buffer tid;
	tid.b = (byte*)dictForAnnounce->GetString("t" ,&tid.len);
	if(tid.len != 4)
		return false;

	transactionIDBytesOut.clear();
	for(unsigned int x=0; x<tid.len; ++x){
		transactionIDBytesOut.push_back(tid.b[x]);
	}
	return true;
}

/**
 the input bencoded string should be deliniated with "d1:ad" for each set of dht
 output bytes for which a transaction id is to be extracted.
*/
bool ExtractTransactionIDs(const std::string &bstring, std::vector<std::vector<byte> > &transactionIDsOut)
{
	size_t index = 0;
	transactionIDsOut.clear();

	do{
		index = bstring.find("d1:ad", index);
		if(index == std::string::npos)
			continue;

		BencEntity bEntityAnounceQuery;
		// verify the bencoded string that went out the socket
		BencEntity::Parse((const byte *)&bstring[index], bEntityAnounceQuery, (const byte *)(&bstring[index] + bstring.length()-index));

		// get the query dictionary
		BencodedDict *dictForAnnounce = BencodedDict::AsDict(&bEntityAnounceQuery);
		if (!dictForAnnounce) {
			return false;
		}

		// get the transaction ID to return to the user
		Buffer tid;
		tid.b = (byte*)dictForAnnounce->GetString("t" ,&tid.len);
		if(tid.len != 4)
			return false;

		std::vector<byte> transactionIDBytes;
		for(unsigned int x=0; x<tid.len; ++x){
			transactionIDBytes.push_back(tid.b[x]);
		}
		transactionIDsOut.push_back(transactionIDBytes);

		index++;
	}
	while(index != std::string::npos);
	return true;
}



/**
          Test                    |                  DHT
----------------------------------|--------------------------------------------
1) invoke doAnnounce() several    |
   times                          |
                                  | Responds by emitting a 'get_peers' query
								  | for each doAnnounce()
								  |
2) Fabricate and "send" a         |
   response to get_peers that     |
   has compact IP-address/port    |
   info for a peer                |
                                  | Responds by emitting 'announce_peer' query
								  | and invoking the callback twice for each
								  | target
*/
TEST(TestDhtImplResponse, MultipleAnnounce_ReplyWithSinglePeer)
{
	UnitTestUDPSocket socket4;
	UnitTestUDPSocket socket6;
	BencodedDict bDictGetPeer;
	SockAddr sAddr(0x7a7a7a7a,0x7878); // ip = zzzz and socket = xx
	socket4.SetBindAddr(sAddr);
	smart_ptr<DhtImpl> dhtTestObj(new DhtImpl(&socket4, &socket6));
	dhtTestObj->SetSHACallback(&sha1_callback);

	// prepare the object for use
	dhtTestObj->Enable(true,0);
	SetDHT_my_id_Bytes(dhtTestObj);

	// put a peer into the dht for it to work with
	DhtPeerID peerID;
	peerID.id.id[0] = '1111'; // 1111
	peerID.id.id[1] = 'BBBB'; // BBBB
	peerID.id.id[2] = 'CCCC'; // CCCC
	peerID.id.id[3] = 'DDDD'; // DDDD
	peerID.id.id[4] = '0000'; // 0000
	peerID.addr.set_port(('8' << 8) + '8'); // 88
	peerID.addr.set_addr4('aaaa'); // aaaa
	dhtTestObj->Update(peerID, 0, false);
	Buffer peerIDBuffer;
	peerIDBuffer.len = 20;
	peerIDBuffer.b = (byte*)&peerID.id.id[0];

	const unsigned int numTargets = 5;
	std::vector<byte> transactionIDs[numTargets];
	std::string filenamesTxt[numTargets];
	DhtID targets[numTargets];

	for(unsigned int x=0; x<numTargets; ++x){
		targets[x].id[0] = 'FFFF'; // FFFF
		targets[x].id[1] = 'GGGG'; // GGGG
		targets[x].id[2] = 'HHHH'; // HHHH
		targets[x].id[3] = 'IIII'; // IIII
		targets[x].id[4] = ((((((x + 0x30)<<8) + x + 0x30)<<8) + x + 0x30)<<8) +x+0x30; //
	}

	for(unsigned int x=0; x<numTargets; ++x){
		filenamesTxt[x] = "filename_";
		std::string LastChar("0");
		LastChar[0] += (char)x;
		filenamesTxt[x] += LastChar;
	}

	// make sure the callback dummy is clear
	AddNodesCallbackDummy::Reset();

	// *****************************************************
	// make the dht emit an announce message (the get_peers rpc)
	// and capture the transaction ID
	// *****************************************************

	for(unsigned int x=0; x<numTargets; ++x){
		socket4.Reset();
		ASSERT_TRUE(PerformDoAnnounce(dhtTestObj, targets[x], filenamesTxt[x], transactionIDs[x], socket4)) << "DoAnnounce failed on iteration:  " << x;
	}

	// *****************************************************
	// now fabricate a nodes response message using the
	// transaction ID extracted above and include a token
	// that the dht should return to us.  Provide the compact IP
	// of a peer for the dht to use in the 'announce_peer'
	// message it should emit next
	// *****************************************************
	std::vector<byte>	messageBytes;
	std::vector<byte>	replyDictionaryBytes;

	// make the response tokens
	std::string responseTokens[numTargets];
	for(unsigned int x=0; x<numTargets; ++x){
		responseTokens[x] = "20_byte_reply_token";
		std::string LastChar("0");
		LastChar[0] += (char)x;
		responseTokens[x] += LastChar;
	}

	// make a list of compact IPs (in this case only one ip)
	std::string compactIP("aaaa88");
	std::vector<std::string> values;
	values.push_back(compactIP);

	for(unsigned int x=0; x<numTargets; ++x){

		ASSERT_TRUE(DoGetPeersReply(dhtTestObj, peerID, responseTokens[x], values, transactionIDs[x], transactionIDs[x], socket4)) << "Reply to 'get_peers' failed on iteration:  " << x;

		EXPECT_TRUE(dhtTestObj->IsBusy()) << "The dht should still be busy";

		// *****************************************************
		// verify the announce_peer message emitted by the dht
		// *****************************************************
		std::string announceString = socket4.GetSentDataAsString();
		BencEntity bEntityAnounceQuery;
		BencEntity::Parse((const byte *)announceString.c_str(), bEntityAnounceQuery, (const byte *)(announceString.c_str() + announceString.length()));

		// get the query dictionary
		BencodedDict* dictForAnnounce;
		dictForAnnounce = BencodedDict::AsDict(&bEntityAnounceQuery);
		EXPECT_TRUE(dictForAnnounce);
		if (!dictForAnnounce) {
			FAIL() << "ERROR:  The dht did not emit a bencoded dictionary for announce";
		}

		Buffer type;
		type.b = (byte*)dictForAnnounce->GetString("y" ,&type.len);
		ASSERT_EQ(1, type.len) << "ERROR: the 'y' type length is wrong (should be 1 for 'q', 'r', or 'e')";
		ASSERT_EQ('q', type.b[0]) << "ERROR: 'y' type is wrong; should be 'q' for query instead of:  " << type.b[0];

		Buffer command;
		command.b = (byte*)dictForAnnounce->GetString("q" ,&command.len);
		EXPECT_EQ(13, command.len);
		EXPECT_FALSE(memcmp("announce_peer", command.b, 13)) << "ERROR: 'q' command is wrong; should be 'announce_peer'";

		// get the transaction ID to use later
		Buffer tid;
		tid.b = (byte*)dictForAnnounce->GetString("t" ,&tid.len);
		EXPECT_EQ(4, tid.len) << "transaction ID is wrong size";

		// now look into the query data
		BencodedDict* announceQuery;
		announceQuery = dictForAnnounce->GetDict("a");
		if (!announceQuery) {
			FAIL() << "ERROR:  Failed to extract 'a' dictionary from get_peer response";
		}

		Buffer id;
		id.b = (byte*)announceQuery->GetString("id" ,&id.len);
		EXPECT_EQ(20, id.len);
		EXPECT_FALSE(memcmp("AAAABBBBCCCCDDDDEEEE", id.b, 20)) << "ERROR: announced id is wrong";

		Buffer infoHash;
		infoHash.b = (byte*)announceQuery->GetString("info_hash" ,&infoHash.len);
		EXPECT_EQ(20, infoHash.len);
		EXPECT_FALSE(memcmp(&(targets[x].id[0]), infoHash.b, 20)) << "ERROR: info_hash is not the correct target";

		Buffer name;
		name.b = (byte*)announceQuery->GetString("name" ,&name.len);
		EXPECT_EQ(filenamesTxt[x].size(), name.len);
		EXPECT_FALSE(strcmp(filenamesTxt[x].c_str(), (char*)name.b));

		int port;
		port = announceQuery->GetInt("port");
		EXPECT_EQ(0x7878, port) << "Expected 0x7878 ('XX) for port; actual value = " << port;

		Buffer token;
		token.b = (byte*)announceQuery->GetString("token" ,&token.len);
		EXPECT_EQ(20, token.len);
		EXPECT_FALSE(strcmp(responseTokens[x].c_str(), (char*)token.b));
	}


	// *****************************************************
	// create and send a response to the 'announce_peer
	// message
	// *****************************************************
	for(unsigned int x=0; x<numTargets; ++x){
		messageBytes.clear();
		replyDictionaryBytes.clear();

		// construct the message bytes
		BencStartDictionary(replyDictionaryBytes);
		{
			BencAddNameValuePair(replyDictionaryBytes,"id",peerIDBuffer);
		}
		BencEndDictionary(replyDictionaryBytes);

		BencStartDictionary(messageBytes);
		{
			BencAddNameAndBencodedDictionary(messageBytes,"r",replyDictionaryBytes);
			BencAddNameValuePair(messageBytes,"t",transactionIDs[x]);
			BencAddNameValuePair(messageBytes,"y","r");
		}
		BencEndDictionary(messageBytes);

		// clear the socket and "send" the reply;
		socket4.Reset();
		dhtTestObj->ProcessIncoming((byte*)&messageBytes.front(), messageBytes.size(), peerID.addr);

		// check that nothing went out the socket.
		EXPECT_EQ(0, socket4.GetSentByteVector().size()) << "Nothing should be sent out the socket in response to the reply to the dht's 'announce_peer' query";
	}

	// *****************************************************
	// look in the addnodes call back dummy to see what was
	// passed through
	// *****************************************************
	ASSERT_EQ(2*numTargets, AddNodesCallbackDummy::callbackData.size()) << "Expected " << 2*numTargets << " callback events";

	for(unsigned int x=0; x<numTargets; ++x){
		// verify the first callback events
		EXPECT_FALSE(memcmp(&(targets[x].id[0]), AddNodesCallbackDummy::callbackData[x].infoHash, 20)) << "first callback, iteration:  " << x;
		EXPECT_EQ(1, AddNodesCallbackDummy::callbackData[x].numPeers) << "first callback, iteration:  " << x;
		EXPECT_FALSE(memcmp(compactIP.c_str(), &AddNodesCallbackDummy::callbackData[x].compactPeerAddressBytes[0], compactIP.size())) << "first callback, iteration:  " << x;

		// verify the second callback event
		EXPECT_FALSE(memcmp(&(targets[x].id[0]), AddNodesCallbackDummy::callbackData[x+numTargets].infoHash, 20)) << "second callback, iteration:  " << x;
		EXPECT_EQ(0, AddNodesCallbackDummy::callbackData[x+numTargets].numPeers) << "second callback, iteration:  " << x;
	}
	EXPECT_FALSE(dhtTestObj->IsBusy()) << "The dht should no longer be busy";
}

/**
          Test                    |                  DHT
----------------------------------|--------------------------------------------
1) invoke doAnnounce() once       |
                                  | Responds by emitting a 'get_peers' query
								  | for each doAnnounce()
								  |
2) Fabricate and "send" a         |
   response to get_peers that     |
   has compact IP-address/port    |
   info for multiple peers       |
                                  | Responds by emitting 'announce_peer' query
								  | and invoking the callback with all of the
								  | compact node info.
*/
TEST(TestDhtImplResponse, SingleAnnounce_ReplyWithMultiplePeers)
{
	UnitTestUDPSocket socket4;
	UnitTestUDPSocket socket6;
	BencodedDict bDictGetPeer;
	SockAddr sAddr(0x7a7a7a7a,0x7878); // ip = zzzz and socket = xx
	socket4.SetBindAddr(sAddr);
	smart_ptr<DhtImpl> dhtTestObj(new DhtImpl(&socket4, &socket6));
	dhtTestObj->SetSHACallback(&sha1_callback);

	// prepare the object for use
	dhtTestObj->Enable(true,0);
	SetDHT_my_id_Bytes(dhtTestObj);

	// put a peer into the dht for it to work with
	DhtPeerID peerID;
	peerID.id.id[0] = '1111'; // 1111
	peerID.id.id[1] = 'BBBB'; // BBBB
	peerID.id.id[2] = 'CCCC'; // CCCC
	peerID.id.id[3] = 'DDDD'; // DDDD
	peerID.id.id[4] = '0000'; // 0000
	peerID.addr.set_port(('8' << 8) + '8'); // 88
	peerID.addr.set_addr4('aaaa'); // aaaa
	dhtTestObj->Update(peerID, 0, false);
	Buffer peerIDBuffer;
	peerIDBuffer.len = 20;
	peerIDBuffer.b = (byte*)&peerID.id.id[0];

	const unsigned int numTargets = 1;
	const unsigned int numPeers = 3;

	std::vector<byte> transactionIDs[numTargets];
	std::string filenamesTxt[numTargets];
	DhtID targets[numTargets];

	for(unsigned int x=0; x<numTargets; ++x){
		targets[x].id[0] = 'FFFF'; // FFFF
		targets[x].id[1] = 'GGGG'; // GGGG
		targets[x].id[2] = 'HHHH'; // HHHH
		targets[x].id[3] = 'IIII'; // IIII
		targets[x].id[4] = ((((((x + 0x30)<<8) + x + 0x30)<<8) + x + 0x30)<<8) +x+0x30; //
	}

	for(unsigned int x=0; x<numTargets; ++x){
		filenamesTxt[x] = "filename_";
		std::string LastChar("0");
		LastChar[0] += (char)x;
		filenamesTxt[x] += LastChar;
	}

	// make sure the callback dummy is clear
	AddNodesCallbackDummy::Reset();

	// *****************************************************
	// make the dht emit an announce message (the get_peers rpc)
	// and capture the transaction ID
	// *****************************************************

	for(unsigned int x=0; x<numTargets; ++x){
		socket4.Reset();
		ASSERT_TRUE(PerformDoAnnounce(dhtTestObj, targets[x], filenamesTxt[x], transactionIDs[x], socket4)) << "DoAnnounce failed on iteration:  " << x;
	}

	// *****************************************************
	// now fabricate a nodes response message using the
	// transaction ID extracted above and include a token
	// that the dht should return to us.  Provide the compact IP
	// of a peer for the dht to use in the 'announce_peer'
	// message it should emit next
	// *****************************************************
	std::vector<byte>	messageBytes;
	std::vector<byte>	replyDictionaryBytes;

	// make the response tokens
	std::string responseTokens[numTargets];
	for(unsigned int x=0; x<numTargets; ++x){
		responseTokens[x] = "20_byte_reply_token";
		std::string LastChar("0");
		LastChar[0] += (char)x;
		responseTokens[x] += LastChar;
	}

	// make a list of compact IPs (in this case only one ip)
	std::string compactIP("aaaa88");
	std::vector<std::string> values;

	for(unsigned int x=0; x<numPeers; ++x){
		values.push_back(compactIP);
		compactIP[0] += 1;
	}

	for(unsigned int x=0; x<numTargets; ++x){

		ASSERT_TRUE(DoGetPeersReply(dhtTestObj, peerID, responseTokens[x], values, transactionIDs[x], transactionIDs[x], socket4)) << "Reply to 'get_peers' failed on iteration:  " << x;

		EXPECT_TRUE(dhtTestObj->IsBusy()) << "The dht should still be busy";

		// *****************************************************
		// verify the announce_peer message emitted by the dht
		// *****************************************************
		std::string announceString = socket4.GetSentDataAsString();
		BencEntity bEntityAnounceQuery;
		BencEntity::Parse((const byte *)announceString.c_str(), bEntityAnounceQuery, (const byte *)(announceString.c_str() + announceString.length()));

		// get the query dictionary
		BencodedDict* dictForAnnounce;
		dictForAnnounce = BencodedDict::AsDict(&bEntityAnounceQuery);
		EXPECT_TRUE(dictForAnnounce);
		if (!dictForAnnounce) {
			FAIL() << "ERROR:  The dht did not emit a bencoded dictionary for announce";
		}

		Buffer type;
		type.b = (byte*)dictForAnnounce->GetString("y" ,&type.len);
		ASSERT_EQ(1, type.len) << "ERROR: the 'y' type length is wrong (should be 1 for 'q', 'r', or 'e')";
		ASSERT_EQ('q', type.b[0]) << "ERROR: 'y' type is wrong; should be 'q' for query instead of:  " << type.b[0];

		Buffer command;
		command.b = (byte*)dictForAnnounce->GetString("q" ,&command.len);
		EXPECT_EQ(13, command.len);
		EXPECT_FALSE(memcmp("announce_peer", command.b, 13)) << "ERROR: 'q' command is wrong; should be 'announce_peer'";

		// get the transaction ID to use later
		Buffer tid;
		tid.b = (byte*)dictForAnnounce->GetString("t" ,&tid.len);
		EXPECT_EQ(4, tid.len) << "transaction ID is wrong size";

		// now look into the query data
		BencodedDict* announceQuery;
		announceQuery = dictForAnnounce->GetDict("a");
		if (!announceQuery) {
			FAIL() << "ERROR:  Failed to extract 'a' dictionary from get_peer response";
		}

		Buffer id;
		id.b = (byte*)announceQuery->GetString("id" ,&id.len);
		EXPECT_EQ(20, id.len);
		EXPECT_FALSE(memcmp("AAAABBBBCCCCDDDDEEEE", id.b, 20)) << "ERROR: announced id is wrong";

		Buffer infoHash;
		infoHash.b = (byte*)announceQuery->GetString("info_hash" ,&infoHash.len);
		EXPECT_EQ(20, infoHash.len);
		EXPECT_FALSE(memcmp(&(targets[x].id[0]), infoHash.b, 20)) << "ERROR: info_hash is not the correct target";

		Buffer name;
		name.b = (byte*)announceQuery->GetString("name" ,&name.len);
		EXPECT_EQ(filenamesTxt[x].size(), name.len);
		EXPECT_FALSE(strcmp(filenamesTxt[x].c_str(), (char*)name.b));

		int port;
		port = announceQuery->GetInt("port");
		EXPECT_EQ(0x7878, port) << "Expected 0x7878 ('XX) for port; actual value = " << port;

		Buffer token;
		token.b = (byte*)announceQuery->GetString("token" ,&token.len);
		EXPECT_EQ(20, token.len);
		EXPECT_FALSE(strcmp(responseTokens[x].c_str(), (char*)token.b));
	}


	// *****************************************************
	// create and send a response to the 'announce_peer
	// message
	// *****************************************************
	for(unsigned int x=0; x<numTargets; ++x){
		messageBytes.clear();
		replyDictionaryBytes.clear();

		// construct the message bytes
		BencStartDictionary(replyDictionaryBytes);
		{
			BencAddNameValuePair(replyDictionaryBytes,"id",peerIDBuffer);
		}
		BencEndDictionary(replyDictionaryBytes);

		BencStartDictionary(messageBytes);
		{
			BencAddNameAndBencodedDictionary(messageBytes,"r",replyDictionaryBytes);
			BencAddNameValuePair(messageBytes,"t",transactionIDs[x]);
			BencAddNameValuePair(messageBytes,"y","r");
		}
		BencEndDictionary(messageBytes);

		// clear the socket and "send" the reply;
		socket4.Reset();
		dhtTestObj->ProcessIncoming((byte*)&messageBytes.front(), messageBytes.size(), peerID.addr);

		// check that nothing went out the socket.
		EXPECT_EQ(0, socket4.GetSentByteVector().size()) << "Nothing should be sent out the socket in response to the reply to the dht's 'announce_peer' query";
	}

	// *****************************************************
	// look in the addnodes call back dummy to see what was
	// passed through
	// *****************************************************
	ASSERT_EQ(2*numTargets, AddNodesCallbackDummy::callbackData.size()) << "Expected " << 2*numTargets << " callback events";

	for(unsigned int x=0; x<numTargets; ++x){
		// verify the first callback events
		EXPECT_FALSE(memcmp(&(targets[x].id[0]), AddNodesCallbackDummy::callbackData[x].infoHash, 20)) << "first callback, iteration:  " << x;
		EXPECT_EQ(numPeers, AddNodesCallbackDummy::callbackData[x].numPeers) << "first callback, iteration:  " << x;
		for(unsigned int y=0; y<numPeers; ++y){
			EXPECT_FALSE(memcmp(values[y].c_str(), &AddNodesCallbackDummy::callbackData[x].compactPeerAddressBytes[y*6], 6)) << "first callback, iteration:  " << x;
		}

		// verify the second callback event
		EXPECT_FALSE(memcmp(&(targets[x].id[0]), AddNodesCallbackDummy::callbackData[x+numTargets].infoHash, 20)) << "second callback, iteration:  " << x;
		EXPECT_EQ(0, AddNodesCallbackDummy::callbackData[x+numTargets].numPeers) << "second callback, iteration:  " << x;
	}
	EXPECT_FALSE(dhtTestObj->IsBusy()) << "The dht should no longer be busy";
}

/**
          Test                    |                  DHT
----------------------------------|--------------------------------------------
1) invoke doAnnounce() several    |
   times                          |
                                  | Responds by emitting a 'get_peers' query
								  | for each doAnnounce()
								  |
2) Fabricate and "send" a         |
   response to get_peers that     |
   has compact IP-address/port    |
   info for a peer                |
                                  | Responds by emitting 'announce_peer' query
								  | and invoking the callback twice for each
								  | target
*/
TEST(TestDhtImplResponse, AnnounceWithMultiplePeers_ReplyWithSinglePeer)
{
	UnitTestUDPSocket socket4;
	UnitTestUDPSocket socket6;
	BencodedDict bDictGetPeer;
	SockAddr sAddr(0x7a7a7a7a,0x7878); // ip = zzzz and socket = xx
	socket4.SetBindAddr(sAddr);
	smart_ptr<DhtImpl> dhtTestObj(new DhtImpl(&socket4, &socket6));
	dhtTestObj->SetSHACallback(&sha1_callback);

	// prepare the object for use
	dhtTestObj->Enable(true,0);
	SetDHT_my_id_Bytes(dhtTestObj);

	// put the FIRST peer into the dht for it to work with
	DhtPeerID peerID;
	peerID.id.id[0] = '1111'; // 1111
	peerID.id.id[1] = 'BBBB'; // BBBB
	peerID.id.id[2] = 'CCCC'; // CCCC
	peerID.id.id[3] = 'DDDD'; // DDDD
	peerID.id.id[4] = '0000'; // 0000
	peerID.addr.set_port(('8' << 8) + '8'); // 88
	peerID.addr.set_addr4('aaaa'); // aaaa
	dhtTestObj->Update(peerID, 0, false);
	Buffer peerIDBuffer;
	peerIDBuffer.len = 20;
	peerIDBuffer.b = (byte*)&peerID.id.id[0];

	// put a SECOND peer into the dht for it to work with
	DhtPeerID peerID2;
	peerID2.id.id[0] = '1111'; // 1111
	peerID2.id.id[1] = 'BBBB'; // BBBB
	peerID2.id.id[2] = 'CCCC'; // CCCC
	peerID2.id.id[3] = 'DDDD'; // DDDD
	peerID2.id.id[4] = '7777'; // 7777
	peerID2.addr.set_port(('8' << 8) + '8'); // 88
	peerID2.addr.set_addr4('aaab'); // aaaa
	dhtTestObj->Update(peerID2, 0, false);
	Buffer peerIDBuffer2;
	peerIDBuffer2.len = 20;
	peerIDBuffer2.b = (byte*)&peerID2.id.id[0];

	const unsigned int numTargets = 1;
	std::vector<std::vector<byte> > transactionIDs; // produced by the dht
	std::string filenamesTxt[numTargets];
	DhtID targets[numTargets];

	for(unsigned int x=0; x<numTargets; ++x){
		targets[x].id[0] = 'FFFF'; // FFFF
		targets[x].id[1] = 'GGGG'; // GGGG
		targets[x].id[2] = 'HHHH'; // HHHH
		targets[x].id[3] = 'IIII'; // IIII
		targets[x].id[4] = ((((((x + 0x30)<<8) + x + 0x30)<<8) + x + 0x30)<<8) +x+0x30; //
	}

	for(unsigned int x=0; x<numTargets; ++x){
		filenamesTxt[x] = "filename_";
		std::string LastChar("0");
		LastChar[0] += (char)x;
		filenamesTxt[x] += LastChar;
	}

	// make sure the callback dummy is clear
	AddNodesCallbackDummy::Reset();

	// *****************************************************
	// make the dht emit an announce message (the get_peers rpc)
	// and capture the transaction ID
	// *****************************************************

	for(unsigned int x=0; x<numTargets; ++x){
		socket4.Reset();
		ASSERT_TRUE(PerformDoAnnounce(dhtTestObj, targets[x], filenamesTxt[x], transactionIDs, socket4)) << "DoAnnounce failed on iteration:  " << x;
	}

	// *****************************************************
	// now fabricate response messages using the
	// transaction IDs extracted above and include a token
	// that the dht should return to us.  Provide the compact IP
	// of a peer for the dht to use in the 'announce_peer'
	// message it should emit next
	// *****************************************************
	std::vector<byte>	messageBytes;
	std::vector<byte>	replyDictionaryBytes;

	// make the response tokens
	std::string* responseTokens = new std::string[transactionIDs.size()];
	for(unsigned int x=0; x<transactionIDs.size(); ++x){
		responseTokens[x] = "20_byte_reply_token";
		std::string LastChar("0");
		LastChar[0] += (char)x;
		responseTokens[x] += LastChar;
	}

	// make a list of compact IPs (in this case only one ip)
	std::string compactIP("aaaa88");
	std::vector<std::string> values;
	values.push_back(compactIP);

	// The current dht implementation only issues the announce_peer rpc's once
	// all of the get_peers have responded (or maybe timed out).  Future implementatios
	// may issue announces incrementally, so the sent string is capture after
	// each response to a get_peer

	std::vector<byte> tidout;
	std::string announceString;
	DoGetPeersReply(dhtTestObj, peerID, responseTokens[0], values, transactionIDs[0], tidout, socket4);
	announceString += socket4.GetSentDataAsString();
	DoGetPeersReply(dhtTestObj, peerID2, responseTokens[1], values, transactionIDs[1], tidout, socket4);
	announceString += socket4.GetSentDataAsString();

	// look to see if the response tokens are in the sent data string
	// ONCE AND ONLY ONCE.  If this is so, then assume the remainder of the output is good
	for(unsigned int x=0; x<transactionIDs.size(); ++x){
		size_t index = announceString.find(responseTokens[x]);
		ASSERT_NE(index, std::string::npos) << "response token '" << responseTokens[x] << "' was NOT found in the announce_peer output string";
		if(index == std::string::npos)
			continue;
		index = announceString.find(responseTokens[x], index+1);
		ASSERT_EQ(index, std::string::npos) << "response token '" << responseTokens[x] << "' was found MORE THAN ONCE in the announce_peer output string";
	}

	delete[] responseTokens;
}

TEST(TestDhtImplResponse, DoFindNodesWithMultipleNodesInDHT)
{
	UnitTestUDPSocket socket4;
	UnitTestUDPSocket socket6;
	BencodedDict bDictGetPeer;
	SockAddr sAddr(0x7a7a7a7a,0x7878); // ip = zzzz and socket = xx
	socket4.SetBindAddr(sAddr);
	smart_ptr<DhtImpl> dhtTestObj(new DhtImpl(&socket4, &socket6));
	dhtTestObj->SetSHACallback(&sha1_callback);

	// prepare the object for use
	dhtTestObj->Enable(true,0);
	SetDHT_my_id_Bytes(dhtTestObj);

	// put the FIRST peer into the dht for it to work with
	DhtPeerID peerID;
	peerID.id.id[0] = '1111';
	peerID.id.id[1] = 'BBBB'; // BBBB
	peerID.id.id[2] = 'CCCC'; // CCCC
	peerID.id.id[3] = 'DDDD'; // DDDD
	peerID.id.id[4] = '0000'; // 0000
	peerID.addr.set_port(('8' << 8) + '8'); // 88
	peerID.addr.set_addr4('aaaa'); // aaaa
	dhtTestObj->Update(peerID, 0, false);
	Buffer peerIDBuffer;
	peerIDBuffer.len = 20;
	peerIDBuffer.b = (byte*)&peerID.id.id[0];

	// put a SECOND peer into the dht for it to work with
	DhtPeerID peerID2;
	peerID2.id.id[0] = '1111'; // 1111
	peerID2.id.id[1] = 'BBBB'; // BBBB
	peerID2.id.id[2] = 'CCCC'; // CCCC
	peerID2.id.id[3] = 'DDDD'; // DDDD
	peerID2.id.id[4] = '7777'; // 7777
	peerID2.addr.set_port(('8' << 8) + '8'); // 88
	peerID2.addr.set_addr4('aaab'); // aaab
	dhtTestObj->Update(peerID2, 0, false);
	Buffer peerIDBuffer2;
	peerIDBuffer2.len = 20;
	peerIDBuffer2.b = (byte*)&peerID2.id.id[0];

	DhtID target;
	target.id[0] = 'FFFF'; // FFFF
	target.id[1] = 'GGGG'; // GGGG
	target.id[2] = 'HHHH'; // HHHH
	target.id[3] = 'IIII'; // IIII
	target.id[4] = 'JJJJ'; // JJJJ

	// *****************************************************
	// tell the dht to issue a find_nodes request and
	// capture the query string that goes out the socket
	// *****************************************************
	EXPECT_FALSE(dhtTestObj->IsBusy()) << "The dht should not be busy yet";
	FindNodeCallbackDummy CallbackObj;
	dhtTestObj->DoFindNodes(target, 20, &CallbackObj);
	std::string doFindNodesOutput = socket4.GetSentDataAsString();
	EXPECT_TRUE(dhtTestObj->IsBusy()) << "The dht should be busy";

	// extract the transaction id's to use in the replys back to the dht
	std::vector<std::vector<byte> > transactionIDs;
	ASSERT_TRUE(ExtractTransactionIDs(doFindNodesOutput, transactionIDs)) << "There was a problem extracting transaction ID's";
	ASSERT_TRUE(transactionIDs.size() != 0) << "No transaction IDs were emitted, test can not continue.";

	// now fabricate a nodes response message using the transaction ID extracted above
	std::vector<byte>	messageBytes, messageBytes2;
	std::vector<byte>	replyDictionaryBytes, replyDictionaryBytes2;

	// *****************************************************
	// make a response message to the above query.  Use the
	// transaction id extracted above.  Note the "compact
	// node" information for later use
	// *****************************************************
	// encode the compact node with IP address: 'aaaa' , port: '88' (aaaa88) and use this in the second response below
	std::string compactNode("WWWWWXXXXXYYYYYZZZZZaaaa88"); // send the same node info back from both queried nodes

	// construct the message bytes (for the FIRST node)
	std::string responseToken("20_byte_reply_token.");
	BencStartDictionary(replyDictionaryBytes);
	{
		BencAddNameValuePair(replyDictionaryBytes,"id",peerIDBuffer);
		BencAddNameValuePair(replyDictionaryBytes,"nodes",compactNode);
		BencAddNameValuePair(replyDictionaryBytes,"token",responseToken);
	}
	BencEndDictionary(replyDictionaryBytes);
	BencStartDictionary(messageBytes);
	{
		BencAddNameAndBencodedDictionary(messageBytes,"r",replyDictionaryBytes);
		BencAddNameValuePair(messageBytes,"t",transactionIDs[0]);
		BencAddNameValuePair(messageBytes,"y","r");
	}
	BencEndDictionary(messageBytes);

	// construct the message bytes (for the SECOND node)
	std::string responseToken2("20_byte_reply_token2");
	BencStartDictionary(replyDictionaryBytes2);
	{
		BencAddNameValuePair(replyDictionaryBytes2,"id",peerIDBuffer2);
		BencAddNameValuePair(replyDictionaryBytes2,"nodes",compactNode);
		BencAddNameValuePair(replyDictionaryBytes2,"token",responseToken2);
	}
	BencEndDictionary(replyDictionaryBytes2);
	BencStartDictionary(messageBytes2);
	{
		BencAddNameAndBencodedDictionary(messageBytes2,"r",replyDictionaryBytes2);
		BencAddNameValuePair(messageBytes2,"t",transactionIDs[1]);
		BencAddNameValuePair(messageBytes2,"y","r");
	}
	BencEndDictionary(messageBytes2);

	// *****************************************************
	// clear the socket, "send" the replys, and capture the
	// second query string to be issued by the dht.
	// Since the same compact node info was returned from both
	// queries above, there should only be one query emitted
	// to the node indentified in the compactID above.
	// *****************************************************
	std::string secondtime;
	socket4.Reset();
	dhtTestObj->ProcessIncoming((byte*)&messageBytes.front(), messageBytes.size(), peerID.addr);
	secondtime += socket4.GetSentDataAsString();

	socket4.Reset();
	dhtTestObj->ProcessIncoming((byte*)&messageBytes2.front(), messageBytes2.size(), peerID2.addr);
	secondtime += socket4.GetSentDataAsString();

	EXPECT_TRUE(dhtTestObj->IsBusy()) << "The dht should be busy";

	ASSERT_TRUE(ExtractTransactionIDs(secondtime, transactionIDs)) << "There was a problem extracting transaction ID's";
	ASSERT_EQ(1, transactionIDs.size()) << "There should only be one transaction ID";

	// *****************************************************
	// now fabricate a nodes response message using the
	// transaction ID extracted above.  ALSO, use the IP
	// address and port that were returned to the dht
	// in the response to it's initial query (aaaa88)
	// *****************************************************
	messageBytes.clear();
	replyDictionaryBytes.clear();

	// construct the message bytes
	BencStartDictionary(replyDictionaryBytes);
	{
		BencAddNameValuePair(replyDictionaryBytes,"id","WWWWWXXXXXYYYYYZZZZZ");
		BencAddNameValuePair(replyDictionaryBytes,"nodes",compactNode);
		BencAddNameValuePair(replyDictionaryBytes,"token",responseToken);
	}
	BencEndDictionary(replyDictionaryBytes);

	BencStartDictionary(messageBytes);
	{
		BencAddNameAndBencodedDictionary(messageBytes,"r",replyDictionaryBytes);
		BencAddNameValuePair(messageBytes,"t",transactionIDs[0]);
		BencAddNameValuePair(messageBytes,"y","r");
	}
	BencEndDictionary(messageBytes);

	// clear the socket and "send" the reply
	socket4.Reset();
	DhtPeerID secondPeerID;
	secondPeerID.addr.set_addr4('aaaa'); // aaaa
	secondPeerID.addr.set_port(('8' << 8) + '8'); //88

	dhtTestObj->ProcessIncoming((byte*)&messageBytes.front(), messageBytes.size(), secondPeerID.addr);

	// *****************************************************
	// The DhtProcess object that is internally called back to uses private members
	// and member functions with no access points.  So, only circumstantial evidence
	// can be used to see if things are working as they should.
	// *****************************************************

	// see that our call back was invoked (this may be invoked even if there is an internal error)
	EXPECT_EQ(1, CallbackObj.callbackCount) << "Our callback object should have been invoked 1 time";
	EXPECT_FALSE(dhtTestObj->IsBusy()) << "The dht should no longer be busy";
}

/**
This test is designed to exercise the scheduling aspect of the dht lookup process.
When first doing the dht lookup using "get_peers" the dht process should issue
an initial burst of 4 queries.  When peer values are received, additional get-peers
queries are issued in such a way as to always keep the 4 closest nodes in the
developing nodes list occupied with queries.  This rule trumps the rule that no more
than 4 get_peers queries can be in flight at a time.  Otherwise, there should be no more
than 4 active queries in flight at a time (slow peers are excepted).  Once all of the
get_peers queries are complete then the dht switches to issuing "announce_peer" queries.
An initial burst of 3 queries should be issued followed by additional queries
as replys are received.  No more than 3 announce queries should be in flight at
a time.

          Test                    |                  DHT
----------------------------------|--------------------------------------------
1) invoke doAnnounce()            |
                                  | Responds by emitting a 'get_peers' query
								  |
2) Fabricate and "send" a         |
   response to get_peers that     |
   has only compact node values   |
   for 8 nodes close to the target|
                                  | Responds by emitting 'get_peers' querys
								  | (an initial group of 4)
								  |
3) Fabricate and "send" a         |
   response to one of the queries |
   that has compact node value    |
   information that is CLOSER to  |
   the target than step 2 above   |
                                  | Responds by emitting 'get_peers' querys
								  | (an additional group of 4 in addition to
								  | the three that are still outstanding for
								  | a total of 7 outstanding)
								  |
3) Send a "values" response back  |
   to the dht for each transaction|
   ID that the dht outputs        |
                                  | Issues another get_peers for each response until
								  | all nodes have been contacted.  Then it switches
								  | to issuing "announce_peer" queries (an initial
								  | group of 3)
4) responds with a acknowledgement|
   reply for each announce query  |
                                  |
*/
TEST(TestDhtImplResponse, Announce_ReplyWithMultipleNodes)
{
	UnitTestUDPSocket socket4;
	UnitTestUDPSocket socket6;
	BencodedDict bDictGetPeer;
	SockAddr sAddr(0x7a7a7a7a,0x7878); // ip = zzzz and socket = xx
	socket4.SetBindAddr(sAddr);
	smart_ptr<DhtImpl> dhtTestObj(new DhtImpl(&socket4, &socket6));
	dhtTestObj->SetSHACallback(&sha1_callback);
	dhtTestObj->_dht_utversion[2] = 'x';
	dhtTestObj->_dht_utversion[3] = 'x';

	// prepare the object for use
	dhtTestObj->Enable(true,0);
	SetDHT_my_id_Bytes(dhtTestObj);

	// put a peer into the dht for it to work with
	DhtPeerID peerID;
	peerID.id.id[0] = '1111'; // 1111
	peerID.id.id[1] = 'BBBB'; // BBBB
	peerID.id.id[2] = 'CCCC'; // CCCC
	peerID.id.id[3] = 'DDDD'; // DDDD
	peerID.id.id[4] = '0000'; // 0000
	peerID.addr.set_port(128);
	peerID.addr.set_addr4(0xf0f0f0f0);
	dhtTestObj->Update(peerID, 0, false);
	Buffer peerIDBuffer;
	peerIDBuffer.len = 20;
	peerIDBuffer.b = (byte*)&peerID.id.id[0];

	DhtID target;
	target.id[0] = 'zzzz';
	target.id[1] = 'zzzz';
	target.id[2] = 'zzzz';
	target.id[3] = 'zzzz';
	target.id[4] = 'zzzz';

	// make sure the callback dummy is clear
	AddNodesCallbackDummy::Reset();

	// *****************************************************
	// make the dht emit an announce message (the get_peers rpc)
	// *****************************************************
	EXPECT_FALSE(dhtTestObj->IsBusy()) << "The dht should not be busy yet";
	dhtTestObj->DoAnnounce(target, 20, NULL, &AddNodesCallbackDummy::Callback, NULL, "filename.txt", NULL, 0);
	EXPECT_TRUE(dhtTestObj->IsBusy()) << "The dht should be busy";

	// *****************************************************
	// grab from the socket the emitted message and extract
	// the transaction ID and verify the remainder of the
	// message
	// *****************************************************
	std::string doAnnounceOutput = socket4.GetSentDataAsString();
	BencEntity bEntityAnounceQuery;
	// verify the bencoded string that went out the socket
	BencEntity::Parse((const byte *)doAnnounceOutput.c_str(), bEntityAnounceQuery, (const byte *)(doAnnounceOutput.c_str() + doAnnounceOutput.length()));

	// get the query dictionary
	BencodedDict *dictForAnnounce = BencodedDict::AsDict(&bEntityAnounceQuery);
	EXPECT_TRUE(dictForAnnounce);
	if (!dictForAnnounce) {
		FAIL() << "ERROR:  The dht did not emit a bencoded dictionary for announce";
	}

	Buffer type;
	type.b = (byte*)dictForAnnounce->GetString("y" ,&type.len);
	ASSERT_EQ(1, type.len) << "ERROR: the 'y' type length is wrong (should be 1 for 'q', 'r', or 'e')";
	ASSERT_EQ('q', type.b[0]) << "ERROR: 'y' type is wrong; should be 'q' for query instead of:  " << type.b[0];

	Buffer command;
	command.b = (byte*)dictForAnnounce->GetString("q" ,&command.len);
	EXPECT_EQ(9, command.len);
	EXPECT_FALSE(memcmp("get_peers", command.b, 9)) << "ERROR: 'q' command is wrong";

	// get the transaction ID to use later
	Buffer tid;
	tid.b = (byte*)dictForAnnounce->GetString("t" ,&tid.len);
	EXPECT_EQ(4, tid.len) << "transaction ID is wrong size";

	// now look into the query data
	BencodedDict *announceQuery = dictForAnnounce->GetDict("a");
	if (!announceQuery) {
		FAIL() << "ERROR:  Failed to extract 'a' dictionary from get_peer response";
	}

	Buffer id;
	id.b = (byte*)announceQuery->GetString("id" ,&id.len);
	EXPECT_EQ(20, id.len);
	EXPECT_FALSE(memcmp("AAAABBBBCCCCDDDDEEEE", id.b, 20)) << "ERROR: announced id is wrong";

	Buffer infoHash;
	infoHash.b = (byte*)announceQuery->GetString("info_hash" ,&infoHash.len);
	EXPECT_EQ(20, infoHash.len);
	EXPECT_FALSE(memcmp("zzzzzzzzzzzzzzzzzzzz", infoHash.b, 20)) << "ERROR: info_hash is not the correct target";

	// *****************************************************
	// now fabricate a nodes response message using the
	// transaction ID extracted above and include a token
	// *****************************************************
	std::vector<byte>	messageBytes;
	std::vector<byte>	replyDictionaryBytes;

	const char* compactIPs[] = {"bbbb..","cccc..","dddd..","eeee..","ffff..","gggg..","hhhh..","iiii..","bbbb..","cccc..","dddd..","eeee..","ffff..","gggg..","hhhh..","iiii.."};

	std::string responseToken("20_byte_reply_token.");
	// make a string of 8 compact nodes (based on what was designed above)
	std::string nearistNode  ("zzzzzzzzzzzzzzzzzzAAbbbb..zzzzzzzzzzzzzzzzzzBBcccc..zzzzzzzzzzzzzzzzzzCCdddd..zzzzzzzzzzzzzzzzzzDDeeee..zzzzzzzzzzzzzzzzzzEEffff..zzzzzzzzzzzzzzzzzzFFgggg..zzzzzzzzzzzzzzzzzzGGhhhh..zzzzzzzzzzzzzzzzzzHHiiii..");
	std::string closerNodes  ("zzzzzzzzzzzzzzzzzzzybbbb..zzzzzzzzzzzzzzzzzzzxcccc..zzzzzzzzzzzzzzzzzzzwdddd..zzzzzzzzzzzzzzzzzzzveeee..zzzzzzzzzzzzzzzzzzzuffff..zzzzzzzzzzzzzzzzzzztgggg..zzzzzzzzzzzzzzzzzzzshhhh..zzzzzzzzzzzzzzzzzzzriiii..");
	// construct the message bytes for sending just the near nodes
	BencStartDictionary(replyDictionaryBytes);
	{
		BencAddNameValuePair(replyDictionaryBytes,"id",peerIDBuffer);
		BencAddNameValuePair(replyDictionaryBytes,"nodes",nearistNode);
		BencAddNameValuePair(replyDictionaryBytes,"token",responseToken);
	}
	BencEndDictionary(replyDictionaryBytes);

	BencStartDictionary(messageBytes);
	{
		BencAddNameAndBencodedDictionary(messageBytes,"r",replyDictionaryBytes);
		BencAddNameValuePair(messageBytes,"t",tid);
		BencAddNameValuePair(messageBytes,"y","r");
	}
	BencEndDictionary(messageBytes);

	// clear the socket and "send" the reply
	socket4.Reset();
	dhtTestObj->ProcessIncoming((byte*)&messageBytes.front(), messageBytes.size(), peerID.addr);

	EXPECT_TRUE(dhtTestObj->IsBusy()) << "The dht should still be busy";

	// *****************************************************
	// get the bencoded string(s) out of the socket and extract
	// the transaction id's.  The dht should issue an initial burst of queries
	// that are throttled back to one new query for each response received
	// until all nodes have been queried.
	// *****************************************************

	// we are only interested in the transaction ID's
	std::string bencMessage = socket4.GetSentDataAsString();
	std::vector<std::vector<byte> > transactionIDs;
	ASSERT_TRUE(ExtractTransactionIDs(bencMessage, transactionIDs)) << "There was a problem extracting transaction ID's";
	// at this time there should be "#define KADEMLIA_LOOKUP_OUTSTANDING 4" transaction id's for 4 outstanding messages
	EXPECT_EQ(KADEMLIA_LOOKUP_OUTSTANDING, transactionIDs.size()) << "Expected KADEMLIA_LOOKUP_OUTSTANDING (4) transaction IDs but found " << transactionIDs.size() << " instead.";

	byte bufferBytes[20];
	Buffer nodeID;
	nodeID.b = (byte*)bufferBytes;
	nodeID.len = 20;

	// send a reply back to the dht with closer nodes; see that 4 more are issued
	// construct the message bytes for sending just the near nodes
	DhtRequest *req2 = dhtTestObj->LookupRequest(Read32(&transactionIDs[0][0]));
	DhtIDToBytes(nodeID.b, req2->peer.id);
	replyDictionaryBytes.clear();
	messageBytes.clear();
	BencStartDictionary(replyDictionaryBytes);
	{
		BencAddNameValuePair(replyDictionaryBytes,"id",nodeID);
		BencAddNameValuePair(replyDictionaryBytes,"nodes",closerNodes); // using closer nodes
		BencAddNameValuePair(replyDictionaryBytes,"token",responseToken);
	}
	BencEndDictionary(replyDictionaryBytes);

	BencStartDictionary(messageBytes);
	{
		BencAddNameAndBencodedDictionary(messageBytes,"r",replyDictionaryBytes);
		BencAddNameValuePair(messageBytes,"t",transactionIDs[0]);
		BencAddNameValuePair(messageBytes,"y","r");
	}
	BencEndDictionary(messageBytes);

	// clear the socket and "send" the reply with closer nodes
	socket4.Reset();
	dhtTestObj->ProcessIncoming((byte*)&messageBytes.front(), messageBytes.size(), req2->peer.addr);

	// we are only interested in the transaction ID's
	std::string bencMessage2 = socket4.GetSentDataAsString();
	std::vector<std::vector<byte> > transactionIDs2;
	ASSERT_TRUE(ExtractTransactionIDs(bencMessage2, transactionIDs2)) << "There was a problem extracting transaction ID's";
	// at this time there should be "#define KADEMLIA_LOOKUP_OUTSTANDING 4" transaction id's for 4 outstanding messages
	EXPECT_EQ(KADEMLIA_LOOKUP_OUTSTANDING, transactionIDs2.size()) << "Expected KADEMLIA_LOOKUP_OUTSTANDING (4) transaction IDs but found " << transactionIDs2.size() << " instead.";

	for(int x=0; x< transactionIDs2.size(); ++x)
		transactionIDs.push_back(transactionIDs2[x]);

	// feed responses back to the dht.
	for(int x=0; x<transactionIDs.size(); ++x)
	{
		socket4.Reset();
		replyDictionaryBytes.clear();
		messageBytes.clear();

		// get the request info out of the dht (since we can)
		DhtRequest *req = dhtTestObj->LookupRequest(Read32(&transactionIDs[x][0]));

		if(req){
			DhtIDToBytes(nodeID.b, req->peer.id);

			// construct a response with a "value"
			BencStartDictionary(replyDictionaryBytes);
			{
				BencAddNameValuePair(replyDictionaryBytes,"id",nodeID);
				BencAddNameValuePair(replyDictionaryBytes,"token",responseToken);
				BencAddString(replyDictionaryBytes,"values");
				BencStartList(replyDictionaryBytes);
				{
					BencAddString(replyDictionaryBytes, compactIPs[x]);
				}
				BencEndList(replyDictionaryBytes);
			}
			BencEndDictionary(replyDictionaryBytes);

			BencStartDictionary(messageBytes);
			{
				BencAddNameAndBencodedDictionary(messageBytes,"r",replyDictionaryBytes);
				BencAddNameValuePair(messageBytes,"t",transactionIDs[x]);
				BencAddNameValuePair(messageBytes,"y","r");
			}
			BencEndDictionary(messageBytes);

			// send the reply
			dhtTestObj->ProcessIncoming((byte*)&messageBytes.front(), messageBytes.size(), req->peer.addr);
		}

		// see if anything went out the socket
		std::string nextString = socket4.GetSentDataAsString();
		// clear the socket
		if((nextString.size() != 0) && (x < transactionIDs.size()-1))
		{
			// get a transaction id and add it to the transactionIDs list
			std::vector<std::vector<byte> > thisTransactionID;
			ASSERT_EQ(true,ExtractTransactionIDs(nextString, thisTransactionID)) << "There was a problem extracting transaction ID's";
			transactionIDs.push_back(thisTransactionID[0]);
		}
	}
	// there should now be 12 transaction id's (the first 4 from the initial request and
	// then 8 more for the "closer" nodes
	EXPECT_EQ(12, transactionIDs.size());

	// after the final reply to the get_peers request is made, since we are responding
	// with "values" the dht will emit the first set of "announce_peer" queries.
	// These should be sitting in the socket
	std::string announceString = socket4.GetSentDataAsString();

	ASSERT_TRUE(ExtractTransactionIDs(announceString, transactionIDs)) << "There was a problem extracting transaction ID's for the announce_peer phase";
	// at this time there should be "#define KADEMLIA_BROADCAST_OUTSTANDING 3" transaction id's for 4 outstanding messages
	EXPECT_EQ(KADEMLIA_BROADCAST_OUTSTANDING, transactionIDs.size()) << "Expected KADEMLIA_BROADCAST_OUTSTANDING transaction IDs but found " << transactionIDs.size() << " instead.";


	// Again, feed responses back to the dht. (this time, replys to the "announce_peers" queries
	for(int x=0; x<transactionIDs.size(); ++x)
	{
		socket4.Reset();
		replyDictionaryBytes.clear();
		messageBytes.clear();

		// get the request info out of the dht (since we can)
		DhtRequest *req = dhtTestObj->LookupRequest(Read32(&transactionIDs[x][0]));

		if(req){
			DhtIDToBytes(nodeID.b, req->peer.id);

			// construct a response with a "value"
			BencStartDictionary(replyDictionaryBytes);
			{
				BencAddNameValuePair(replyDictionaryBytes,"id",nodeID);
			}
			BencEndDictionary(replyDictionaryBytes);

			BencStartDictionary(messageBytes);
			{
				BencAddNameAndBencodedDictionary(messageBytes,"r",replyDictionaryBytes);
				BencAddNameValuePair(messageBytes,"t",transactionIDs[x]);
				BencAddNameValuePair(messageBytes,"y","r");
			}
			BencEndDictionary(messageBytes);

			// send the reply
			dhtTestObj->ProcessIncoming((byte*)&messageBytes.front(), messageBytes.size(), req->peer.addr);
		}

		// see if anything went out the socket
		std::string nextString = socket4.GetSentDataAsString();
		// clear the socket
		if((nextString.size() != 0) && (x < transactionIDs.size()-1))
		{
			// get a transaction id and add it to the transactionIDs list
			std::vector<std::vector<byte> > thisTransactionID;
			ASSERT_TRUE(ExtractTransactionIDs(nextString, thisTransactionID)) << "There was a problem extracting transaction ID's";
			transactionIDs.push_back(thisTransactionID[0]);
		}
	}
	// see that the correct number of announces were emitted
	EXPECT_EQ(KADEMLIA_K_ANNOUNCE, transactionIDs.size()) << "Expected 8 transaction IDs but found " << transactionIDs.size() << " instead.";
	EXPECT_EQ(12, AddNodesCallbackDummy::callbackData.size()) << "12 callback events were expected but there were:  " << AddNodesCallbackDummy::callbackData.size();
}


/**
          Test                    |                  DHT
----------------------------------|--------------------------------------------
1) invoke doAnnounce()            |
                                  | Responds by emitting a 'get_peers' query
								  |
2) Adjust the timestamp of the    |
   query to make it look "slow"   |
								  | The dht should internally keep mark the node
								  | as slow.  Nothing is output.
								  |
2) Fabricate and "send" a         |
   response to get_peers that     |
   has compact IP-address/port    |
   info for a peer                |
                                  | Responds by emitting 'announce_peer' query
								  |
*/
TEST(TestDhtImplResponse, Announce_Slow_ReplyWithPeers)
{
	UnitTestUDPSocket socket4;
	UnitTestUDPSocket socket6;
	BencodedDict bDictGetPeer;
	SockAddr sAddr(0x7a7a7a7a,0x7878); // ip = zzzz and socket = xx
	socket4.SetBindAddr(sAddr);
	smart_ptr<DhtImpl> dhtTestObj(new DhtImpl(&socket4, &socket6));
	dhtTestObj->SetSHACallback(&sha1_callback);

	// prepare the object for use
	dhtTestObj->Enable(true,0);
	SetDHT_my_id_Bytes(dhtTestObj);

	// put a peer into the dht for it to work with
	DhtPeerID peerID;
	peerID.id.id[0] = '1111'; // 1111
	peerID.id.id[1] = 'BBBB'; // BBBB
	peerID.id.id[2] = 'CCCC'; // CCCC
	peerID.id.id[3] = 'DDDD'; // DDDD
	peerID.id.id[4] = '0000'; // 0000
	peerID.addr.set_port(('8' << 8) + '8'); // 88
	peerID.addr.set_addr4('aaaa'); // aaaa
	dhtTestObj->Update(peerID, 0, false);
	Buffer peerIDBuffer;
	peerIDBuffer.len = 20;
	peerIDBuffer.b = (byte*)&peerID.id.id[0];

	DhtID target;
	target.id[0] = 'FFFF'; // FFFF
	target.id[1] = 'GGGG'; // GGGG
	target.id[2] = 'HHHH'; // HHHH
	target.id[3] = 'IIII'; // IIII
	target.id[4] = 'JJJJ'; // JJJJ

	// make sure the callback dummy is clear
	AddNodesCallbackDummy::Reset();

	EXPECT_EQ(1, dhtTestObj->GetNumPeers());
	EXPECT_EQ(0, dhtTestObj->GetNumPeersTracked());

	DhtPeerID *ids[16];
	uint num = dhtTestObj->FindNodes(target, ids, 8, 8, 0); // Find 8 good ones and 8 bad ones
	EXPECT_EQ(1, num) << "Num Nodes: " << num;
	EXPECT_FALSE(dhtTestObj->IsBusy()) << "The dht should not be busy yet";

	// *****************************************************
	// make the dht emit an announce message (the get_peers rpc)
	// *****************************************************
	std::string filenameTxt("filaname.txt");
	dhtTestObj->DoAnnounce(target, 20, NULL, &AddNodesCallbackDummy::Callback, NULL, filenameTxt.c_str(), NULL, 0);
	EXPECT_TRUE(dhtTestObj->IsBusy()) << "The dht should be busy";

	// *****************************************************
	// grab from the socket the emitted message and extract
	// the transaction ID and verify the remainder of the
	// message
	// *****************************************************
	std::string doAnnounceOutput = socket4.GetSentDataAsString();
	BencEntity bEntityAnounceQuery;
	// verify the bencoded string that went out the socket
	BencEntity::Parse((const byte *)doAnnounceOutput.c_str(), bEntityAnounceQuery, (const byte *)(doAnnounceOutput.c_str() + doAnnounceOutput.length()));

	// get the query dictionary
	BencodedDict *dictForAnnounce = BencodedDict::AsDict(&bEntityAnounceQuery);
	EXPECT_TRUE(dictForAnnounce);
	if (!dictForAnnounce) {
		FAIL() << "ERROR:  The dht did not emit a bencoded dictionary for announce";
	}

	Buffer type;
	type.b = (byte*)dictForAnnounce->GetString("y" ,&type.len);
	ASSERT_EQ(1, type.len) << "ERROR: the 'y' type length is wrong (should be 1 for 'q', 'r', or 'e')";
	ASSERT_EQ('q', type.b[0]) << "ERROR: 'y' type is wrong; should be 'q' for query instead of:  " << type.b[0];

	Buffer command;
	command.b = (byte*)dictForAnnounce->GetString("q" ,&command.len);
	EXPECT_EQ(9, command.len);
	EXPECT_FALSE(memcmp("get_peers", command.b, 9)) << "ERROR: 'q' command is wrong; should be 'get_peers'";

	// get the transaction ID to use later
	Buffer tid;
	tid.b = (byte*)dictForAnnounce->GetString("t" ,&tid.len);
	EXPECT_EQ(4, tid.len) << "transaction ID is wrong size";

	// now look into the query data
	BencodedDict *announceQuery = dictForAnnounce->GetDict("a");
	if (!announceQuery) {
		FAIL() << "ERROR:  Failed to extract 'a' dictionary from get_peer response";
	}

	Buffer id;
	id.b = (byte*)announceQuery->GetString("id" ,&id.len);
	EXPECT_EQ(20, id.len);
	EXPECT_FALSE(memcmp("AAAABBBBCCCCDDDDEEEE", id.b, 20)) << "ERROR: announced id is wrong";

	Buffer infoHash;
	infoHash.b = (byte*)announceQuery->GetString("info_hash" ,&infoHash.len);
	EXPECT_EQ(20, infoHash.len);
	EXPECT_FALSE(memcmp("FFFFGGGGHHHHIIIIJJJJ", infoHash.b, 20)) << "ERROR: info_hash is not the correct target";

	int noseed = announceQuery->GetInt("noseed");
	EXPECT_EQ(0,noseed) << "'noseed' is set when it should not be.";

	// *********************************************************************************
	// get the request info and make it look like enough time has passed to call it slow
	// *********************************************************************************
	DhtRequest* req = dhtTestObj->LookupRequest(Read32(tid.b));
	req->time -= 1100;
	dhtTestObj->Tick();

	// *****************************************************
	// now fabricate a nodes response message using the
	// transaction ID extracted above and include a token
	// that the dht should return to us.  Provide the compact IP
	// of a peer for the dht to use in the 'announce_peer'
	// message it should emit next
	// *****************************************************
	std::vector<byte>	messageBytes;
	std::vector<byte>	replyDictionaryBytes;

	std::string responseToken("20_byte_reply_token.");
	std::string compactIP("aaaa88");

	// construct the message bytes
	BencStartDictionary(replyDictionaryBytes);
	{
		BencAddNameValuePair(replyDictionaryBytes,"id",peerIDBuffer);
		BencAddNameValuePair(replyDictionaryBytes,"token",responseToken);
		BencAddString(replyDictionaryBytes,"values");
		BencStartList(replyDictionaryBytes);
		{
			BencAddString(replyDictionaryBytes, compactIP);
		}
		BencEndList(replyDictionaryBytes);
	}
	BencEndDictionary(replyDictionaryBytes);

	BencStartDictionary(messageBytes);
	{
		BencAddNameAndBencodedDictionary(messageBytes,"r",replyDictionaryBytes);
		BencAddNameValuePair(messageBytes,"t",tid);
		BencAddNameValuePair(messageBytes,"y","r");
	}
	BencEndDictionary(messageBytes);

	// clear the socket and "send" the reply and capture the announce_peer emitted by the dht
	socket4.Reset();
	dhtTestObj->ProcessIncoming((byte*)&messageBytes.front(), messageBytes.size(), peerID.addr);
	std::string announceString = socket4.GetSentDataAsString();

	EXPECT_TRUE(dhtTestObj->IsBusy()) << "The dht should still be busy";

	// *****************************************************
	// verify the announce_peer message emitted by the dht
	// *****************************************************
	BencEntity::Parse((const byte *)announceString.c_str(), bEntityAnounceQuery, (const byte *)(announceString.c_str() + announceString.length()));

	// get the query dictionary
	dictForAnnounce = BencodedDict::AsDict(&bEntityAnounceQuery);
	EXPECT_TRUE(dictForAnnounce);
	if (!dictForAnnounce) {
		FAIL() << "ERROR:  The dht did not emit a bencoded dictionary for announce";
	}

	type.b = (byte*)dictForAnnounce->GetString("y" ,&type.len);
	ASSERT_EQ(1, type.len) << "ERROR: the 'y' type length is wrong (should be 1 for 'q', 'r', or 'e')";
	ASSERT_EQ('q', type.b[0]) << "ERROR: 'y' type is wrong; should be 'q' for query instead of:  " << type.b[0];

	command.b = (byte*)dictForAnnounce->GetString("q" ,&command.len);
	EXPECT_EQ(13, command.len);
	EXPECT_FALSE(memcmp("announce_peer", command.b, 13)) << "ERROR: 'q' command is wrong; should be 'announce_peer'";

	// get the transaction ID to use later
	tid.b = (byte*)dictForAnnounce->GetString("t" ,&tid.len);
	EXPECT_EQ(4, tid.len) << "transaction ID is wrong size";

	// now look into the query data
	announceQuery = dictForAnnounce->GetDict("a");
	if (!announceQuery) {
		FAIL() << "ERROR:  Failed to extract 'a' dictionary from get_peer response";
	}

	id.b = (byte*)announceQuery->GetString("id" ,&id.len);
	EXPECT_EQ(20, id.len);
	EXPECT_FALSE(memcmp("AAAABBBBCCCCDDDDEEEE", id.b, 20)) << "ERROR: announced id is wrong";

	infoHash.b = (byte*)announceQuery->GetString("info_hash" ,&infoHash.len);
	EXPECT_EQ(20, infoHash.len);
	EXPECT_FALSE(memcmp("FFFFGGGGHHHHIIIIJJJJ", infoHash.b, 20)) << "ERROR: info_hash is not the correct target";

	Buffer name;
	name.b = (byte*)announceQuery->GetString("name" ,&name.len);
	EXPECT_EQ(filenameTxt.size(), name.len);
	EXPECT_FALSE(strcmp(filenameTxt.c_str(), (char*)name.b));

	int port;
	port = announceQuery->GetInt("port");
	EXPECT_EQ(0x7878, port) << "Expected 0x7878 ('XX) for port; actual value = " << port;

	Buffer token;
	token.b = (byte*)announceQuery->GetString("token" ,&token.len);
	EXPECT_EQ(20, token.len);
	EXPECT_FALSE(strcmp(responseToken.c_str(), (char*)token.b));

	int seed = announceQuery->GetInt("seed");
	EXPECT_EQ(0,seed) << "'seed' is set when it should not be.";

	// *****************************************************
	// create and send a response to the 'announce_peer
	// message
	// *****************************************************
	messageBytes.clear();
	replyDictionaryBytes.clear();

	// construct the message bytes
	BencStartDictionary(replyDictionaryBytes);
	{
		BencAddNameValuePair(replyDictionaryBytes,"id",peerIDBuffer);
	}
	BencEndDictionary(replyDictionaryBytes);

	BencStartDictionary(messageBytes);
	{
		BencAddNameAndBencodedDictionary(messageBytes,"r",replyDictionaryBytes);
		BencAddNameValuePair(messageBytes,"t",tid);
		BencAddNameValuePair(messageBytes,"y","r");
	}
	BencEndDictionary(messageBytes);

	// clear the socket and "send" the reply;
	socket4.Reset();
	dhtTestObj->ProcessIncoming((byte*)&messageBytes.front(), messageBytes.size(), peerID.addr);

	// check that nothing went out the socket.
	EXPECT_EQ(0, socket4.GetSentByteVector().size()) << "Nothing should be sent out the socket in response to the reply to the dht's 'announce_peer' query";

	// *****************************************************
	// look in the addnodes call back dummy to see what was
	// passed through
	// *****************************************************
	ASSERT_EQ(2, AddNodesCallbackDummy::callbackData.size()) << "Expected two callback events";

	// verify the first callback event
	EXPECT_FALSE(memcmp("FFFFGGGGHHHHIIIIJJJJ", AddNodesCallbackDummy::callbackData[0].infoHash, 20));
	EXPECT_EQ(1, AddNodesCallbackDummy::callbackData[0].numPeers);
	EXPECT_FALSE(memcmp(compactIP.c_str(), &AddNodesCallbackDummy::callbackData[0].compactPeerAddressBytes[0], compactIP.size()));

	// verify the second callback event
	EXPECT_FALSE(memcmp("FFFFGGGGHHHHIIIIJJJJ", AddNodesCallbackDummy::callbackData[1].infoHash, 20));
	EXPECT_EQ(0, AddNodesCallbackDummy::callbackData[1].numPeers);
	EXPECT_EQ(1, dhtTestObj->GetNumPeers());
	EXPECT_EQ(0, dhtTestObj->GetNumPeersTracked());
	num = dhtTestObj->FindNodes(target, ids, 8, 8, 0); // Find 8 good ones and 8 bad ones
	EXPECT_EQ(1, num) << "Num Nodes: " << num;

	DhtRequest* req2 = dhtTestObj->LookupRequest(Read32(tid.b));
	EXPECT_FALSE(req2) << "The outstanding transaction id was not removed by the response";

	EXPECT_FALSE(dhtTestObj->IsBusy()) << "The dht should no longer be busy";
}


/**
This test is designed to exercise the scheduling aspect of the dht process with
a "slow" node.

When first doing the dht lookup using "get_peers" the dht process should issue
an initial burst of 4 queries and follow it up with additional queries and replys
are received until the nodes list is exausted.  There should be no more than 4
active queries in flight at a time (slow peers are excepted).  Once all of the
get_peers queries are complete then it switched to issuing "announce_peer" queries.
An initial burst of 3 queries should be issued followed by additional queries
as replys are received.  No more than 3 announce queries should be in flight at
a time.

          Test                    |                  DHT
----------------------------------|--------------------------------------------
1) invoke doAnnounce()            |
                                  | Responds by emitting a 'get_peers' query
								  |
2) Fabricate and "send" a         |
   response to get_peers that     |
   has only compact node info     |
   for 8 nodes                    |
                                  | Responds by emitting another 'get_peers' querys
								  | (an initial group of 4)
								  |
3) pick a node and adjust its time|
   to make it look slow; then     |
   call Tick()                    |
                                  | dht internally notes the slow node and emits
								  | an additional query.
								  |
4) Send a "values" response back  |
   to the dht for each transaction|
   ID that the dht outputs        |
                                  | Issues another get_peers for each response until
								  | all nodes have been contacted.  Then it switches
								  | to issuing "announce_peer" queries (an initial
								  | group of 3)
5) responds with a acknowledgement|
   reply for each announce query  |
                                  |
*/
TEST(TestDhtImplResponse, Announce_Slow_ReplyWithMultipleNodes)
{
	UnitTestUDPSocket socket4;
	UnitTestUDPSocket socket6;
	BencodedDict bDictGetPeer;
	SockAddr sAddr(0x7a7a7a7a,0x7878); // ip = zzzz and socket = xx
	socket4.SetBindAddr(sAddr);
	smart_ptr<DhtImpl> dhtTestObj(new DhtImpl(&socket4, &socket6));
	dhtTestObj->SetSHACallback(&sha1_callback);
	dhtTestObj->_dht_utversion[2] = 'x';
	dhtTestObj->_dht_utversion[3] = 'x';

	// prepare the object for use
	dhtTestObj->Enable(true,0);
	SetDHT_my_id_Bytes(dhtTestObj);

	// put a peer into the dht for it to work with
	DhtPeerID peerID;
	peerID.id.id[0] = '1111'; // 1111
	peerID.id.id[1] = 'BBBB'; // BBBB
	peerID.id.id[2] = 'CCCC'; // CCCC
	peerID.id.id[3] = 'DDDD'; // DDDD
	peerID.id.id[4] = '0000'; // 0000
	peerID.addr.set_port(128);
	peerID.addr.set_addr4(0xf0f0f0f0);
	dhtTestObj->Update(peerID, 0, false);
	Buffer peerIDBuffer;
	peerIDBuffer.len = 20;
	peerIDBuffer.b = (byte*)&peerID.id.id[0];

	DhtID target;
	target.id[0] = 'FFFF'; // FFFF
	target.id[1] = 'GGGG'; // GGGG
	target.id[2] = 'HHHH'; // HHHH
	target.id[3] = 'IIII'; // IIII
	target.id[4] = 'JJJJ'; // JJJJ

	// do this to have the bootstrap ping messages be emitted now.
	// (instead of having them get mixed in with the test data later)
	dhtTestObj->Tick();
	socket4.Reset();

	// make sure the callback dummy is clear
	AddNodesCallbackDummy::Reset();

	// *****************************************************
	// make the dht emit an announce message (the get_peers rpc)
	// *****************************************************
	EXPECT_FALSE(dhtTestObj->IsBusy()) << "The dht should not be busy yet";
	dhtTestObj->DoAnnounce(target, 20, NULL, &AddNodesCallbackDummy::Callback, NULL, "filename.txt", NULL, IDht::announce_non_aggressive);
	EXPECT_TRUE(dhtTestObj->IsBusy()) << "The dht should be busy";

	// *****************************************************
	// grab from the socket the emitted message and extract
	// the transaction ID and verify the remainder of the
	// message
	// *****************************************************
	std::string doAnnounceOutput = socket4.GetSentDataAsString();
	BencEntity bEntityAnounceQuery;
	// verify the bencoded string that went out the socket
	BencEntity::Parse((const byte *)doAnnounceOutput.c_str(), bEntityAnounceQuery, (const byte *)(doAnnounceOutput.c_str() + doAnnounceOutput.length()));

	// get the query dictionary
	BencodedDict *dictForAnnounce = BencodedDict::AsDict(&bEntityAnounceQuery);
	EXPECT_TRUE(dictForAnnounce);
	if (!dictForAnnounce) {
		FAIL() << "ERROR:  The dht did not emit a bencoded dictionary for announce";
	}

	Buffer type;
	type.b = (byte*)dictForAnnounce->GetString("y" ,&type.len);
	ASSERT_EQ(1, type.len) << "ERROR: the 'y' type length is wrong (should be 1 for 'q', 'r', or 'e')";
	ASSERT_EQ('q', type.b[0]) << "ERROR: 'y' type is wrong; should be 'q' for query instead of:  " << type.b[0];

	Buffer command;
	command.b = (byte*)dictForAnnounce->GetString("q" ,&command.len);
	EXPECT_EQ(9, command.len);
	EXPECT_FALSE(memcmp("get_peers", command.b, 9)) << "ERROR: 'q' command is wrong";

	// get the transaction ID to use later
	Buffer tid;
	tid.b = (byte*)dictForAnnounce->GetString("t" ,&tid.len);
	EXPECT_EQ(4, tid.len) << "transaction ID is wrong size";

	// now look into the query data
	BencodedDict *announceQuery = dictForAnnounce->GetDict("a");
	if (!announceQuery) {
		FAIL() << "ERROR:  Failed to extract 'a' dictionary from get_peer response";
	}

	Buffer id;
	id.b = (byte*)announceQuery->GetString("id" ,&id.len);
	EXPECT_EQ(20, id.len);
	EXPECT_FALSE(memcmp("AAAABBBBCCCCDDDDEEEE", id.b, 20)) << "ERROR: announced id is wrong";

	Buffer infoHash;
	infoHash.b = (byte*)announceQuery->GetString("info_hash" ,&infoHash.len);
	EXPECT_EQ(20, infoHash.len);
	EXPECT_FALSE(memcmp("FFFFGGGGHHHHIIIIJJJJ", infoHash.b, 20)) << "ERROR: info_hash is not the correct target";

	// *****************************************************
	// now fabricate a nodes response message using the
	// transaction ID extracted above and include a token
	// *****************************************************
	std::vector<byte>	messageBytes;
	std::vector<byte>	replyDictionaryBytes;

	const char* compactIPs[] = {"bbbb..","cccc..","dddd..","eeee..","ffff..","gggg..","hhhh..","iiii.."};

	std::string responseToken("20_byte_reply_token.");
	// make a string of 8 compact nodes (based on what was designed above)
	std::string nearistNode  ("26_byte_nearist_n008bbbb..26_byte_nearist_n007cccc..26_byte_nearist_n006dddd..26_byte_nearist_n005eeee..26_byte_nearist_n004ffff..26_byte_nearist_n003gggg..26_byte_nearist_n002hhhh..26_byte_nearist_n001iiii..");
	// construct the message bytes
	BencStartDictionary(replyDictionaryBytes);
	{
		BencAddNameValuePair(replyDictionaryBytes,"id",peerIDBuffer);
		BencAddNameValuePair(replyDictionaryBytes,"nodes",nearistNode);
		BencAddNameValuePair(replyDictionaryBytes,"token",responseToken);
	}
	BencEndDictionary(replyDictionaryBytes);

	BencStartDictionary(messageBytes);
	{
		BencAddNameAndBencodedDictionary(messageBytes,"r",replyDictionaryBytes);
		BencAddNameValuePair(messageBytes,"t",tid);
		BencAddNameValuePair(messageBytes,"y","r");
	}
	BencEndDictionary(messageBytes);

	// clear the socket and "send" the reply
	socket4.Reset();
	dhtTestObj->ProcessIncoming((byte*)&messageBytes.front(), messageBytes.size(), peerID.addr);

	EXPECT_TRUE(dhtTestObj->IsBusy()) << "The dht should still be busy";

	// *****************************************************
	// get the bencoded string(s) out of the socket and extract
	// the transaction id's.  The dht should issue an initial burst of queries
	// that are throttled back to one new query for each response received
	// until all nodes have been queried.
	// *****************************************************

	// we are only interested in the transaction ID's
	std::string bencMessage = socket4.GetSentDataAsString();
	std::vector<std::vector<byte> > transactionIDs;
	ASSERT_TRUE(ExtractTransactionIDs(bencMessage, transactionIDs)) << "There was a problem extracting transaction ID's";
	// at this time there should be "#define KADEMLIA_LOOKUP_OUTSTANDING 4" transaction id's for 4 outstanding messages
	EXPECT_EQ(KADEMLIA_LOOKUP_OUTSTANDING + KADEMLIA_LOOKUP_OUTSTANDING_DELTA, transactionIDs.size()) << "Expected (KADEMLIA_LOOKUP_OUTSTANDING + KADEMLIA_LOOKUP_OUTSTANDING_DELTA) transaction IDs but found " << transactionIDs.size() << " instead.";

	// *********************************************************************************
	// Get the request info and make it look like enough time has passed to call it slow.
	// An additional request should be issued.
	// *********************************************************************************
	socket4.Reset();
	DhtRequest* req0 = dhtTestObj->LookupRequest(Read32(&transactionIDs[0][0]));
	req0->time -= 1100;
	dhtTestObj->Tick();

	// get the transaction id out of the additional message
	std::string additionalMessage = socket4.GetSentDataAsString();
	ASSERT_TRUE(additionalMessage.size() != 0) << "no additional message was issued for a slow node";
	std::vector<std::vector<byte> > additionalTid;
	ASSERT_TRUE(ExtractTransactionIDs(additionalMessage, additionalTid)) << "There was a problem extracting the transaction id from the additional message";
	ASSERT_EQ(1,additionalTid.size()) << "expected only one additional message for the slow node";
	transactionIDs.push_back(additionalTid[0]);

	byte bufferBytes[20];
	Buffer nodeID;
	nodeID.b = (byte*)bufferBytes;
	nodeID.len = 20;

	// feed responses back to the dht.
	for(int x=0; x<transactionIDs.size(); ++x)
	{
		socket4.Reset();
		replyDictionaryBytes.clear();
		messageBytes.clear();

		// get the request info out of the dht (since we can)
		DhtRequest *req = dhtTestObj->LookupRequest(Read32(&transactionIDs[x][0]));

		if(req){
			DhtIDToBytes(nodeID.b, req->peer.id);

			// construct a response with a "value"
			BencStartDictionary(replyDictionaryBytes);
			{
				BencAddNameValuePair(replyDictionaryBytes,"id",nodeID);
				BencAddNameValuePair(replyDictionaryBytes,"token",responseToken);
				BencAddString(replyDictionaryBytes,"values");
				BencStartList(replyDictionaryBytes);
				{
					BencAddString(replyDictionaryBytes, compactIPs[x]);
				}
				BencEndList(replyDictionaryBytes);
			}
			BencEndDictionary(replyDictionaryBytes);

			BencStartDictionary(messageBytes);
			{
				BencAddNameAndBencodedDictionary(messageBytes,"r",replyDictionaryBytes);
				BencAddNameValuePair(messageBytes,"t",transactionIDs[x]);
				BencAddNameValuePair(messageBytes,"y","r");
			}
			BencEndDictionary(messageBytes);

			// send the reply
			dhtTestObj->ProcessIncoming((byte*)&messageBytes.front(), messageBytes.size(), req->peer.addr);
		}

		// see if anything went out the socket
		std::string nextString = socket4.GetSentDataAsString();
		// clear the socket
		if((nextString.size() != 0) && (x < transactionIDs.size()-1))
		{
			// get a transaction id and add it to the transactionIDs list
			std::vector<std::vector<byte> > thisTransactionID;
			ASSERT_EQ(true,ExtractTransactionIDs(nextString, thisTransactionID)) << "There was a problem extracting transaction ID's";
			transactionIDs.push_back(thisTransactionID[0]);
		}
	}
	// there should now be 8 (KADEMLIA_K) transaction id's
	EXPECT_EQ(KADEMLIA_K, transactionIDs.size()) << "Expected 8 transaction IDs but found " << transactionIDs.size() << " instead.";

	// after the final reply to the get_peers request is made, since we are responding
	// with "values" the dht will emit the first set of "announce_peer" queries.
	// These should be sitting in the socket
	std::string announceString = socket4.GetSentDataAsString();

	ASSERT_TRUE(ExtractTransactionIDs(announceString, transactionIDs)) << "There was a problem extracting transaction ID's for the announce_peer phase";
	// at this time there should be "#define KADEMLIA_BROADCAST_OUTSTANDING 3" transaction id's for 4 outstanding messages
	EXPECT_EQ(KADEMLIA_BROADCAST_OUTSTANDING, transactionIDs.size()) << "Expected KADEMLIA_BROADCAST_OUTSTANDING transaction IDs but found " << transactionIDs.size() << " instead.";


	// Again, feed responses back to the dht. (this time, replys to the "announce_peers" queries
	for(int x=0; x<transactionIDs.size(); ++x)
	{
		socket4.Reset();
		replyDictionaryBytes.clear();
		messageBytes.clear();

		// get the request info out of the dht (since we can)
		DhtRequest *req = dhtTestObj->LookupRequest(Read32(&transactionIDs[x][0]));

		if(req){
			DhtIDToBytes(nodeID.b, req->peer.id);

			// construct a response with a "value"
			BencStartDictionary(replyDictionaryBytes);
			{
				BencAddNameValuePair(replyDictionaryBytes,"id",nodeID);
			}
			BencEndDictionary(replyDictionaryBytes);

			BencStartDictionary(messageBytes);
			{
				BencAddNameAndBencodedDictionary(messageBytes,"r",replyDictionaryBytes);
				BencAddNameValuePair(messageBytes,"t",transactionIDs[x]);
				BencAddNameValuePair(messageBytes,"y","r");
			}
			BencEndDictionary(messageBytes);

			// send the reply
			dhtTestObj->ProcessIncoming((byte*)&messageBytes.front(), messageBytes.size(), req->peer.addr);
		}

		// see if anything went out the socket
		std::string nextString = socket4.GetSentDataAsString();
		// clear the socket
		if((nextString.size() != 0) && (x < transactionIDs.size()-1))
		{
			// get a transaction id and add it to the transactionIDs list
			std::vector<std::vector<byte> > thisTransactionID;
			ASSERT_TRUE(ExtractTransactionIDs(nextString, thisTransactionID)) << "There was a problem extracting transaction ID's";
			transactionIDs.push_back(thisTransactionID[0]);
		}
	}
	// see that the correct number of announces were emitted
	EXPECT_EQ(KADEMLIA_K_ANNOUNCE, transactionIDs.size()) << "Expected 8 transaction IDs but found " << transactionIDs.size() << " instead.";
	EXPECT_EQ(9, AddNodesCallbackDummy::callbackData.size()) << "9 callback events were expected but there were:  " << AddNodesCallbackDummy::callbackData.size();
}


/**
This test is designed to exercise the scheduling aspect of the dht process with
a "slow" node that then delays to the point of a time-out error.

When first doing the dht lookup using "get_peers" the dht process shoulc issue
an initial burst of 4 queries and follow it up with additional queries and replys
are received until the nodes list is exausted.  There should be no more than 4
active queries in flight at a time (slow peers are excepted).  Once all of the
get_peers queries are complete then it switched to issuing "announce_peer" queries.
An initial burst of 3 queries should be issued followed by additional queries
as replys are received.  No more than 3 announce queries should be in flight at
a time.

          Test                    |                  DHT
----------------------------------|--------------------------------------------
1) invoke doAnnounce()            |
                                  | Responds by emitting a 'get_peers' query
								  |
2) Fabricate and "send" a         |
   response to get_peers that     |
   has only compact node info     |
   for 8 nodes                    |
                                  | Responds by emitting another 'get_peers' querys
								  | (an initial group of 4)
								  |
3) pick a node and adjust its time|
   to make it look slow; then     |
   call Tick()                    |
                                  | dht intarnally notes the slow node and emits
								  | an additional query.
								  |
4) adjust the time of the same    |
   node to have it time-out       |
                                  | dht marks the node as errored.  it should not
								  | issue another request since it should have 4
								  | outstanding good (non-slow) requests in flight
								  |
3) Send a "values" response back  |
   to the dht for each transaction|
   ID that the dht outputs        |
                                  | Issues another get_peers for each response until
								  | all nodes have been contacted.  Then it switches
								  | to issuing "announce_peer" queries (an initial
								  | group of 3)
4) responds with a acknowledgement|
   reply for each announce query  |
                                  |
*/
TEST(TestDhtImplResponse, Announce_TimeOut_ReplyWithMultipleNodes)
{
	UnitTestUDPSocket socket4;
	UnitTestUDPSocket socket6;
	BencodedDict bDictGetPeer;
	SockAddr sAddr(0x7a7a7a7a,0x7878); // ip = zzzz and socket = xx
	socket4.SetBindAddr(sAddr);
	smart_ptr<DhtImpl> dhtTestObj(new DhtImpl(&socket4, &socket6));
	dhtTestObj->SetSHACallback(&sha1_callback);
	dhtTestObj->_dht_utversion[2] = 'x';
	dhtTestObj->_dht_utversion[3] = 'x';

	// prepare the object for use
	dhtTestObj->Enable(true,0);
	SetDHT_my_id_Bytes(dhtTestObj);

	// put a peer into the dht for it to work with
	DhtPeerID peerID;
	peerID.id.id[0] = '1111'; // 1111
	peerID.id.id[1] = 'BBBB'; // BBBB
	peerID.id.id[2] = 'CCCC'; // CCCC
	peerID.id.id[3] = 'DDDD'; // DDDD
	peerID.id.id[4] = '0000'; // 0000
	peerID.addr.set_port(128);
	peerID.addr.set_addr4(0xf0f0f0f0);
	dhtTestObj->Update(peerID, 0, false);
	Buffer peerIDBuffer;
	peerIDBuffer.len = 20;
	peerIDBuffer.b = (byte*)&peerID.id.id[0];

	DhtID target;
	target.id[0] = 'FFFF'; // FFFF
	target.id[1] = 'GGGG'; // GGGG
	target.id[2] = 'HHHH'; // HHHH
	target.id[3] = 'IIII'; // IIII
	target.id[4] = 'JJJJ'; // JJJJ

	// do this to have the bootstrap ping messages be emitted now.
	// (instead of having them get mixed in with the test data later)
	dhtTestObj->Tick();
	socket4.Reset();

	// make sure the callback dummy is clear
	AddNodesCallbackDummy::Reset();

	// *****************************************************
	// make the dht emit an announce message (the get_peers rpc)
	// *****************************************************
	EXPECT_FALSE(dhtTestObj->IsBusy()) << "The dht should not be busy yet";
	dhtTestObj->DoAnnounce(target, 20, NULL, &AddNodesCallbackDummy::Callback, NULL, "filename.txt", NULL, 0);
	EXPECT_TRUE(dhtTestObj->IsBusy()) << "The dht should be busy";

	// *****************************************************
	// grab from the socket the emitted message and extract
	// the transaction ID and verify the remainder of the
	// message
	// *****************************************************
	std::string doAnnounceOutput = socket4.GetSentDataAsString();
	BencEntity bEntityAnounceQuery;
	// verify the bencoded string that went out the socket
	BencEntity::Parse((const byte *)doAnnounceOutput.c_str(), bEntityAnounceQuery, (const byte *)(doAnnounceOutput.c_str() + doAnnounceOutput.length()));

	// get the query dictionary
	BencodedDict *dictForAnnounce = BencodedDict::AsDict(&bEntityAnounceQuery);
	EXPECT_TRUE(dictForAnnounce);
	if (!dictForAnnounce) {
		FAIL() << "ERROR:  The dht did not emit a bencoded dictionary for announce";
	}

	Buffer type;
	type.b = (byte*)dictForAnnounce->GetString("y" ,&type.len);
	ASSERT_EQ(1, type.len) << "ERROR: the 'y' type length is wrong (should be 1 for 'q', 'r', or 'e')";
	ASSERT_EQ('q', type.b[0]) << "ERROR: 'y' type is wrong; should be 'q' for query instead of:  " << type.b[0];

	Buffer command;
	command.b = (byte*)dictForAnnounce->GetString("q" ,&command.len);
	EXPECT_EQ(9, command.len);
	EXPECT_FALSE(memcmp("get_peers", command.b, 9)) << "ERROR: 'q' command is wrong";

	// get the transaction ID to use later
	Buffer tid;
	tid.b = (byte*)dictForAnnounce->GetString("t" ,&tid.len);
	EXPECT_EQ(4, tid.len) << "transaction ID is wrong size";

	// now look into the query data
	BencodedDict *announceQuery = dictForAnnounce->GetDict("a");
	if (!announceQuery) {
		FAIL() << "ERROR:  Failed to extract 'a' dictionary from get_peer response";
	}

	Buffer id;
	id.b = (byte*)announceQuery->GetString("id" ,&id.len);
	EXPECT_EQ(20, id.len);
	EXPECT_FALSE(memcmp("AAAABBBBCCCCDDDDEEEE", id.b, 20)) << "ERROR: announced id is wrong";

	Buffer infoHash;
	infoHash.b = (byte*)announceQuery->GetString("info_hash" ,&infoHash.len);
	EXPECT_EQ(20, infoHash.len);
	EXPECT_FALSE(memcmp("FFFFGGGGHHHHIIIIJJJJ", infoHash.b, 20)) << "ERROR: info_hash is not the correct target";

	// *****************************************************
	// now fabricate a nodes response message using the
	// transaction ID extracted above and include a token
	// *****************************************************
	std::vector<byte>	messageBytes;
	std::vector<byte>	replyDictionaryBytes;

	const char* compactIPs[] = {"bbbb..","cccc..","dddd..","eeee..","ffff..","gggg..","hhhh..","iiii.."};

	std::string responseToken("20_byte_reply_token.");
	// make a string of 8 compact nodes (based on what was designed above)
	std::string nearistNode  ("26_byte_nearist_n008bbbb..26_byte_nearist_n007cccc..26_byte_nearist_n006dddd..26_byte_nearist_n005eeee..26_byte_nearist_n004ffff..26_byte_nearist_n003gggg..26_byte_nearist_n002hhhh..26_byte_nearist_n001iiii..");
	// construct the message bytes
	BencStartDictionary(replyDictionaryBytes);
	{
		BencAddNameValuePair(replyDictionaryBytes,"id",peerIDBuffer);
		BencAddNameValuePair(replyDictionaryBytes,"nodes",nearistNode);
		BencAddNameValuePair(replyDictionaryBytes,"token",responseToken);
	}
	BencEndDictionary(replyDictionaryBytes);

	BencStartDictionary(messageBytes);
	{
		BencAddNameAndBencodedDictionary(messageBytes,"r",replyDictionaryBytes);
		BencAddNameValuePair(messageBytes,"t",tid);
		BencAddNameValuePair(messageBytes,"y","r");
	}
	BencEndDictionary(messageBytes);

	// clear the socket and "send" the reply
	socket4.Reset();
	dhtTestObj->ProcessIncoming((byte*)&messageBytes.front(), messageBytes.size(), peerID.addr);

	EXPECT_TRUE(dhtTestObj->IsBusy()) << "The dht should still be busy";

	// *****************************************************
	// get the bencoded string(s) out of the socket and extract
	// the transaction id's.  The dht should issue an initial burst of queries
	// that are throttled back to one new query for each response received
	// until all nodes have been queried.
	// *****************************************************

	// we are only interested in the transaction ID's
	std::string bencMessage = socket4.GetSentDataAsString();
	std::vector<std::vector<byte> > transactionIDs;
	ASSERT_TRUE(ExtractTransactionIDs(bencMessage, transactionIDs)) << "There was a problem extracting transaction ID's";
	// at this time there should be "#define KADEMLIA_LOOKUP_OUTSTANDING 4" transaction id's for 4 outstanding messages
	EXPECT_EQ(KADEMLIA_LOOKUP_OUTSTANDING, transactionIDs.size()) << "Expected KADEMLIA_LOOKUP_OUTSTANDING transaction IDs but found " << transactionIDs.size() << " instead.";

	// *********************************************************************************
	// Get the request info and make it look like enough time has passed to call it slow.
	// An additional request should be issued.
	// *********************************************************************************
	socket4.Reset();
	DhtRequest* req0 = dhtTestObj->LookupRequest(Read32(&transactionIDs[0][0]));
	req0->time -= 1100;
	dhtTestObj->Tick();

	// get the transaction id out of the additional message
	std::string additionalMessage = socket4.GetSentDataAsString();
	ASSERT_TRUE(additionalMessage.size() != 0) << "no additional message was issued for a slow node";
	std::vector<std::vector<byte> > additionalTid;
	ASSERT_TRUE(ExtractTransactionIDs(additionalMessage, additionalTid)) << "There was a problem extracting the transaction id from the additional message";
	ASSERT_EQ(1,additionalTid.size()) << "expected only one additional message for the slow node";
	transactionIDs.push_back(additionalTid[0]);

	// now make it look like the request timed out (an additonal message should be sent)
	socket4.Reset();
	req0->time -= 4000;
	dhtTestObj->Tick();

	// get the transaction id out of the additional message
	std::string additionalMessage2 = socket4.GetSentDataAsString();
	ASSERT_EQ(0,additionalMessage2.size()) << "An additional message was issued for a timed-out node when no message was expected";

	// now follow through with the regular feeding of node info back to the dht
	byte bufferBytes[20];
	Buffer nodeID;
	nodeID.b = (byte*)bufferBytes;
	nodeID.len = 20;
	// feed responses back to the dht.
	for(int x=0; x<transactionIDs.size(); ++x)
	{
		socket4.Reset();
		replyDictionaryBytes.clear();
		messageBytes.clear();

		// get the request info out of the dht (since we can)
		DhtRequest *req = dhtTestObj->LookupRequest(Read32(&transactionIDs[x][0]));

		if(req){
			DhtIDToBytes(nodeID.b, req->peer.id);

			// construct a response with a "value"
			BencStartDictionary(replyDictionaryBytes);
			{
				BencAddNameValuePair(replyDictionaryBytes,"id",nodeID);
				BencAddNameValuePair(replyDictionaryBytes,"token",responseToken);
				BencAddString(replyDictionaryBytes,"values");
				BencStartList(replyDictionaryBytes);
				{
					BencAddString(replyDictionaryBytes, compactIPs[x]);
				}
				BencEndList(replyDictionaryBytes);
			}
			BencEndDictionary(replyDictionaryBytes);

			BencStartDictionary(messageBytes);
			{
				BencAddNameAndBencodedDictionary(messageBytes,"r",replyDictionaryBytes);
				BencAddNameValuePair(messageBytes,"t",transactionIDs[x]);
				BencAddNameValuePair(messageBytes,"y","r");
			}
			BencEndDictionary(messageBytes);

			// send the reply
			dhtTestObj->ProcessIncoming((byte*)&messageBytes.front(), messageBytes.size(), req->peer.addr);
		}

		// see if anything went out the socket
		std::string nextString = socket4.GetSentDataAsString();
		// clear the socket
		if((nextString.size() != 0) && (x < transactionIDs.size()-1))
		{
			// get a transaction id and add it to the transactionIDs list
			std::vector<std::vector<byte> > thisTransactionID;
			ASSERT_EQ(true,ExtractTransactionIDs(nextString, thisTransactionID)) << "There was a problem extracting transaction ID's";
			transactionIDs.push_back(thisTransactionID[0]);
		}
	}
	// there should now be 8 (KADEMLIA_K) transaction id's
	EXPECT_EQ(KADEMLIA_K, transactionIDs.size()) << "Expected 8 transaction IDs but found " << transactionIDs.size() << " instead.";

	// after the final reply to the get_peers request is made, since we are responding
	// with "values" the dht will emit the first set of "announce_peer" queries.
	// These should be sitting in the socket
	std::string announceString = socket4.GetSentDataAsString();

	ASSERT_TRUE(ExtractTransactionIDs(announceString, transactionIDs)) << "There was a problem extracting transaction ID's for the announce_peer phase";
	// at this time there should be "#define KADEMLIA_BROADCAST_OUTSTANDING 3" transaction id's for 4 outstanding messages
	EXPECT_EQ(KADEMLIA_BROADCAST_OUTSTANDING, transactionIDs.size()) << "Expected KADEMLIA_BROADCAST_OUTSTANDING transaction IDs but found " << transactionIDs.size() << " instead.";


	// Again, feed responses back to the dht. (this time, replys to the "announce_peers" queries
	for(int x=0; x<transactionIDs.size(); ++x)
	{
		socket4.Reset();
		replyDictionaryBytes.clear();
		messageBytes.clear();

		// get the request info out of the dht (since we can)
		DhtRequest *req = dhtTestObj->LookupRequest(Read32(&transactionIDs[x][0]));

		if(req){
			DhtIDToBytes(nodeID.b, req->peer.id);

			// construct a response with a "value"
			BencStartDictionary(replyDictionaryBytes);
			{
				BencAddNameValuePair(replyDictionaryBytes,"id",nodeID);
			}
			BencEndDictionary(replyDictionaryBytes);

			BencStartDictionary(messageBytes);
			{
				BencAddNameAndBencodedDictionary(messageBytes,"r",replyDictionaryBytes);
				BencAddNameValuePair(messageBytes,"t",transactionIDs[x]);
				BencAddNameValuePair(messageBytes,"y","r");
			}
			BencEndDictionary(messageBytes);

			// send the reply
			dhtTestObj->ProcessIncoming((byte*)&messageBytes.front(), messageBytes.size(), req->peer.addr);
		}

		// see if anything went out the socket
		std::string nextString = socket4.GetSentDataAsString();
		// clear the socket
		if((nextString.size() != 0) && (x < transactionIDs.size()-1))
		{
			// get a transaction id and add it to the transactionIDs list
			std::vector<std::vector<byte> > thisTransactionID;
			ASSERT_TRUE(ExtractTransactionIDs(nextString, thisTransactionID)) << "There was a problem extracting transaction ID's";
			transactionIDs.push_back(thisTransactionID[0]);
		}
	}
	// see that the correct number of announces were emitted
	EXPECT_EQ(KADEMLIA_K_ANNOUNCE, transactionIDs.size()) << "Expected 8 transaction IDs but found " << transactionIDs.size() << " instead.";
	// since we caused one node to have a time-out error, there should only be 8 callback events (instead of 9)
	EXPECT_EQ(8, AddNodesCallbackDummy::callbackData.size()) << "8 callback events were expected but there were:  " << AddNodesCallbackDummy::callbackData.size();
}


/**
This test is designed to exercise the scheduling aspect of the dht process with
a "slow" node.

When first doing the dht lookup using "get_peers" the dht process shoulc issue
an initial burst of 4 queries and follow it up with additional queries and replys
are received until the nodes list is exausted.  There should be no more than 4
active queries in flight at a time (slow peers are excepted).  Once all of the
get_peers queries are complete then it switched to issuing "announce_peer" queries.
An initial burst of 3 queries should be issued followed by additional queries
as replys are received.  No more than 3 announce queries should be in flight at
a time.

          Test                    |                  DHT
----------------------------------|--------------------------------------------
1) invoke doAnnounce()            |
                                  | Responds by emitting a 'get_peers' query
								  |
2) Fabricate and "send" a         |
   response to get_peers that     |
   has only compact node info     |
   for 8 nodes                    |
                                  | Responds by emitting another 'get_peers' querys
								  | (an initial group of 4)
								  |
3) pick a node and submit an ICMP |
   error as a response.           |
                                  | dht intarnally notes the errored node and emits
								  | an additional query.
								  |
4) Send a "values" response back  |
   to the dht for each transaction|
   ID that the dht outputs        |
                                  | Issues another get_peers for each response until
								  | all nodes have been contacted.  Then it switches
								  | to issuing "announce_peer" queries (an initial
								  | group of 3)
5) responds with a acknowledgement|
   reply for each announce query  |
                                  |
*/
TEST(TestDhtImplResponse, Announce_ICMPerror_ReplyWithMultipleNodes)
{
	UnitTestUDPSocket socket4;
	UnitTestUDPSocket socket6;
	BencodedDict bDictGetPeer;
	SockAddr sAddr(0x7a7a7a7a,0x7878); // ip = zzzz and socket = xx
	socket4.SetBindAddr(sAddr);
	smart_ptr<DhtImpl> dhtTestObj(new DhtImpl(&socket4, &socket6));
	dhtTestObj->SetSHACallback(&sha1_callback);
	dhtTestObj->_dht_utversion[2] = 'x';
	dhtTestObj->_dht_utversion[3] = 'x';

	// prepare the object for use
	dhtTestObj->Enable(true,0);
	SetDHT_my_id_Bytes(dhtTestObj);

	// put a peer into the dht for it to work with
	DhtPeerID peerID;
	peerID.id.id[0] = '1111'; // 1111
	peerID.id.id[1] = 'BBBB'; // BBBB
	peerID.id.id[2] = 'CCCC'; // CCCC
	peerID.id.id[3] = 'DDDD'; // DDDD
	peerID.id.id[4] = '0000'; // 0000
	peerID.addr.set_port(128);
	peerID.addr.set_addr4(0xf0f0f0f0);
	dhtTestObj->Update(peerID, 0, false);
	Buffer peerIDBuffer;
	peerIDBuffer.len = 20;
	peerIDBuffer.b = (byte*)&peerID.id.id[0];

	DhtID target;
	target.id[0] = 'FFFF'; // FFFF
	target.id[1] = 'GGGG'; // GGGG
	target.id[2] = 'HHHH'; // HHHH
	target.id[3] = 'IIII'; // IIII
	target.id[4] = 'JJJJ'; // JJJJ

	// do this to have the bootstrap ping messages be emitted now.
	// (instead of having them get mixed in with the test data later)
	dhtTestObj->Tick();
	socket4.Reset();

	// make sure the callback dummy is clear
	AddNodesCallbackDummy::Reset();

	// *****************************************************
	// make the dht emit an announce message (the get_peers rpc)
	// *****************************************************
	EXPECT_FALSE(dhtTestObj->IsBusy()) << "The dht should not be busy yet";
	dhtTestObj->DoAnnounce(target, 20, NULL, &AddNodesCallbackDummy::Callback, NULL, "filename.txt", NULL, 0);
	EXPECT_TRUE(dhtTestObj->IsBusy()) << "The dht should be busy";

	// *****************************************************
	// grab from the socket the emitted message and extract
	// the transaction ID and verify the remainder of the
	// message
	// *****************************************************
	std::string doAnnounceOutput = socket4.GetSentDataAsString();
	BencEntity bEntityAnounceQuery;
	// verify the bencoded string that went out the socket
	BencEntity::Parse((const byte *)doAnnounceOutput.c_str(), bEntityAnounceQuery, (const byte *)(doAnnounceOutput.c_str() + doAnnounceOutput.length()));

	// get the query dictionary
	BencodedDict *dictForAnnounce = BencodedDict::AsDict(&bEntityAnounceQuery);
	EXPECT_TRUE(dictForAnnounce);
	if (!dictForAnnounce) {
		FAIL() << "ERROR:  The dht did not emit a bencoded dictionary for announce";
	}

	Buffer type;
	type.b = (byte*)dictForAnnounce->GetString("y" ,&type.len);
	ASSERT_EQ(1, type.len) << "ERROR: the 'y' type length is wrong (should be 1 for 'q', 'r', or 'e')";
	ASSERT_EQ('q', type.b[0]) << "ERROR: 'y' type is wrong; should be 'q' for query instead of:  " << type.b[0];

	Buffer command;
	command.b = (byte*)dictForAnnounce->GetString("q" ,&command.len);
	EXPECT_EQ(9, command.len);
	EXPECT_FALSE(memcmp("get_peers", command.b, 9)) << "ERROR: 'q' command is wrong";

	// get the transaction ID to use later
	Buffer tid;
	tid.b = (byte*)dictForAnnounce->GetString("t" ,&tid.len);
	EXPECT_EQ(4, tid.len) << "transaction ID is wrong size";

	// now look into the query data
	BencodedDict *announceQuery = dictForAnnounce->GetDict("a");
	if (!announceQuery) {
		FAIL() << "ERROR:  Failed to extract 'a' dictionary from get_peer response";
	}

	Buffer id;
	id.b = (byte*)announceQuery->GetString("id" ,&id.len);
	EXPECT_EQ(20, id.len);
	EXPECT_FALSE(memcmp("AAAABBBBCCCCDDDDEEEE", id.b, 20)) << "ERROR: announced id is wrong";

	Buffer infoHash;
	infoHash.b = (byte*)announceQuery->GetString("info_hash" ,&infoHash.len);
	EXPECT_EQ(20, infoHash.len);
	EXPECT_FALSE(memcmp("FFFFGGGGHHHHIIIIJJJJ", infoHash.b, 20)) << "ERROR: info_hash is not the correct target";

	// *****************************************************
	// now fabricate a nodes response message using the
	// transaction ID extracted above and include a token
	// *****************************************************
	std::vector<byte>	messageBytes;
	std::vector<byte>	replyDictionaryBytes;

	const char* compactIPs[] = {"bbbb..","cccc..","dddd..","eeee..","ffff..","gggg..","hhhh..","iiii.."};

	std::string responseToken("20_byte_reply_token.");
	// make a string of 8 compact nodes (based on what was designed above)
	std::string nearistNode  ("26_byte_nearist_n008bbbb..26_byte_nearist_n007cccc..26_byte_nearist_n006dddd..26_byte_nearist_n005eeee..26_byte_nearist_n004ffff..26_byte_nearist_n003gggg..26_byte_nearist_n002hhhh..26_byte_nearist_n001iiii..");
	// construct the message bytes
	BencStartDictionary(replyDictionaryBytes);
	{
		BencAddNameValuePair(replyDictionaryBytes,"id",peerIDBuffer);
		BencAddNameValuePair(replyDictionaryBytes,"nodes",nearistNode);
		BencAddNameValuePair(replyDictionaryBytes,"token",responseToken);
	}
	BencEndDictionary(replyDictionaryBytes);

	BencStartDictionary(messageBytes);
	{
		BencAddNameAndBencodedDictionary(messageBytes,"r",replyDictionaryBytes);
		BencAddNameValuePair(messageBytes,"t",tid);
		BencAddNameValuePair(messageBytes,"y","r");
	}
	BencEndDictionary(messageBytes);

	// clear the socket and "send" the reply
	socket4.Reset();
	dhtTestObj->ProcessIncoming((byte*)&messageBytes.front(), messageBytes.size(), peerID.addr);

	EXPECT_TRUE(dhtTestObj->IsBusy()) << "The dht should still be busy";

	// *****************************************************
	// get the bencoded string(s) out of the socket and extract
	// the transaction id's.  The dht should issue an initial burst of queries
	// that are throttled back to one new query for each response received
	// until all nodes have been queried.
	// *****************************************************

	// we are only interested in the transaction ID's
	std::string bencMessage = socket4.GetSentDataAsString();
	std::vector<std::vector<byte> > transactionIDs;
	ASSERT_TRUE(ExtractTransactionIDs(bencMessage, transactionIDs)) << "There was a problem extracting transaction ID's";
	// at this time there should be "#define KADEMLIA_LOOKUP_OUTSTANDING 4" transaction id's for 4 outstanding messages
	EXPECT_EQ(KADEMLIA_LOOKUP_OUTSTANDING, transactionIDs.size()) << "Expected KADEMLIA_LOOKUP_OUTSTANDING transaction IDs but found " << transactionIDs.size() << " instead.";

	// *********************************************************************************
	// Get the request info and make it look like enough time has passed to call it slow.
	// An additional request should be issued.  Capture this additional request and
	// feed it back as an ICMP error
	// *********************************************************************************
	socket4.Reset();
	DhtRequest* req0 = dhtTestObj->LookupRequest(Read32(&transactionIDs[0][0]));
	req0->time -= 1100;
	dhtTestObj->Tick();

	// get the transaction id out of the additional message
	std::string additionalMessage = socket4.GetSentDataAsString();
	ASSERT_TRUE(additionalMessage.size() != 0) << "no additional message was issued for a slow node";
	std::vector<std::vector<byte> > additionalTid;
	ASSERT_TRUE(ExtractTransactionIDs(additionalMessage, additionalTid)) << "There was a problem extracting the transaction id from the additional message";
	ASSERT_EQ(1,additionalTid.size()) << "expected only one additional message for the slow node";
	transactionIDs.push_back(additionalTid[0]); // this should be ignored after the icmp error
	// do the ICMP error
	BencEntity bEntity2;
	DhtRequest* reqICMP = dhtTestObj->LookupRequest(Read32(&additionalTid[0][0]));
	BencEntity::Parse((const byte *)additionalMessage.c_str(), bEntity2, (const byte *)(additionalMessage.c_str() + additionalMessage.length()));
	socket4.Reset();
	EXPECT_TRUE(dhtTestObj->ParseIncomingICMP(bEntity2, reqICMP->peer.addr));
	// get the tid out of the message issued in response to the icmp error
	std::string additionalMessage2 = socket4.GetSentDataAsString();
	ASSERT_TRUE(additionalMessage2.size() != 0) << "no additional message was issued for an ICMP error";
	std::vector<std::vector<byte> > additionalTid2;
	ASSERT_TRUE(ExtractTransactionIDs(additionalMessage2, additionalTid2)) << "There was a problem extracting the transaction id from the additional message";
	ASSERT_EQ(1,additionalTid2.size()) << "expected only one additional message for the ICMP error";
	transactionIDs.push_back(additionalTid2[0]);

	// follow through responding to the remainder of the requests
	byte bufferBytes[20];
	Buffer nodeID;
	nodeID.b = (byte*)bufferBytes;
	nodeID.len = 20;
	// feed responses back to the dht.
	for(int x=0; x<transactionIDs.size(); ++x)
	{
		socket4.Reset();
		replyDictionaryBytes.clear();
		messageBytes.clear();

		// get the request info out of the dht (since we can)
		DhtRequest *req = dhtTestObj->LookupRequest(Read32(&transactionIDs[x][0]));

		if(req){
			DhtIDToBytes(nodeID.b, req->peer.id);

			// construct a response with a "value"
			BencStartDictionary(replyDictionaryBytes);
			{
				BencAddNameValuePair(replyDictionaryBytes,"id",nodeID);
				BencAddNameValuePair(replyDictionaryBytes,"token",responseToken);
				BencAddString(replyDictionaryBytes,"values");
				BencStartList(replyDictionaryBytes);
				{
					BencAddString(replyDictionaryBytes, compactIPs[x]);
				}
				BencEndList(replyDictionaryBytes);
			}
			BencEndDictionary(replyDictionaryBytes);

			BencStartDictionary(messageBytes);
			{
				BencAddNameAndBencodedDictionary(messageBytes,"r",replyDictionaryBytes);
				BencAddNameValuePair(messageBytes,"t",transactionIDs[x]);
				BencAddNameValuePair(messageBytes,"y","r");
			}
			BencEndDictionary(messageBytes);

			// send the reply
			dhtTestObj->ProcessIncoming((byte*)&messageBytes.front(), messageBytes.size(), req->peer.addr);
		}

		// see if anything went out the socket
		std::string nextString = socket4.GetSentDataAsString();
		// clear the socket
		if((nextString.size() != 0) && (x < transactionIDs.size()-1))
		{
			// get a transaction id and add it to the transactionIDs list
			std::vector<std::vector<byte> > thisTransactionID;
			ASSERT_EQ(true,ExtractTransactionIDs(nextString, thisTransactionID)) << "There was a problem extracting transaction ID's";
			transactionIDs.push_back(thisTransactionID[0]);
		}
	}
	// there should now be 8 (KADEMLIA_K) transaction id's
	EXPECT_EQ(KADEMLIA_K, transactionIDs.size()) << "Expected 8 transaction IDs but found " << transactionIDs.size() << " instead.";

	// after the final reply to the get_peers request is made, since we are responding
	// with "values" the dht will emit the first set of "announce_peer" queries.
	// These should be sitting in the socket
	std::string announceString = socket4.GetSentDataAsString();

	ASSERT_TRUE(ExtractTransactionIDs(announceString, transactionIDs)) << "There was a problem extracting transaction ID's for the announce_peer phase";
	// at this time there should be "#define KADEMLIA_BROADCAST_OUTSTANDING 3" transaction id's for 4 outstanding messages
	EXPECT_EQ(KADEMLIA_BROADCAST_OUTSTANDING, transactionIDs.size()) << "Expected KADEMLIA_BROADCAST_OUTSTANDING transaction IDs but found " << transactionIDs.size() << " instead.";


	// Again, feed responses back to the dht. (this time, replys to the "announce_peers" queries
	for(int x=0; x<transactionIDs.size(); ++x)
	{
		socket4.Reset();
		replyDictionaryBytes.clear();
		messageBytes.clear();

		// get the request info out of the dht (since we can)
		DhtRequest *req = dhtTestObj->LookupRequest(Read32(&transactionIDs[x][0]));

		if(req){
			DhtIDToBytes(nodeID.b, req->peer.id);

			// construct a response with a "value"
			BencStartDictionary(replyDictionaryBytes);
			{
				BencAddNameValuePair(replyDictionaryBytes,"id",nodeID);
			}
			BencEndDictionary(replyDictionaryBytes);

			BencStartDictionary(messageBytes);
			{
				BencAddNameAndBencodedDictionary(messageBytes,"r",replyDictionaryBytes);
				BencAddNameValuePair(messageBytes,"t",transactionIDs[x]);
				BencAddNameValuePair(messageBytes,"y","r");
			}
			BencEndDictionary(messageBytes);

			// send the reply
			dhtTestObj->ProcessIncoming((byte*)&messageBytes.front(), messageBytes.size(), req->peer.addr);
		}

		// see if anything went out the socket
		std::string nextString = socket4.GetSentDataAsString();
		// clear the socket
		if((nextString.size() != 0) && (x < transactionIDs.size()-1))
		{
			// get a transaction id and add it to the transactionIDs list
			std::vector<std::vector<byte> > thisTransactionID;
			ASSERT_TRUE(ExtractTransactionIDs(nextString, thisTransactionID)) << "There was a problem extracting transaction ID's";
			transactionIDs.push_back(thisTransactionID[0]);
		}
	}
	// see that the correct number of announces were emitted
	EXPECT_EQ(KADEMLIA_K_ANNOUNCE, transactionIDs.size()) << "Expected 8 transaction IDs but found " << transactionIDs.size() << " instead.";
	// since we caused one node to have an ICMP error, there should only be 8 callback events (instead of 9)
	EXPECT_EQ(8, AddNodesCallbackDummy::callbackData.size()) << "8 callback events were expected but there were:  " << AddNodesCallbackDummy::callbackData.size();
}
