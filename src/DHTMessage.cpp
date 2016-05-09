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

#include <string.h> // for strlen

#include <utility> // for std::pair

#include "DHTMessage.h"
#include "bencoding.h"

/**
 This version of DecodeMessageData() will extract a 'v' region.  The region
 values will be assigned to vBuf once it has been determined that this message
 is a 'put' query.
*/
void DHTMessage::DecodeMessageData(byte* bencMessageBytes, int numBytes)
{
	std::vector<const char*> keys;
	keys.push_back("a\0v\0");
	keys.push_back("r\0v\0");
	if(!BencEntity::ParseInPlace(bencMessageBytes, *_bDict, bencMessageBytes + numBytes, keys, &region)){
		_parseSuccessful = false;
		dhtMessageType = DHT_UNDEFINED_MESSAGE;
		return;
	}
	_parseSuccessful = true;
	DecodeMessageData(*_bDict);
}

DHTMessage::DHTMessage(byte* bencMessageBytes, int numBytes)
{
	Init();
	_bDict = new BencodedDict;
	DecodeMessageData(bencMessageBytes, numBytes);
}

DHTMessage::~DHTMessage()
{
	delete _bDict;
}

void DHTMessage::Init()
{
	replyDict = _bDict = NULL;
	_argumentsAreValid = _parseSuccessful = false;
	dhtMessageType = DHT_UNDEFINED_MESSAGE;
	dhtCommand = DHT_QUERY_UNDEFINED;
	type = command = NULL;
	id = NULL;
	args = NULL;
	read_only = false;
	region.first = region.second = NULL;
	portNum = vote = seed = scrape = noseed = sequenceNum = 0;
	error_code = 0;
	error_message = NULL;
	impliedPort = 0;
	_bDictForUser = NULL;
}

/** This version of DecodeMessageData() can NOT extract a 'v' region
since the original string has already been parsed outside the scope of this object. */
void DHTMessage::DecodeMessageData(BencodedDict &bDict)
{
	_bDictForUser = &bDict;

	// if not a dictionary, it's not a valid DHT RPC
	if(bDict.GetType() != BENC_DICT)
	{
		_parseSuccessful = false;
		dhtMessageType = DHT_UNDEFINED_MESSAGE;
		return;
	}
	_parseSuccessful = true;

	// extract the components common to all DHT messages
	transactionID.b = (byte*)bDict.GetString("t", &transactionID.len);
	version.b = (byte*)bDict.GetString("v", &version.len);
	external_ip.b = (byte*)bDict.GetString("ip", &external_ip.len);
	read_only = bDict.GetInt("ro", 0) != 0;

	type = bDict.GetString("y", 1);
	if (!type)
		return;

	switch(*type)
	{
		case 'q':
		{
			dhtMessageType = DHT_QUERY;
			DecodeQuery(bDict);
			break;
		}
		case 'r':
		{
			// Just extract the reply dictionary.  Specific elements can be
			// extracted further down the call chain once it is known what
			// specific query this is a reply to.
			replyDict = bDict.GetDict("r");
			if(replyDict){
				id = (byte*)replyDict->GetString("id", DHT_ID_SIZE);
				dhtMessageType = DHT_RESPONSE;
				sequenceNum = replyDict->GetInt("seq", 1);
				vBuf.len = region.second - region.first;
				vBuf.b = region.first;
				signature.b = (byte*)replyDict->GetString("sig", &signature.len);
				key.b = (byte*)replyDict->GetString("k", &key.len);
			}
			else {
				dhtMessageType = DHT_UNDEFINED_MESSAGE;
			}

			break;
		}
		case 'e':
		{
			dhtMessageType = DHT_ERROR;
			DecodeError(bDict);
			break;
		}
		default:
			dhtMessageType = DHT_UNDEFINED_MESSAGE;
	}
}

void DHTMessage::DecodeError(BencodedDict &bDict) {
	BencodedList* l = bDict.GetList("e");
	if (l != NULL) {
		error_code = l->GetInt(0);
		error_message = l->GetString(1);
	}
}

void DHTMessage::DecodeQuery(BencodedDict &bDict)
{
	// Handle a query from a peer
	command = bDict.GetString("q");
	if (!command) {
		dhtCommand = DHT_QUERY_UNDEFINED;
		return; // bad/missing command.
	}

	// get the arguments dictionary
	args = bDict.GetDict("a");
	if (!args) {
		_argumentsAreValid = false;
		return; // bad/missing argument.
	}
	_argumentsAreValid = true;
	id = (byte*)args->GetString("id", DHT_ID_SIZE);

	// set the command enum and extract only arguments used by the command
	if(strcmp(command,"find_node") == 0){
		dhtCommand = DHT_QUERY_FIND_NODE;
		target.b = (byte*)args->GetString("target", &target.len);
		if (target.len != DHT_ID_SIZE) _argumentsAreValid = false;
	}
	else if(strcmp(command,"get_peers") == 0){
		dhtCommand = DHT_QUERY_GET_PEERS;
		infoHash.b = (byte*)args->GetString("info_hash", &infoHash.len);
		if (infoHash.len != DHT_ID_SIZE) _argumentsAreValid = false;
		filename.b = (byte*)args->GetString("name", &filename.len);
		scrape = args->GetInt("scrape", 0);
		noseed = args->GetInt("noseed", 0);
	}
	else if(strcmp(command,"announce_peer") == 0){
		dhtCommand = DHT_QUERY_ANNOUNCE_PEER;
		infoHash.b = (byte*)args->GetString("info_hash", &infoHash.len);
		if (infoHash.len != DHT_ID_SIZE) _argumentsAreValid = false;
		portNum = args->GetInt("port", -1);
		token.b = (byte*)args->GetString("token", &token.len);
		filename.b = (byte*)args->GetString("name", &filename.len);
		seed = args->GetInt("seed", 0);
		impliedPort = args->GetInt("implied_port", 0);
	}
	else if(strcmp(command,"vote") == 0){
		dhtCommand = DHT_QUERY_VOTE;
		target.b = (byte*)args->GetString("target", &target.len);
		if (target.len != DHT_ID_SIZE) _argumentsAreValid = false;
		token.b = (byte*)args->GetString("token", &token.len);
		vote = args->GetInt("vote", 0);
		filename.b = (byte*)args->GetString("name", &filename.len);
	}
	else if (strcmp(command,"get") == 0) {
		dhtCommand = DHT_QUERY_GET;
		target.b = (byte*)args->GetString("target", &target.len);
		if (target.len != DHT_ID_SIZE) _argumentsAreValid = false;
		sequenceNum = args->GetInt64("seq", 0);
	}
	else if (strcmp(command,"put") == 0) {
		dhtCommand = DHT_QUERY_PUT;
		token.b = (byte*)args->GetString("token", &token.len);
		vBuf.len = region.second - region.first;
		vBuf.b = region.first;
		signature.b = (byte*)args->GetString("sig", &signature.len); // 64 bytes
		if (signature.b && signature.len != DHT_SIG_SIZE) _argumentsAreValid = false;
		key.b = (byte*)args->GetString("k", &key.len); // 32 bytes
		if (key.b && key.len != DHT_KEY_SIZE) _argumentsAreValid = false;
		salt.b = (byte*)args->GetString("salt", &salt.len);
		sequenceNum = args->GetInt64("seq", 0);
		cas = args->GetInt("cas", 0);
	}
	else if (strcmp(command,"ping") == 0) {
		dhtCommand = DHT_QUERY_PING;
	}
#if USE_HOLEPUNCH
	else if (strcmp(command, "punch") == 0) {
		dhtCommand = DHT_QUERY_PUNCH;
		target_ip.b = (byte*)args->GetString("ip", &target_ip.len);
		if (target_ip.b == NULL || target_ip.len != 6)
			_argumentsAreValid = false;
	}
#endif
	else {
		// unknown messages with either a 'target'
		// or an 'info-hash' argument are treated
		// as a find node to not block future extensions
		dhtCommand = DHT_QUERY_FIND_NODE; // assume find_node...
		target.b = (byte*)args->GetString("target", &target.len);
		// check that there is a target; if not...
		if (target.b) {
			if (target.len != DHT_ID_SIZE) _argumentsAreValid = false;
		}
		else {
			target.b = (byte*)args->GetString("info_hash", &target.len);
			if (target.len != DHT_ID_SIZE) _argumentsAreValid = false;
			// see if there is an info_hash to use as a target; if not...
			if (!target.b) {
				// we have an invalid query command
				dhtCommand = DHT_QUERY_UNDEFINED;
			}
		}
	}
}

void DHTMessage::CopyFrom(DHTMessage &src)
{
	if (&src == this) return;

	delete _bDict; // free ours if necessary
	_bDict = NULL;

	// If the source _bDict object is not null, then the src object allocated
	// its own BencodedDict.  So this object needs to do its own allocation
	// before copying.
	if (src._bDict){
		_bDict = new BencodedDict;
		*_bDict = *src._bDict;
	}

	// if _bDict is not null, set to our _bDict, otherwise the consumer provided
	// a BencodedDict when creating the source object, so point to the consumers dictionary.
	_bDictForUser = (_bDict)?_bDict:src._bDictForUser;

	_argumentsAreValid = src._argumentsAreValid;
	_parseSuccessful = src._parseSuccessful;
	type = src.type;
	command = src.command;
	filename = src.filename;
	id = src.id;
	target = src.target;
	infoHash = src.infoHash;
	token = src.token;
	portNum = src.portNum;
	vote = src.vote;
	seed = src.seed;
	scrape = src.scrape;
	args = src.args;
	transactionID = src.transactionID;
	version = src.version;
	key = src.key;
	sequenceNum = src.sequenceNum;
	signature = src.signature;
	region = src.region;
	vBuf = src.vBuf;
	target_ip = src.target_ip;
	impliedPort = src.impliedPort;
	cas = src.cas;

	// Warning:  If this was set, it will still point to the dictionary
	// created by the original _bDict object
	replyDict = src.replyDict;
}

