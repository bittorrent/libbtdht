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

#include "TestDHT.h"

class data_store_test : public dht_test {
	protected:
		sha1_hash hash;
		DataStore<DhtID, int> ds;
		DataStore<DhtID, int>::pair_iterator it;
		PairContainerBase<int>* containerPtr;
		DhtID key1, key2, key3, key4, key5;
		time_t cur_time;

		virtual void SetUp() override {
			SockAddr addr;

			key1.id[0] = 1;
			key2.id[0] = 2;
			key3.id[0] = 3;
			key4.id[0] = 4;
			key5.id[0] = 5;
			cur_time = time(NULL);
			hash = sha1_callback(reinterpret_cast<const byte*>(addr.get_hash_key()),
					addr.get_hash_key_len());
		}
};

TEST_F(data_store_test, AddPairToList) {
	// look for a key when no keys have been added
	it = ds.FindInList(key1, cur_time, hash);
	ASSERT_TRUE(it == ds.end()) << "A end iterator should have been returned"
		" from an attempt to find something in an empty list.";

	// add keys in reverse order and check that they are inserted in ascending
	// order
	ds.AddPairToList(hash, key3, 33, &containerPtr);
	ds.AddPairToList(hash, key2, 22, &containerPtr);
	ds.AddPairToList(hash, key1, 11, &containerPtr);
	ASSERT_EQ(3, ds.pair_list.size()); // there should now be 3 peers total

	std::pair<const DhtID, PairContainerBase<int> > compare[] = {
		std::pair<const DhtID, PairContainerBase<int> >(key1, 11),
		std::pair<const DhtID, PairContainerBase<int> >(key2, 22),
		std::pair<const DhtID, PairContainerBase<int> >(key3, 33),
	};

	EXPECT_TRUE(std::equal(ds.pair_list.begin(), ds.pair_list.end(), compare));

	// add the same key and see that the list size doesn't change
	ds.AddPairToList(hash, key3, 33, &containerPtr);
	ds.AddPairToList(hash, key3, 33, &containerPtr);
	ASSERT_EQ(3, ds.pair_list.size()); // there should now be 5 peers total

	// test the find for a key in the list
	it = ds.FindInList(key3, cur_time, hash);
	EXPECT_TRUE(it->second.value == 33);
	it = ds.FindInList(key2, cur_time, hash);
	EXPECT_TRUE(it->second.value == 22);
	it = ds.FindInList(key1, cur_time, hash);
	EXPECT_TRUE(it->second.value == 11);

	// test the find for a key that is NOT in the list
	it = ds.FindInList(key4, cur_time, hash);
	EXPECT_TRUE(it == ds.end());
}

TEST_F(data_store_test, AddKeyToList) {
	// look for a key when no keys have been added
	it = ds.FindInList(key1, cur_time, hash);
	ASSERT_TRUE(it == ds.end());

	// add keys in reverse order and check that they are inserted in ascending
	// order
	ds.AddKeyToList(hash, key3, &containerPtr);
	containerPtr->value = 33;
	ds.AddKeyToList(hash, key2, &containerPtr);
	containerPtr->value = 22;
	ds.AddKeyToList(hash, key1, &containerPtr);
	containerPtr->value = 11;
	ASSERT_EQ(3, ds.pair_list.size()); // there should now be 3 peers total

	std::pair<const DhtID, PairContainerBase<int> > compare[] = {
		std::pair<const DhtID, PairContainerBase<int> >(key1, 11),
		std::pair<const DhtID, PairContainerBase<int> >(key2, 22),
		std::pair<const DhtID, PairContainerBase<int> >(key3, 33),
	};

	EXPECT_TRUE(std::equal(ds.pair_list.begin(), ds.pair_list.end(), compare));

	// add the same key and see that the list size doesn't change
	ds.AddKeyToList(hash, key3, &containerPtr);
	ds.AddKeyToList(hash, key3, &containerPtr);
	ASSERT_EQ(3, ds.pair_list.size()); // there should now be 5 peers total

	// test the find for a key in the list
	it = ds.FindInList(key3, cur_time, hash);
	EXPECT_TRUE(it->second.value == 33);
	it = ds.FindInList(key2, cur_time, hash);
	EXPECT_TRUE(it->second.value == 22);
	it = ds.FindInList(key1, cur_time, hash);
	EXPECT_TRUE(it->second.value == 11);

	// test the find for a key that is NOT in the list
	it = ds.FindInList(key4, cur_time, hash);
	EXPECT_TRUE(it == ds.end());
}


TEST_F(data_store_test, FindInList) {
	// look for a key when no keys have been added
	it = ds.FindInList(key1, cur_time, hash);
	ASSERT_TRUE(it == ds.end()) << "An end iterator should have been returned"
		" from an attempt to find something in an empty list.";

	// add keys in reverse order and check that they are inserted in ascending
	// order
	ds.AddPairToList(hash, key4, 44, &containerPtr);
	ds.AddPairToList(hash, key2, 22, &containerPtr);
	ds.AddPairToList(hash, key1, 11, &containerPtr);

	// look for a key that is not in the list
	it = ds.FindInList(key3, cur_time, hash);
	ASSERT_TRUE(it == ds.end()) << "An end iterator should have been returned"
		" from an attempt to find something not in the list.";
}


TEST_F(data_store_test, EliminateTimeouts) {
	ds.SetMaximumAge(7200);
	int numEliminated;

	// test elimination when list is empty
	try {
		// use a time greater than the max time provided to the constructor
		numEliminated = ds.EliminateTimeouts(8000);
	} catch(...) {
		FAIL() << "An exception was thrown when eliminating from an empty list.";
	}
	EXPECT_EQ(0, numEliminated) <<
		"The list was empty, there shouldn't be any eliminations";
	EXPECT_EQ(0, ds.pair_list.size());

	// add 4 items (with default time of 0) and eliminate all 4 items
	ds.AddPairToList(hash, key1, 11, &containerPtr, 0);
	ds.AddPairToList(hash, key2, 22, &containerPtr, 0);
	ds.AddPairToList(hash, key3, 33, &containerPtr, 0);
	ds.AddPairToList(hash, key4, 44, &containerPtr, 0);
	try {
		// use a time greater than the max time provided to the constructor
		numEliminated = ds.EliminateTimeouts(8000);
	} catch(...) {
		FAIL() <<
			"An exception was thrown when eliminating everything in the list.";
	}
	EXPECT_EQ(4, numEliminated) <<
		"4 items should have been eliminated from the list";
	EXPECT_EQ(0, ds.pair_list.size());

	// add 4 items with none old enough to eliminate
	ds.AddPairToList(hash, key1, 11, &containerPtr, 7000);
	ds.AddPairToList(hash, key2, 22, &containerPtr, 7000);
	ds.AddPairToList(hash, key3, 33, &containerPtr, 7000);
	ds.AddPairToList(hash, key4, 44, &containerPtr, 7000);
	try {
		// use a time greater than the max time provided to the constructor
		numEliminated = ds.EliminateTimeouts(8000);
	} catch(...) {
		FAIL() << "An exception was thrown when eliminating nothing list.";
	}
	EXPECT_EQ(0, numEliminated) <<
		"no items should have been eliminated from the list";
	EXPECT_EQ(4, ds.pair_list.size());
	// add 4 items with one old enough to eliminate
	ds.AddPairToList(hash, key1, 11, &containerPtr, 0);
	ds.AddPairToList(hash, key2, 22, &containerPtr, 7000);
	ds.AddPairToList(hash, key3, 33, &containerPtr, 7000);
	ds.AddPairToList(hash, key4, 44, &containerPtr, 7000);
	try {
		// use a time greater than the max time provided to the constructor
		numEliminated = ds.EliminateTimeouts(8000);
	} catch(...) {
		FAIL() << "An exception was thrown when eliminating from the beginning"
			" of the list.";
	}
	EXPECT_EQ(1, numEliminated) <<
		"only 1 item should have been eliminated from the list";
	EXPECT_EQ(3, ds.pair_list.size());
	// repeat above but from the other end
	ds.AddPairToList(hash, key1, 11, &containerPtr, 7000);
	ds.AddPairToList(hash, key2, 22, &containerPtr, 7000);
	ds.AddPairToList(hash, key3, 33, &containerPtr, 7000);
	ds.AddPairToList(hash, key4, 44, &containerPtr, 0);
	try {
		// use a time greater than the max time provided to the constructor
		numEliminated = ds.EliminateTimeouts(8000);
	} catch(...) {
		FAIL() <<
			"An exception was thrown when eliminating from the end of the list.";
	}
	EXPECT_EQ(1, numEliminated) <<
		"only 1 item should have been eliminated from the list";
	EXPECT_EQ(3, ds.pair_list.size());
	// set up to eliminate from the middle
	ds.AddPairToList(hash, key1, 11, &containerPtr, 7000);
	ds.AddPairToList(hash, key2, 22, &containerPtr, 0);
	ds.AddPairToList(hash, key3, 33, &containerPtr, 0);
	ds.AddPairToList(hash, key4, 44, &containerPtr, 7000);
	try {
		// use a time greater than the max time provided to the constructor
		numEliminated = ds.EliminateTimeouts(8000);
	} catch(...) {
		FAIL() << "An exception was thrown when eliminating from the middle of"
			" the list.";
	}
	EXPECT_EQ(2, numEliminated) <<
		"only 2 items should have been eliminated from the list";
	EXPECT_EQ(2, ds.pair_list.size());
}

TEST_F(data_store_test, RemoveItem) {
	ds.SetMaximumAge(7200);
	int numEliminated;

	// test removing from an empty list
	try {
		numEliminated = ds.RemoveItem(key2);
	} catch(...) {
		FAIL() << "An exception was thrown when eliminating from an empty list.";
	}
	EXPECT_EQ(0, numEliminated) <<
		"The list was empty, there shouldn't be any eliminations";
	EXPECT_EQ(0, ds.pair_list.size());

	// add 4 items try to remove something not there
	ds.AddPairToList(hash, key1, 11, &containerPtr, 0);
	ds.AddPairToList(hash, key2, 22, &containerPtr, 0);
	ds.AddPairToList(hash, key3, 33, &containerPtr, 0);
	ds.AddPairToList(hash, key5, 55, &containerPtr, 0);
	try {
		numEliminated = ds.RemoveItem(key4);
	} catch(...) {
		FAIL() << "An exception was thrown when eliminating from an empty list.";
	}
	EXPECT_EQ(0, numEliminated) << "The item to be removed was not in the list,"
		" nothing should have been removed";
	EXPECT_EQ(4, ds.pair_list.size());

	// remove from the beginning of the list
	try {
		numEliminated = ds.RemoveItem(key1);
	} catch(...) {
		FAIL() << "An exception was thrown when eliminating from an empty list.";
	}
	EXPECT_EQ(1, numEliminated) << "A single item should have been removed";
	EXPECT_EQ(3, ds.pair_list.size());

	// remove from the end of the list
	try {
		numEliminated = ds.RemoveItem(key5);
	} catch(...) {
		FAIL() << "An exception was thrown when eliminating from an empty list.";
	}
	EXPECT_EQ(1, numEliminated) << "A single item should have been removed";
	EXPECT_EQ(2, ds.pair_list.size());
}

TEST_F(data_store_test, EvictLeastUsed) {
	ds.SetMaximumAge(500);
	ds.SetMaximumSize(4);
	int numEliminated;

	SockAddr addr1, addr2, addr3, addr4;
	addr1.set_addr4(0xff000000);
	addr2.set_addr4(0x00ff0000);
	addr3.set_addr4(0x0000ff00);
	addr4.set_addr4(0x000000ff);

	// make a hash of the address for the DataStores to use to record usage of
	// an item
	sha1_hash hash1 = sha1_callback(reinterpret_cast<const byte*>
			(addr1.get_hash_key()), addr1.get_hash_key_len());
	sha1_hash hash2 = sha1_callback(reinterpret_cast<const byte*>
			(addr2.get_hash_key()), addr2.get_hash_key_len());
	sha1_hash hash3 = sha1_callback(reinterpret_cast<const byte*>
			(addr3.get_hash_key()), addr3.get_hash_key_len());
	sha1_hash hash4 = sha1_callback(reinterpret_cast<const byte*>
			(addr4.get_hash_key()), addr4.get_hash_key_len());

	// put the initial items into the list using hash1
	ds.AddPairToList(hash1, key1, 11, &containerPtr, 0);
	ds.AddPairToList(hash1, key2, 22, &containerPtr, 0);
	ds.AddPairToList(hash1, key3, 33, &containerPtr, 0);
	ds.AddPairToList(hash1, key4, 44, &containerPtr, 0);

	// put activity onto items 1, 2, and 4 (no activity on item 3)
	ds.FindInList(key1, cur_time, hash2);
	ds.FindInList(key2, cur_time, hash2);
	ds.FindInList(key4, cur_time, hash2);
	ds.FindInList(key1, cur_time, hash3);
	ds.FindInList(key2, cur_time, hash3);

	try {
		numEliminated = ds.EvictLeastUsed();
	} catch(...) {
		FAIL() <<
			"An exception was thrown when Evicting an unused item from the list";
	}
	EXPECT_EQ(1, numEliminated) << "The item to be removed was not in the list,"
		" nothing should have been removed";
	EXPECT_EQ(3, ds.pair_list.size());

	// look for key 3 - it should have been evicted
	it = ds.FindInList(key3, cur_time, hash4);
	ASSERT_FALSE(it != ds.end()) <<
		"The item that should have been removed is still in the list.";

	// make an update happen, then add all items back so everything is in the
	// current bloom filter.
	// Items 1, 2, and 4 should now have a history in the previous
	// bloom filter estimated count.
	// use a time greater than half of the max age (500) specified in the
	// constructor
	ds.UpdateUsage(400);
	ds.AddPairToList(hash1, key1, 11, &containerPtr, 450);
	ds.AddPairToList(hash1, key2, 22, &containerPtr, 450);
	ds.AddPairToList(hash1, key3, 33, &containerPtr, 450);
	ds.AddPairToList(hash1, key4, 44, &containerPtr, 450);
	// again, item 3 should be evicted
	try {
		numEliminated = ds.EvictLeastUsed();
	} catch(...) {
		FAIL() << "An exception was thrown when Evicting an unused item from"
			" the list";
	}
	EXPECT_EQ(1, numEliminated) << "The item to be removed was not in the list,"
		" nothing should have been removed";
	EXPECT_EQ(3, ds.pair_list.size());

	// look for key 3 - it should have been evicted
	it = ds.FindInList(key3, cur_time, hash4);
	ASSERT_TRUE(it == ds.end()) <<
		"The item that should have been removed is still in the list.";

	// add a new item to the end of the list and see that it is evicted
	// without error
	ds.AddPairToList(hash1, key5, 55, &containerPtr, 455);
	try {
		numEliminated = ds.EvictLeastUsed();
	} catch(...) {
		FAIL() <<
			"An exception was thrown when Evicting an unused item from the list";
	}
	EXPECT_EQ(1, numEliminated) << "The item to be removed was not in the list,"
		" nothing should have been removed";
	EXPECT_EQ(3, ds.pair_list.size());

	// look for key 5 - it should have been evicted
	it = ds.FindInList(key3, cur_time, hash4);
	ASSERT_TRUE(it == ds.end()) <<
		"The item that should have been removed is still in the list.";

	// make sure items 1,2, and 4 are still in the list
	EXPECT_TRUE(ds.FindInList(key1, cur_time, hash4) != ds.end()) <<
		"Item 1 should still be in the list";
	EXPECT_TRUE(ds.FindInList(key2, cur_time, hash4) != ds.end()) <<
		"Item 2 should still be in the list";
	EXPECT_TRUE(ds.FindInList(key4, cur_time, hash4) != ds.end()) <<
		"Item 4 should still be in the list";

	// add items 3 and 5
	// see that item 3 is evicted in favor of 5 when adding 5 to a full list
	ds.AddPairToList(hash2, key1, 11, &containerPtr, 459);
	ds.AddPairToList(hash2, key2, 22, &containerPtr, 459);
	ds.AddPairToList(hash2, key3, 33, &containerPtr, 459);
	ds.AddPairToList(hash2, key4, 44, &containerPtr, 459);
	ds.AddPairToList(hash2, key5, 55, &containerPtr, 459);
	EXPECT_EQ(4, ds.pair_list.size()) <<
		"The list should be at the maximum size specified:  4";
	EXPECT_FALSE(ds.FindInList(key3, cur_time, hash4) != ds.end()) <<
		"Item 3 should have been evicted";
	EXPECT_TRUE(ds.FindInList(key5, cur_time, hash4) != ds.end()) <<
		"Item 5 should be in the list";
}
