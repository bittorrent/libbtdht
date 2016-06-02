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

#pragma once
#include <cassert>
#include <cstdio>
#include <vector>
#include <string>
#include "snprintf.h"

#include <stack>

// a stupid, write-once bencoder, and for when no C++11 is available
class bencoder {
	unsigned char* buffer;
	unsigned char* start;
	int64 len;
	std::stack<char> checker; // state machine for bencoded result validation

	// maintains encountered dictionary state, 'k' means key
	void update_checker() {
		if (!checker.empty()) {
			if (checker.top() == 'd') {
				checker.push('k');
			} else if (checker.top() == 'k') {
				checker.pop();
			}
		}
	}

	public:
		bencoder(unsigned char* buffer, int64 len) : buffer(buffer),
				start(buffer), len(len) {}
		bencoder& operator() (int64 value) {
			update_checker();
			long written = snprintf(reinterpret_cast<char*>(buffer), len,
					"i%de", int(value));
			assert(written <= len);
			buffer += written;
			len -= written;
			return *this;
		}
		// use only with values -- would be silly to use with keys anyway
		inline bencoder& raw(char const *value) {
			assert(strlen(value) <= len);
			update_checker();
			std::memcpy(buffer, value, strlen(value));
			buffer += strlen(value);
			len -= strlen(value);
			return *this;
		}
		inline bencoder& operator() (char const *value) {
			update_checker();
			long written = snprintf(reinterpret_cast<char*>(buffer), len, "%d:%s",
					int(strlen(value)), value);
			assert(written <= len);
			buffer += written;
			len -= written;
			return *this;
		}
		inline bencoder& operator() (unsigned char const *value, int64 v_len) {
			assert(v_len > 0);
			update_checker();
			long written = snprintf(reinterpret_cast<char*>(buffer), len,
#ifdef _MSC_VER
				"%I64d:",
#else
				"%" PRId64 ":",
#endif
				v_len);
			assert(written + v_len <= len);
			std::memcpy(buffer + written, value, v_len);
			buffer += written + v_len;
			len -= written + v_len;
			return *this;
		}
		inline bencoder& operator() (std::vector<unsigned char> const &value) {
			update_checker();
			long written = snprintf(reinterpret_cast<char*>(buffer), len, "%u:",
				uint(value.size()));
			assert(written + value.size() <= len);
			std::memcpy(buffer + written, &(value[0]), value.size());
			buffer += written + value.size();
			len -= written + value.size();
			return *this;
		}
		inline bencoder& operator() (std::string const &value) {
			update_checker();
			long written = snprintf(reinterpret_cast<char*>(buffer), len, "%u:",
					uint(value.size()));
			assert(written + value.size() <= len);
			std::memcpy(buffer + written, &(value[0]), value.size());
			buffer += written + value.size();
			len -= written + value.size();
			return *this;
		}
		inline bencoder& operator() (char value) {
			assert(len >= 1);
			assert(value == 'd' || value == 'l' || value == 'e');
			if (value == 'e') {
				assert(!checker.empty());
				assert(checker.top() == 'l' || checker.top() == 'd');
				checker.pop();
			} else {
				update_checker();
				checker.push(value);
			}
			*buffer = value;
			buffer++;
			len--;
			return *this;
		}

		inline bencoder& d() {
			return (*this)('d');
		}
		inline bencoder& l() {
			return (*this)('l');
		}
		inline bencoder& e() {
			return (*this)('e');
		}

		inline int64 operator() () {
			assert(checker.empty());
			return buffer - start;
		}
};
