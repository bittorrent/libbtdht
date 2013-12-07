#pragma once
#include <cinttypes>
#include <cstdint>
#include <cassert>
#include <cstdio>
#include <vector>
#include <string>

#include <stack>

// a stupid, write-once bencoder, and for when no C++11 is available
class bencoder {
	unsigned char* buffer;
	int64_t len;
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
		bencoder(unsigned char* buffer, int64_t len) : buffer(buffer), len(len) {}
		bencoder& operator() (int64_t value) {
			update_checker();
			long written = snprintf(reinterpret_cast<char*>(buffer), len,
					"i%" PRId64 "e", value);
			assert(written <= len);
			buffer += written;
			len -= written;
			return *this;
		}
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
			long written = snprintf(reinterpret_cast<char*>(buffer), len, "%zu:%s",
					strlen(value), value);
			assert(written <= len);
			buffer += written;
			len -= written;
			return *this;
		}
		inline bencoder& operator() (unsigned char const *value, int64_t v_len) {
			assert(v_len > 0);
			update_checker();
			long written = snprintf(reinterpret_cast<char*>(buffer), len, "%zu:",
					static_cast<size_t>(v_len));
			assert(written + v_len <= len);
			std::memcpy(buffer + written, value, v_len);
			buffer += written + v_len;
			len -= written + v_len;
			return *this;
		}
		inline bencoder& operator() (std::vector<unsigned char> const &value) {
			update_checker();
			long written = snprintf(reinterpret_cast<char*>(buffer), len, "%zu:",
					value.size());
			assert(written + value.size() <= len);
			std::memcpy(buffer + written, &(value[0]), value.size());
			buffer += written + value.size();
			len -= written + value.size();
			return *this;
		}
		inline bencoder& operator() (std::string const &value) {
			update_checker();
			long written = snprintf(reinterpret_cast<char*>(buffer), len, "%zu:",
					value.size());
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

		inline unsigned char* operator() () {
			assert(checker.empty());
			return buffer;
		}
};
