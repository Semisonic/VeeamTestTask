#pragma once

using buffer_t = std::vector<unsigned char>;
using hash_t = std::vector<unsigned char>;

enum class HashFunctionId : uint16_t {
	CRC32 = 0,
	MD5 = 1
};