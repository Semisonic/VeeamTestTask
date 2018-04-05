#include "stdafx.h"
#include "HashWrappers.h"

#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1

#include "../CryptoPP/md5.h"
#include "../CryptoPP/crc.h"

// -------------------------------------------------------------------------- //
/*
	MD5HashWrapper class

	incapsulation of the MD5 algorithm implementation
 */
// -------------------------------------------------------------------------- //

class MD5HashWrapper : public GenericHashWrapper {
public:

	MD5HashWrapper() = default;
	
	void createDigest(const buffer_t& input, hash_t& hash) override {
		assert(hash.size() == m_hasher.DigestSize());

		m_hasher.CalculateDigest(hash.data(), input.data(), input.size());
	}

private:

	CryptoPP::Weak::MD5 m_hasher;
};

// -------------------------------------------------------------------------- //
/*
	CRC32HashWrapper class

	incapsulation of the CRC32 algorithm implementation
 */
// -------------------------------------------------------------------------- //

class CRC32HashWrapper : public GenericHashWrapper {
public:

	CRC32HashWrapper() = default;
	
	void createDigest(const buffer_t& input, hash_t& hash) override {
		assert(hash.size() == m_hasher.DigestSize());

		m_hasher.CalculateDigest(hash.data(), input.data(), input.size());
	}

private:

	CryptoPP::CRC32 m_hasher;
};

// -------------------------------------------------------------------------- //
/*
	HashWrapperFactory methods implementation
 */
// -------------------------------------------------------------------------- //

HashWrapperPtr HashWrapperFactory::createHashWrapper(HashFunctionId id) {
	switch (id) {
	case HashFunctionId::CRC32: return HashWrapperPtr(new CRC32HashWrapper{});
	case HashFunctionId::MD5: return HashWrapperPtr(new MD5HashWrapper{});
	default: assert(false); throw std::runtime_error("Hashing algorithm not supported");
	}
}

// -------------------------------------------------------------------------- //
/*
	HashTraits methods implementation
 */
// -------------------------------------------------------------------------- //

unsigned int HashTraits::digestSize(HashFunctionId id) {
	switch (id) {
	case HashFunctionId::CRC32: return CryptoPP::CRC32::DIGESTSIZE;
	case HashFunctionId::MD5: return CryptoPP::Weak::MD5::DIGESTSIZE;
	default: assert(false); throw std::runtime_error("Hashing algorithm not supported");
	}
}