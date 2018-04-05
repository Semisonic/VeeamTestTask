#pragma once

#include "types.h"

// -------------------------------------------------------------------------- //
/*
	GenericHashWrapper class

	base class for the hierarchy of classes implementing
	different hashing algorithms
 */
// -------------------------------------------------------------------------- //

class GenericHashWrapper {
public:
	
	virtual ~GenericHashWrapper () = default;

	virtual void createDigest (const buffer_t& input, hash_t& hash) = 0;	
};

using HashWrapperPtr = std::unique_ptr<GenericHashWrapper>;

// -------------------------------------------------------------------------- //
/*
	HashWrapperFactory class

	produces the concrete implementations of the hashing algorithms
 */
 // -------------------------------------------------------------------------- //

class HashWrapperFactory {
public:

	static HashWrapperPtr createHashWrapper(HashFunctionId id);
};

// -------------------------------------------------------------------------- //
/*
	HashTraits class

	retrieves various information about the hashing algorithms
 */
 // -------------------------------------------------------------------------- //

class HashTraits {
public:

	static unsigned int digestSize(HashFunctionId id);
};