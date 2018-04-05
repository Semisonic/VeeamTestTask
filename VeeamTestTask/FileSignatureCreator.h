#pragma once

#include <cstdint>
#include <filesystem>

#include "types.h"

#ifdef _MSC_VER 
using namespace std::experimental::filesystem::v1;
#else
using namespace std::filesystem;
#endif

// -------------------------------------------------------------------------- //
/*
	SignatureHeader struct

	represents the header of the signature file
	note that the struct is serialized on a per-field basis, with no padding assumed
 */
// -------------------------------------------------------------------------- //

struct SignatureHeader {
	uint32_t fileMark{ 0x53464D56 }; // this should look like "VMFS", Veeam File Signature
	uint16_t formatVersion{ 1 };
	uint16_t hashFunctionId{ 0 };
	uint64_t originalFileSize{ 0 };
	uint32_t blockSize{ 0 };
	
	// reserved fields to pad the structure to have the size of 32
	uint32_t reserved1{ 0 };
	uint32_t reserved2{ 0 };
	uint32_t reserved3{ 0 };
};

class SignatureHeaderTraits {
public:

	static constexpr uint32_t size() { return 32; }
};

// -------------------------------------------------------------------------- //
/*
	FileSignatureCreator class

	create an object of this class to start hasing the input file into the output file
	using the block size and hash function provided

	if the output path points to an already existing file, may delete its contents.
	if the hashing fails during the process, will attempt to delete an output file

	may throw:
	- std::invalid_argument - in case the file paths are invalid or the block size is zero
	- std::ios_base::failure - in case of I/O errors
	- std::runtime_error - in case of an internal error, most probably I/O related
	- std::bad_alloc - in case of memory shortage
	- std::system_error - in case of thread-related issues
	- std::filesystem_error - in case of the filesystem errors
 */
// -------------------------------------------------------------------------- //

class FileSignatureCreator {
public:
	
	FileSignatureCreator (const char* inFilePath, const char* outFilePath,
						  uint32_t blockSize, HashFunctionId id);
	FileSignatureCreator (const std::enable_if_t<!std::is_same_v<char, path::value_type>, path::value_type>* inFilePath,
						  const std::enable_if_t<!std::is_same_v<char, path::value_type>, path::value_type>* outFilePath,
		                  uint32_t blockSize, HashFunctionId id);
	~FileSignatureCreator() = default;
};

