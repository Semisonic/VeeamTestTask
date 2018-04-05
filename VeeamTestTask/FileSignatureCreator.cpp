#include "stdafx.h"
#include "types.h"
#include "FileSignatureCreator.h"
#include "HashWrappers.h"

// -------------------------------------------------------------------------- //
/*
	InputFileReader class

	processes the input file and reads it in chunks
 */
// -------------------------------------------------------------------------- //

class InputFileReader {
public:

	InputFileReader() {
		m_ifs.exceptions(std::ifstream::badbit | std::ifstream::failbit);
	}
	
	template <class Source>
	uint64_t open (const Source& filePath) {
		path inFilePath{ filePath };

		uint64_t fileSize = static_cast<uint64_t>(file_size(inFilePath));

		m_ifs.open(inFilePath, std::ios_base::in | std::ios_base::binary);

		return fileSize;
	}

	void readNextChunk(buffer_t& buffer) {
		assert(buffer.size());

		m_ifs.read(reinterpret_cast<char*>(buffer.data()), buffer.size());
		
		assert(m_ifs.gcount() == buffer.size());
	}

private:

	std::ifstream m_ifs;
};

// -------------------------------------------------------------------------- //
/*
	OutputFileWriter class

	prepares the output file and writes to it in chunks
 */
// -------------------------------------------------------------------------- //

class OutputFileWriter {
public:

	template <class Source>
	OutputFileWriter (const Source& filePath, unsigned int hashSize, uint64_t blockCount) : m_path(filePath) {
		m_ofs.exceptions(std::ifstream::badbit | std::ifstream::failbit);

		{
			// creating file if one hasn't been created yet
			
			m_ofs.open(m_path, std::ios_base::out | std::ios_base::binary);
			m_ofs.write("x", 1);
			m_ofs.close();
		}

		resize_file(m_path, SignatureHeaderTraits::size() + hashSize * blockCount);

		m_ofs.open(m_path, std::ios_base::out | std::ios_base::binary);
	}
	
	~OutputFileWriter() {
		if (!m_isFinalized) {
			m_ofs.close();

			std::error_code stub;

			// the overload with the error code is used to avoid an exception to be possibly thrown
			remove(m_path, stub);
		}
	}

	void writeHeader (const SignatureHeader& header) {
		m_ofs.seekp(0, std::ios_base::beg);

		m_ofs.write(reinterpret_cast<const char*>(&header.fileMark), sizeof(header.fileMark));
		m_ofs.write(reinterpret_cast<const char*>(&header.formatVersion), sizeof(header.formatVersion));
		m_ofs.write(reinterpret_cast<const char*>(&header.hashFunctionId), sizeof(header.hashFunctionId));
		m_ofs.write(reinterpret_cast<const char*>(&header.originalFileSize), sizeof(header.originalFileSize));
		m_ofs.write(reinterpret_cast<const char*>(&header.blockSize), sizeof(header.blockSize));
		m_ofs.write(reinterpret_cast<const char*>(&header.reserved1), sizeof(header.reserved1));
		m_ofs.write(reinterpret_cast<const char*>(&header.reserved2), sizeof(header.reserved2));
		m_ofs.write(reinterpret_cast<const char*>(&header.reserved3), sizeof(header.reserved3));
	}

	void writeHash (uint64_t blockNumber, const hash_t& hash) {
		m_ofs.seekp(SignatureHeaderTraits::size() + hash.size() * blockNumber, std::ios_base::beg);

		m_ofs.write(reinterpret_cast<const char*>(hash.data()), hash.size());
	}
	
	void finalize() { m_isFinalized = true; }


private:

	path m_path;
	std::ofstream m_ofs;
	bool m_isFinalized{ false };
};

// -------------------------------------------------------------------------- //
/*
	FileSignatureCreatorImpl class

	reads the file contents, splits it in blocks and hashes them efficiently,
	and then drops the results into another file
 */
// -------------------------------------------------------------------------- //

class FileSignatureCreatorImpl {

	using buffer_ptr_t = std::unique_ptr<buffer_t>;
	using hash_ptr_t = std::unique_ptr<hash_t>;
	using job_t = std::tuple<buffer_ptr_t, hash_ptr_t, uint64_t>;
	using result_t = std::pair<hash_ptr_t, uint64_t>;

	using job_queue_t = std::deque<job_t>;
	using result_queue_t = std::deque<result_t>;
	using buffer_pool_t = std::vector<buffer_ptr_t>;
	using hash_pool_t = std::vector<hash_ptr_t>;

	static constexpr auto s_threadTimeout{ std::chrono::milliseconds{100} };
	static constexpr auto s_defaultConcurrency{ 4 };

	class bad_flag_error : public std::exception {};

public:

	FileSignatureCreatorImpl() = default;
	~FileSignatureCreatorImpl() {
		waitForWorkers();
	}

	template <class Source>
	void launch (const Source& inFilePath, const Source& outFilePath, uint32_t blockSize, HashFunctionId hash);

private:

	void runHasher(HashWrapperPtr hasher);
	void runResultWriter(OutputFileWriter& writer, uint64_t blocksToWrite);
	void waitForWorkers() {
		for (auto& t : m_workerPool) {
			t.join();
		}

		m_workerPool.clear();
	}

private:

	std::vector<std::thread> m_workerPool;
	
	buffer_pool_t m_memoryBufferPool;
	std::mutex m_mbpGuard;

	hash_pool_t m_hashPool;
	std::mutex m_hpGuard;

	job_queue_t m_jobs;
	std::mutex m_jobGuard;

	result_queue_t m_results;
	std::mutex m_resGuard;

	std::condition_variable m_jobsNotEmpty;
	std::condition_variable m_jobsNotFull;
	std::condition_variable m_resultsNotEmpty;

	std::atomic_bool m_badFlag{ false };
	uint64_t m_blocksToHash{ 0 };
};

// -------------------------------------------------------------------------- //

template <class Source>
void FileSignatureCreatorImpl::launch (const Source& inFilePath, const Source& outFilePath,
									   uint32_t blockSize, HashFunctionId id) {
	try {
		if (!blockSize) {
			throw std::invalid_argument("Block size is zero");
		}

		InputFileReader reader;
		auto inputSize = reader.open(inFilePath);

		if (!inputSize) {
			throw std::invalid_argument("Input file is empty");
		}

		auto digestSize = HashTraits::digestSize(id);
		auto blockCount = m_blocksToHash = inputSize / blockSize + (inputSize % blockSize > 0);

		OutputFileWriter writer{ outFilePath, digestSize, m_blocksToHash };

		auto hasherThreadCount = std::thread::hardware_concurrency();

		if (!hasherThreadCount) {
			hasherThreadCount = s_defaultConcurrency;
		}

		// allocating the memory resources required
		{
			// we create a double amount of buffers in order to enable the reader thread
			// to prefetch data while all the hasher threads are busy

			m_memoryBufferPool.reserve(hasherThreadCount * 2);
			m_hashPool.reserve(hasherThreadCount * 2);

			for (unsigned i = 0; i < hasherThreadCount * 2; ++i) {
				m_memoryBufferPool.emplace_back(new buffer_t(blockSize, unsigned char{0}));
				m_hashPool.emplace_back(new hash_t(digestSize, unsigned char{0}));
			}
		}

		// launching worker threads
		{
			m_workerPool.reserve(hasherThreadCount + 1);

			for (unsigned i = 0; i < hasherThreadCount; ++i) {
				HashWrapperPtr hasher = HashWrapperFactory::createHashWrapper(id);

				m_workerPool.emplace_back(&FileSignatureCreatorImpl::runHasher, this, std::move(hasher));
			}

			m_workerPool.emplace_back(&FileSignatureCreatorImpl::runResultWriter, this, std::ref(writer), m_blocksToHash);
		}

		// if we've reached so far then the files have been opened and their size
		// either validated or set up, memory buffers allocated and threads launched
		// we're ready for hashing

		uint64_t blockNumber{ 0 };
		
		for (auto bytesToRead = inputSize; blockNumber < blockCount; bytesToRead -= blockSize, ++blockNumber) {
			buffer_ptr_t buffer;

			{
				std::unique_lock<std::mutex> ulBuffers{ m_mbpGuard };

				if (m_memoryBufferPool.empty()) {
					while (!m_jobsNotFull.wait_for(ulBuffers, s_threadTimeout,
												   [this]() { return !m_memoryBufferPool.empty() ||
																	  m_badFlag.load(std::memory_order_relaxed);
															}));
				}

				if (m_badFlag.load(std::memory_order_relaxed)) {
					throw bad_flag_error{};
				}

				buffer = std::move(m_memoryBufferPool.back());
				m_memoryBufferPool.resize(m_memoryBufferPool.size() - 1);
			}

			if (bytesToRead < blockSize) {
				// in case the last block is less than the others
				
				buffer->resize(static_cast<buffer_t::size_type>(bytesToRead));
			}

			reader.readNextChunk(*buffer.get());

			hash_ptr_t hash;

			{
				std::lock_guard<std::mutex> lg{ m_hpGuard };

				if (m_hashPool.size()) {
					hash = std::move(m_hashPool.back());
					m_hashPool.resize(m_hashPool.size() - 1);
				}				
			}

			if (!hash) {
				// hash buffers are relatively small and may be additionally allocated if so needed

				hash.reset(new hash_t(digestSize, unsigned char{0}));
			}

			{
				std::lock_guard<std::mutex> lg{ m_jobGuard };

				m_jobs.emplace_back(std::move(buffer), std::move(hash), blockNumber);
			}

			m_jobsNotEmpty.notify_one();
		}

		waitForWorkers();

		if (m_badFlag.load(std::memory_order_relaxed)) {
			throw bad_flag_error{};
		}

		SignatureHeader header;

		header.hashFunctionId = static_cast<decltype(header.hashFunctionId)>(id);
		header.originalFileSize = inputSize;
		header.blockSize = blockSize;

		writer.writeHeader(header);
		writer.finalize();
	} catch (const bad_flag_error&) {
		throw std::runtime_error("Worker thread error (most probably I/O related)");
	} catch (...) {
		m_badFlag.store(true, std::memory_order_relaxed);		

		throw;
	}
}

// -------------------------------------------------------------------------- //

void FileSignatureCreatorImpl::runHasher(HashWrapperPtr hasher) {
	try {
		while (true) {
			job_t job;
			
			{
				std::unique_lock<std::mutex> ulJobs{ m_jobGuard };			
				
				if (m_jobs.empty() && m_blocksToHash) {
					while (!m_jobsNotEmpty.wait_for(ulJobs, s_threadTimeout,
												    [this]() { return !m_jobs.empty() ||
																	   m_badFlag.load(std::memory_order_relaxed) ||
																	  !m_blocksToHash;
															 }));
				}

				if (m_badFlag.load(std::memory_order_relaxed) ||
					m_jobs.empty()) {

					return;
				}

				// at this point we definitely a have a spare job

				job = std::move(m_jobs[0]);
				m_jobs.pop_front();
				--m_blocksToHash;
			}

			auto& data = std::get<0>(job);
			auto& hash = std::get<1>(job);
			auto blockNumber = std::get<2>(job);

			hasher->createDigest(*data.get(), *hash.get());

			{
				std::lock_guard<std::mutex> lg{ m_resGuard };

				m_results.emplace_back(std::move(hash), blockNumber);
			}

			m_resultsNotEmpty.notify_one();

			{
				std::lock_guard<std::mutex> lg{ m_mbpGuard };

				m_memoryBufferPool.emplace_back(std::move(data));
			}

			m_jobsNotFull.notify_one();
		}
	} catch (...) {
		m_badFlag.store(true, std::memory_order_relaxed);
	}
}

// -------------------------------------------------------------------------- //

void FileSignatureCreatorImpl::runResultWriter(OutputFileWriter& writer, uint64_t blocksToWrite) {
	try {
		for (; blocksToWrite > 0; --blocksToWrite) {
			result_t result;
			
			{
				std::unique_lock<std::mutex> ulResults{ m_resGuard };

				if (m_results.empty()) {
					while (!m_resultsNotEmpty.wait_for(ulResults, s_threadTimeout,
													   [this]() { return !m_results.empty() ||
																		  m_badFlag.load(std::memory_order_relaxed);
															    }));
				}

				if (m_badFlag.load(std::memory_order_relaxed)) {
					return;
				}

				// at this point we definitely a have a spare result

				result = std::move(m_results[0]);
				m_results.pop_front();
			}

			auto& hash = result.first;
			auto blockNumber = result.second;

			writer.writeHash(blockNumber, *hash.get());
			
			{
				std::lock_guard<std::mutex> lg{ m_hpGuard };

				m_hashPool.emplace_back(std::move(hash));
			}
		}
	} catch (...) {
		m_badFlag.store(true, std::memory_order_relaxed);
	}
}

// -------------------------------------------------------------------------- //
/*
	FileSignatureCreator methods implementation
 */
// -------------------------------------------------------------------------- //

FileSignatureCreator::FileSignatureCreator (const char* inFilePath, const char* outFilePath,
											uint32_t blockSize, HashFunctionId id) {
	FileSignatureCreatorImpl impl;

	impl.launch(inFilePath, outFilePath, blockSize, id);
}

// -------------------------------------------------------------------------- //

FileSignatureCreator::FileSignatureCreator (const std::enable_if_t<!std::is_same_v<char, path::value_type>, path::value_type>* inFilePath,
										    const std::enable_if_t<!std::is_same_v<char, path::value_type>, path::value_type>* outFilePath,
											uint32_t blockSize, HashFunctionId id) {
	FileSignatureCreatorImpl impl;

	impl.launch(inFilePath, outFilePath, blockSize, id);
}