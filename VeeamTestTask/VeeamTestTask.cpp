// VeeamTestTask.cpp : Defines the entry point for the console application.

#include "stdafx.h"

#include "FileSignatureCreator.h"


int wmain (int argc, wchar_t* argv[]) {
	if (argc < 3 || argc > 7 || argc == 4 || argc == 6) {
		std::cout << "Usage: <app-name> <input-file-path> <output-file-path> [-bs <block size, 1MB by default>] [-h <hash-method, CRC32 by default>]" << std::endl
			<< "\t- enter block size as a decimal number of bytes, 1024B min, 64MB max" << std::endl
			<< "\t- possible hash methods: CRC32, MD5" << std::endl;

		return 0;
	}

	uint32_t blockSize{ 1024*1024 };
	HashFunctionId id{ HashFunctionId::CRC32 };

	auto blockSizeSet{ false }, hashMethodSet{ false };

	for (auto i = 3; i < argc; i += 2) {
		std::wstring ws(argv[i]);

		if (ws == L"-bs") {
			if (blockSizeSet) {
				std::cout << "Error: -bs key used multiple times, launch app with no arguments for help" << std::endl;

				return 1;
			}

			blockSizeSet = true;

			std::wistringstream wiss{ argv[i + 1] };

			wiss >> blockSize;

			if (!wiss) {
				std::cout << "Error: Wrong block size format, launch app with no arguments for help" << std::endl;

				return 1;
			}

			if (blockSize > 64 * 1024 * 1024 || blockSize < 1024) {
				std::cout << "Error: Wrong block size, launch app with no arguments for help" << std::endl;

				return 1;
			}
		} else if (ws == L"-h") {
			if (hashMethodSet) {
				std::cout << "Error: -h key used multiple times, launch app with no arguments for help" << std::endl;

				return 1;
			}

			hashMethodSet = true;

			std::wstring ws{ argv[i + 1] };

			if (ws == L"CRC32") {
				// doing nothing, it's the default
			}
			else if (ws == L"MD5") {
				id = HashFunctionId::MD5;
			} else {
				std::cout << "Error: Wrong hash method name, launch app with no arguments for help" << std::endl;

				return 1;
			}
		}
	}
	
	try {
		FileSignatureCreator fsc{ argv[1], argv[2], blockSize, id };
	} catch (const std::exception& e) {
		std::cout << "Hashing error: " << e.what() << std::endl;

		return 1;
	} catch (...) {
		std::cout << "Unknown error!" << std::endl;

		return 1;
	}
	
	return 0;
}

