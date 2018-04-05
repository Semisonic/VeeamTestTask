# C++ developer test task, [Veeam Software](https://www.veeam.com)

This project is my implementation of the test task that **Veeam Software**, the maker of various IT infrastructure management tools, offers to their **C++ developer** applicants.
# Task description
The goal is to create a command-line tool for making so called "signatures" of the input files. It should take a file as its input, split its contents in block, hash those chunks using one of the supported hashing/checksum algorithms and write the hashes into an output file.
## Tool interface
The command-line tool must take the following arguments:
 - Input file path
 - Output file path
 - Block size (optional, 1MB by default)

## Conditions and limitations
 - The tool must efficiently utilize the **multiprocessing capabilities** of the computer.
 - The error handling must be implemented using **exceptions**.
 - The resource management must be implemented using **smart pointers**.
 - To enable parallel computing one must not use the 3rd party libraries, e.g. **OpenCL** or **OpenMP**.
 - The tool must correctly process **large files** whose size exceeds the amount of available memory (i.e. 4GB and more).
 - Which hashing algorithm to use is at the developer's discretion.
## Implementation
The implementation is written using **Microsoft Visual Studio 2017** and can be compiled into a Windows console application, but the core algorithm uses only the standard C++ and is portable.

To provide the hashing functionality, **CryptoPP** library is used, its source code is bundled with the project and must be built before the tool itself.

To demonstrate the potential use of different hashing algorithms, the tool supports two algorithms, **CRC32** and **MD5**, out of the box and provides the means of extending the support to any number of algorithms.
The algorithm may be chosen by the user via the command line arguments.
## Main source files
 - **VeeamTestTask.cpp** - the entry point for the application, implements the command-line arguments processing.
 - **HashWrappers.cpp/h** - incapsulation of the hashing algorithm and a generic interface for using them in a uniform way.
 - **FileSignatureCreator.cpp/h** - implementation of the core functionality of the tool (input/output file processing, thread pooling and synchronization, memory management) and a definition of a "signature" file header with all the metadata required.

