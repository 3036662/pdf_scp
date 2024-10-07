#pragma once

#include <boost/interprocess/allocators/allocator.hpp>
#include <boost/interprocess/containers/string.hpp>
#include <boost/interprocess/containers/vector.hpp>
#include <boost/interprocess/managed_shared_memory.hpp>
#include <cstdint>

namespace pdfcsp::ipc_bridge {

namespace bip = boost::interprocess;

using IpcByteAllocator =
    bip::allocator<unsigned char, bip::managed_shared_memory::segment_manager>;
using IpcBytesVector = bip::vector<unsigned char, IpcByteAllocator>;

using IpcCharAllocator =
    bip::allocator<char, bip::managed_shared_memory::segment_manager>;
using IpcString =
    bip::basic_string<char, std::char_traits<char>, IpcCharAllocator>;
using IpcStringAllocator =
    bip::allocator<IpcString, bip::managed_shared_memory::segment_manager>;

using IpcTimeTAllocator =
    bip::allocator<time_t, bip::managed_shared_memory::segment_manager>;
using IpcTimeTVector = bip::vector<time_t, IpcTimeTAllocator>;

using IpcUint64Allocator =
    bip::allocator<uint64_t, bip::managed_shared_memory::segment_manager>;
using IpcUint64Vector = bip::vector<uint64_t, IpcUint64Allocator>;

constexpr int kMaxResultTimeout = 30;
constexpr int kMaxParamTimeout = 3;
constexpr const char *kSharedMemoryName = "MySharedMemory";
constexpr const char *kParamSemaphoreName = "ParamSem";
constexpr const char *kResultSemaphoreName = "ResultSeM";
constexpr const char *kParamName = "ParamVal";
constexpr const char *kResultName = "ResultVal";

} // namespace pdfcsp::ipc_bridge