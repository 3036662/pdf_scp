#pragma once
#include <boost/interprocess/allocators/allocator.hpp>
#include <boost/interprocess/containers/string.hpp>
#include <boost/interprocess/containers/vector.hpp>
#include <boost/interprocess/managed_shared_memory.hpp>
#include <cstdint>
#include <sys/types.h>

namespace pdfcsp::ipc_bridge {

namespace bip = boost::interprocess;

using IpcByteAllocator =
    bip::allocator<uint64_t, bip::managed_shared_memory::segment_manager>;

using IpcBytesVector = bip::vector<uint64_t, IpcByteAllocator>;

using IpcCharAllocator =
    bip::allocator<char, bip::managed_shared_memory::segment_manager>;
using IpcString =
    bip::basic_string<char, std::char_traits<char>, IpcCharAllocator>;
using IpcStringAllocator =
    bip::allocator<IpcString, bip::managed_shared_memory::segment_manager>;

struct IPCParam {
  explicit IPCParam(const IpcStringAllocator &string_alloc,
                    const IpcByteAllocator &byte_allocator)
      : byte_range_arr(byte_allocator), raw_signature_data(byte_allocator),
        file_path(string_alloc) {}
  IpcBytesVector byte_range_arr;
  IpcBytesVector raw_signature_data;
  IpcString file_path;
};

} // namespace pdfcsp::ipc_bridge