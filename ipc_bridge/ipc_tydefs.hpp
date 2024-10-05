#pragma once

#include <boost/interprocess/allocators/allocator.hpp>
#include <boost/interprocess/containers/string.hpp>
#include <boost/interprocess/containers/vector.hpp>
#include <boost/interprocess/managed_shared_memory.hpp>

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

} // namespace pdfcsp::ipc_bridge