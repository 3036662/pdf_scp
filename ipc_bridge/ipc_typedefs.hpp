/* File: ipc_typedefs.hpp
Copyright (C) Basealt LLC,  2024
Author: Oleg Proskurin, <proskurinov@basealt.ru>

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public License
along with this program; if not, write to the Free Software Foundation,
Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

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

}  // namespace pdfcsp::ipc_bridge