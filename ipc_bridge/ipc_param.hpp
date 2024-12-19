/* File: ipc_param.hpp  
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

#include "ipc_typedefs.hpp"
#include <ctime>
#include <sys/types.h>

namespace pdfcsp::ipc_bridge {

/**
 * @brief Used for passing parameters for signature creation and check  through
 * the IPC
 */
struct IPCParam {
  explicit IPCParam(const IpcStringAllocator &string_alloc,
                    const IpcByteAllocator &byte_allocator,
                    const IpcUint64Allocator &uint64_alloc)
      : command(string_alloc), byte_range_arr(uint64_alloc),
        raw_signature_data(byte_allocator), file_path(string_alloc),
        cert_subject(string_alloc), cert_serial(string_alloc),
        cades_type(string_alloc), tsp_link(string_alloc) {}
  IpcString command; /// @see c_bridge/pod_structs.hpp#CPodParam
  IpcUint64Vector byte_range_arr;
  IpcBytesVector raw_signature_data;
  IpcString file_path;
  // for creating signature
  IpcString cert_subject;
  IpcString cert_serial;
  IpcString cades_type;
  IpcString tsp_link;
};

} // namespace pdfcsp::ipc_bridge