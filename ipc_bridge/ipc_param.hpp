#pragma once

#include "ipc_tydefs.hpp"
#include <ctime>
#include <sys/types.h>

namespace pdfcsp::ipc_bridge {

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