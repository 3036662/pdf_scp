#pragma once

#include "ipc_typedefs.hpp"
#include <ctime>
#include <sys/types.h>

namespace pdfcsp::ipc_bridge {

struct IPCParam {
  explicit IPCParam(const IpcStringAllocator &string_alloc,
                    const IpcByteAllocator &byte_allocator,
                    const IpcUint64Allocator &uint64_alloc)
      : command(string_alloc), byte_range_arr(uint64_alloc),
        raw_signature_data(byte_allocator), file_path(string_alloc) {}
  IpcString command;
  IpcUint64Vector byte_range_arr;
  IpcBytesVector raw_signature_data;
  IpcString file_path;
};

} // namespace pdfcsp::ipc_bridge