#pragma once

#include "bool_results.hpp"
#include "ipc_tydefs.hpp"
#include "typedefs.hpp"

namespace pdfcsp::ipc_bridge {

struct IPCResult {
  pdfcsp::csp::checks::BoolResults bres;
  pdfcsp::csp::CadesType cades_type = pdfcsp::csp::CadesType::kUnknown;
  IpcString cades_t_str;
  IpcString hashing_oid;
  IpcBytesVector encrypted_digest;
  IpcTimeTVector times_collection;
  IpcTimeTVector x_times_collection;
  IpcString cert_issuer_dname;
  IpcString cert_subject_dname;
  IpcBytesVector cert_public_key;
  IpcBytesVector cert_serial;
  time_t signers_time = 0;
  time_t cert_not_before = 0;
  time_t cert_not_after = 0;

  explicit IPCResult(const IpcStringAllocator &string_alloc,
                     const IpcByteAllocator &byte_allocator,
                     const IpcTimeTAllocator &time_allocator)
      : cades_t_str(string_alloc), hashing_oid(string_alloc),
        encrypted_digest(byte_allocator), times_collection(time_allocator),
        x_times_collection(time_allocator), cert_issuer_dname(string_alloc),
        cert_subject_dname(string_alloc), cert_public_key(byte_allocator),
        cert_serial(byte_allocator) {}
};

} // namespace pdfcsp::ipc_bridge