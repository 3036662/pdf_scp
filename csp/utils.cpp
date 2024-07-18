#include "utils.hpp"
#include "resolve_symbols.hpp"
#include <cstdint>
#include <exception>
#include <iostream>
#include <limits>
#include <memory>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <vector>

namespace pdfcsp::csp {

std::vector<unsigned char> CreateBuffer(size_t size) {
  std::vector<unsigned char> res;
  if (size > res.max_size()) {
    throw std::logic_error("Can't reserve a buffer, size > max_size");
  }
  res.reserve(size + 1);
  return res;
}

std::optional<std::vector<unsigned char>>
IntBlobToVec(const CRYPT_INTEGER_BLOB *p_blob) noexcept {
  if (p_blob == nullptr || p_blob->cbData <= 0 || p_blob->cbData > 0x7FFFFFFF) {
    return std::nullopt;
  }
  std::vector<unsigned char> res;
  const DWORD index_last = p_blob->cbData - 1;
  for (int64_t i = static_cast<int>(index_last); i >= 0; --i) {
    // NOLINTNEXTLINE (cppcoreguidelines-pro-bounds-pointer-arithmetic)
    res.push_back(p_blob->pbData[i]);
  }
  if (res.empty()) {
    return std::nullopt;
  }
  return res;
}

std::string
VecBytesStringRepresentation(const std::vector<unsigned char> &vec) noexcept {
  std::stringstream builder;
  for (const auto symbol : vec) {
    builder << std::hex << static_cast<int>(symbol);
  }
  return builder.str();
}

// throw exception if FALSE
void ResCheck(BOOL res, const std::string &msg,
              const PtrSymbolResolver &symbols) {
  if (res != TRUE) {
    std::stringstream string_builder;
    string_builder << msg << " error " << std::hex
                   << symbols->dl_GetLastError();
    throw std::runtime_error(string_builder.str());
  }
}

[[nodiscard]] std::optional<std::string>
NameBlobToString(CERT_NAME_BLOB *ptr_name_blob) noexcept {
  const PtrSymbolResolver symbols_ = std::make_shared<ResolvedSymbols>();
  if (ptr_name_blob == nullptr) {
    return std::nullopt;
  }
  const DWORD dw_size = symbols_->dl_CertNameToStrA(
      X509_ASN_ENCODING, ptr_name_blob, CERT_X500_NAME_STR, nullptr, 0);
  std::string buff;
  std::cout << "DECODED numb=" << dw_size << "\n";
  if (dw_size == 0 || dw_size > std::numeric_limits<unsigned int>::max()) {
    return std::nullopt;
  }
  try {
    auto tmp_buff = CreateBuffer(dw_size);
    // NOLINTNEXTLINE (cppcoreguidelines-pro-type-reinterpret-cast)
    char *ptr_buff_raw = reinterpret_cast<char *>(tmp_buff.data());
    const DWORD resSize = symbols_->dl_CertNameToStrA(
        X509_ASN_ENCODING, ptr_name_blob, CERT_X500_NAME_STR, ptr_buff_raw,
        dw_size); // NOLINT
    if (resSize == 0) {
      return std::nullopt;
    }
    // NOLINTNEXTLINE (cppcoreguidelines-pro-bounds-pointer-arithmetic)
    std::copy(tmp_buff.data(), tmp_buff.data() + resSize - 1,
              std::back_inserter(buff));
    tmp_buff.clear();
    return buff;
  } catch (const std::exception &) {
    return std::nullopt;
  }
  return std::nullopt;
}

} // namespace pdfcsp::csp