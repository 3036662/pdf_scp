#include "crypto_attribute.hpp"
#include "typedefs.hpp"
#include <cstdint>
#include <iterator>
#include <limits>
#include <stdexcept>

namespace pdfcsp::csp {

CryptoAttributesBunch::CryptoAttributesBunch(
    const CRYPT_ATTRIBUTES *raw_attributes) {
  if (raw_attributes == nullptr) {
    throw std::runtime_error("pointer to attributes = nullptr");
  }
  if (raw_attributes->cAttr > std::numeric_limits<DWORD>::max()) {
    throw std::runtime_error("invalid attributes count field");
  }
  if (raw_attributes->cAttr == 0) {
    count_ = 0;
    return;
  }
  // iterate all attributes
  for (uint i = 0; i < raw_attributes->cAttr; ++i) {
    const CRYPT_ATTRIBUTE *attr = (raw_attributes->rgAttr) + i;
    bunch_.emplace_back(attr);
    ++count_;
  }
}

CryptoAttribute::CryptoAttribute(const CRYPT_ATTRIBUTE *raw_attr) {
  if (raw_attr == nullptr) {
    throw std::runtime_error("nullptr pointer to CRYPT_ATTRIBUTE");
  }
  if (raw_attr->pszObjId == nullptr ||
      raw_attr->cValue > std::numeric_limits<unsigned int>::max() ||
      (raw_attr->cValue > 0 && raw_attr->rgValue == nullptr)) {
    throw std::runtime_error("invalid fields in CRYPT_ATTRIBUTE");
  }
  id_ = raw_attr->pszObjId;
  blobs_count_ = raw_attr->cValue;
  // copy blobs
  for (unsigned int i = 0; i < blobs_count_; ++i) {
    BytesVector blob;
    const CRYPT_ATTR_BLOB *ptr_blob = raw_attr->rgValue + i;
    if ((ptr_blob->cbData > 0 && ptr_blob->pbData == nullptr) ||
        ptr_blob->cbData > std::numeric_limits<unsigned int>::max()) {
      throw std::runtime_error("CRYPT_ATTR_BLOB invalid data");
    }
    // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    std::copy(ptr_blob->pbData, ptr_blob->pbData + ptr_blob->cbData,
              std::back_inserter(blob));
    blobs_.push_back(std::move(blob));
    blob.clear();
  }
  // BytesVector blob;
}

} // namespace pdfcsp::csp
