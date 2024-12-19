/* File: crypto_attribute.cpp
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

#include "crypto_attribute.hpp"

#include <algorithm>
#include <iterator>
#include <limits>
#include <stdexcept>

#include "typedefs.hpp"

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

const BytesVector &CryptoAttributesBunch::GetAttrBlobByID(
  const std::string &oid) const {
  const auto it_attr = std::find_if(
    bunch_.cbegin(), bunch_.cend(),
    [&oid](const CryptoAttribute &attr) { return attr.get_id() == oid; });
  if (it_attr == bunch_.cend()) {
    throw std::runtime_error(oid + " attribute no found");
  }
  if (it_attr->get_blobs_count() != 1) {
    throw std::runtime_error("invalid number of blobs in the attribute");
  }
  return it_attr->get_blobs()[0];
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
}

}  // namespace pdfcsp::csp
