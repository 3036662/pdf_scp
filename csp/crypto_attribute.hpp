/* File: crypto_attribute.hpp
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
#include <string>
#include <vector>

#include "resolve_symbols.hpp"
#include "typedefs.hpp"

namespace pdfcsp::csp {

/**
 * @brief representation of CRYPT_ATTRIBUTE object
 * @throws runtime_error exception on contructor fail
 */
class CryptoAttribute {
 public:
  [[nodiscard]] const std::string &get_id() const noexcept { return id_; };
  [[nodiscard]] unsigned int get_blobs_count() const noexcept {
    return blobs_count_;
  }
  [[nodiscard]] const std::vector<BytesVector> &get_blobs() const noexcept {
    return blobs_;
  }

  explicit CryptoAttribute(const CRYPT_ATTRIBUTE *raw_attr);

 private:
  std::string id_;
  unsigned int blobs_count_ = 0;
  std::vector<BytesVector> blobs_;
};

/**
 * @brief Bunch of CryptoAttribute objects
 * @throws runtime_error on construct
 */
class CryptoAttributesBunch {
 public:
  [[nodiscard]] unsigned int get_count() const noexcept { return count_; }
  [[nodiscard]] const std::vector<CryptoAttribute> &get_bunch() const noexcept {
    return bunch_;
  }
  explicit CryptoAttributesBunch(const CRYPT_ATTRIBUTES *raw_attributes);

  [[nodiscard]] const BytesVector &GetAttrBlobByID(
    const std::string &oid) const;

 private:
  unsigned int count_ = 0;
  std::vector<CryptoAttribute> bunch_;
};

}  // namespace pdfcsp::csp