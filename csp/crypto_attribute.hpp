#pragma once

#include <vector>
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Winvalid-utf8"
#include "CSP_WinCrypt.h"
#pragma GCC diagnostic pop

#include "typedefs.hpp"
#include <string>

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

  [[nodiscard]] const BytesVector &
  GetAttrBlobByID(const std::string &oid) const;

private:
  unsigned int count_ = 0;
  std::vector<CryptoAttribute> bunch_;
};

} // namespace pdfcsp::csp