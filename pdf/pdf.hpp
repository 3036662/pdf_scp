#pragma once

#include <string>
#include <vector>

namespace pdfcsp::pdf {

class Pdf {
public:
  /**
   * @brief Open a pdf file
   * @param path string path to file
   * @throws std::logical_error if file doesn't exist or can't open
   */
  void Open(const std::string &path);

  /**
   * @brief Get the Raw Signature data
   * @return std::vector<unsigned char>
   */
  std::vector<unsigned char> getRawSignature() noexcept;

  /**
   * @brief Get the Raw Data object excluding the signature value
   * @return std::vector<unsigned char>
   */
  std::vector<unsigned char> getRawData() noexcept;

private:
};

} // namespace  pdfcsp::pdf