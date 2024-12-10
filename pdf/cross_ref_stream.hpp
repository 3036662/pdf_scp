#pragma once
#include "pdf_defs.hpp"
#include "pdf_structs.hpp"
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace pdfcsp::pdf {

/**
 * @brief Beginning with PDF 1.5, cross-reference information may be stored in a
 * cross- reference stream instead of in a cross-reference table.
 * @details ISO32000 [7.5.8] Cross-Reference Streams
 */
struct CrossRefStream {
  ObjRawId id;
  std::string type = kTagXref; // /XRef
  int size_val = 0;            // highest object number + 1

  /* /Index[....] - pair of integers for each subsection
   * pair: first_object_id => number_of_objects
   * this array must be soted by first field
   */
  std::vector<std::pair<int, int>> index_vec;

  /* /W Array
   * An array of integers representing the size of the fields in a single cross-
   * reference entry.
   * W always contains three integers
   */
  int w_field_0_size = 1;
  int w_field_1_size = 4; // size of int
  int w_field_2_size = 2;

  std::string prev_val;               // /Prev
  std::string root_id;                // /Root
  std::optional<std::string> info_id; // Info
  // /ID An array of two byte-strings consti-tuting a file identifier
  std::optional<std::string> id_val;
  std::optional<std::string> enctypt; // /Encrypted
  int length = 0;                     // /Length of data stream
  std::vector<XRefEntry> entries;

  /**
   * @brief Return data ready for copying to file
   * @return BytesVector
   * @throws runtime_error on duplicate values
   */
  [[nodiscard]] BytesVector ToRawData() const;
};

} // namespace pdfcsp::pdf