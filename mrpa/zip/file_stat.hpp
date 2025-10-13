#pragma once

#include <boost/json/object.hpp>
#include <cstdint>
#include <optional>
#include <string>

namespace zip_cpp {

struct FileStat {
  std::optional<std::string> name;
  std::optional<uint64_t> index;
  std::optional<uint64_t> size;
  std::optional<uint64_t> size_compressed;
  std::optional<time_t> time_mod;
  std::optional<uint32_t> crc;
  std::optional<uint16_t> comp_method;
  std::optional<uint16_t> encryption_method;
  bool encrypted = false;

  [[nodiscard]] std::string toString() const noexcept;
  [[nodiscard]] boost::json::object toJson() const;
};

}  // namespace zip_cpp