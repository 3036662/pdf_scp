#pragma once
#include <libxml++/libxml++.h>

#include <memory>
#include <optional>
#include <string>

namespace mrpa {

/**
 * @brief Represents a machine readable power attorney
 */
class Mrpa {
 public:
  Mrpa() = default;
  explicit Mrpa(const std::string& filename) noexcept;

  [[nodiscard]] bool IsValid() const noexcept { return is_valid_; }

 private:
  bool is_valid_ = false;
  std::optional<std::string> err_string_;
  std::unique_ptr<xmlpp::DomParser> dom_parser;
};

}  // namespace mrpa