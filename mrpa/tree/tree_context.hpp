#pragma once

#include <atomic>
#include <cstdint>

#include "logger_utils.hpp"
#include "node.hpp"

namespace mrpa {

class TreeContext {
 public:
  TreeContext();

  [[nodiscard]] bool AddFile(const std::string& path) noexcept;

  uint64_t static NextId() {
    return counter_.fetch_add(1, std::memory_order_relaxed) + 1;
  }

 private:
  PtrNode root_;
  std::shared_ptr<spdlog::logger> logger_;
  static std::atomic_uint64_t counter_;
};

}  // namespace mrpa