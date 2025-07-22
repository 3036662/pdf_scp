#pragma once
#include <filesystem>

#include "node.hpp"

namespace mrpa {

PtrNode createNodeFromFile(const std::string& path, uint64_t node_id) noexcept;

}  // namespace mrpa