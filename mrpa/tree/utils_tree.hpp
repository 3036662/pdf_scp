#pragma once
#include <filesystem>

#include "node.hpp"

namespace mrpa {

/// @throws
PtrNode createNodeFromFile(const std::string& path, uint64_t node_id);

}  // namespace mrpa