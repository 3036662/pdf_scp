#pragma once
#include <filesystem>

#include "node.hpp"

namespace mrpa {

PtrNode createNodeFromFile(const std::string& path) noexcept;

}  // namespace mrpa