#include "tree_context.hpp"

#include <memory>

#include "node.hpp"

namespace mrpa {

std::atomic_uint64_t TreeContext::counter_ = 0;

TreeContext::TreeContext()
  : root_(std::make_shared<DirNode>("", NodeType::kRoot, 0, false)),
    logger_{pdfcsp::logger::InitLog()} {}

// bool TreeContext::AddFile(const std::string& path) noexcept { return false;
// };

}  // namespace mrpa