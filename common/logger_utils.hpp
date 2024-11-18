#include <memory>
#include <spdlog/logger.h>

namespace pdfcsp::logger {

std::shared_ptr<spdlog::logger> InitLog() noexcept;

} // namespace pdfcsp::logger