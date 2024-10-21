#pragma once

#include "cert_common_info.hpp"
#include "message.hpp"
#include "resolve_symbols.hpp"
#include "typedefs.hpp"
#include <memory>

namespace pdfcsp::csp {

using PtrMsg = std::shared_ptr<Message>;

class Csp {
public:
  /**
   * @brief Construct a new Csp object
   * @throws std::runtime_error if failed to resolve symbols
   */
  Csp() : dl_{std::make_shared<ResolvedSymbols>()} {}

  // no-copy, no assignment
  Csp(const Csp &) = delete;
  Csp(Csp &&) = delete;
  Csp &operator=(const Csp &) = delete;
  Csp &operator=(Csp &&) = delete;
  ~Csp() = default;

  /**
   * @brief Open a detached message
   *
   * @param message raw message data
   * @param data data signed by this message
   * @return Message (smart pointer)
   */
  PtrMsg OpenDetached(const BytesVector &message) noexcept;

  void EnableLogToStdErr(bool val) noexcept { std_err_flag_ = val; }

  std::vector<CertCommonInfo> GetCertList() noexcept;

private:
  bool std_err_flag_ = true;
  void Log(const char *msg) const noexcept;
  inline void Log(const std::string &msg) const noexcept;

  PtrSymbolResolver dl_;
};

} // namespace pdfcsp::csp