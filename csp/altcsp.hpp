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

  /**
   * @brief Get the list of certificates for current user
   * @return std::vector<CertCommonInfo>
   */
  std::vector<CertCommonInfo> GetCertList() noexcept;

  /**
   * @brief Construct a CADES message
   *
   * @param cert_serial string
   * @param cert_subject string, common name
   * @param cades_type
   * @param data
   * @param tsp_link wide char string,the TSP server url
   * @return BytesVector - result message
   */
  [[nodiscard]] BytesVector SignData(const std::string &cert_serial,
                                     const std::string &cert_subject,
                                     CadesType cades_type,
                                     const BytesVector &data,
                                     const std::wstring &tsp_link = {});

  // void EnableLogToStdErr(bool val) noexcept { std_err_flag_ = val; }

private:
  PtrSymbolResolver dl_;
};

} // namespace pdfcsp::csp