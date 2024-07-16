#pragma once

#include "message_handler.hpp"
#include "resolve_symbols.hpp"
#include "typedefs.hpp"
#include <memory>

namespace pdfcsp::csp {

enum class CadesType {
  kCadesBes,
  kCadesT,
  kCadesXLong1,
  kPkcs7
};

class Message {
public:
  /**
   * @brief Construct a new Message object
   * @param dl a Symbol Resolver
   * @param raw_signature raw signature data
   * @param data
   * @throws std::runtime exception on fail
   */
  explicit Message(std::shared_ptr<ResolvedSymbols> dl,
                   BytesVector &&raw_signature, BytesVector &&data);

private:
  /**
   * @brief Decode raw message
   * @param sig a raw signature data
   * @param data a raw signed data
   * @throws std::runtime exception on fail
   */
  void DecodeDetachedMessage(const BytesVector &sig, const BytesVector &data);

  /**
   * @brief Throws a runtime_error if res=FALSE
   * @param res
   * @throws std::runtime_error
   */
  void ResCheck(BOOL res, const std::string &msg) const;

  std::shared_ptr<ResolvedSymbols> symbols_;
  MsgDescriptorWrapper msg_handler_;
};

} // namespace pdfcsp::csp