#include "message.hpp"
#include "message_handler.hpp"
#include <exception>
#include <sstream>
#include <stdexcept>
#include <vector>

namespace pdfcsp::csp {

// check resolver and data and call DecodeDetachedMessage
Message::Message(std::shared_ptr<ResolvedSymbols> dl,
                 BytesVector &&raw_signature, BytesVector &&data)
    : symbols_(std::move(dl)) {
  if (!symbols_) {
    throw std::runtime_error("Symbol resolver is null");
  }
  if (raw_signature.empty() || data.empty()) {
    throw std::logic_error("Empty data");
  }
  DecodeDetachedMessage(raw_signature, data);
}

CadesType Message::getCadesType() const noexcept {
  CadesType res = CadesType::kUnknown;
  if (!symbols_ || !msg_handler_) {
    return res;
  }
  DWORD buff_size = 0;
  try {
    // get size
    ResCheck(symbols_->dl_CryptMsgGetParam(
                 *msg_handler_, CMSG_SIGNER_CERT_INFO_PARAM, 0, 0, &buff_size),
             "get CMSG_SIGNER_CERT_INFO_PARAM");

  } catch (const std::exception &ex) {
    return res;
  }
  return res;
}

// ------------------------- private ----------------------------------

// throw exception if FALSE
void Message::ResCheck(BOOL res, const std::string &msg) const {
  if (res != TRUE) {
    std::stringstream ss;
    ss << msg << " error " << std::hex << symbols_->dl_GetLastError();
    throw std::runtime_error(ss.str());
  }
}

// decode a message
void Message::DecodeDetachedMessage(const BytesVector &sig,
                                    const BytesVector &data) {
  // create new message
  msg_handler_ = MsgDescriptorWrapper(
      symbols_->dl_CryptMsgOpenToDecode(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                                        CMSG_DETACHED_FLAG, 0, 0, 0, 0),
      symbols_);
  if (!msg_handler_) {
    throw std::runtime_error("CryptMsgOpenToDecode failed");
  }
  // load data to message
  ResCheck(
      symbols_->dl_CryptMsgUpdate(*msg_handler_, sig.data(), sig.size(), TRUE),
      "Msg update with data");
  // load data to the Msg
  ResCheck(symbols_->dl_CryptMsgUpdate(*msg_handler_, data.data(), data.size(),
                                       TRUE),
           "Load data to msg");
}

} // namespace pdfcsp::csp