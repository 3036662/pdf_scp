#include "pdf_csp_c.hpp"
#include "csppdf.hpp"
#include <exception>
#include <iostream>
#include <memory>
#include <stdexcept>

namespace pdfcsp::pdf {

void FreePrepareDocResult(CSignPrepareResult *ptr_res) {
  if (ptr_res == nullptr) {
    return;
  }
  delete ptr_res->storage; // NOLINT
  delete ptr_res;          // NOLINT
}

CSignPrepareResult *PrepareDoc(CSignParams params) {
  // TODO(Oleg) implement
  std::cout << "PDFCSP Prepare doc\n";
  try {
    if (params.file_to_sign_path == nullptr) {
      throw std::runtime_error("file_to_sign == nullptr");
    }
    auto pdf = std::make_unique<Pdf>(params.file_to_sign_path);
    pdf->CreateObjectKit(params);
  } catch (const std::exception &ex) {
    std::cerr << "[PDFCSP::PrepareDoc] error, " << ex.what() << "\n";
  }
  return {};
}

} // namespace pdfcsp::pdf