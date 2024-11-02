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
    auto stage1_result = pdf->CreateObjectKit(params);
    pdf.reset(); // free the source file
    // TODO(Oleg) sign file
    pdf = std::make_unique<Pdf>(stage1_result.file_name);
    auto res = pdf->FindSignatures();
    std::cout << res << "\n";
    auto branges = pdf->getSigByteRanges(0);
    for (const auto &off : branges) {
      std::cout << off.first << " " << off.second << "\n";
    }

  } catch (const std::exception &ex) {
    std::cerr << "[PDFCSP::PrepareDoc] error, " << ex.what() << "\n";
  }
  return {};
}

} // namespace pdfcsp::pdf