#pragma once
#include "pdf_pod_structs.hpp"

namespace pdfcsp::pdf {

#define LIB_API __attribute__((visibility("default")))
#define LIB_LOCAL __attribute__((visibility("hidden")))

extern "C" {

LIB_API
CSignPrepareResult *PrepareDoc(CSignParams params);

LIB_API
void FreePrepareDocResult(CSignPrepareResult *ptr_res);
}

} // namespace pdfcsp::pdf
