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

/**
 * @brief Get the Stamp Resulting Size object
 * @param signature parameters
 * @return StampResizeFactor
 */
LIB_API
StampResizeFactor *GetStampResultingSizeFactor(CSignParams params);

LIB_API
void FreeImgResizeFactorResult(StampResizeFactor *p_resize_factor);
}

} // namespace pdfcsp::pdf
