#pragma once
#include "pod_structs.hpp"

namespace pdfcsp::c_bridge {

#define LIB_API __attribute__((visibility("default")))
#define LIB_LOCAL __attribute__((visibility("hidden")))

extern "C" {

LIB_API
CPodResult *CGetCheckResult(CPodParam params);

LIB_API
void CFreeResult(CPodResult *p_res);
}

} // namespace pdfcsp::c_bridge