/* File: pdf_csp_c.hpp  
Copyright (C) Basealt LLC,  2024
Author: Oleg Proskurin, <proskurinov@basealt.ru>

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public License
along with this program; if not, write to the Free Software Foundation,
Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/


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
