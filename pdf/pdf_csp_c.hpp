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

/**
 * @brief Sign the document
 * @param  @see CSignParamsn structs
 * @details creates a temporary file
 */
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

/**
 * @brief Creates a temporary file with embedded annotations
 *
 * @param params An array of CAnnotParams
 * @param number the params array size
 * @param temp_dir_path the path to the temporary folder
 * @param src_file_path the path to the temporary source file
 * @return @see CEmbedAnnotResult
 */
LIB_API
CEmbedAnnotResult *PerfomAnnotEmbeddign(const CAnnotParams params[],
                                        size_t number,
                                        const char *temp_dir_path,
                                        const char *src_file_path);
LIB_API
void CFreeEmbedAnnotResult(CEmbedAnnotResult *ptr);

/**
 * @brief Create a signature stamp and mask
 * @param params @see CSignParams
 * @return BakeSignatureStampResult* the raw images for stamp
 * @warning caller must call the FreeBakedSigStampImage function
 */
LIB_API
BakeSignatureStampResult *BakeSignatureStampImage(CSignParams params);

LIB_API
void FreeBakedSigStampImage(BakeSignatureStampResult *ptr);
}

}  // namespace pdfcsp::pdf
