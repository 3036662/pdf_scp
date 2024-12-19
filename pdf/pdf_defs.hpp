/* File: pdf_defs.hpp  
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
#include <cstddef>
#define POINTERHOLDER_TRANSITION 3 // NOLINT (cppcoreguidelines-macro-usage)
#include <cstdint>
#include <qpdf/QPDF.hh>
#include <qpdf/QPDFAcroFormDocumentHelper.hh>
#include <qpdf/QPDFAnnotationObjectHelper.hh>
#include <qpdf/QPDFObjectHandle.hh>
#include <qpdf/QPDFPageObjectHelper.hh>
#include <qpdf/QUtil.hh>
#include <vector>

namespace pdfcsp::pdf {
using RangesVector = std::vector<std::pair<uint64_t, uint64_t>>;
using BytesVector = std::vector<unsigned char>;
using PtrPdfObj = std::unique_ptr<QPDFObjectHandle>;
using PtrPdfObjShared = std::shared_ptr<QPDFObjectHandle>;

constexpr const char *const kTagAcroForm = "/AcroForm";
constexpr const char *const kTagFields = "/Fields";
constexpr const char *const kTagType = "/Type";
constexpr const char *const kTagSubType = "/Subtype";
constexpr const char *const kTagFilter = "/Filter";
constexpr const char *const kTagSubFilter = "/SubFilter";
constexpr const char *const kTagContents = "/Contents";
constexpr const char *const kTagByteRange = "/ByteRange";
constexpr const char *const kTagXObject = "/XObject";
constexpr const char *const kTagForm = "/Form";
constexpr const char *const kTagFormType = "/FormType";
constexpr const char *const kTagBBox = "/BBox";
constexpr const char *const kTagImage = "/Image";
constexpr const char *const kTagWidth = "/Width";
constexpr const char *const kTagHeight = "/Height";
constexpr const char *const kTagColorSpace = "/ColorSpace";
constexpr const char *const kTagBitsPerComponent = "/BitsPerComponent";
constexpr const char *const kTagLength = "/Length";
constexpr const char *const kTagResources = "/Resources";
constexpr const char *const kTagFT = "/FT";
constexpr const char *const kTagSig = "/Sig";
constexpr const char *const kTagSigFlags = "/SigFlags";
constexpr const char *const kTagT = "/T";
constexpr const char *const kTagF = "/F";
constexpr const char *const kTagAnnot = "/Annot";
constexpr const char *const kTagAnnots = "/Annots";
constexpr const char *const kTagWidget = "/Widget";
constexpr const char *const kTagP = "/P";
constexpr const char *const kTagRect = "/Rect";
constexpr const char *const kTagAP = "/AP";
constexpr const char *const kTagN = "/N";
constexpr const char *const kTagV = "/V";
constexpr const char *const kTagTrustedParams = "/TrustedParams";
constexpr const char *const kTagPages = "/Pages";
constexpr const char *const kTagPage = "/Page";
constexpr const char *const kTagKids = "/Kids";
constexpr const char *const kTagMediaBox = "/MediaBox";
constexpr const char *const kTagPrev = "/Prev";
constexpr const char *const kTagSize = "/Size";
constexpr const char *const kTagDocChecksum = "/DocChecksum";
constexpr const char *const kTagPropBuild = "/Prop_Build";
constexpr const char *const kTagAppFullName = "/app_fullname";
constexpr const char *const kTagRoot = "/Root";
constexpr const char *const kTagEncrypt = "/Encrypt";
constexpr const char *const kTagInfo = "/Info";
constexpr const char *const kTagID = "/ID";
constexpr const char *const kTagXref = "/XRef";
constexpr const char *const kTagIndex = "/Index";
constexpr const char *const kTagW = "/W";

constexpr const char *const kDictStart = "<<";
constexpr const char *const kDictEnd = ">>";
constexpr const char *const kStreamStart = "stream\n";
constexpr const char *const kStreamEnd = "endstream\n";
constexpr const char *const kObjEnd = "endobj\n";
constexpr const char *const kXref = "xref\n";
constexpr const char *const kStartXref = "startxref";
constexpr const char *const kEof = "%%EOF";

constexpr const char *const kDeviceRgb = "/DeviceRGB";
constexpr const char *const kErrNoAcro = "No acroform found";

constexpr const char *const kErrPageSize = "Can't determine page size";
constexpr const char *const kAdobePPKLite = "/Adobe.PPKLite";
constexpr const char *const kETSICAdESdetached = "/ETSI.CAdES.detached";
constexpr const char *const kAltLinuxPdfSignTool = "AltLinux sign tool";

// stamp generation
constexpr int kStampImgDefaultWidth = 900;
constexpr int kStampImgDefaultHeight = 300;
constexpr const char *const kStampTitle =
    "ДОКУМЕНТ ПОДПИСАН ЭЛЕКТРОННОЙ ПОДПИСЬЮ";
constexpr const char *const kStampCertText = "Сертификат: ";
constexpr const char *const kStampSubjText = "Владелец: ";
constexpr const char *const kStampValidText = "Действителен: ";
constexpr int kStampTitleFontSize = 40;
constexpr int kStampFontSize = 25;
constexpr size_t kMaxSubjectSymbolsForStandartFontSize = 70;
constexpr int kStampBorderWidth = 7;

constexpr size_t kSizeOfSpacesReservedForByteRanges = 40;

} // namespace pdfcsp::pdf