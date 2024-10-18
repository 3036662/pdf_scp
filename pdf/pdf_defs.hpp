#pragma once
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

constexpr const char *const kDictStart = "<<";
constexpr const char *const kDictEnd = ">>";
constexpr const char *const kStreamStart = "stream\n";
constexpr const char *const kStreamEnd = "endstream\n";
constexpr const char *const kObjEnd = "endobj\n";

constexpr const char *const kDeviceRgb = "/DeviceRGB";
constexpr const char *const kErrNoAcro = "No acroform found";
} // namespace pdfcsp::pdf