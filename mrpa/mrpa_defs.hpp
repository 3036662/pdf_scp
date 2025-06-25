#pragma once
#include <cstddef>

namespace mrpa {

constexpr size_t kXmlToJsonMaxRecursionLevel = 100;
constexpr size_t kFlagsValLen = 8;
constexpr size_t kFlagDovelPos = 3;
constexpr const char* const kAttributeFlags = "ПрЭлФорм";
constexpr const char* const kAttributeFileID = "ИдФайл";
constexpr const char* const kAttributeFileIDTax = "ИдФайлНО";
constexpr const char* const kPrefixNormal = "ON_EMCHD";
constexpr const char* const kPrefixTax = "ON_DOVEL";
constexpr const char* const kNodeDocument = "Документ";
constexpr const char* const kNodeAttorney = "Довер";
constexpr const char* const kNodeAttorneyInfo = "СвДов";
constexpr const char* const kAttributeAttorneyID = "НомДовер";
constexpr const char* const kHeaderString =
  R"(<?xml version="1.0" encoding="UTF-8"?>)";  // НомДовер

// XML Tags
constexpr const char* const kXMLDoc = "Документ";
constexpr const char* const kXMLAttorney = "Довер";
constexpr const char* const kXMLGranterInfoTop = "СвДоверит";

}  // namespace mrpa