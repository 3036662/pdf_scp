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
constexpr const char* const kXMLGrantorInfoTop = "СвДоверит";
constexpr const char* const kXMLGrantor = "Доверит";
constexpr const char* const kXMLGrantorRussianCompany = "РосОргДовер";
constexpr const char* const kXMLRussianCompanyInfo = "СвРосОрг";
constexpr const char* const kXMLAuthorityDoc = "ДокПдтвТип";
constexpr const char* const kXMLRegAddress = "АдрРег";
constexpr const char* const kXMLAddressRF = "АдрРФ";
constexpr const char* const kXMLFiasAddressRF = "ФИАСАдрРФ";
constexpr const char* const kXMLEntityWithoutAttorney = "ЛицоБезДов";
constexpr const char* const kXMLExetuiveCompany = "СВЮЛ";
constexpr const char* const kXMLExetuiveCompanyInfo = "СвЮЛЕИО";

// JSON attribs
constexpr const char* const kGranterTypeAttr = "@ТипДоверит";
constexpr const char* const kManaginCompany = "@ЕИОУК";
constexpr const char* const kManaginPerson = "@ЕИОФЛ";
constexpr const char* const kManaginIP = "@ЕИОИП";
constexpr const char* const kRussianCompanyName = "@НаимОрг";
constexpr const char* const kKPP = "@КПП";
constexpr const char* const kOGRN = "@ОГРН";
constexpr const char* const kDepartmentNumber = "@РегНомер";
constexpr const char* const kINNle = "@ИННЮЛ";
constexpr const char* const kIncorpPapers = "@НаимУчрДок";
constexpr const char* const kPhone = "@КонтактТлф";
constexpr const char* const kEmail = "@АдрЭлПочт";
constexpr const char* const kNotarialStatus = "@СтУчНД";
constexpr const char* const kAuthorityDocName = "@НаимДокПдтв";
constexpr const char* const kDocIssueDate = "@ДатаВыд";
constexpr const char* const kDocIssuer = "@КемВыд";
constexpr const char* const kAuthorityDocInfo = "@СвУдДок";
constexpr const char* const kState = "@Регион";
constexpr const char* const kIDFias = "@ИдФИАС";
constexpr const char* const kManyPersons = "@ПолнЮЛ";

}  // namespace mrpa