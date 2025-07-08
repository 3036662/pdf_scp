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
constexpr const char* const kXMLGrantorForeignCompany = "ИнОргДовер";
constexpr const char* const kXMLGrantorIp = "ИПДовер";
constexpr const char* const kXMLGrantorPerson = "ФЛДовер";
constexpr const char* const kXMLRussianCompanyInfo = "СвРосОрг";
constexpr const char* const kXMLAuthorityDoc = "ДокПдтв";
constexpr const char* const kXMLRegAddress = "АдрРег";
constexpr const char* const kXMLAddressRF = "АдрРФ";
constexpr const char* const kXMLFiasAddressRF = "ФИАСАдрРФ";
constexpr const char* const kXMLEntityWithoutAttorney = "ЛицоБезДов";
constexpr const char* const kXMLExetuiveCompany = "СВЮЛ";
constexpr const char* const kXMLExetuiveCompanyInfo = "СвЮЛЕИО";
constexpr const char* const kXMLPersonInfo = "СвФЛ";
constexpr const char* const kXMLPersonInfoDetails = "СведФЛ";
constexpr const char* const kXMLRepresentativePersonInfo = "СведФизЛ";
constexpr const char* const kXMLPersonalID = "УдЛичнФЛ";
constexpr const char* const kXMLPersonalAddress = "АдрМЖ";
constexpr const char* const kXMLPersonalIDinfo = "УдЛичнФЛ";
constexpr const char* const kXMLPersonNameStruct = "ФИО";
constexpr const char* const kXMLIpInfo = "СвИП";
constexpr const char* const kXMLForeignCompanyInfo = "СвИнОрг";
constexpr const char* const kXMLForeignCompanyInfoAddressRu = "АдрМНФакт";
constexpr const char* const kXMLRepresentativeInfo = "СвУпПред";
constexpr const char* const kXMLRepresentativeNested = "Пред";
constexpr const char* const kXMLForeignCompanyBoss = "СвРукОП";
constexpr const char* const kXMLIncapPersonRepr = "СвЗакПредРук";
constexpr const char* const kXMLNotaryInfo = "СвНотУд";
constexpr const char* const kXMLNotaryPersonInfo = "СвНотДейств";
constexpr const char* const kXMLNotaryExecutorPersonInfo = "ВриоНот";
constexpr const char* const kXMLNotaryExecutorPersonInfoName = "ФИОВриоНот";
constexpr const char* const kXMLNotaryPersonNameInfo = "ФИОНотДейств";
//

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
constexpr const char* const kNotarialMemberStatus = "@СтУчНД";
constexpr const char* const kInnPerson = "@ИННФЛ";
constexpr const char* const kSnilsPerson = "@СНИЛС";
constexpr const char* const kPersonalDuty = "@Должность";
constexpr const char* const kPersonSex = "@Пол";
constexpr const char* const kPersonCitizenship = "@ПрГражд";
constexpr const char* const kPersonEgrn = "@НомЕРН";
constexpr const char* const kPersonBithDate = "@ДатаРожд";
constexpr const char* const kPersonBithPlace = "@МестоРожд";
constexpr const char* const kPersonCitizenshipCountry = "@Гражданство";

constexpr const char* const kPersonLastName = "@Фамилия";
constexpr const char* const kPersonName = "@Имя";
constexpr const char* const kPersonPatronymic = "@Отчество";
constexpr const char* const kPersonalIDdocNumber = "@СерНомДок";
constexpr const char* const kPersonalIDdocDate = "@ДатаДок";
constexpr const char* const kPersonalIDdocIssuer = "@ВыдДок";
constexpr const char* const kPersonalIDdocIssuerID = "@КодВыдДок";

constexpr const char* const kOrgnIP = "@ОГРНИП";
constexpr const char* const kIPTitle = "@НаимИП";
constexpr const char* const kForeignCompanyTitle = "@НаимИО";
constexpr const char* const kLegalCapacitySign = "@ПрДеесп";
constexpr const char* const kHasRepresentativeFlag = "@ПрНалРук";
constexpr const char* const kPersonIncapacityDoc = "@ДокНедеесп";
constexpr const char* const kRepresentativeType = "@ТипПред";
//

}  // namespace mrpa