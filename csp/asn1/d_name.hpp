#pragma once

#include "asn1.hpp"
#include <optional>
#include <string>
#include <utility>
#include <vector>
namespace pdfcsp::csp::asn {

using OptString = std::optional<std::string>;

struct DName {
  OptString name;
  OptString surname;
  OptString givenName;
  OptString initials;
  OptString generationQualifier;
  OptString organizationalUnitName;
  OptString countryName;
  OptString serialNumber;
  OptString commonName;
  OptString localityName;
  OptString stateOrProvinceName;
  OptString streetAddress;
  OptString organizationName;
  OptString title;
  OptString dnQualifier;
  OptString pseudonym;
  OptString emailAddress;
  OptString inn;
  OptString ogrn;
  OptString snils;
  std::vector<std::pair<std::string, std::string>> unknownOidVals;

  DName() = default;
  explicit DName(const AsnObj &obj);
  [[nodiscard]] std::string DistinguishedName() const noexcept;
};

} // namespace pdfcsp::csp::asn

/*
rfc3280#appendix-A

X520LocalityName ::= CHOICE {
      teletexString     TeletexString   (SIZE (1..ub-locality-name)),
      printableString   PrintableString (SIZE (1..ub-locality-name)),
      universalString   UniversalString (SIZE (1..ub-locality-name)),
      utf8String        UTF8String      (SIZE (1..ub-locality-name)),
      bmpString         BMPString       (SIZE (1..ub-locality-name)) }

X520StateOrProvinceName ::= CHOICE {
      teletexString     TeletexString   (SIZE (1..ub-state-name)),
      printableString   PrintableString (SIZE (1..ub-state-name)),
      universalString   UniversalString (SIZE (1..ub-state-name)),
      utf8String        UTF8String      (SIZE (1..ub-state-name)),
      bmpString         BMPString       (SIZE(1..ub-state-name)) }

X520OrganizationName ::= CHOICE {
      teletexString     TeletexString
                          (SIZE (1..ub-organization-name)),
      printableString   PrintableString
                          (SIZE (1..ub-organization-name)),
      universalString   UniversalString
                          (SIZE (1..ub-organization-name)),
      utf8String        UTF8String
                          (SIZE (1..ub-organization-name)),
      bmpString         BMPString
                          (SIZE (1..ub-organization-name))  }
X520OrganizationalUnitName ::= CHOICE {
      teletexString     TeletexString
                          (SIZE (1..ub-organizational-unit-name)),
      printableString   PrintableString
                          (SIZE (1..ub-organizational-unit-name)),
      universalString   UniversalString
                          (SIZE (1..ub-organizational-unit-name)),
      utf8String        UTF8String
                          (SIZE (1..ub-organizational-unit-name)),
      bmpString         BMPString
                          (SIZE (1..ub-organizational-unit-name)) }

X520Title ::= CHOICE {
      teletexString     TeletexString   (SIZE (1..ub-title)),
      printableString   PrintableString (SIZE (1..ub-title)),
      universalString   UniversalString (SIZE (1..ub-title)),
      utf8String        UTF8String      (SIZE (1..ub-title)),
      bmpString         BMPString       (SIZE (1..ub-title)) }

X520dnQualifier ::=     PrintableString

X520countryName ::=     PrintableString (SIZE (2))

X520SerialNumber ::=    PrintableString (SIZE (1..ub-serial-number))

DomainComponent ::=     IA5String

EmailAddress ::=         IA5String (SIZE (1..ub-emailaddress-length))

Name ::= CHOICE { -- only one possibility for now --
      rdnSequence  RDNSequence }

RDNSequence ::= SEQUENCE OF RelativeDistinguishedName

DistinguishedName ::=   RDNSequence

RelativeDistinguishedName  ::=
                    SET SIZE (1 .. MAX) OF AttributeTypeAndValue
AttributeTypeAndValue ::= SEQUENCE {
     type     AttributeType,
     value    AttributeValue }

AttributeType ::= OBJECT IDENTIFIER

AttributeValue ::= ANY DEFINED BY AttributeType


*/