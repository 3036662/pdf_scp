#pragma once

/**
 * @brief Common Cryptographic Message Syntax (CMS) RFC 5652
 * @details summary from RFC 3161, 5652, 5280, 3161, 2630, 5755
 */

#include "asn1.hpp"
#include "typedefs.hpp"
#include <cstdint>
#include <string>
#include <variant>
#include <vector>

namespace pdfcsp::csp::asn {

/* RFC 5652
ContentInfo ::= SEQUENCE {
        contentType ContentType,
        content [0] EXPLICIT ANY DEFINED BY contentType }

ContentType ::= OBJECT IDENTIFIER
*/
template <typename CONTENT_T> struct ContentInfo {
  std::string contentType; // OID
  CONTENT_T content;
};

// CertificateSerialNumber  ::=  INTEGER
using CertificateSerialNumber = BytesVector;

/*
AttributeType ::= OBJECT IDENTIFIER
AttributeValue ::= ANY -- DEFINED BY AttributeType
AttributeTypeAndValue ::= SEQUENCE {
     type     AttributeType,
     value    AttributeValue }
 */
struct AttributeTypeAndValue {
  std::string oid; // oid
  std::string val;

  AttributeTypeAndValue() = default;
  explicit AttributeTypeAndValue(const AsnObj &obj);
};

/* RelativeDistinguishedName ::=
     SET SIZE (1..MAX) OF AttributeTypeAndValue */
using RelativeDistinguishedName = std::vector<AttributeTypeAndValue>;

// RDNSequence ::= SEQUENCE OF RelativeDistinguishedName
using RDNSequence = std::vector<RelativeDistinguishedName>;

/* Name ::= CHOICE { -- only one possibility for now --
     rdnSequence  RDNSequence } */
using Name = RDNSequence;

// UniqueIdentifier  ::=  BIT STRING
using UniqueIdentifier = BytesVector;

/* Extension  ::=  SEQUENCE  {
     extnID      OBJECT IDENTIFIER,
     critical    BOOLEAN DEFAULT FALSE,
     extnValue   OCTET STRING
                 -- contains the DER encoding of an ASN.1 value
                 -- corresponding to the extension type identified
                 -- by extnID
     } */
struct Extension {
  std::string extnID; // OID
  bool critical;
  BytesVector extnValue;
};

// Extensions  ::=  SEQUENCE SIZE (1..MAX) OF Extension
using Extensions = std::vector<Extension>;

/* AnotherName ::= SEQUENCE {
     type-id    OBJECT IDENTIFIER,
     value      [0] EXPLICIT ANY DEFINED BY type-id } */
struct AnotherName {
  std::string type_id; // OID
  std::string val;
};

/* EDIPartyName ::= SEQUENCE {
           nameAssigner            [0]     DirectoryString OPTIONAL,
           partyName               [1]     DirectoryString } */
struct EDIPartyName {
  std::string nameAssigner;
  std::string partyName;
};

/* GeneralName ::= CHOICE {
     otherName                 [0]  AnotherName,
     rfc822Name                [1]  IA5String,
     dNSName                   [2]  IA5String,
     x400Address               [3]  ORAddress,
     directoryName             [4]  Name,
     ediPartyName              [5]  EDIPartyName,
     uniformResourceIdentifier [6]  IA5String,
     iPAddress                 [7]  OCTET STRING,
     registeredID              [8]  OBJECT IDENTIFIER } */
using GeneralName =
    std::variant<AnotherName, Name, std::string, EDIPartyName, BytesVector>;

// GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
using GeneralNames = std::vector<GeneralName>;

/* IssuerSerial  ::=  SEQUENCE {
          issuer         GeneralNames,
          serial         CertificateSerialNumber,
          issuerUID      UniqueIdentifier OPTIONAL
        } */
struct IssuerSerial {
  std::string issuer;
  CertificateSerialNumber serial;
  std::optional<UniqueIdentifier> issuerUID;

  IssuerSerial() = default;
  explicit IssuerSerial(const AsnObj &obj);
};

/* RFC 5652
CMSVersion ::= INTEGER
                     { v0(0), v1(1), v2(2), v3(3), v4(4), v5(5) }
*/

/* RFC 5280 [4.1.1.2]
AlgorithmIdentifier  ::=  SEQUENCE  {
        algorithm               OBJECT IDENTIFIER,
        parameters              ANY DEFINED BY algorithm OPTIONAL  } */
struct AlgorithmIdentifier {
  std::string algorithm;  // OID
  BytesVector parameters; // raw parameters

  AlgorithmIdentifier() = default;
  explicit AlgorithmIdentifier(const AsnObj &obj);
};

// DigestAlgorithmIdentifier ::= AlgorithmIdentifier
using DigestAlgorithmIdentifier = AlgorithmIdentifier;

// DigestAlgorithmIdentifiers ::= SET OF DigestAlgorithmIdentifier
using DigestAlgorithmIdentifiers = std::vector<DigestAlgorithmIdentifier>;

/* IssuerAndSerialNumber ::= SEQUENCE {
     issuer Name,
     serialNudmber CertificateSerialNumber } */
struct IssuerAndSerialNumber {
  std::string issuer;
  BytesVector serialNudmber;
};

// SubjectKeyIdentifier ::= OCTET STRING
using SubjectKeyIdentifier = BytesVector;

/* SignerInfo ::= SEQUENCE {
     version CMSVersion,
     sid SignerIdentifier,
     digestAlgorithm DigestAlgorithmIdentifier,
     signedAttrs [0] IMPLICIT SignedAttributes OPTIONAL,
     signatureAlgorithm SignatureAlgorithmIdentifier,
     signature SignatureValue,
     unsignedAttrs [1] IMPLICIT UnsignedAttributes OPTIONAL } */
struct SignerInfo {
  int version = 0;
  std::variant<IssuerAndSerialNumber, SubjectKeyIdentifier> sid;
  DigestAlgorithmIdentifier digestAlgorithm;
};

// SignerInfos ::= SET OF SignerInfo
using SignerInfos = std::vector<SignerInfo>;

/* RFC 5652
EncapsulatedContentInfo ::= SEQUENCE {
     eContentType ContentType,
     eContent [0] EXPLICIT OCTET STRING OPTIONAL }
eContent is the content itself, carried as an octet string.  The
      eContent need not be DER encoded.
ContentType ::= OBJECT IDENTIFIER
*/
template <typename CONTENT = BytesVector> struct EncapsulatedContentInfo {
  std::string eContentType; // OID
  CONTENT eContent;

  EncapsulatedContentInfo() = default;
  explicit EncapsulatedContentInfo(const AsnObj &asn_obj);
};

/* RFC 5652
SignedData ::= SEQUENCE {
        version CMSVersion,
        digestAlgorithms DigestAlgorithmIdentifiers,
        encapContentInfo EncapsulatedContentInfo,
        certificates [0] IMPLICIT CertificateSet OPTIONAL,
        crls [1] IMPLICIT RevocationInfoChoices OPTIONAL,
        signerInfos SignerInfos }
*/
template <typename CONTENT_T> struct SignedData {
  uint version = 0;
  DigestAlgorithmIdentifiers digestAlgorithms; // OID
  EncapsulatedContentInfo<CONTENT_T> encapContentInfo;
  std::vector<BytesVector> certificates; // encoded certificates
  std::vector<BytesVector> crls;         // ecncoded RevocationInfoChoices
  SignerInfos signerInfos;

  SignedData() = default;
  explicit SignedData(const AsnObj &asn_obj);
};

// Version  ::=  INTEGER  {  v1(0), v2(1), v3(2)  }
using Version = uint64_t;

// Extensions  ::=  SEQUENCE SIZE (1..MAX) OF Extension
using Extensions = std::vector<Extension>;

struct RevocedCert {
  CertificateSerialNumber userCertificate;
  std::string revocationDate;
  Extension crlEntryExtensions;
};

/* RFC 5280
TBSCertList  ::=  SEQUENCE  {
        version                 Version OPTIONAL,
                                     -- if present, MUST be v2
        signature               AlgorithmIdentifier,
        issuer                  Name,
        thisUpdate              Time,
        nextUpdate              Time OPTIONAL,
        revokedCertificates     SEQUENCE OF SEQUENCE  {
             userCertificate         CertificateSerialNumber,
             revocationDate          Time,
             crlEntryExtensions      Extensions OPTIONAL
                                      -- if present, version MUST be v2
                                  }  OPTIONAL,
        crlExtensions           [0]  EXPLICIT Extensions OPTIONAL
                                      -- if present, version MUST be v2
                                  }*/
struct TBSCertList {
  std::optional<Version> version;
  AlgorithmIdentifier signature;
  std::string issuer;
  std::string thisUpdate;
  std::string nextUpdate;
  std::vector<RevocedCert> revokedCertificates;
  Extensions crlExtensions;
};

/* RFC 5280
CertificateList  ::=  SEQUENCE  {
        tbsCertList          TBSCertList,
        signatureAlgorithm   AlgorithmIdentifier,
        signatureValue       BIT STRING  }*/
struct CertificateList {
  TBSCertList tbsCertList;
  AlgorithmIdentifier signatureAlgorithm;
  BytesVector signatureValue;
};

/*
GeneralName ::= CHOICE {
     otherName                       [0]     AnotherName,
     rfc822Name                      [1]     IA5String,
     dNSName                         [2]     IA5String,
     x400Address                     [3]     ORAddress,
     directoryName                   [4]     Name,
     ediPartyName                    [5]     EDIPartyName,
     uniformResourceIdentifier       [6]     IA5String,
     iPAddress                       [7]     OCTET STRING,
     registeredID                    [8]     OBJECT IDENTIFIER }

*/

/* RFC 5652
CertificateSet ::= SET OF CertificateChoices

CertificateChoices ::= CHOICE {
       certificate Certificate,
       extendedCertificate [0] IMPLICIT ExtendedCertificate, -- Obsolete
       v1AttrCert [1] IMPLICIT AttributeCertificateV1,       -- Obsolete
       v2AttrCert [2] IMPLICIT AttributeCertificateV2,
       other [3] IMPLICIT OtherCertificateFormat }

*/

/* RFC 5280
Certificate  ::=  SEQUENCE  {
     tbsCertificate       TBSCertificate,
     signatureAlgorithm   AlgorithmIdentifier,
     signature            BIT STRING  }

*/

/* RFC5280
TBSCertificate  ::=  SEQUENCE  {
     version         [0]  Version DEFAULT v1,
     serialNumber         CertificateSerialNumber,
     signature            AlgorithmIdentifier,
     issuer               Name,
     validity             Validity,
     subject              Name,
     subjectPublicKeyInfo SubjectPublicKeyInfo,
     issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
                          -- If present, version MUST be v2 or v3
     subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
                          -- If present, version MUST be v2 or v3
     extensions      [3]  Extensions OPTIONAL
                          -- If present, version MUST be v3 --  }
*/

/* SubjectPublicKeyInfo  ::=  SEQUENCE  {
     algorithm            AlgorithmIdentifier,
     subjectPublicKey     BIT STRING  } */

/* RFC5662
AttributeCertificateV2 ::= AttributeCertificate */

/* RFC5755
AttributeCertificate ::= SEQUENCE {
          acinfo               AttributeCertificateInfo,
          signatureAlgorithm   AlgorithmIdentifier,
          signatureValue       BIT STRING
        }

AttributeCertificateInfo ::= SEQUENCE {
          version                 AttCertVersion, -- version is v2
          holder                  Holder,
          issuer                  AttCertIssuer,
          signature               AlgorithmIdentifier,
          serialNumber            CertificateSerialNumber,
          attrCertValidityPeriod  AttCertValidityPeriod,
          attributes              SEQUENCE OF Attribute,
          issuerUniqueID          UniqueIdentifier OPTIONAL,
          extensions              Extensions OPTIONAL
        }

AttCertVersion ::= INTEGER { v2(1) }

Holder ::= SEQUENCE {
          baseCertificateID   [0] IssuerSerial OPTIONAL,
              -- the issuer and serial number of
              -- the holder's Public Key Certificate
          entityName          [1] GeneralNames OPTIONAL,
              -- the name of the claimant or role
          objectDigestInfo    [2] ObjectDigestInfo OPTIONAL
              -- used to directly authenticate the holder,
              -- for example, an executable
        }
*/

/* RFC5280

ORAddress ::= SEQUENCE {
   built-in-standard-attributes BuiltInStandardAttributes,
   built-in-domain-defined-attributes
                   BuiltInDomainDefinedAttributes OPTIONAL,
   -- see also teletex-domain-defined-attributes
   extension-attributes ExtensionAttributes OPTIONAL }

BuiltInStandardAttributes ::= SEQUENCE {
   country-name                  CountryName OPTIONAL,
   administration-domain-name    AdministrationDomainName OPTIONAL,
   network-address           [0] IMPLICIT NetworkAddress OPTIONAL,
     -- see also extended-network-address
   terminal-identifier       [1] IMPLICIT TerminalIdentifier OPTIONAL,
   private-domain-name       [2] PrivateDomainName OPTIONAL,
   organization-name         [3] IMPLICIT OrganizationName OPTIONAL,
     -- see also teletex-organization-name
   numeric-user-identifier   [4] IMPLICIT NumericUserIdentifier
                                 OPTIONAL,
   personal-name             [5] IMPLICIT PersonalName OPTIONAL,
     -- see also teletex-personal-name
   organizational-unit-names [6] IMPLICIT OrganizationalUnitNames
                                 OPTIONAL }
*/

/* RFC 5755
AttCertIssuer ::= CHOICE {
     v1Form      GeneralNames,  -- MUST NOT be used in this
                                -- profile
     v2Form  [0] V2Form         -- v2 only
   }

V2Form ::= SEQUENCE {
     issuerName             GeneralNames  OPTIONAL,
     baseCertificateID  [0] IssuerSerial  OPTIONAL,
     objectDigestInfo   [1] ObjectDigestInfo  OPTIONAL
            -- issuerName MUST be present in this profile
            -- baseCertificateID and objectDigestInfo MUST
            -- NOT be present in this profile
   }

AttCertValidityPeriod  ::= SEQUENCE {
     notBeforeTime  GeneralizedTime,
     notAfterTime   GeneralizedTime
   }
*/

/* RFC5662
RevocationInfoChoices ::= SET OF RevocationInfoChoice

RevocationInfoChoice ::= CHOICE {
        crl CertificateList,
        other [1] IMPLICIT OtherRevocationInfoFormat }

OtherRevocationInfoFormat ::= SEQUENCE {
        otherRevInfoFormat OBJECT IDENTIFIER,
        otherRevInfo ANY DEFINED BY otherRevInfoFormat }
*/

/*
TBSCertList  ::=  SEQUENCE  {
        version                 Version OPTIONAL,
                                     -- if present, MUST be v2
        signature               AlgorithmIdentifier,
        issuer                  Name,
        thisUpdate              Time,
        nextUpdate              Time OPTIONAL,
        revokedCertificates     SEQUENCE OF SEQUENCE  {
             userCertificate         CertificateSerialNumber,
             revocationDate          Time,
             crlEntryExtensions      Extensions OPTIONAL
                                      -- if present, version MUST be v2
                                  }  OPTIONAL,
        crlExtensions           [0]  EXPLICIT Extensions OPTIONAL
                                      -- if present, version MUST be v2
                                  }
*/

/* RFC5652

SignerIdentifier ::= CHOICE {
     issuerAndSerialNumber IssuerAndSerialNumber,
     subjectKeyIdentifier [0] SubjectKeyIdentifier }

SignedAttributes ::= SET SIZE (1..MAX) OF Attribute

UnsignedAttributes ::= SET SIZE (1..MAX) OF Attribute

Attribute ::= SEQUENCE {
     attrType OBJECT IDENTIFIER,
     attrValues SET OF AttributeValue }

AttributeValue ::= ANY

SignatureValue ::= OCTET STRING

SignatureAlgorithmIdentifier ::= AlgorithmIdentifier

*/

/*
Certificate  ::=  SEQUENCE  {
        tbsCertificate       TBSCertificate,
        signatureAlgorithm   AlgorithmIdentifier,
        signatureValue       BIT STRING  }
*/

} // namespace pdfcsp::csp::asn