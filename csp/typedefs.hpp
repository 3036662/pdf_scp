#pragma once

#include <cstdint>
#include <map>
#include <vector>

namespace pdfcsp::csp {

using BytesVector = std::vector<unsigned char>;

enum class CadesType : uint8_t {
  kUnknown = 0,
  kPkcs7 = 1,
  kCadesBes = 2,
  kCadesT = 3,
  kCadesXLong1 = 4
};

enum class AttributesType : uint8_t { kSigned, kUnsigned };

enum class MessageType : uint8_t { kAttached, kDetached };

using ExplicitlySetRawCers = std::map<unsigned int, BytesVector>;

// forward declaration
class Message;

// forward declaration
namespace checks {
class BesChecks;
} // namespace checks

} // namespace pdfcsp::csp