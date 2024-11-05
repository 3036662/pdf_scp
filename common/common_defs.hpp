#pragma  once
#include <cstdint>
constexpr uint64_t kMaxPdfFileSize=2147483648; //  2GB


#define LIB_API __attribute__((visibility("default")))
#define LIB_LOCAL __attribute__((visibility("hidden")))

const char* const kErrExpiredCert="Expired certificate";
const char* const kErrMayBeTspInvalid="Error,may be the TSP url is invalid";