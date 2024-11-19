#pragma once
#include <cstdint>
constexpr uint64_t kMaxPdfFileSize = 2147483648; //  2GB

#define LIB_API __attribute__((visibility("default")))
#define LIB_LOCAL __attribute__((visibility("hidden")))

// string error codes for qml frontend
const char *const kErrExpiredCert = "CERT_EXPIRED";
const char *const kErrMayBeTspInvalid = "MAYBE_TSP_URL_INVALID";