#pragma once

#include <cstdint>

namespace zip_cpp {

inline bool checkFlag(uint64_t val, uint64_t flag) { return (val & flag) != 0; }

}  // namespace zip_cpp