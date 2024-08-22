#pragma once

#include "check_result.hpp"
namespace pdfcsp::csp::checks {

class ICheckStrategy {
public:
  ICheckStrategy() = default;
  ICheckStrategy(const ICheckStrategy &) = default;
  ICheckStrategy(ICheckStrategy &&) = default;
  ICheckStrategy &operator=(const ICheckStrategy &) = default;
  ICheckStrategy &operator=(ICheckStrategy &&) = default;

  virtual ~ICheckStrategy() = default;
  virtual const CheckResult &All(const BytesVector &data) noexcept = 0;
};

} // namespace pdfcsp::csp::checks