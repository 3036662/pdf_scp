#pragma once

#include <cstdint>
#include <string>
#include <vector>
namespace pdfcsp::pdf {

struct CSignParams {
  int page_index = 0;
  double page_width = 0;
  double page_height = 0;
  double stamp_x = 0;
  double stamp_y = 0;
  double stamp_width = 0;
  double stamp_height = 0;
  const char *logo_path = nullptr;
  const char *config_path = nullptr;
  const char *cert_serial = nullptr;
  const char *cert_subject = nullptr;
  const char *cert_time_validity = nullptr;
  const char *stamp_type = nullptr;
  const char *cades_type = nullptr; /// CADES_BES or CADES_T or CADES_XLT1
  const char *file_to_sign_path = nullptr;
  const char *temp_dir_path = nullptr;
  const char *tsp_link = nullptr;
};

struct CSignPrepareResult {
  struct SignResStorage {
    std::string file_path;
    std::string err_string;
  };

  bool status = false;
  const char *tmp_file_path = nullptr;
  const char *err_string = nullptr;
  SignResStorage *storage = nullptr;
};

} // namespace pdfcsp::pdf