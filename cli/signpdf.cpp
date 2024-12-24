/* File: signpdf.cpp
Copyright (C) Basealt LLC,  2024
Author: Oleg Proskurin, <proskurinov@basealt.ru>

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public License
along with this program; if not, write to the Free Software Foundation,
Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

#include <libintl.h>
#include <spdlog/sinks/stdout_color_sinks.h>

#include <cstddef>
#include <exception>
#include <iostream>
#include <memory>

#include "altcsp.hpp"
#include "cli_utils.hpp"
#include "image_obj.hpp"
#include "options.hpp"
#include "pdf_csp_c.hpp"
#include "pdf_pod_structs.hpp"
#include "tr.hpp"

int main(int argc, char* argv[]) {
  using pdfcsp::cli::tr;
  using pdfcsp::cli::trs;
  // setup the transtlator
  if (setlocale(LC_ALL, "") == nullptr) {  // NOLINT
    std::cerr << "Failed to set locale.\n";
    return 1;
  }
  bindtextdomain(TRANSLATION_DOMAIN, TRANSLATIONS_INSTALL_DIR);
  bind_textdomain_codeset(TRANSLATION_DOMAIN, "UTF-8");
  textdomain(TRANSLATION_DOMAIN);
  try {
    // ----------------
    // setup logging
    auto console = spdlog::stdout_color_mt(TRANSLATION_DOMAIN);
    if (!console) {
      std::cerr << pdfcsp::cli::tr("Setup logger failed");
    }
    const pdfcsp::cli::Options options(argc, argv, console);
    if (options.help()) {
      return 0;
    }
    auto input_files = options.GetInputFiles();
    const bool files_ok = pdfcsp::cli::CheckInputFiles(input_files, console);
    if (files_ok) {
      console->info(tr("Files are OK"));
    } else {
      console->error(tr("Files are not OK"));
      return 1;
    }
    const std::string output_dir = options.GetOutputDir();
    const bool output_dir_ok = pdfcsp::cli::CheckOutputDir(output_dir, console);
    if (output_dir_ok) {
      console->info(tr("Output directory is OK"));
    } else {
      console->error(tr("Output directory is not OK"));
    }
    // ----------------
    // check the certificate
    auto csp = std::make_shared<pdfcsp::csp::Csp>();
    {
      // check the certificate
      const bool cert_is_ok =
        pdfcsp::cli::CheckCertSerial(options.GetCertSerial(), csp, console);
      if (cert_is_ok) {
        console->info(tr("Certificate is OK"));
      } else {
        console->error(tr("Certificate is not OK"));
      }
    }
    // ----------------
    // sign files
    std::shared_ptr<pdfcsp::pdf::ImageObj> cached_img;
    size_t succeeded_count = 0;
    for (const auto& src_file : input_files) {
      console->debug(trs("Processing file ") + src_file);
      pdfcsp::pdf::CSignPrepareResult* result = pdfcsp::cli::PerformSign(
        src_file, options, csp, console, cached_img.get());
      if (result != nullptr && result->status) {
        ++succeeded_count;
        // if after first call wi have the image object cached
        if (result->storage->cached_img) {
          cached_img = std::move(result->storage->cached_img);
          console->debug(tr("Image object was cached"));
        }
      }
      pdfcsp::pdf::FreePrepareDocResult(result);
    }
    // return 0 if all files succeeded
    return succeeded_count == input_files.size() ? 0 : 1;
  } catch (const std::exception& ex) {
    std::cerr << pdfcsp::cli::tr("Error:") << ex.what() << "\n";
    return 1;
  }
  return 0;
}