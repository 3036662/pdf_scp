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

#include <exception>
#include <iostream>

#include "cli_utils.hpp"
#include "options.hpp"
#include "tr.hpp"

int main(int argc, char* argv[]) {
  using pdfcsp::cli::tr;
  using pdfcsp::cli::trs;
  // setup the transtlator
  if (setlocale(LC_ALL, "") == nullptr) {  // NOLINT
    std::cerr << "Failed to set locale.\n";
    return 1;
  }
  bindtextdomain(TRANSLATION_DOMAIN, TRANSLATIONS_DIR_COMPILED);
  bind_textdomain_codeset(TRANSLATION_DOMAIN, "UTF-8");
  textdomain(TRANSLATION_DOMAIN);
  // print help
  try {
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
    // for (const auto& file_name : input_files) {
    //   std::cout << file_name << "\n";
    //   ;
    // }
  } catch (const std::exception& ex) {
    std::cerr << pdfcsp::cli::tr("Error:") << ex.what() << "\n";
    return 1;
  }

  return 0;
}