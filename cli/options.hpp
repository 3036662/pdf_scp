/* File: options.hpp
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

#pragma once

#include <spdlog/spdlog.h>

#include <boost/algorithm/string.hpp>
#include <boost/program_options.hpp>
#include <string>

namespace pdfcsp::cli {

namespace po = boost::program_options;

const char *const kInputFileTag = "input-file,i";
const char *const kInputFileTagL = "input-file";
const char *const kHelpTag = "help,h";
const char *const kHelpTagL = "help";
const char *const kPageNumberTag = "page-number,p";
const char *const kPageNumberTagL = "page-number";

const char *const kXTag = "x,X";
const char *const kXTagL = "x";
const char *const kYTag = "y,Y";
const char *const kYTagL = "y";
const char *const kWidthTag = "width,W";
const char *const kWidthTagL = "width";
const char *const kHeightTag = "height,H";
const char *const kHeightTagL = "height";
const char *const kLogoTag = "logo,l";
const char *const kOutputDIRTag = "output-dir,d";
const char *const kOutputDIRTagL = "output-dir";
const char *const kOutputPostfixTag = "output-file-postfix,P";
const char *const KCadesTypeTag = "cades,c";
const char *const KCadesTypeTagL = "cades";
const char *const KTSPLinkTag = "tsp,t";
const char *const KTSPLinkTagL = "tsp";
const char *const kError = "Error:";

class Options {
 public:
  Options(int argc, char **&argv, std::shared_ptr<spdlog::logger> logger);

  [[nodiscard]] bool help() const;
  [[nodiscard]] bool AllMandatoryAreSet() const;
  [[nodiscard]] bool WrongParams() const { return wrong_params_; }

  [[nodiscard]] std::vector<std::string> GetInputFiles() const;

 private:
  [[nodiscard]] std::string ResolvePath(const std::string &path) const;

  std::shared_ptr<spdlog::logger> log_;
  po::positional_options_description pos_opt_desc_;
  po::options_description description_;
  bool wrong_params_ = false;
  po::variables_map var_map_;
};

}  // namespace pdfcsp::cli