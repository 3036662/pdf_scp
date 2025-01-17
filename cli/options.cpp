/* File: options.cpp
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

#include "options.hpp"

#include "tr.hpp"
// #include <boost/locale.hpp>
// #include <boost/locale/message.hpp>
#include <algorithm>
#include <boost/algorithm/string/predicate.hpp>
#include <boost/program_options/value_semantic.hpp>
#include <cmath>
#include <filesystem>
#include <iostream>
#include <limits>
#include <string>
#include <utility>
#include <vector>

namespace pdfcsp::cli {

Options::Options(int argc, char **&argv, std::shared_ptr<spdlog::logger> logger)
  : log_(std::move(logger)), description_(tr("Allowed options")) {
  description_.add_options()
    // clang-format off
      (kHelpTag, tr("produce this help message"))
      (kInputFileTag, po::value<std::vector<std::string>>(),tr("input file"))
      (kPageNumberTag,po::value<double>(),tr("page number"))
      (kXTag,po::value<double>(),tr("Stamp X coordianate"))
      (kYTag,po::value<double>(),tr("Stamp Y coordianate"))
      (kWidthTag,po::value<double>(),tr("Stamp width"))
      //(kHeightTag,po::value<double>(),tr("Stamp height ( default = width/3 )"))
      (kLogoTag,po::value<std::string>(),tr("Logo file (BMP,PNG)"))
      (kOutputDIRTag,po::value<std::string>(),tr("Outpur directory"))
      (kOutputPostfixTag,po::value<std::string>(),tr("Postfix to add to the filename"))
      (KCadesTypeTag,po::value<std::string>(),tr("CADES type: BES or T or X"))
      (KTSPLinkTag,po::value<std::string>(),tr("TSP URL"))
      (kCertTag,po::value<std::string>(),tr("Certificate's serial number"));
      ;
  // clang-format on
  try {
    pos_opt_desc_.add(kInputFileTagL, -1);
    po::store(po::command_line_parser(argc, argv)
                .options(description_)
                .positional(pos_opt_desc_)
                .run(),
              var_map_);
    po::notify(var_map_);
  } catch (
    boost::wrapexcept<boost::program_options::invalid_command_line_syntax>
      & /*ex*/) {
    log_->error(tr("Wrong parameters, see --help"));
    wrong_params_ = true;
  } catch (boost::wrapexcept<boost::program_options::unknown_option> &ex) {
    log_->error(trs("Unknown option passed.") + ex.what());
    wrong_params_ = true;
  } catch (
    const boost::wrapexcept<boost::program_options::ambiguous_option> &ex) {
    wrong_params_ = true;
    log_->error(
      tr("Ambiguous option passed,use - for short options and -- "
         "for full otions,--help for help"));
  }
}

bool Options::help() const {
  std::cout << tr("A tool for signing a PDF file") << "\n";
  if (var_map_.empty() || var_map_.count(kHelpTagL) > 0 || wrong_params_ ||
      !AllMandatoryAreSet()) {
    // clang-format off
    std::cout << tr("Usage") << ": " 
              << TRANSLATION_DOMAIN << " "
              << "--page-number 1"
              << " --x 10 --y 10"
              << " --width 43"
              << " --logo ./logo.bpm"
              << " --output-dir ./signed_docs"
              << " -P _signed" 
              << " --cades T"
              << " --tsp http:://tsp.srf"
              << " --certificate 234aa5439aa85429ed85"
              << " source_file1.pdf source_file2.pdf\n";
    std::cout << description_ << "\n";
    // clang-format on
    return true;
  }
  return false;
}

std::string Options::ResolvePath(const std::string &path) const {
  std::string local_path = path;
  std::string current_path = std::filesystem::current_path();
  current_path += "/";
  std::string home_path = std::filesystem::path(getenv("HOME"));  // NOLINT
  home_path += "/";
  if (local_path.empty() || local_path == ".") {
    local_path = std::filesystem::current_path();
  }
  if (boost::starts_with(local_path, "./")) {
    boost::replace_first(local_path, "./", current_path);
  }
  if (boost::starts_with(local_path, "~/")) {
    boost::replace_first(local_path, "~/", home_path);
  }
  std::filesystem::path fs_path = local_path;
  std::error_code err_code;
  fs_path = std::filesystem::absolute(fs_path, err_code);
  if (err_code) {
    log_->error(err_code.message());
  }
  local_path = fs_path;
  return local_path;
}

bool Options::AllMandatoryAreSet() const {
  if (var_map_.count(kInputFileTagL) == 0) {
    log_->error(tr("No input files are set"));
  }
  if (var_map_.count(kPageNumberTagL) == 0) {
    log_->error(tr("No page number is set"));
    return false;
  }
  const double page_n = var_map_.at(kPageNumberTagL).as<double>();
  if (page_n <= 0 || std::floor(page_n) != page_n) {
    log_->error(tr("Page number should be positive integer greater than null"));
    return false;
  }
  if (var_map_.count(kXTagL) == 0) {
    log_->error(tr("No X coordinate is set"));
    return false;
  }
  if (var_map_.count(kYTagL) == 0) {
    log_->error(tr("No Y coordinate is set"));
    return false;
  }
  if (var_map_.count(kWidthTagL) == 0) {
    log_->error(tr("No stamp width is set"));
    return false;
  }
  // if (var_map_.count(kHeightTagL) == 0) {
  //   log_->error(tr("No stamp height is set"));
  //   return false;
  // }
  const double x_coord = var_map_.at(kXTagL).as<double>();
  const double y_coord = var_map_.at(kYTagL).as<double>();
  const double w_stamp = var_map_.at(kWidthTagL).as<double>();
  double h_stamp = var_map_.count(kHeightTagL) > 0
                     ? var_map_.at(kHeightTagL).as<double>()
                     : std::floor(w_stamp / 3);
  if (h_stamp == 0) {
    h_stamp = w_stamp;
  }
  if (x_coord <= 0 || y_coord <= 0 || w_stamp <= 0 || h_stamp <= 0 ||
      std::floor(x_coord) != x_coord || std::floor(y_coord) != y_coord ||
      std::floor(w_stamp) != w_stamp || std::floor(h_stamp) != h_stamp ||
      x_coord > 100 || y_coord > 100 || w_stamp > 100 || h_stamp > 100) {
    log_->error(
      tr("All sizes and coordinates should be positive integer between 1 and "
         "100"));
    return false;
  }
  // check size and position
  if (x_coord + w_stamp > 100) {
    log_->error(tr("Invalid horizontal position of the stamp"));
    return false;
  }
  if (y_coord + h_stamp > 100) {
    log_->error(tr("Invalid vertical position of the stamp"));
    return false;
  }
  if (var_map_.count(kOutputDIRTagL) == 0) {
    log_->error(tr("No output-dir is set"));
    return false;
  }
  if (var_map_.count(KCadesTypeTagL) == 0) {
    log_->error(tr("No CADES type is set"));
    return false;
  }
  const std::string cades_type = var_map_.at(KCadesTypeTagL).as<std::string>();
  if (cades_type != "BES" && cades_type != "T" && cades_type != "X") {
    log_->error(tr("CADES message type is expected to be: BES or T or X"));
    return false;
  }
  if (cades_type != "BES" && var_map_.count(KTSPLinkTagL) == 0) {
    log_->error(tr("No TSP URL is set"));
    return false;
  }
  if (var_map_.count(kOutputPostfixTagL) > 0 &&
      boost::contains(var_map_.at(kOutputPostfixTagL).as<std::string>(), "/")) {
    log_->error(tr("File postfix can not contain / symbol"));
    return false;
  }
  if (var_map_.count(kLogoTagL) > 0 &&
      !std::filesystem::exists(
        ResolvePath(var_map_.at(kLogoTagL).as<std::string>()))) {
    log_->error(trs("Logo file not found") + " " +
                ResolvePath(var_map_.at(kLogoTagL).as<std::string>()));
    return false;
  }
  if (var_map_.count(kCertTagL) == 0) {
    log_->error(tr("Certificate's serial number is not set"));
    return false;
  }
  return true;
}

std::vector<std::string> Options::GetInputFiles() const {
  if (var_map_.count(kInputFileTagL) > 0) {
    auto files_list =
      var_map_.at(kInputFileTagL).as<std::vector<std::string>>();
    std::for_each(
      files_list.begin(), files_list.end(),
      [this](std::string &file_name) { file_name = ResolvePath(file_name); });
    return files_list;
  }
  return {};
}

[[nodiscard]] std::string Options::GetOutputDir() const {
  if (var_map_.count(kOutputDIRTagL) == 0) {
    return {};
  }
  std::string res = ResolvePath(var_map_.at(kOutputDIRTagL).as<std::string>());
  if (!res.empty() && res.back() != '/') {
    res.push_back('/');
  }
  return res;
}

[[nodiscard]] std::string Options::GetCertSerial() const {
  if (var_map_.count(kCertTagL) == 0) {
    return {};
  }
  std::string cert = var_map_.at(kCertTagL).as<std::string>();
  std::transform(cert.begin(), cert.end(), cert.begin(),
                 [](unsigned char symbol) { return std::tolower(symbol); });
  return cert;
}

int Options::GetPageNumber() const {
  const char *expl = "Page number not found, using first page";
  if (var_map_.count(kPageNumberTagL) == 0) {
    log_->warn(tr(expl));
    return 1;
  }
  const double page_index = var_map_.at(kPageNumberTagL).as<double>();
  if (page_index > std::numeric_limits<int>::max() || page_index < 0) {
    log_->warn(tr(expl));
    return 1;
  }
  return static_cast<int>(page_index);
};

std::pair<double, double> Options::GetStampXYPercent() const {
  if (var_map_.count(kXTagL) == 0 || var_map_.count(kYTagL) == 0) {
    log_->warn(
      tr("Stamp coordinates not found, default value 10,10 will be used"));
    return {10.0, 10.0};
  }
  return std::make_pair(var_map_.at(kXTagL).as<double>(),
                        var_map_.at(kYTagL).as<double>());
}

std::pair<double, double> Options::GetStampSizePercent() const {
  if (var_map_.count(kWidthTagL) == 0 && var_map_.count(kHeightTagL) == 0) {
    log_->warn(tr("Stamp size not found, default value 43,10 will be used"));
    return {43.0, 10.0};
  }
  if (var_map_.count(kWidthTagL) != 0 && var_map_.count(kHeightTagL) == 0) {
    log_->debug(
      tr("Stamp height was not set, default value width/3 will be used"));
    return std::make_pair(var_map_.at(kWidthTagL).as<double>(),
                          var_map_.at(kWidthTagL).as<double>() / 3);
  }
  return std::make_pair(var_map_.at(kWidthTagL).as<double>(),
                        var_map_.at(kHeightTagL).as<double>());
}

std::string Options::GetLogoPath() const {
  if (var_map_.count(kLogoTagL) == 0) {
    return {};
  }
  return ResolvePath(var_map_.at(kLogoTagL).as<std::string>());
}

std::string Options::GetCadesType() const {
  if (var_map_.count(KCadesTypeTagL) == 0) {
    log_->warn("CADES type was not found, devault type BES will be used");
    return "CADES_BES";
  }
  const std::string cades_param = var_map_.at(KCadesTypeTagL).as<std::string>();
  if (cades_param == "BES") {
    return "CADES_BES";
  }
  if (cades_param == "T") {
    return "CADES_T";
  }
  if (cades_param == "X") {
    return "CADES_XLT1";
  }
  return "CADES_BES";
}

std::string Options::GetTSPLink() const {
  if (var_map_.count(KTSPLinkTagL) == 0) {
    return {};
  }
  return var_map_.at(KTSPLinkTagL).as<std::string>();
}

std::string Options::GetNamePostifx() const {
  if (var_map_.count(kOutputPostfixTagL) == 0) {
    return {};
  }
  return var_map_.at(kOutputPostfixTagL).as<std::string>();
}

}  // namespace pdfcsp::cli