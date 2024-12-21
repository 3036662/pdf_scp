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
#include <string>
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
      (kHeightTag,po::value<double>(),tr("Stamp height"))
      (kLogoTag,po::value<std::string>(),tr("Logo file (BMP,PNG)"))
      (kOutputDIRTag,po::value<std::string>(),tr("Outpur directory"))
      (kOutputPostfixTag,po::value<std::string>(),tr("Postfix to add to the filename"))
      (KCadesTypeTag,po::value<std::string>(),tr("CADES type: BES or T or X"))
      (KTSPLinkTag,po::value<std::string>(),tr("TSP URL"));
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
              << " --x 100 --y 100"
              << " --width 900 --height 300"
              << " --logo ./logo.bpm"
              << " --output-dir ./signed_docs"
              << " -P _signed" 
              << " --cades T"
              << " --tsp http:://tsp.srf"
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
  if (var_map_.count(kHeightTagL) == 0) {
    log_->error(tr("No stamp height is set"));
    return false;
  }
  const double x_coord = var_map_.at(kXTagL).as<double>();
  const double y_coord = var_map_.at(kYTagL).as<double>();
  const double w_stamp = var_map_.at(kWidthTagL).as<double>();
  const double h_stamp = var_map_.at(kHeightTagL).as<double>();
  if (x_coord <= 0 || y_coord <= 0 || w_stamp <= 0 || h_stamp <= 0 ||
      std::floor(x_coord) != x_coord || std::floor(y_coord) != y_coord ||
      std::floor(w_stamp) != w_stamp || std::floor(h_stamp) != h_stamp) {
    log_->error(
      tr("All sizes and coordinates should be positive integer greater than "
         "null"));
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
  return ResolvePath(var_map_.at(kOutputDIRTagL).as<std::string>());
}

}  // namespace pdfcsp::cli