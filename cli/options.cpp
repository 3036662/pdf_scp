#include "options.hpp"
#include "tr.hpp"
// #include <boost/locale.hpp>
// #include <boost/locale/message.hpp>
#include <boost/program_options/value_semantic.hpp>
#include <filesystem>
#include <iostream>
#include <string>
#include <vector>

namespace pdfcsp::cli {

Options::Options(int argc, char **&argv) : description_(tr("Allowed options")) {
  description_.add_options()
      // clang-format off
      (kHelpTag, tr("produce this help message"))
      (kInputFileTag, po::value<std::vector<std::string>>(),tr("input file"))
      (kPageNumberTag,po::value<uint>(),tr("page number"))
      (kXTag,po::value<uint>(),tr("Stamp X coordianate"))
      (kYTag,po::value<uint>(),tr("Stamp Y coordianate"))
      (kWidthTag,po::value<uint>(),tr("Stamp width"))
      (kHeightTag,po::value<uint>(),tr("Stamp height"))
      (kLogoTag,po::value<std::string>(),tr("Logo file (BMP,PNG)"))
      (kOutputDIRTag,po::value<std::string>(),tr("Outpur directory"))
      (kOutputPostfixTag,po::value<std::string>(),tr("Postfix to add to the filename"))
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
    std::cerr << tr("Wrong parameters, see --help") << "\n";
    wrong_params_ = true;
  } catch (boost::wrapexcept<boost::program_options::unknown_option> &ex) {
    std::cerr << tr("Unknown option passed.") << "\n" << ex.what() << "\n";
    wrong_params_ = true;
  } catch (
      const boost::wrapexcept<boost::program_options::ambiguous_option> &ex) {
    wrong_params_ = true;
    std::cerr << tr("Ambiguous option passed,use - for short options and -- "
                    "for full otions,--help for help")
              << "\n";
  }
}

bool Options::help() const {
  std::cout << tr("A tool for signing a PDF file") << "\n";
  if (var_map_.empty() || var_map_.count(kHelpTagL) > 0 || wrong_params_) {
    // clang-format off
    std::cout << tr("Usage") << ": " 
              << TRANSLATION_DOMAIN << " "
              << "--page-number 1"
              << " --x 100 --y 100"
              << " --width 900 --height 300"
              << " --logo ./logo.bpm"
              << " --output-dir ./signed_docs"
              << " -P _signed" 
              << " source_file1.pdf source_file2.pdf\n";
    std::cout << description_ << "\n";
    // clang-format on
    return true;
  }
  return false;
}

std::string Options::ResolvePath(const std::string &path) {
  std::string local_path = path;
  std::string current_path = std::filesystem::current_path();
  current_path += "/";
  std::string home_path = std::filesystem::path(getenv("HOME")); // NOLINT
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
    std::cerr << err_code.message();
  }
  local_path = fs_path;
  return local_path;
}

bool Options::AllMandatoryAreSet() const {
  if (var_map_.count(kInputFileTagL) == 0) {
    std::cerr << tr("No input files are set") << "\n";
    return false;
  }
  if (var_map_.count(kPageNumberTagL) == 0) {
    std::cerr << tr("No page number is set") << "\n";
    return false;
  }
  if (var_map_.count(kXTagL) == 0) {
    std::cerr << tr("No X coordinate is set") << "\n";
    return false;
  }
  if (var_map_.count(kYTagY) == 0) {
    std::cerr << tr("No Y coordinate is set") << "\n";
    return false;
  }
  if (var_map_.count(kWidthTagL) == 0) {
    std::cerr << tr("No stamp width is set") << "\n";
    return false;
  }
  if (var_map_.count(kHeightTagL) == 0) {
    std::cerr << tr("No stamp height is set") << "\n";
    return false;
  }
  if (var_map_.count(kOutputDIRTagL) == 0) {
    std::cerr << tr("No output-dir is set") << "\n";
    return false;
  }
  return true;
}

} // namespace pdfcsp::cli